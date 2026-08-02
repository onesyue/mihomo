package route

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
)

// `server_lifecycle_test.go` 只走了 `start`（普通 HTTP 监听）。清单 §5 把
// `startTLS` / `startUnix` / `startPipe` 记成**剩余缺口**，理由是「它们与 start 同构」——
// 但同构不是被测过：fork 的第二条不可退回是 **Shutdown 必须释放全部 listener**，
// 而「全部」恰恰是只测一条时永远测不到的那个字。
// 只关 httpServer、把另外三个漏掉的实现，能让 `server_lifecycle_test.go` 全绿。
//
// 本文件补的就是这三条分支，外加一条把四种监听同时拉起来、一次 Shutdown
// 全部释放的合测——那条才是「全部」这个词的机器判据。
//
// 与 `server_lifecycle_test.go` 同理：server 变量是包级的，不能 t.Parallel()。

// settleAsyncStart 给 ReCreateServer 派出的 goroutine 一点时间去做它可能做的事。
// 只用在「断言它什么都没做」的用例里——有事可等的用例一律用 waitListening/waitUnix。
const settleAsyncStart = 150 * time.Millisecond

// serverStates 在锁下快照四个包级 server 变量是否为 nil。
// 早退分支（空 Addr、非法 pipe 名）的直接判据。
func serverStates() (httpNil, tlsNil, unixNil, pipeNil bool) {
	serverMu.Lock()
	defer serverMu.Unlock()
	return httpServer == nil, tlsServer == nil, unixServer == nil, pipeServer == nil
}

// waitUnix 等到 unix socket 真的可连。
func waitUnix(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("外部控制器在 5s 内没有在 unix socket %s 上监听起来", addr)
}

// mustNotDialUnix 断言 unix socket 此刻连不上 = listener 已经关掉。
//
// 这里**不能**用「能不能重新 bind」当判据：startUnix 在 Listen 之前会先
// syscall.Unlink，所以就算旧 listener 还活着，重新 bind 一样会成功——
// 用 rebind 判 unix 的话，漏关 unixServer 也照样绿。
func mustNotDialUnix(t *testing.T, addr, when string) {
	t.Helper()
	conn, err := net.DialTimeout("unix", addr, 200*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("%s：unix socket %s 仍然可连，listener 没被 Shutdown 关掉", when, addr)
	}
}

// ── startTLS ────────────────────────────────────────────────────────────────

// Certificate/PrivateKey 都留空时 ca.NewTLSKeyPairLoader 会现生成一对随机 RSA，
// 所以这些用例不需要任何证书夹具。

// Shutdown() 对 TLS 监听同样必须是同步的：返回即端口可重新 bind。
func TestShutdownReleasesTLSPortSynchronously(t *testing.T) {
	addr := freeAddr(t)

	ReCreateServer(&Config{TLSAddr: addr})
	waitListening(t, addr)

	Shutdown()
	// 同 server_lifecycle_test.go：不 sleep、不轮询，否则异步关停会被掩盖。
	mustRebind(t, addr, "Shutdown() 刚返回（TLS）")
}

// 桌面端切模式 = StopCore→StartCore 且复用同一端口。TLS 分支同样要经得起连做。
func TestStopCoreThenStartCoreRebindsSameTLSPort(t *testing.T) {
	addr := freeAddr(t)

	for i := 1; i <= 3; i++ {
		t.Run(fmt.Sprintf("第%d轮", i), func(t *testing.T) {
			ReCreateServer(&Config{TLSAddr: addr})
			waitListening(t, addr)
			Shutdown()
			mustRebind(t, addr, fmt.Sprintf("第 %d 轮 StopCore 之后（TLS）", i))
		})
	}
}

// 钉住 startTLS 里 `len(cfg.TLSAddr) == 0` 的提前返回：不监听、不建 server。
func TestEmptyTLSAddrStartsNothing(t *testing.T) {
	probe := freeAddr(t)

	ReCreateServer(&Config{TLSAddr: ""})
	time.Sleep(settleAsyncStart)
	_, tlsNil, _, _ := serverStates()
	if !tlsNil {
		t.Fatal("空 TLSAddr 却建出了 tlsServer")
	}
	Shutdown()

	mustRebind(t, probe, "空 TLSAddr 配置之后")
}

// ── startUnix ───────────────────────────────────────────────────────────────

func unixAddr(t *testing.T) string {
	t.Helper()
	// sockaddr_un.sun_path 只有 ~104 字节。t.TempDir() 会把**测试函数名**拼进
	// 路径，在 macOS 的 /var/folders/... 前缀下直接超限，bind 报 EINVAL——
	// 看起来像「监听没起来」，实际是路径太长。所以自己在 /tmp 下开短目录。
	dir, err := os.MkdirTemp("/tmp", "ylr")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "a.sock")
}

// Shutdown() 必须同步关掉 unix listener：返回即已连不上。
func TestShutdownReleasesUnixListenerSynchronously(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 上 AF_UNIX 支持随版本而异，不在此断言")
	}
	addr := unixAddr(t)

	ReCreateServer(&Config{UnixAddr: addr})
	waitUnix(t, addr)

	Shutdown()
	mustNotDialUnix(t, addr, "Shutdown() 刚返回（unix）")
}

// 同一个 socket 路径连做多轮 StopCore→StartCore。
func TestStopCoreThenStartCoreReusesSameUnixPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 上 AF_UNIX 支持随版本而异，不在此断言")
	}
	addr := unixAddr(t)

	for i := 1; i <= 3; i++ {
		t.Run(fmt.Sprintf("第%d轮", i), func(t *testing.T) {
			ReCreateServer(&Config{UnixAddr: addr})
			waitUnix(t, addr)
			Shutdown()
			mustNotDialUnix(t, addr, fmt.Sprintf("第 %d 轮 StopCore 之后（unix）", i))
		})
	}
}

// 钉住 startUnix 里 `len(cfg.UnixAddr) == 0` 的提前返回。
func TestEmptyUnixAddrStartsNothing(t *testing.T) {
	ReCreateServer(&Config{UnixAddr: ""})
	time.Sleep(settleAsyncStart)
	_, _, unixNil, _ := serverStates()
	if !unixNil {
		t.Fatal("空 UnixAddr 却建出了 unixServer")
	}
	Shutdown()
}

// ── startPipe ───────────────────────────────────────────────────────────────

// startPipe 只在 inbound.SupportNamedPipe（= Windows）时被 ReCreateServer 派出，
// 所以下面两条**直接调 startPipe**，让非 Windows 也能覆盖它的早退分支。
// 非 Windows 上 inbound.ListenNamedPipe 返回 os.ErrInvalid，正好是「listen 失败」那条。

// 非 `\\.\pipe\` 前缀必须被拒绝，且不得留下 pipeServer。
func TestStartPipeRejectsNonPipeAddr(t *testing.T) {
	startPipe(&Config{PipeAddr: "/tmp/not-a-named-pipe"})
	if _, _, _, pipeNil := serverStates(); !pipeNil {
		t.Fatal("非法 pipe 名却建出了 pipeServer")
	}
	Shutdown()
}

// 钉住 startPipe 里 `len(cfg.PipeAddr) == 0` 的提前返回。
func TestEmptyPipeAddrStartsNothing(t *testing.T) {
	startPipe(&Config{PipeAddr: ""})
	if _, _, _, pipeNil := serverStates(); !pipeNil {
		t.Fatal("空 PipeAddr 却建出了 pipeServer")
	}
	Shutdown()
}

// listen 本身失败时（非 Windows 恒失败）不得 panic，也不得留下 pipeServer。
func TestStartPipeListenFailureLeavesNoServer(t *testing.T) {
	if inbound.SupportNamedPipe {
		t.Skip("Windows 上这个地址会真的 bind 成功，改由下面那条覆盖")
	}
	startPipe(&Config{PipeAddr: `\\.\pipe\yuelink-test`})
	if _, _, _, pipeNil := serverStates(); !pipeNil {
		t.Fatal("pipe listen 失败后却留下了 pipeServer")
	}
	Shutdown()
}

// Windows 上走真实 bind：Shutdown 必须同步关掉 pipe listener。
//
// ⚠️ **只有 Windows runner 能验证这条。** 2026-08-02 在 macOS 上做变异测试
// （把 Shutdown 里关 pipeServer 那段删掉）实测**全绿**——非 Windows 平台
// pipeServer 恒为 nil，删掉也没人察觉。TLS/unix 两种变异则每次都红。
// 所以 `Shutdown` 漏关 pipe 这一种，在 macOS/Linux 上是**测不出来**的，
// 别把本地全绿当成四条都被守住了。
func TestShutdownReleasesPipeListener(t *testing.T) {
	if !inbound.SupportNamedPipe {
		t.Skip("非 Windows 平台没有命名管道")
	}
	addr := fmt.Sprintf(`\\.\pipe\yuelink-route-test-%d`, time.Now().UnixNano())

	ReCreateServer(&Config{PipeAddr: addr})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, _, _, pipeNil := serverStates(); !pipeNil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("命名管道 %s 在 5s 内没起来", addr)
		}
		time.Sleep(10 * time.Millisecond)
	}

	Shutdown()
	if _, _, _, pipeNil := serverStates(); !pipeNil {
		t.Fatal("Shutdown 之后 pipeServer 仍不为 nil")
	}
	// 同名管道能再建一次 = 上一个真的释放了。
	ReCreateServer(&Config{PipeAddr: addr})
	time.Sleep(settleAsyncStart)
	if _, _, _, pipeNil := serverStates(); pipeNil {
		t.Fatalf("同名管道 %s 无法重建，上一轮的 listener 没释放", addr)
	}
	Shutdown()
}

// ── 全部 listener 一起 ───────────────────────────────────────────────────────

// fork 第二条不可退回的字面意思：**一次 Shutdown 释放全部 listener**。
//
// 🔑 这是本文件里唯一能抓「只关了其中一种」的用例。单独测 TLS/unix 的用例，
// 在「Shutdown 只关 httpServer」这种变异下会因为 http 那路没被拉起来而恰好
// 走不到冲突；只有把三种监听同时拉起来、只调一次 Shutdown，
// 漏关哪一种都会立刻现形。
func TestShutdownReleasesEveryListenerAtOnce(t *testing.T) {
	httpAddr := freeAddr(t)
	tlsAddr := freeAddr(t)
	cfg := &Config{Addr: httpAddr, TLSAddr: tlsAddr}
	if runtime.GOOS != "windows" {
		cfg.UnixAddr = unixAddr(t)
	}

	ReCreateServer(cfg)
	waitListening(t, httpAddr)
	waitListening(t, tlsAddr)
	if cfg.UnixAddr != "" {
		waitUnix(t, cfg.UnixAddr)
	}

	Shutdown()

	mustRebind(t, httpAddr, "一次 Shutdown 之后（http）")
	mustRebind(t, tlsAddr, "一次 Shutdown 之后（tls）")
	if cfg.UnixAddr != "" {
		mustNotDialUnix(t, cfg.UnixAddr, "一次 Shutdown 之后（unix）")
	}

	httpNil, tlsNil, unixNil, pipeNil := serverStates()
	if !httpNil || !tlsNil || !unixNil || !pipeNil {
		t.Fatalf("Shutdown 之后仍有 server 变量不为 nil: http=%v tls=%v unix=%v pipe=%v",
			!httpNil, !tlsNil, !unixNil, !pipeNil)
	}
}
