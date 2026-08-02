package route

import (
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"
)

// fork 最大自改面（`d5ec9a35` +178 −54，配合 `listener` 的 `6402cae2`）的自动化覆盖。
//
// 背景见 `yuelink/docs/governance/mihomo-fork-rebase-checklist.md`：
// 这块是 fork 相对上游改得最多的地方，也是 rebase 时冲突面最集中的地方，
// 但清单 §5 记着它**至今没有 Go 测试**——只由「在桌面机上手工 StopCore→StartCore
// 看看端口有没有重绑失败」覆盖。而清单 §4 又明确说「编译过 ≠ 能用」。
// 结果就是：这个最该被守住的东西，恰恰只能靠人记得去手工点一遍。
//
// 这些测试把那道人工检查变成机器可判的断言，好让下一次 bump 上游时，
// 「同步 Shutdown + 释放全部 listener」这个意图**丢了会立刻红**，
// 而不是等到用户切一次模式才发现 `address already in use`。
//
// 注意：本包的 server 变量是**包级**的，这些用例因此不能 `t.Parallel()`。

// freeAddr 取一个当前空闲的回环地址。
// 先 Listen 再关掉，把端口号让出来——存在理论上的竞态窗口，但测试内无人竞争。
func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("取空闲端口失败: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("释放探测用监听失败: %v", err)
	}
	return addr
}

// waitListening 等到 addr 真的可连（ReCreateServer 是 `go start(cfg)`，异步起）。
func waitListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("外部控制器在 5s 内没有在 %s 上监听起来", addr)
}

// mustRebind 断言 addr 此刻确实不再被本进程的 listener 占着。
//
// 判据分两种，因为「能不能重新 bind」在 Windows 上根本不成立：
//
//   - **非 Windows**：直接重新 `net.Listen`。这是最强的判据，也是
//     `address already in use` 的正面反义。
//   - **Windows**：改判「此刻拨号必须失败」。
//
// 为什么 Windows 不能用 rebind（2026-08-02 实测定案）：`waitListening` 会先拨
// 一次探测连接，它关闭后在本地端口留下 TIME_WAIT。Linux/macOS 的 Go 给
// listener 默认设 SO_REUSEADDR，所以 TIME_WAIT 之上照样 bind 得回来；
// **Windows 的 Go 刻意不设**（在那里 SO_REUSEADDR 允许套接字劫持）。于是同一段
// 代码在 Windows 上会间歇性地报
// "Only one usage of each socket address ... is normally permitted" ——
// 报的是 TIME_WAIT，**不是没关掉的 listener**。
//
// 这不是推测：2026-08-02 第一次让这套测试在 Windows runner 上跑起来
// （在此之前 workflow 只在 `Alpha` 分支触发，本分叉的 `main` 从未跑过），
// 7 个 Go 版本里 5 个红、2 个绿，ubuntu / macos 全绿，红的全是这一条
// `TestShutdownReleasesPortSynchronously`。
//
// 换判据**没有放宽这条守卫**：listener 还开着就一定连得上，所以「立刻拨号必须
// 失败」同样能抓住「Shutdown 没关 listener」和「Shutdown 是异步的」这两种回归；
// 而 TIME_WAIT 状态的端口不接受新连接，不会造成假阳性。两条路径都**不重试**
// ——「Shutdown 返回即已释放」这条同步契约靠的就是不给它任何宽限时间。
func mustRebind(t *testing.T, addr, when string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			t.Fatalf("%s：%s 仍然可连，listener 没被 Shutdown 关掉\n"+
				"这正是 fork 的 Shutdown()/listener 关停要消灭的形态"+
				"（桌面端切模式 = StopCore→StartCore，漏释放一个 listener 下次启动就起不来）。",
				when, addr)
		}
		return
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("%s：端口 %s 仍被占用，无法重新 bind: %v\n"+
			"这正是 fork 的 Shutdown()/listener 关停要消灭的形态"+
			"（桌面端切模式 = StopCore→StartCore，漏释放一个 listener 下次启动就起不来）。",
			when, addr, err)
	}
	_ = l.Close()
}

// Shutdown() 必须是**同步**的：它一返回，端口就已经可以重新 bind。
//
// 这是 fork 注释里写死的契约（"returns only once all listeners are released,
// so an embedding host can StopCore→StartCore back to back safely"）。
// 上游原本的 `ReCreateServer(&Config{})` 走的是异步 goroutine，
// 快速 Shutdown→ReCreateServer 会让过期的 goroutine 关掉刚建好的 server——
// 那正是这 178 行要修的东西。
func TestShutdownReleasesPortSynchronously(t *testing.T) {
	addr := freeAddr(t)

	ReCreateServer(&Config{Addr: addr})
	waitListening(t, addr)

	Shutdown()
	// 关键：不 sleep、不轮询。Shutdown 返回即应已释放，
	// 加任何等待都会把「异步关停」这个 bug 掩盖掉。
	mustRebind(t, addr, "Shutdown() 刚返回")
}

// 桌面端最常见的动作：切模式 / 改配置 = StopCore→StartCore，且**用同一个端口**。
// 连做多轮，任何一轮漏释放都会在下一轮 bind 失败。
//
// 🔑 **这条是本文件里最可靠的探测器。** 2026-08-02 做变异测试（把 Shutdown 改回
// 上游那种异步关停）时实测：本条与 TestShutdownIsIdempotent **每次都红**，而上面那条
// 单发的 TestShutdownReleasesPortSynchronously **有时会侥幸绿**——异步 goroutine 偶尔
// 会在断言之前就被调度跑完。所以判断「同步关停这个性质还在不在」要看这条，
// 不要因为单发那条绿了就放心。
func TestStopCoreThenStartCoreRebindsSamePort(t *testing.T) {
	addr := freeAddr(t)

	for i := 1; i <= 3; i++ {
		t.Run(fmt.Sprintf("第%d轮", i), func(t *testing.T) {
			ReCreateServer(&Config{Addr: addr})
			waitListening(t, addr)
			Shutdown()
			mustRebind(t, addr, fmt.Sprintf("第 %d 轮 StopCore 之后", i))
		})
	}
}

// Shutdown() 必须幂等：桌面端存在「已经停了又停一次」的路径
// （用户连点、或关停流程与生命周期回调同时触发），第二次不得 panic。
func TestShutdownIsIdempotent(t *testing.T) {
	addr := freeAddr(t)

	ReCreateServer(&Config{Addr: addr})
	waitListening(t, addr)

	Shutdown()
	Shutdown() // 不得 panic（四个包级变量都已被置 nil）
	Shutdown()

	mustRebind(t, addr, "连续三次 Shutdown 之后")
}

// 从未启动过就 Shutdown 同样不得 panic（冷启动失败后的清理路径会这么走）。
func TestShutdownWithoutStartIsSafe(t *testing.T) {
	Shutdown()
	Shutdown()
}

// 空 Addr 不应该留下任何监听，也不应该让后续 Shutdown 出问题。
// 这条钉住 `start()` 里 `len(cfg.Addr) == 0` 那个提前返回分支。
func TestEmptyAddrStartsNothing(t *testing.T) {
	probe := freeAddr(t)

	ReCreateServer(&Config{Addr: ""})
	// 给异步 goroutine 一点时间去做它可能做的事，然后确认它没占任何端口。
	time.Sleep(100 * time.Millisecond)
	Shutdown()

	mustRebind(t, probe, "空 Addr 配置之后")
}
