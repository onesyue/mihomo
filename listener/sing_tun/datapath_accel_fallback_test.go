package sing_tun

import (
	"errors"
	"os"
	"strings"
	"testing"

	tun "github.com/metacubex/sing-tun"
)

// 这组测试守的是一件在生产上无法观测、只能在这里钉住的事：iOS 的 NE extension
// 里没有桌面那条 Dart 自愈闩，所以一次被内核拒绝的 recvmsg_x sockopt 会直接变成
// 「隧道起不来」。降级必须发生在 Go 这一层。

type recordingFactory struct {
	calls []bool // 每次调用时 EXP_RecvMsgX 的取值
	fail  func(attempt int, opts tun.Options) error
}

func (f *recordingFactory) build(opts tun.Options, _ bool) (tun.Tun, error) {
	f.calls = append(f.calls, opts.EXP_RecvMsgX)
	if f.fail != nil {
		if err := f.fail(len(f.calls), opts); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

func TestRecvMsgXRejectionDowngradesInsteadOfFailingTheTunnel(t *testing.T) {
	sockoptErr := errors.New("SetsockoptInt UTUN_OPT_MAX_PENDING_PACKETS: invalid argument")
	f := &recordingFactory{fail: func(attempt int, opts tun.Options) error {
		if opts.EXP_RecvMsgX {
			return sockoptErr
		}
		return nil
	}}

	_, err := newTunWithDatapathAccelFallbackUsing(
		tun.Options{EXP_RecvMsgX: true}, false, f.build)
	if err != nil {
		t.Fatalf("一次被拒绝的 sockopt 不应让隧道起不来，实际 err=%v", err)
	}
	if len(f.calls) != 2 {
		t.Fatalf("期望降级重试一次（两次构造），实际构造了 %d 次: %v", len(f.calls), f.calls)
	}
	if !f.calls[0] {
		t.Error("第一次构造应当仍然带着 EXP_RecvMsgX —— 否则加速从未被尝试过")
	}
	if f.calls[1] {
		t.Error("重试必须关掉 EXP_RecvMsgX，否则它会用同一个必然失败的选项再撞一次")
	}
}

func TestDowngradeIsNotAttemptedWhenRecvMsgXWasNeverRequested(t *testing.T) {
	// 反向对照：没开加速时的失败是真失败，绝不能被这层重试掩盖成「试两次」。
	// 少了这条，一个「无论如何都重试一次」的实现也能让上一条通过。
	bootErr := errors.New("open /dev/net/tun: permission denied")
	f := &recordingFactory{fail: func(int, tun.Options) error { return bootErr }}

	_, err := newTunWithDatapathAccelFallbackUsing(
		tun.Options{EXP_RecvMsgX: false}, false, f.build)
	if !errors.Is(err, bootErr) {
		t.Fatalf("未开加速时必须原样返回原始错误，实际 %v", err)
	}
	if len(f.calls) != 1 {
		t.Fatalf("未开加速时不应有第二次构造，实际 %d 次", len(f.calls))
	}
}

func TestSuccessfulBuildWithRecvMsgXIsLeftAlone(t *testing.T) {
	f := &recordingFactory{}
	if _, err := newTunWithDatapathAccelFallbackUsing(
		tun.Options{EXP_RecvMsgX: true}, false, f.build); err != nil {
		t.Fatalf("成功路径不应被改写: %v", err)
	}
	if len(f.calls) != 1 {
		t.Fatalf("成功时不该重试，实际构造 %d 次", len(f.calls))
	}
	if !f.calls[0] {
		t.Error("成功路径必须保留 EXP_RecvMsgX —— 否则加速被无条件关掉了")
	}
}

func TestOriginalErrorSurvivesWhenTheDowngradeAlsoFails(t *testing.T) {
	// 降级也失败时，起因几乎肯定不是那个 sockopt。返回原始错误，别让这层重试的
	// 错误盖掉真正的原因 —— 那会把排查引向完全错误的方向。
	sockoptErr := errors.New("sockopt rejected")
	otherErr := errors.New("tun device busy")
	f := &recordingFactory{fail: func(attempt int, opts tun.Options) error {
		if opts.EXP_RecvMsgX {
			return sockoptErr
		}
		return otherErr
	}}

	_, err := newTunWithDatapathAccelFallbackUsing(
		tun.Options{EXP_RecvMsgX: true}, false, f.build)
	if !errors.Is(err, sockoptErr) {
		t.Fatalf("应返回原始错误 %v，实际 %v", sockoptErr, err)
	}
}

// TestListenerActuallyGoesThroughTheFallback 钉住**生产入口**。
//
// 上面四条测的是 newTunWithDatapathAccelFallbackUsing（注入 factory 的变体）。
// 它们全绿并不能证明监听器真的走这条路 —— 把 server.go 的调用改回裸
// tunNewForListener，上面四条照样全过。这正是「测试在自己体内复刻了被测机制」
// 那一族：判据必须是「生产代码调的是哪个入口」，不是「我搭的等价物行不行」。
func TestListenerActuallyGoesThroughTheFallback(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("读不到 server.go，守卫无法到达被测对象: %v", err)
	}
	body := string(src)

	const wired = "newTunWithDatapathAccelFallback(tunOptions"
	if !strings.Contains(body, wired) {
		t.Errorf("server.go 没有经过降级闩构造 TUN（找不到 %q）—— "+
			"iOS 的 NE extension 里没有 Dart 侧自愈闩，绕过这一层就意味着"+
			"一次被拒绝的 sockopt 直接等于隧道起不来。", wired)
	}
	if strings.Contains(body, "tunNewForListener(tunOptions") {
		t.Errorf("server.go 仍然直接调用 tunNewForListener(tunOptions —— " +
			"降级闩被绕过了")
	}
}
