package sing_tun

import (
	"github.com/metacubex/mihomo/log"

	tun "github.com/metacubex/sing-tun"
)

// newTunWithDatapathAccelFallback 让一次被拒绝的 sockopt 成为一次**透明降级**，
// 而不是一条起不来的隧道。
//
// 背景：sing-tun 的 darwin 路径在 EXP_RecvMsgX 为真时会
// `SetsockoptInt(fd, SYSPROTO_CONTROL, UTUN_OPT_MAX_PENDING_PACKETS, batchSize)`，
// 而 `configure()` 在这一步失败时直接让 `tun.New` 返回错误 —— TUN 根本起不来。
// 桌面端有 Dart 侧的自愈闩（起核失败就翻 setTunDatapathAccelDisabled、不带加速
// 重试一次），但 iOS 的 NE extension 够不到那条路径：它在自己的进程里，Dart 侧
// 的闩对它不存在。
//
// 所以把回退挪进 Go：谁开的这个加速，谁在同一层把它关掉重试。这样无论哪个平台、
// 无论有没有上层闩，一次内核拒绝都只是"这次不用批量收包"，不是"这次没有网"。
//
// 🚨 这条**不能**覆盖的失败模式，必须说清楚：sockopt 成功、但 recvmsg_x 在沙箱里
// 行为异常 —— 那是"隧道起来了、不过流量"。任何按"启动失败"触发的回退都救不了它，
// 包括这一条。所以它是开启 iOS EXP_RecvMsgX 的**必要**前置，不是充分条件；
// 充分条件是真机 NE extension 里确认 sockopt 成功**并且**真实过流量。
// 见 yuelink/docs/debt.md 的「iOS TUN 批量 syscall」条目。
func newTunWithDatapathAccelFallback(options tun.Options, borrowed bool) (tun.Tun, error) {
	return newTunWithDatapathAccelFallbackUsing(options, borrowed, tunNewForListener)
}

type tunFactory func(tun.Options, bool) (tun.Tun, error)

func newTunWithDatapathAccelFallbackUsing(options tun.Options, borrowed bool, factory tunFactory) (tun.Tun, error) {
	device, err := factory(options, borrowed)
	if err == nil || !options.EXP_RecvMsgX {
		return device, err
	}

	log.Errorln("[TUN] batch receive (recvmsg_x) was rejected by the kernel: %v; retrying once without it", err)

	downgraded := options
	downgraded.EXP_RecvMsgX = false
	device, retryErr := factory(downgraded, borrowed)
	if retryErr != nil {
		// 降级也失败：原因几乎肯定不是那个 sockopt。返回**原始**错误，
		// 否则真正的起因会被这层重试的错误盖掉。
		log.Errorln("[TUN] retry without batch receive also failed: %v", retryErr)
		return nil, err
	}

	log.Warnln("[TUN] running without batch receive for this session (recvmsg_x unavailable on this kernel/sandbox)")
	return device, nil
}
