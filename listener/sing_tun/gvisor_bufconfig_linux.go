//go:build with_gvisor && linux

package sing_tun

import "github.com/metacubex/gvisor/pkg/tcpip/link/fdbased"

// sing-tun's tun_linux_gvisor.go does `fdbased.BufConfig = []int{65535}` in an
// init(). BufConfig is the *shape* of the scatter buffer gVisor hands to
// readv() for each packet, and gVisor consumes whole entries: `pullBuffer(n)`
// walks the views until their cumulative size covers n, hands those to the
// stack, and re-allocates exactly those on the next read.
//
// With a single 65535-entry that means EVERY packet — a 60-byte ACK included —
// takes a 64 KiB chunk out of gVisor's pool, and keeps it for as long as the
// packet is referenced. Two consequences, both on the hot path:
//
//   - churn: one 64 KiB pooled chunk per received packet. sync.Pool is cheap
//     until a GC clears it, after which the next packets each pay a fresh
//     `make([]byte, 65536)`. Under a tight GOMEMLIMIT that GC is frequent.
//   - amplification: a packet sitting in a TCP receive queue pins its whole
//     chunk, while gVisor's buffer accounting only counts the payload. A
//     1500-byte segment reports ~1.5 KB against the receive budget and holds
//     64 KiB of RSS — a 43x gap. That gap was invisible while the receive
//     budget was sing-tun's 20 KiB (nothing could queue); widening it in
//     gvisor_tuning.go is precisely what makes it reachable, so the two
//     changes belong together.
//
// gVisor's own default is a 10-entry ladder (128 … 32768) that avoids both.
// We use a shorter, MTU-aware ladder instead of restoring it verbatim,
// because our TUN runs mtu 9000 (AppConstants.defaultTunMtu):
//
//	packet          views pulled          chunks held
//	≤ 2048 (ACKs,   1                     2 KiB
//	 1500B frames)
//	≤ 10240 (a full 2                     10 KiB
//	 9000B frame)
//	64 KiB GSO      4                     90 KiB
//	 super-frame
//
// So the common cases stay contiguous (no PullUp copy for header parsing —
// which the 10-entry ladder does incur, splitting a 1500-byte frame across
// five views) while costing at most 4 iovecs per readv. The GSO super-frame
// case is desktop-Linux-only (`gso: true` opens the tun with IFF_VNET_HDR)
// and is already large, so its rounding overhead is noise.
//
// Reach: gVisor compiles fdbased for the linux family only, and sing-tun sets
// BufConfig only in its linux file — macOS, iOS and Windows already run
// gVisor's stock ladder. This file therefore changes Android and Linux, which
// are exactly the two that were on the flat 64 KiB.
//
// Ordering: Go initialises imported packages first, so sing-tun's init() has
// already written 65535 by the time this one runs. gvisor_bufconfig_linux_test.go
// asserts the final value rather than trusting that.
func init() {
	fdbased.BufConfig = yuelinkBufConfig
}

// yuelinkBufConfig must cover a full GSO super-frame (sing-tun's gsoMaxSize is
// 65536) or gVisor truncates reads.
var yuelinkBufConfig = []int{2048, 8192, 16384, 40960}
