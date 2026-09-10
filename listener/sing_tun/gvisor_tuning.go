//go:build with_gvisor

package sing_tun

import (
	"os"
	"reflect"
	"runtime"
	"strconv"
	"unsafe"

	"github.com/metacubex/gvisor/pkg/tcpip"
	gvstack "github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/mihomo/log"
	tun "github.com/metacubex/sing-tun"
)

// Why this file exists
// -------------------
// sing-tun builds every gVisor stack with a HARD 20 KiB cap on both TCP
// buffers (`stack_gvisor.go`: `bufSize := 20 * 1024`, written into
// TCPReceiveBufferSizeRangeOption / TCPSendBufferSizeRangeOption with
// Min/Default/Max all pinned to it). Because Max is pinned too, the
// TCPModerateReceiveBufferOption(true) that the same function enables can
// never grow a window past 20 KiB — auto-tuning is armed and then boxed in.
//
// gVisor's own defaults for the same knobs are 1 MiB default / 4 MiB max
// (`transport/tcp/protocol.go`), so 20 KiB is a 50x reduction, presumably a
// mobile-memory decision taken upstream.
//
// The cost is not subtle. A TCP window caps a connection at window/RTT, and
// the RTT here is the local TUN hop — gVisor writes the packet to the tun fd,
// the kernel hands it to the app, the app's ACK comes back through a second
// syscall and two goroutine wakeups. That hop is ~0.2–4 ms depending on how
// loaded the device is, NOT zero. Worse, YueLink runs mtu 9000
// (AppConstants.defaultTunMtu), so 20 KiB is barely 2.3 segments in flight —
// below the 4 MSS that TCP needs for delayed-ACK and fast-retransmit to work
// at all.
//
// Measured on this machine against the real metacubex/gvisor build (two
// stacks joined by channel endpoints with a fixed one-way delay; only bufSize
// varies), 8 MiB payload, mtu 9000:
//
//	local-hop RTT   20 KiB        256 KiB       1 MiB
//	200 µs          287 Mbps      2478 Mbps     10049 Mbps
//	1 ms             59 Mbps       590 Mbps      2694 Mbps
//	4 ms             15 Mbps       165 Mbps       694 Mbps
//
// So a single TCP download through the TUN is capped somewhere around
// 15–60 Mbps by the client's own netstack, no matter how fast the node is.
// That is the same 30–50 Mbps band we had recorded as "the node/tunnel is
// the bottleneck". Parallel-stream speedtests hide it; one big file does not.
//
// Both mobile platforms run 100% of their TCP through this stack
// (`stack: gvisor` is forced on Android by the non-root VpnService-fd path and
// on iOS by PacketTunnelProvider), which is why this is a mobile-first fix.
// On desktop `stack: mixed` routes TCP through the system stack and only UDP
// through gVisor, so there the TCP half is a no-op and the UDP half still helps.
//
// sing-tun exposes no option for this and keeps the *stack.Stack unexported,
// so we reach it by type — not by field name — right after Start(). Options
// set on a stack apply to endpoints created afterwards, and no connection
// exists yet at that point. gvisor_tuning_test.go pins the whole path against
// the real sing-tun types so a dependency bump that moves the field fails
// loudly instead of silently restoring the 20 KiB ceiling.

// bufferProfile is the replacement for sing-tun's 20 KiB.
//
// Every value is a LIMIT, not a reservation: gVisor allocates receive segments
// as they arrive and send-queue bytes as they are written, so Default/Max bound
// how much a connection may buffer, they do not cost that much per connection.
type bufferProfile struct {
	min     int
	def     int
	max     int
	tierTag string
}

// gvisorBufferProfile picks the tier for the platform this core was built for.
//
// The profile has to be decided HERE, in Go, not handed in over FFI: on iOS the
// core that matters runs inside the NEPacketTunnelProvider extension, a separate
// process, so a Dart-side call would configure the app's copy of the c-archive
// and never touch the one carrying traffic. (Same reason SetMemoryBudget is
// armed by the extension itself.)
func gvisorBufferProfile() bufferProfile {
	return bufferProfileFor(runtime.GOOS)
}

// bufferProfileFor is gvisorBufferProfile with the platform as a parameter, so
// the tiers we can never execute on this build host (a Go test binary only ever
// runs as one GOOS) are still pinned by a test.
func bufferProfileFor(goos string) bufferProfile {
	switch goos {
	case "ios":
		// Tightest budget in the fleet: the packet-tunnel extension arms
		// SetMemoryBudget(45, 30) against Apple's ~50 MiB ceiling. 256 KiB
		// still measures ~590 Mbps at a 1 ms local hop — an order of magnitude
		// over any node we run — while bounding a 20-connection burst to ~5 MiB
		// of worst-case buffering.
		return bufferProfile{min: 4 << 10, def: 128 << 10, max: 256 << 10, tierTag: "ios"}
	case "android":
		// Shares the Flutter process, which has a normal app heap. 1 MiB max
		// is ~2.7 Gbps at a 1 ms hop; the ceiling stops a pathological reader
		// from parking megabytes per connection.
		return bufferProfile{min: 4 << 10, def: 256 << 10, max: 1 << 20, tierTag: "android"}
	default:
		// Desktop: gVisor's own upstream defaults. Reached by the UDP half of
		// `stack: mixed` and by the whole stack when the TUN self-heal
		// supervisor falls back to `stack: gvisor` (tun_stack_blocked).
		return bufferProfile{min: 4 << 10, def: 512 << 10, max: 4 << 20, tierTag: "desktop"}
	}
}

// gvisorBufferOverrideEnv lets a desktop run restore the old ceiling or try a
// different one without a rebuild: MIHOMO_GVISOR_BUFFER_KIB=20 reproduces
// sing-tun's stock behaviour, =0 skips the tuning entirely.
//
// Desktop only, and deliberately so. A c-archive Go runtime snapshots environ
// during schedinit() at library load, so a setenv() from Swift/Kotlin after
// launch is a no-op — the same trap that made the old GOMEMLIMIT-from-Swift
// approach silently do nothing on iOS.
const gvisorBufferOverrideEnv = "MIHOMO_GVISOR_BUFFER_KIB"

// tuneGVisorStack widens the TCP/UDP buffer ranges of every gVisor stack
// reachable from s. Safe to call on a non-gVisor stack: it finds nothing and
// returns.
func tuneGVisorStack(s tun.Stack) {
	if s == nil {
		return
	}
	profile := gvisorBufferProfile()
	if raw := os.Getenv(gvisorBufferOverrideEnv); raw != "" {
		kib, err := strconv.Atoi(raw)
		switch {
		case err != nil || kib < 0:
			log.Warnln("[TUN] ignoring %s=%q: want a non-negative number of KiB", gvisorBufferOverrideEnv, raw)
		case kib == 0:
			log.Infoln("[TUN] gVisor buffer tuning disabled by %s=0", gvisorBufferOverrideEnv)
			return
		default:
			size := kib << 10
			profile = bufferProfile{min: min(profile.min, size), def: size, max: size, tierTag: "env"}
		}
	}

	stacks := findGVisorStacks(s)
	if len(stacks) == 0 {
		return
	}
	for _, ipStack := range stacks {
		rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: profile.min, Default: profile.def, Max: profile.max}
		if err := ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &rcv); err != nil {
			log.Warnln("[TUN] set gVisor TCP receive buffer range: %v", err)
			continue
		}
		snd := tcpip.TCPSendBufferSizeRangeOption{Min: profile.min, Default: profile.def, Max: profile.max}
		if err := ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &snd); err != nil {
			log.Warnln("[TUN] set gVisor TCP send buffer range: %v", err)
			continue
		}
	}
	log.Infoln("[TUN] gVisor TCP buffers widened (%s tier): %d KiB default / %d KiB max — sing-tun ships 20/20",
		profile.tierTag, profile.def>>10, profile.max>>10)
}

// findGVisorStacks returns every *gvstack.Stack reachable from the concrete
// value behind s.
//
// It matches on TYPE, never on field name: `GVisor.stack` and `Mixed.stack` are
// both unexported, and a rename upstream should not silently turn this into a
// no-op. Recursion goes one level into embedded/!nil struct pointers because
// Mixed embeds *System.
func findGVisorStacks(s tun.Stack) []*gvstack.Stack {
	var out []*gvstack.Stack
	seen := make(map[uintptr]bool)
	collectGVisorStacks(reflect.ValueOf(s), 0, seen, &out)
	return out
}

const gvisorStackScanDepth = 3

func collectGVisorStacks(v reflect.Value, depth int, seen map[uintptr]bool, out *[]*gvstack.Stack) {
	if depth > gvisorStackScanDepth || !v.IsValid() {
		return
	}
	for v.Kind() == reflect.Interface {
		if v.IsNil() {
			return
		}
		v = v.Elem()
	}
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return
		}
		if seen[v.Pointer()] {
			return
		}
		seen[v.Pointer()] = true
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct || !v.CanAddr() {
		return
	}
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		switch f.Kind() {
		case reflect.Ptr:
			if f.IsNil() {
				continue
			}
			if f.Type() == gvisorStackPtrType {
				if ptr := readUnexportedPtr[gvstack.Stack](f); ptr != nil {
					*out = append(*out, ptr)
				}
				continue
			}
			if f.Type().Elem().Kind() == reflect.Struct {
				collectGVisorStacks(f, depth+1, seen, out)
			}
		case reflect.Interface:
			collectGVisorStacks(f, depth+1, seen, out)
		}
	}
}

var gvisorStackPtrType = reflect.TypeOf((*gvstack.Stack)(nil))

// readUnexportedPtr reads a pointer field that reflect refuses to hand over
// because it is unexported. The field must be addressable, which it is: we only
// ever reach it through a pointer's Elem().
func readUnexportedPtr[T any](f reflect.Value) *T {
	if !f.CanAddr() {
		return nil
	}
	if f.CanInterface() {
		ptr, _ := f.Interface().(*T)
		return ptr
	}
	return *(**T)(unsafe.Pointer(f.UnsafeAddr()))
}
