//go:build with_gvisor

package sing_tun

import (
	"math"
	"os"
	"runtime"
	"strconv"

	"github.com/metacubex/mihomo/log"
	tun "github.com/metacubex/sing-tun"
)

// Upstream sing-tun defaults both TCP Default/Max buffer sizes to 20 KiB.
// The existing YueLink platform budgets allow receive-window autotuning within
// explicit memory bounds. They are unchanged by the native API migration.
//
// The maintained sing-tun fork exposes GVisorTCPBufferRange in StackOptions.
// It applies the range before attaching the NIC, so the first flow receives
// the selected budget without reflection or post-start private-state mutation.
// These are TCP limits; mixed-stack TCP uses the system stack, and this option
// does not change UDP buffering. Actual throughput also depends on the local
// TUN path, scheduling, the remote transport, and the network. Synthetic local
// transfer measurements do not establish a fixed device or WAN speed ceiling.

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
		// The packet-tunnel extension has a separate, tighter memory budget.
		// Both send and receive queues can consume memory up to their limits;
		// the per-connection cap is not a whole-process RSS bound.
		return bufferProfile{min: 4 << 10, def: 128 << 10, max: 256 << 10, tierTag: "ios"}
	case "android":
		// Shares the normal app process; retain the larger mobile budget.
		return bufferProfile{min: 4 << 10, def: 256 << 10, max: 1 << 20, tierTag: "android"}
	default:
		// Retain the desktop profile, including the self-heal fallback to
		// stack: gvisor. The TCP half of stack: mixed uses system buffers.
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

// gvisorTCPBufferRange selects native constructor options, before any packet
// dispatcher or TCP endpoint can observe the upstream defaults.
func gvisorTCPBufferRange() tun.TCPBufferRange {
	return gvisorTCPBufferRangeFor(runtime.GOOS, os.Getenv(gvisorBufferOverrideEnv))
}

func gvisorTCPBufferRangeFor(goos, raw string) tun.TCPBufferRange {
	profile := bufferProfileFor(goos)
	if raw != "" && goos != "ios" && goos != "android" {
		kib, err := strconv.Atoi(raw)
		switch {
		case err != nil || kib < 0 || kib > math.MaxInt>>10:
			log.Warnln("[TUN] ignoring %s=%q: want a non-negative, representable number of KiB", gvisorBufferOverrideEnv, raw)
		case kib == 0:
			return tun.TCPBufferRange{}
		default:
			size := kib << 10
			profile = bufferProfile{min: min(profile.min, size), def: size, max: size, tierTag: "env"}
		}
	}
	return tun.TCPBufferRange{Min: profile.min, Default: profile.def, Max: profile.max}
}
