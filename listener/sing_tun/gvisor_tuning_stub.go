//go:build !with_gvisor

package sing_tun

import tun "github.com/metacubex/sing-tun"

// tuneGVisorStack is a no-op in builds without the gVisor stack compiled in.
func tuneGVisorStack(tun.Stack) {}
