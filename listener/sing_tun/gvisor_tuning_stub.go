//go:build !with_gvisor

package sing_tun

import tun "github.com/metacubex/sing-tun"

func gvisorTCPBufferRange() tun.TCPBufferRange { return tun.TCPBufferRange{} }
