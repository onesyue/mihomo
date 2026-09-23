// Package reachhook is the YueLink fork's leaf hook for mainland
// reachability measurement (component/reachprobe).
//
// The dialer, the QUIC dialer and the VLESS TLS/REALITY layer call Observe
// after every outbound handshake. With no observer installed (the default,
// and the state of every build that never enables reachprobe) Observe is a
// single atomic load and nothing else: no allocation, no lock, no change to
// dial behaviour. The hook never touches the connection it reports on.
package reachhook

import (
	"net"
	"net/netip"
	"sync/atomic"
	"time"
)

// Handshake phases reported by the hook points.
const (
	PhaseTCP  = "tcp"  // TCP connect (component/dialer)
	PhaseTLS  = "tls"  // TLS / REALITY handshake on top of TCP (VLESS)
	PhaseQUIC = "quic" // QUIC handshake (Hysteria2 / TUIC)
)

// Observer receives one handshake result. It must be cheap and must never
// block: it runs on the dialing goroutine.
type Observer func(phase string, dst netip.AddrPort, rtt time.Duration, err error)

var observer atomic.Pointer[Observer]

// SetObserver installs (or, with nil, removes) the process-wide observer.
func SetObserver(o Observer) {
	if o == nil {
		observer.Store(nil)
		return
	}
	observer.Store(&o)
}

// Enabled reports whether an observer is installed. Hook points use it to
// skip even the clock read when measurement is off.
func Enabled() bool { return observer.Load() != nil }

// Observe forwards a handshake result to the installed observer, if any.
func Observe(phase string, dst netip.AddrPort, rtt time.Duration, err error) {
	if p := observer.Load(); p != nil && dst.IsValid() {
		(*p)(phase, netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port()), rtt, err)
	}
}

// AddrPortOf extracts the remote address of a net.Addr, or the zero value.
func AddrPortOf(a net.Addr) netip.AddrPort {
	switch v := a.(type) {
	case *net.TCPAddr:
		return v.AddrPort()
	case *net.UDPAddr:
		return v.AddrPort()
	case nil:
		return netip.AddrPort{}
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.AddrPort{}
	}
	return ap
}
