package outbound

import (
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/metacubex/mihomo/component/reachhook"
	C "github.com/metacubex/mihomo/constant"
)

// observeTLSHandshake reports the TLS/REALITY handshake of a VLESS outbound
// to component/reachhook. With no observer installed it is a plain call.
func observeTLSHandshake(conn net.Conn, handshake func() (net.Conn, error)) (net.Conn, error) {
	if !reachhook.Enabled() {
		return handshake()
	}
	start := time.Now()
	c, err := handshake()
	reachhook.Observe(reachhook.PhaseTLS, reachhook.AddrPortOf(conn.RemoteAddr()), time.Since(start), err)
	return c, err
}

// ErrReachProbeUnsupported is returned for outbounds reachprobe cannot pin.
var ErrReachProbeUnsupported = errors.New("reachprobe: unsupported outbound")

// ReachProbeServer returns the configured server host and port of a VLESS or
// Hysteria2 outbound, so the prober can match a signed entry target to the
// node configuration that owns it.
func ReachProbeServer(p C.ProxyAdapter) (host string, port int, proto string, ok bool) {
	switch v := p.(type) {
	case *Vless:
		return v.option.Server, v.option.Port, "vless", true
	case *Hysteria2:
		return v.option.Server, v.option.Port, "hy2", true
	}
	return "", 0, "", false
}

// CloneForReachProbe builds a fresh outbound with p's exact configuration
// (keys, REALITY parameters, obfuscation, auth) but pinned to ip, so a
// handshake against one entry IP of a multi-address pool is a real protocol
// handshake with that node's own credentials. The TLS server name keeps the
// original hostname when the configuration relied on it. The caller owns
// the returned adapter and must Close it.
func CloneForReachProbe(p C.ProxyAdapter, ip netip.Addr) (C.ProxyAdapter, error) {
	switch v := p.(type) {
	case *Vless:
		opt := *v.option
		if opt.ServerName == "" && !isIPLiteral(opt.Server) {
			opt.ServerName = opt.Server
		}
		opt.Server = ip.String()
		opt.Name = v.option.Name + " [reach]"
		return NewVless(opt)
	case *Hysteria2:
		opt := *v.option
		if opt.SNI == "" && !isIPLiteral(opt.Server) {
			opt.SNI = opt.Server
		}
		opt.Server = ip.String()
		// Pin the configured port: a hop range would spread the probe
		// across ports the target list did not name.
		opt.Ports = ""
		opt.Name = v.option.Name + " [reach]"
		return NewHysteria2(opt)
	}
	return nil, ErrReachProbeUnsupported
}

func isIPLiteral(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}
