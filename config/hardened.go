package config

import (
	"net"
	"net/netip"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

// applyHardenedPolicy strips every config surface that lets the author of a
// config act with the privileges of the process that runs it.
//
// YueLink: under the desktop service helper this process runs as root /
// SYSTEM, while its config is written by the unprivileged user — at start
// through a file the helper copies, and at any later time through
// PUT /configs on the REST API, which never passes the helper. That second
// path is why the policy lives here, in the parser both paths share, and not
// only in the helper. Everything removed is something the YueLink app never
// emits; a subscription that carries one still connects, without it.
//
//   - external-ui / -url / -name: downloads an archive and extracts it
//     (including symlinks) as root.
//   - external-controller-unix / -pipe: unlink(2) + chmod 0666 of an
//     arbitrary path as root, and an unauthenticated controller socket.
//   - ntp.write-to-system: sets the system clock.
//   - iptables: rewrites the host firewall.
//   - listeners: additional inbound listeners (TUN, redir, tproxy, servers)
//     outside the one the app manages.
//   - external-controller[-tls] on a non-loopback address: hands control of
//     a root process to the network.
func applyHardenedPolicy(raw *RawConfig) {
	if !C.Hardened {
		return
	}
	var stripped []string
	if raw.ExternalUI != "" || raw.ExternalUIURL != "" || raw.ExternalUIName != "" {
		raw.ExternalUI, raw.ExternalUIURL, raw.ExternalUIName = "", "", ""
		stripped = append(stripped, "external-ui")
	}
	if raw.ExternalControllerUnix != "" {
		raw.ExternalControllerUnix = ""
		stripped = append(stripped, "external-controller-unix")
	}
	if raw.ExternalControllerPipe != "" {
		raw.ExternalControllerPipe = ""
		stripped = append(stripped, "external-controller-pipe")
	}
	if raw.NTP.WriteToSystem {
		raw.NTP.WriteToSystem = false
		stripped = append(stripped, "ntp.write-to-system")
	}
	if raw.IPTables.Enable {
		raw.IPTables.Enable = false
		stripped = append(stripped, "iptables")
	}
	if len(raw.Listeners) > 0 {
		raw.Listeners = nil
		stripped = append(stripped, "listeners")
	}
	if addr, changed := loopbackOnly(raw.ExternalController); changed {
		raw.ExternalController = addr
		stripped = append(stripped, "external-controller(non-loopback)")
	}
	if addr, changed := loopbackOnly(raw.ExternalControllerTLS); changed {
		raw.ExternalControllerTLS = addr
		stripped = append(stripped, "external-controller-tls(non-loopback)")
	}
	if len(stripped) > 0 {
		log.Warnln("[YueLink] privileged core: ignoring %s", strings.Join(stripped, ", "))
	}
}

// loopbackOnly rebinds a controller address to 127.0.0.1 unless it already
// names a loopback host. An empty address (controller disabled) is kept.
func loopbackOnly(addr string) (string, bool) {
	if addr == "" {
		return addr, false
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// Unparseable: mihomo would fail to listen anyway; make sure it
		// cannot succeed on something wider than loopback.
		return "127.0.0.1:0", true
	}
	if strings.EqualFold(host, "localhost") {
		return addr, false
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
		return addr, false
	}
	return net.JoinHostPort("127.0.0.1", port), true
}
