package reachprobe

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/tls"
)

// maxServerLookups bounds how many proxy server hostnames one entry probe
// resolves while looking for the node configuration that owns the address.
const maxServerLookups = 32

// fakeIPRange is mihomo's default fake-ip pool. An answer inside it means
// the query was answered by our own TUN resolver, not the physical network,
// so the DNS probe says nothing and is dropped.
var fakeIPRange = netip.MustParsePrefix("198.18.0.0/15")

// DefaultProber probes over the real network. Every socket it opens comes
// from component/dialer, so it follows the same tunnel bypass as proxy
// dials: Android protect(fd) via DefaultSocketHook, desktop interface
// binding (auto-detect-interface), and on iOS the extension's own sockets
// already bypass the tunnel.
type DefaultProber struct {
	// Adapters lists candidate outbounds; defaults to the running config.
	Adapters func() []C.ProxyAdapter
}

// Run implements Prober.
func (d DefaultProber) Run(ctx context.Context, taskKind string, t Target) []StageResult {
	switch taskKind {
	case TaskEntry:
		return d.entry(ctx, t)
	case TaskDNS:
		return dnsProbe(ctx, t)
	case TaskDomain:
		return domainProbe(ctx, t)
	}
	return nil
}

func (d DefaultProber) entry(ctx context.Context, t Target) []StageResult {
	ap := netip.AddrPortFrom(t.addr, t.Port)
	switch t.Probe {
	case ProbeTCP:
		start := time.Now()
		conn, err := dialer.DialContext(ctx, "tcp", ap.String())
		if conn != nil {
			_ = conn.Close()
		}
		return []StageResult{{Kind: ObsTCP, Phase: PhaseConnect, RTT: time.Since(start), Err: err}}
	case ProbeTLS:
		return tlsProbe(ctx, ap, "")
	case ProbeVLESS, ProbeHY2:
		return d.handshake(ctx, t)
	}
	return nil
}

func runningAdapters() []C.ProxyAdapter {
	var out []C.ProxyAdapter
	for _, p := range tunnel.Proxies() {
		out = append(out, p.Adapter())
	}
	for _, pp := range tunnel.Providers() {
		for _, p := range pp.Proxies() {
			out = append(out, p.Adapter())
		}
	}
	return out
}

// handshake clones the node configuration that owns t's address and runs a
// real protocol handshake pinned to that address. VLESS: TCP + REALITY/TLS;
// the VLESS request header is written lazily and the connection is closed
// before any byte of it is sent, so no proxied request reaches the node.
// Hysteria2: QUIC + auth; its TCP request is equally lazy.
func (d DefaultProber) handshake(ctx context.Context, t Target) []StageResult {
	src := d.Adapters
	if src == nil {
		src = runningAdapters
	}
	owner := findOwner(ctx, src(), t)
	if owner == nil {
		return nil
	}
	clone, err := outbound.CloneForReachProbe(owner, t.addr)
	if err != nil {
		return nil
	}
	defer clone.Close()
	kind, phase := ObsTLS, PhaseTLS
	if t.Probe == ProbeHY2 {
		kind, phase = ObsQUIC, PhaseConnect
	}
	start := time.Now()
	conn, err := clone.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "reach-probe.invalid", DstPort: 443})
	rtt := time.Since(start)
	if conn != nil {
		_ = conn.Close()
	}
	return []StageResult{{Kind: kind, Phase: phase, RTT: rtt, Err: err}}
}

// findOwner returns the configured outbound of t's protocol and port whose
// server is, or resolves to, t's address.
func findOwner(ctx context.Context, adapters []C.ProxyAdapter, t Target) C.ProxyAdapter {
	var byName []C.ProxyAdapter
	var hosts []string
	for _, a := range adapters {
		host, port, proto, ok := outbound.ReachProbeServer(a)
		if !ok || proto != t.Probe || (port != 0 && port != int(t.Port)) {
			continue
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			if ip.Unmap() == t.addr {
				return a
			}
			continue
		}
		byName = append(byName, a)
		hosts = append(hosts, host)
	}
	resolved := map[string][]netip.Addr{}
	for i, a := range byName {
		ips, done := resolved[hosts[i]]
		if !done {
			if len(resolved) >= maxServerLookups || resolver.ProxyServerHostResolver == nil {
				return nil
			}
			ips, _ = resolver.LookupIPWithResolver(ctx, hosts[i], resolver.ProxyServerHostResolver)
			resolved[hosts[i]] = ips
		}
		if slices.ContainsFunc(ips, func(ip netip.Addr) bool { return ip.Unmap() == t.addr }) {
			return a
		}
	}
	return nil
}

// isBogon reports answers no public resolver should return for a public name.
func isBogon(a netip.Addr) bool {
	a = a.Unmap()
	return !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsUnspecified()
}

// dnsProbe resolves t.Host through the system resolver — the physical
// network's DHCP/OS DNS over plain UDP, never the fake-ip pool. A bogon in
// the answer is classified as poisoned. (A foreign-looking but wrong answer
// cannot be told apart from CDN variance on the client, so it is not.)
func dnsProbe(ctx context.Context, t Target) []StageResult {
	r := resolver.SystemResolver
	if r == nil {
		return nil
	}
	start := time.Now()
	ips, err := r.LookupIPv4(ctx, t.Host)
	res := StageResult{Kind: ObsDNS, Phase: PhaseDNS, IPVer: 4, RTT: time.Since(start), Err: err}
	if err == nil {
		for _, ip := range ips {
			if fakeIPRange.Contains(ip.Unmap()) {
				return nil // answered by our own TUN, not the physical network
			}
		}
		if len(ips) == 0 || slices.ContainsFunc(ips, isBogon) {
			res.Err = errPoisonedDNS
		}
	}
	return []StageResult{res}
}

// domainProbe resolves t.Host through the core's regular (encrypted)
// resolver — so a poisoned plain-DNS answer does not masquerade as a TLS
// failure — then performs TCP + TLS with the SNI. No HTTP is sent.
func domainProbe(ctx context.Context, t Target) []StageResult {
	r := resolver.DefaultResolver
	if r == nil {
		r = resolver.SystemResolver
	}
	if r == nil {
		return nil
	}
	ips, err := r.LookupIPv4(ctx, t.Host)
	if err != nil || len(ips) == 0 {
		return nil // no clean address: nothing to measure on the path
	}
	ip := ips[0].Unmap()
	if fakeIPRange.Contains(ip) || isBogon(ip) {
		return nil
	}
	return tlsProbe(ctx, netip.AddrPortFrom(ip, t.Port), t.Host)
}

// tlsProbe performs a TCP connect and a TLS handshake carrying only the SNI.
// Certificate verification is off on purpose: the measurement is whether
// the path lets the handshake finish, and Android's Go runtime cannot be
// relied on to find the platform trust store.
func tlsProbe(ctx context.Context, ap netip.AddrPort, sni string) []StageResult {
	ver := ipVerOf(ap.Addr())
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ap.Addr().String(), strconv.Itoa(int(ap.Port()))))
	connect := StageResult{Kind: ObsTLS, Phase: PhaseConnect, IPVer: ver, RTT: time.Since(start), Err: err}
	if err != nil {
		return []StageResult{connect}
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	start = time.Now()
	tc := tls.Client(conn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, //nolint:gosec // reachability only, see above
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	err = tc.HandshakeContext(ctx)
	return []StageResult{connect, {Kind: ObsTLS, Phase: PhaseTLS, IPVer: ver, RTT: time.Since(start), Err: err}}
}

// Default is the process-wide probe served by the REST API.
var Default = New(DefaultProber{})
