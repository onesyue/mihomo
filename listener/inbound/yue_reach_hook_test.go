package inbound_test

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/reachhook"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"
)

// The QUIC (Hysteria2) and TLS (VLESS) hook points report the real
// handshake against the real server address.
func TestReachHookSeesQUICAndTLSHandshakes(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]map[netip.AddrPort]bool{}
	reachhook.SetObserver(func(phase string, dst netip.AddrPort, _ time.Duration, err error) {
		if err != nil {
			return
		}
		mu.Lock()
		if seen[phase] == nil {
			seen[phase] = map[netip.AddrPort]bool{}
		}
		seen[phase][dst] = true
		mu.Unlock()
	})
	defer reachhook.SetObserver(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Hysteria2 -> quic
	hin, err := inbound.NewHysteria2(&inbound.Hysteria2Option{
		BaseOption:  inbound.BaseOption{NameStr: "hy2_hook", Listen: "127.0.0.1", Port: "0"},
		Users:       map[string]string{"test": userUUID},
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()
	if err := hin.Listen(tunnel); err != nil {
		t.Fatal(err)
	}
	defer hin.Close()
	hAddr := netip.MustParseAddrPort(hin.Address())
	hout, err := outbound.NewHysteria2(outbound.Hysteria2Option{
		BasicOption: outbound.BasicOption{DialerForAPI: tunnel.NewDialer(), TunnelForAPI: tunnel},
		Name:        "hy2_hook_out", Server: hAddr.Addr().String(), Port: int(hAddr.Port()),
		Password: userUUID, Fingerprint: tlsFingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer hout.Close()
	c, err := hout.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "example.com", DstPort: 80})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()

	// VLESS over TLS -> tls
	vin, err := inbound.NewVless(&inbound.VlessOption{
		BaseOption:  inbound.BaseOption{NameStr: "vless_hook", Listen: "127.0.0.1", Port: "0"},
		Users:       []inbound.VlessUser{{Username: "test", UUID: userUUID}},
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := vin.Listen(tunnel); err != nil {
		t.Fatal(err)
	}
	defer vin.Close()
	vAddr := netip.MustParseAddrPort(vin.Address())
	vout, err := outbound.NewVless(outbound.VlessOption{
		BasicOption: outbound.BasicOption{DialerForAPI: tunnel.NewDialer(), TunnelForAPI: tunnel},
		Name:        "vless_hook_out", Server: vAddr.Addr().String(), Port: int(vAddr.Port()),
		UUID: userUUID, TLS: true, Fingerprint: tlsFingerprint,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer vout.Close()
	vc, err := vout.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "example.com", DstPort: 80})
	if err != nil {
		t.Fatal(err)
	}
	vc.Close()

	mu.Lock()
	defer mu.Unlock()
	if !seen[reachhook.PhaseQUIC][hAddr] {
		t.Fatalf("no quic observation for %s: %v", hAddr, seen)
	}
	if !seen[reachhook.PhaseTLS][vAddr] {
		t.Fatalf("no tls observation for %s: %v", vAddr, seen)
	}
}
