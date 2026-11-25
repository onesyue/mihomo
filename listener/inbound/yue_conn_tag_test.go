package inbound_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/yueconntag"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/inbound"

	"github.com/stretchr/testify/assert"
)

// yueTestTag is the only value any test in this package ever stores in the
// process-wide device tag, so parallel tests cannot observe a different one.
const yueTestTag = "AbCdEf012_-"

// A tagged VLESS request must be accepted by an untagged server that decodes
// Addons with google.golang.org/protobuf (mihomo sing_vless; Xray-core uses
// the same decoder) — with and without XTLS Vision.
func TestInboundVless_YueConnTag(t *testing.T) {
	yueconntag.Set(yueTestTag)
	inboundOptions := inbound.VlessOption{
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
	}
	outboundOptions := outbound.VlessOption{
		TLS:         true,
		Fingerprint: tlsFingerprint,
		YueConnTag:  true,
	}
	testInboundVless(t, inboundOptions, outboundOptions)
	t.Run("xtls-rprx-vision", func(t *testing.T) {
		outboundOptions := outboundOptions
		outboundOptions.Flow = "xtls-rprx-vision"
		testInboundVless(t, inboundOptions, outboundOptions)
	})
}

// hysteria2AuthOK reports whether an outbound with password clientPW and the
// given yue-conn-tag switch authenticates against a server whose only user
// password is serverPW.
func hysteria2AuthOK(t *testing.T, serverPW, clientPW string, connTag bool) bool {
	t.Helper()
	in, err := inbound.NewHysteria2(&inbound.Hysteria2Option{
		BaseOption:  inbound.BaseOption{NameStr: "hy2_yue_tag", Listen: "127.0.0.1", Port: "0"},
		Users:       map[string]string{"test": serverPW},
		Certificate: tlsCertificate,
		PrivateKey:  tlsPrivateKey,
	})
	if !assert.NoError(t, err) {
		return false
	}
	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()
	if !assert.NoError(t, in.Listen(tunnel)) {
		return false
	}
	defer in.Close()
	addrPort, err := netip.ParseAddrPort(in.Address())
	if !assert.NoError(t, err) {
		return false
	}
	out, err := outbound.NewHysteria2(outbound.Hysteria2Option{
		BasicOption:      outbound.BasicOption{DialerForAPI: tunnel.NewDialer(), TunnelForAPI: tunnel},
		Name:             "hy2_yue_tag_out",
		Server:           addrPort.Addr().String(),
		Port:             int(addrPort.Port()),
		Password:         clientPW,
		Fingerprint:      tlsFingerprint,
		YueConnTag:       connTag,
		HandshakeTimeout: 3,
	})
	if !assert.NoError(t, err) {
		return false
	}
	defer out.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := out.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "example.com", DstPort: 80})
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// The Hysteria2 auth suffix is visible on the wire exactly when the proxy is
// marked: switch off = the stock password, switch on = "<password>#<tag>",
// which a stock server rejects (hence the server-declared opt-in).
func TestInboundHysteria2_YueConnTag(t *testing.T) {
	yueconntag.Set(yueTestTag)
	if !hysteria2AuthOK(t, userUUID, userUUID, false) {
		t.Fatal("switch off must authenticate with the unchanged password")
	}
	if hysteria2AuthOK(t, userUUID, userUUID, true) {
		t.Fatal("a stock server accepted the suffixed auth; the opt-in gate would be pointless")
	}
	if !hysteria2AuthOK(t, userUUID+"#"+yueTestTag, userUUID, true) {
		t.Fatal("switch on must send <password>#<tag>")
	}
}
