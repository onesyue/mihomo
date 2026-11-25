package outbound

import (
	"net/netip"
	"testing"

	"github.com/metacubex/mihomo/common/structure"
	"github.com/metacubex/mihomo/component/yueconntag"
	"github.com/metacubex/mihomo/transport/vless"

	"google.golang.org/protobuf/proto"
)

const outboundTestTag = "AbCdEf012_-"

func decodeOption(t *testing.T, mapping map[string]any, dst any) {
	t.Helper()
	d := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	if err := d.Decode(mapping, dst); err != nil {
		t.Fatal(err)
	}
}

func TestYueConnTagOptionDecoding(t *testing.T) {
	base := map[string]any{"name": "n", "server": "203.0.113.1", "port": 443, "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "password": "p"}
	var off VlessOption
	decodeOption(t, base, &off)
	if off.YueConnTag {
		t.Fatal("absent key must decode as off")
	}
	on := map[string]any{"yue-conn-tag": true}
	for k, v := range base {
		on[k] = v
	}
	var v VlessOption
	decodeOption(t, on, &v)
	var h Hysteria2Option
	decodeOption(t, on, &h)
	if !v.YueConnTag || !h.YueConnTag {
		t.Fatal("yue-conn-tag: true must decode for vless and hysteria2")
	}
}

func vlessAddonsOf(t *testing.T, opt VlessOption) *vless.Addons {
	t.Helper()
	opt.Name, opt.Server, opt.Port, opt.UUID = "n", "203.0.113.1", 443, "b831381d-6324-4d53-ad4f-8cda48b30811"
	v, err := NewVless(opt)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	return v.client.Addons
}

func TestYueConnTagVlessGate(t *testing.T) {
	yueconntag.Set(outboundTestTag)
	defer yueconntag.Set("")

	// Switch off: identical to the untagged client, with and without flow.
	if a := vlessAddonsOf(t, VlessOption{}); a != nil {
		t.Fatalf("switch off changed addons: %v", a)
	}
	a := vlessAddonsOf(t, VlessOption{Flow: vless.XRV})
	raw, _ := proto.Marshal(a)
	if want, _ := proto.Marshal(&vless.Addons{Flow: vless.XRV}); string(raw) != string(want) {
		t.Fatalf("switch off changed flow addons: %x", raw)
	}

	// Switch on: the tag rides as the extra field.
	for _, flow := range []string{"", vless.XRV} {
		a := vlessAddonsOf(t, VlessOption{Flow: flow, YueConnTag: true})
		raw, err := proto.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		if got := vless.YueConnTagOf(raw); got != outboundTestTag || a.Flow != flow {
			t.Fatalf("flow %q: tag=%q addons=%v", flow, got, a)
		}
	}

	// Switch on but no host tag: identical again.
	yueconntag.Set("")
	if a := vlessAddonsOf(t, VlessOption{YueConnTag: true}); a != nil {
		t.Fatalf("no device tag must not change addons: %v", a)
	}
}

func TestYueConnTagHysteria2Password(t *testing.T) {
	yueconntag.Set(outboundTestTag)
	defer yueconntag.Set("")
	if got := yueHysteria2Password("secret", false); got != "secret" {
		t.Fatalf("switch off changed the auth string: %q", got)
	}
	if got := yueHysteria2Password("secret", true); got != "secret#"+outboundTestTag {
		t.Fatalf("switch on: %q", got)
	}
	yueconntag.Set("")
	if got := yueHysteria2Password("secret", true); got != "secret" {
		t.Fatalf("no device tag changed the auth string: %q", got)
	}
}

func TestYueConnTagRejectsMalformedHostTag(t *testing.T) {
	defer yueconntag.Set("")
	for _, bad := range []string{"short", "has space in it", "a#b#c#d#e", "x/y+z=12345", string(make([]byte, 40))} {
		yueconntag.Set(bad)
		if yueconntag.Get() != "" {
			t.Fatalf("malformed tag %q accepted", bad)
		}
		if yueHysteria2Password("p", true) != "p" {
			t.Fatalf("malformed tag %q reached the auth string", bad)
		}
	}
}

func TestCloneForReachProbePinsAddress(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.77")
	orig, err := NewVless(VlessOption{Name: "n", Server: "entry.example", Port: 443, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", TLS: true})
	if err != nil {
		t.Fatal(err)
	}
	c, err := CloneForReachProbe(orig, ip)
	if err != nil {
		t.Fatal(err)
	}
	cv := c.(*Vless)
	if cv.option.Server != ip.String() || cv.option.ServerName != "entry.example" || orig.option.Server != "entry.example" {
		t.Fatalf("clone=%+v orig=%+v", cv.option, orig.option)
	}
	h, err := NewHysteria2(Hysteria2Option{Name: "h", Server: "hy.example", Port: 8443, Ports: "20000-20010", Password: "p"})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	hc, err := CloneForReachProbe(h, ip)
	if err != nil {
		t.Fatal(err)
	}
	defer hc.Close()
	ho := hc.(*Hysteria2).option
	if ho.Server != ip.String() || ho.SNI != "hy.example" || ho.Ports != "" || h.option.Ports == "" {
		t.Fatalf("hy2 clone=%+v", ho)
	}
	if host, port, proto, ok := ReachProbeServer(h); !ok || host != "hy.example" || port != 8443 || proto != "hy2" {
		t.Fatalf("ReachProbeServer = %q %d %q %v", host, port, proto, ok)
	}
	if _, err := CloneForReachProbe(NewDirect(), ip); err == nil {
		t.Fatal("direct outbound must not be clonable")
	}
}
