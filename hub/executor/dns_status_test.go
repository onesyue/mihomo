package executor

import (
	"encoding/json"
	"testing"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/dns"
)

func TestRunningDNSStatusReadsTheLiveEnhancer(t *testing.T) {
	previous := resolver.DefaultHostMapper
	t.Cleanup(func() { resolver.DefaultHostMapper = previous })

	resolver.DefaultHostMapper = nil
	disabled := RunningDNSStatus()
	if disabled.Enable || disabled.IPv6 || disabled.EnhancedMode != C.DNSNormal.String() {
		t.Fatalf("disabled DNS = %+v", disabled)
	}

	resolver.DefaultHostMapper = dns.NewEnhancer(dns.EnhancerConfig{
		IPv6:         true,
		EnhancedMode: C.DNSFakeIP,
	})
	enabled := RunningDNSStatus()
	if !enabled.Enable || !enabled.IPv6 || enabled.EnhancedMode != C.DNSFakeIP.String() {
		t.Fatalf("fake-ip DNS = %+v", enabled)
	}
}

func TestConfigViewPublishesDNSBesideGeneral(t *testing.T) {
	previous := resolver.DefaultHostMapper
	t.Cleanup(func() { resolver.DefaultHostMapper = previous })
	resolver.DefaultHostMapper = dns.NewEnhancer(dns.EnhancerConfig{
		EnhancedMode: C.DNSMapping,
	})

	body, err := json.Marshal(CurrentConfigView())
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded["ipv6"]; !ok {
		t.Fatal("general ipv6 was not promoted")
	}
	dnsBody, ok := decoded["dns"].(map[string]any)
	if !ok {
		t.Fatalf("dns = %#v", decoded["dns"])
	}
	if dnsBody["enable"] != true || dnsBody["enhanced-mode"] != "redir-host" || dnsBody["ipv6"] != false {
		t.Fatalf("dns = %#v", dnsBody)
	}
}
