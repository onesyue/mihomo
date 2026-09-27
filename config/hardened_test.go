package config

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

const hardenedProbeConfig = `
mode: rule
external-controller: 0.0.0.0:9090
external-controller-tls: "[::]:9443"
external-controller-unix: /etc/sudoers
external-controller-pipe: \\.\pipe\evil
external-ui: /Library/LaunchDaemons
external-ui-url: https://example.invalid/ui.zip
external-ui-name: evil
ntp:
  enable: false
  write-to-system: true
iptables:
  enable: true
listeners:
  - name: extra
    type: mixed
    port: 17777
`

func withHardened(t *testing.T, on bool) {
	t.Helper()
	prev := C.Hardened
	C.Hardened = on
	t.Cleanup(func() { C.Hardened = prev })
}

// YueLink SEC1: the policy must apply inside Parse, the path shared by the
// start-up file and PUT /configs (which never passes the helper).
func TestHardenedParseStripsPrivilegedSurfaces(t *testing.T) {
	withHardened(t, true)
	cfg, err := Parse([]byte(hardenedProbeConfig))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	c := cfg.Controller
	if c.ExternalUI != "" || c.ExternalUIURL != "" || c.ExternalUIName != "" {
		t.Errorf("external-ui kept: %q %q %q", c.ExternalUI, c.ExternalUIURL, c.ExternalUIName)
	}
	if c.ExternalControllerUnix != "" || c.ExternalControllerPipe != "" {
		t.Errorf("controller socket kept: %q %q", c.ExternalControllerUnix, c.ExternalControllerPipe)
	}
	if c.ExternalController != "127.0.0.1:9090" {
		t.Errorf("external-controller = %q, want loopback", c.ExternalController)
	}
	if c.ExternalControllerTLS != "127.0.0.1:9443" {
		t.Errorf("external-controller-tls = %q, want loopback", c.ExternalControllerTLS)
	}
	if cfg.NTP.WriteToSystem {
		t.Error("ntp.write-to-system kept")
	}
	if cfg.IPTables.Enable {
		t.Error("iptables kept")
	}
	if len(cfg.Listeners) != 0 {
		t.Errorf("listeners kept: %d", len(cfg.Listeners))
	}
}

// Control: outside the helper nothing changes (a desktop user running the
// embedded core owns their own machine).
func TestUnhardenedParseKeepsUpstreamSemantics(t *testing.T) {
	withHardened(t, false)
	raw, err := UnmarshalRawConfig([]byte(hardenedProbeConfig))
	if err != nil {
		t.Fatal(err)
	}
	applyHardenedPolicy(raw)
	if raw.ExternalControllerUnix == "" || !raw.NTP.WriteToSystem || len(raw.Listeners) != 1 ||
		raw.ExternalController != "0.0.0.0:9090" {
		t.Fatalf("policy applied without the helper: %+v", raw)
	}
}

func TestLoopbackOnly(t *testing.T) {
	for in, want := range map[string]string{
		"":                "",
		"127.0.0.1:9090":  "127.0.0.1:9090",
		"localhost:9090":  "localhost:9090",
		"[::1]:9090":      "[::1]:9090",
		"0.0.0.0:9090":    "127.0.0.1:9090",
		":9090":           "127.0.0.1:9090",
		"192.168.1.2:1":   "127.0.0.1:1",
		"not-an-address":  "127.0.0.1:0",
		"example.com:443": "127.0.0.1:443",
	} {
		if got, _ := loopbackOnly(in); got != want {
			t.Errorf("loopbackOnly(%q) = %q, want %q", in, got, want)
		}
	}
}
