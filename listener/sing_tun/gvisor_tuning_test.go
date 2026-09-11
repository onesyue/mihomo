//go:build with_gvisor

package sing_tun

import (
	"math"
	"runtime"
	"strconv"
	"testing"

	tun "github.com/metacubex/sing-tun"
)

// TestGvisorBufferProfileTiers keeps the per-platform budgets honest: every
// tier must beat 20 KiB by a wide margin, and iOS must stay the tightest
// because the packet-tunnel extension lives inside Apple's ~50 MiB ceiling.
func TestGvisorBufferProfileTiers(t *testing.T) {
	p := gvisorBufferProfile()
	if p.def < 64<<10 {
		t.Errorf("default %d is too small to beat the 20 KiB ceiling meaningfully", p.def)
	}
	if p.max < p.def {
		t.Errorf("max %d < default %d", p.max, p.def)
	}
	if p.min <= 0 || p.min > p.def {
		t.Errorf("min %d out of range", p.min)
	}
	if p != bufferProfileFor(runtime.GOOS) {
		t.Errorf("gvisorBufferProfile() disagrees with bufferProfileFor(%q)", runtime.GOOS)
	}
}

// TestGvisorBufferProfileEveryTier pins all three tiers, including the two this
// test binary can never be: a Go test runs as exactly one GOOS, so without this
// the iOS and Android budgets would be unguarded on every host we build from.
func TestGvisorBufferProfileEveryTier(t *testing.T) {
	for _, tc := range []struct {
		goos     string
		wantDef  int
		wantMax  int
		wantTier string
	}{
		{"ios", 128 << 10, 256 << 10, "ios"},
		{"android", 256 << 10, 1 << 20, "android"},
		{"linux", 512 << 10, 4 << 20, "desktop"},
		{"darwin", 512 << 10, 4 << 20, "desktop"},
		{"windows", 512 << 10, 4 << 20, "desktop"},
	} {
		p := bufferProfileFor(tc.goos)
		if p.def != tc.wantDef || p.max != tc.wantMax || p.tierTag != tc.wantTier {
			t.Errorf("%s: got %d/%d %q, want %d/%d %q",
				tc.goos, p.def, p.max, p.tierTag, tc.wantDef, tc.wantMax, tc.wantTier)
		}
		if p.max <= 20<<10 {
			t.Errorf("%s: cap %d does not beat sing-tun's 20 KiB", tc.goos, p.max)
		}
	}
	// iOS must stay the tightest tier: its core lives in the packet-tunnel
	// extension under Apple's ~50 MiB ceiling.
	if bufferProfileFor("ios").max >= bufferProfileFor("android").max {
		t.Error("the ios tier must stay strictly tighter than android")
	}
}

func TestNativeTCPBufferOptions(t *testing.T) {
	for _, goos := range []string{"ios", "android", "linux", "darwin", "windows"} {
		p := bufferProfileFor(goos)
		want := tun.TCPBufferRange{Min: p.min, Default: p.def, Max: p.max}
		if got := gvisorTCPBufferRangeFor(goos, ""); got != want {
			t.Errorf("%s native options = %+v, want %+v", goos, got, want)
		}
		for _, raw := range []string{"-1", "invalid", strconv.Itoa(math.MaxInt)} {
			if got := gvisorTCPBufferRangeFor(goos, raw); got != want {
				t.Errorf("%s invalid override %q changed native options: %+v", goos, raw, got)
			}
		}
		if goos == "ios" || goos == "android" {
			for _, raw := range []string{"0", "20", "4096"} {
				if got := gvisorTCPBufferRangeFor(goos, raw); got != want {
					t.Errorf("%s desktop override %q changed mobile memory budget", goos, raw)
				}
			}
			continue
		}
		if got := gvisorTCPBufferRangeFor(goos, "20"); got != (tun.TCPBufferRange{Min: 4096, Default: 20480, Max: 20480}) {
			t.Errorf("%s stock override = %+v", goos, got)
		}
		if got := gvisorTCPBufferRangeFor(goos, "0"); got != (tun.TCPBufferRange{}) {
			t.Errorf("%s zero override must preserve native upstream defaults: %+v", goos, got)
		}
	}
}
