//go:build with_gvisor && linux

package sing_tun

import (
	"testing"

	"github.com/metacubex/gvisor/pkg/tcpip/link/fdbased"
)

// TestBufConfigOverrideWon proves our init() runs after sing-tun's. If Go's
// init ordering or sing-tun's file layout ever changed, the flat 64 KiB
// config would come back silently and every packet would go back to pinning
// a 64 KiB chunk.
func TestBufConfigOverrideWon(t *testing.T) {
	if len(fdbased.BufConfig) == 1 && fdbased.BufConfig[0] == 65535 {
		t.Fatal("sing-tun's flat 65535 BufConfig is still in effect — our init() did not win")
	}
	if len(fdbased.BufConfig) != len(yuelinkBufConfig) {
		t.Fatalf("BufConfig = %v, want %v", fdbased.BufConfig, yuelinkBufConfig)
	}
	for i := range yuelinkBufConfig {
		if fdbased.BufConfig[i] != yuelinkBufConfig[i] {
			t.Fatalf("BufConfig = %v, want %v", fdbased.BufConfig, yuelinkBufConfig)
		}
	}
}

// TestBufConfigCoversGSOSuperFrame: gVisor reads at most the sum of the ladder
// in one readv. sing-tun asks for GSOMaxSize = 65536 on Linux, so anything
// short of that truncates a super-frame — a silent corruption, not an error.
func TestBufConfigCoversGSOSuperFrame(t *testing.T) {
	const gsoMaxSize = 65536
	sum := 0
	for _, n := range fdbased.BufConfig {
		sum += n
	}
	if sum < gsoMaxSize {
		t.Errorf("BufConfig sums to %d, must cover the %d-byte GSO super-frame", sum, gsoMaxSize)
	}
}

// TestBufConfigKeepsCommonPacketsContiguous pins the property the ladder was
// chosen for: an ACK or a 1500-byte frame must land in ONE view, and a full
// mtu-9000 frame in at most two, so the hot path neither scatters nor pays a
// PullUp to parse its headers.
func TestBufConfigKeepsCommonPacketsContiguous(t *testing.T) {
	viewsFor := func(size int) int {
		c, used := 0, 0
		for _, n := range fdbased.BufConfig {
			c += n
			used++
			if c >= size {
				break
			}
		}
		return used
	}
	for _, tc := range []struct {
		name     string
		size     int
		maxViews int
	}{
		{"bare ack", 60, 1},
		{"ethernet frame", 1500, 1},
		{"tun mtu 9000 frame", 9040, 2},
	} {
		if got := viewsFor(tc.size); got > tc.maxViews {
			t.Errorf("%s (%d bytes) spans %d views, want <= %d", tc.name, tc.size, got, tc.maxViews)
		}
	}
}

// TestBufConfigChunkCostBeatsFlat64K is the memory claim itself, stated as a
// test: the chunk a 1500-byte packet pins must be an order of magnitude below
// the 64 KiB it used to pin.
func TestBufConfigChunkCostBeatsFlat64K(t *testing.T) {
	held := 0
	for _, n := range fdbased.BufConfig {
		held += n
		if held >= 1500 {
			break
		}
	}
	if held > 8192 {
		t.Errorf("a 1500-byte packet now pins %d bytes; the point of the ladder is to keep this far under the old 65535", held)
	}
}
