//go:build with_gvisor

package sing_tun

import (
	"reflect"
	"runtime"
	"testing"
	"unsafe"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv6"
	gvstack "github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	"github.com/metacubex/gvisor/pkg/waiter"
	tun "github.com/metacubex/sing-tun"
)

// newStockStack builds a stack the way sing-tun's NewGVisorStackWithOptions
// does, INCLUDING its 20 KiB cap, so the test starts from the exact state
// production starts from.
func newStockStack(t *testing.T) *gvstack.Stack {
	t.Helper()
	s := gvstack.New(gvstack.Options{
		NetworkProtocols:   []gvstack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []gvstack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	t.Cleanup(s.Close)
	if err := s.CreateNIC(1, channel.New(16, 9000, "")); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}
	const stock = 20 * 1024
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: 1, Default: stock, Max: stock}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcv); err != nil {
		t.Fatalf("seed receive range: %v", err)
	}
	snd := tcpip.TCPSendBufferSizeRangeOption{Min: 1, Default: stock, Max: stock}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &snd); err != nil {
		t.Fatalf("seed send range: %v", err)
	}
	return s
}

// setUnexportedStack plants ipStack into the named unexported field of the
// real sing-tun type. If sing-tun ever removes or retypes that field this
// fails here, which is the point: the production path would otherwise keep
// running at 20 KiB with nothing red.
func setUnexportedStack(t *testing.T, holder any, field string, ipStack *gvstack.Stack) {
	t.Helper()
	v := reflect.ValueOf(holder).Elem()
	f := v.FieldByName(field)
	if !f.IsValid() {
		t.Fatalf("sing-tun %T no longer has a %q field — gvisor_tuning.go cannot reach the stack", holder, field)
	}
	if f.Type() != reflect.TypeOf((*gvstack.Stack)(nil)) {
		t.Fatalf("sing-tun %T.%s is %s, expected *stack.Stack", holder, field, f.Type())
	}
	*(**gvstack.Stack)(unsafe.Pointer(f.UnsafeAddr())) = ipStack
}

func readRanges(t *testing.T, s *gvstack.Stack) (rcv tcpip.TCPReceiveBufferSizeRangeOption, snd tcpip.TCPSendBufferSizeRangeOption) {
	t.Helper()
	if err := s.TransportProtocolOption(tcp.ProtocolNumber, &rcv); err != nil {
		t.Fatalf("read receive range: %v", err)
	}
	if err := s.TransportProtocolOption(tcp.ProtocolNumber, &snd); err != nil {
		t.Fatalf("read send range: %v", err)
	}
	return rcv, snd
}

// TestTuneGVisorStackWidensRealGVisorType is the load-bearing one: it uses the
// actual tun.GVisor struct, not a local stand-in.
func TestTuneGVisorStackWidensRealGVisorType(t *testing.T) {
	ipStack := newStockStack(t)
	holder := &tun.GVisor{}
	setUnexportedStack(t, holder, "stack", ipStack)

	if rcv, _ := readRanges(t, ipStack); rcv.Max != 20*1024 {
		t.Fatalf("precondition: expected the stock 20 KiB cap, got %d", rcv.Max)
	}

	tuneGVisorStack(holder)

	want := gvisorBufferProfile()
	rcv, snd := readRanges(t, ipStack)
	if rcv.Default != want.def || rcv.Max != want.max {
		t.Errorf("receive range = %d/%d, want %d/%d", rcv.Default, rcv.Max, want.def, want.max)
	}
	if snd.Default != want.def || snd.Max != want.max {
		t.Errorf("send range = %d/%d, want %d/%d", snd.Default, snd.Max, want.def, want.max)
	}
	if rcv.Max <= 20*1024 {
		t.Errorf("receive cap %d is still at or below sing-tun's 20 KiB — the fix is inert", rcv.Max)
	}
}

// TestTuneGVisorStackReachesMixed covers `stack: mixed` (desktop default),
// where gVisor carries the UDP half and the stack hangs off a different type.
func TestTuneGVisorStackReachesMixed(t *testing.T) {
	ipStack := newStockStack(t)
	holder := &tun.Mixed{}
	setUnexportedStack(t, holder, "stack", ipStack)

	tuneGVisorStack(holder)

	want := gvisorBufferProfile()
	if rcv, _ := readRanges(t, ipStack); rcv.Max != want.max {
		t.Errorf("mixed stack receive cap = %d, want %d", rcv.Max, want.max)
	}
}

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

// TestGvisorBufferOverrideRestoresStock proves the escape hatch works — a
// desktop run can reproduce sing-tun's exact stock behaviour without a rebuild.
func TestGvisorBufferOverrideRestoresStock(t *testing.T) {
	t.Setenv(gvisorBufferOverrideEnv, "20")
	ipStack := newStockStack(t)
	holder := &tun.GVisor{}
	setUnexportedStack(t, holder, "stack", ipStack)

	tuneGVisorStack(holder)

	if rcv, _ := readRanges(t, ipStack); rcv.Max != 20*1024 {
		t.Errorf("override receive cap = %d, want 20480", rcv.Max)
	}
}

// TestGvisorBufferOverrideZeroSkips: =0 must leave the stack untouched.
func TestGvisorBufferOverrideZeroSkips(t *testing.T) {
	t.Setenv(gvisorBufferOverrideEnv, "0")
	ipStack := newStockStack(t)
	holder := &tun.GVisor{}
	setUnexportedStack(t, holder, "stack", ipStack)

	tuneGVisorStack(holder)

	if rcv, _ := readRanges(t, ipStack); rcv.Max != 20*1024 {
		t.Errorf("expected the stack untouched at 20480, got %d", rcv.Max)
	}
}

// TestTuneGVisorStackNilSafe: a System-only stack (no gVisor anywhere) and a
// nil interface must both be no-ops rather than panics.
func TestTuneGVisorStackNilSafe(t *testing.T) {
	tuneGVisorStack(nil)
	tuneGVisorStack(&tun.GVisor{})
}

// TestTunedStackGivesNewEndpointsTheWiderBuffer closes the last gap between
// "the option value changed" and "a connection actually gets it": gVisor reads
// these ranges when it constructs an endpoint, so a socket created after the
// tuning must report the wider limit. Without this, a future gVisor change to
// where endpoints read their defaults would leave the option set and the data
// path still at 20 KiB.
func TestTunedStackGivesNewEndpointsTheWiderBuffer(t *testing.T) {
	ipStack := newStockStack(t)
	holder := &tun.GVisor{}
	setUnexportedStack(t, holder, "stack", ipStack)

	var beforeWQ waiter.Queue
	before, tErr := ipStack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &beforeWQ)
	if tErr != nil {
		t.Fatalf("NewEndpoint before: %v", tErr)
	}
	stockSnd := before.SocketOptions().GetSendBufferSize()
	before.Close()
	if stockSnd != 20*1024 {
		t.Fatalf("precondition: stock endpoint send buffer = %d, want 20480", stockSnd)
	}

	tuneGVisorStack(holder)

	var afterWQ waiter.Queue
	after, tErr := ipStack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &afterWQ)
	if tErr != nil {
		t.Fatalf("NewEndpoint after: %v", tErr)
	}
	defer after.Close()
	want := int64(gvisorBufferProfile().def)
	if got := after.SocketOptions().GetSendBufferSize(); got != want {
		t.Errorf("endpoint send buffer = %d, want %d", got, want)
	}
	if got := after.SocketOptions().GetReceiveBufferSize(); got != want {
		t.Errorf("endpoint receive buffer = %d, want %d", got, want)
	}
}
