package provider

import (
	"context"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
)

// localDialAdapter reaches a loopback fixture without the Direct loopback
// detector. It is not evidence about a public path.
type localDialAdapter struct {
	*outbound.Base
	address string
	dials   *atomic.Int32
}

func (a *localDialAdapter) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	a.dials.Add(1)
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", a.address)
	if err != nil {
		return nil, err
	}
	return outbound.NewConn(conn, a), nil
}

type stormFixture struct {
	server   *httptest.Server
	requests atomic.Int32
	byPath   sync.Map
	entered  chan struct{}
	release  chan struct{}
	dials    atomic.Int32
}

func newStormFixture(t *testing.T, block bool) *stormFixture {
	t.Helper()
	fix := &stormFixture{entered: make(chan struct{}, 16), release: make(chan struct{})}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fix.requests.Add(1)
		cur, _ := fix.byPath.LoadOrStore(r.URL.Path, new(atomic.Int32))
		cur.(*atomic.Int32).Add(1)
		if block {
			select {
			case fix.entered <- struct{}{}:
			default:
			}
			select {
			case <-fix.release:
			case <-r.Context().Done():
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Start()
	t.Cleanup(server.Close)
	fix.server = server
	return fix
}

func (fix *stormFixture) url(path string) string {
	return "http://probe.fixture.invalid" + path
}

func (fix *stormFixture) proxy(name string) *adapter.Proxy {
	return adapter.NewProxy(&localDialAdapter{
		Base:    outbound.NewBase(outbound.BaseOption{Name: name, Type: C.Vless}),
		address: fix.server.Listener.Addr().String(),
		dials:   &fix.dials,
	})
}

func (fix *stormFixture) pathCount(path string) int32 {
	cur, ok := fix.byPath.Load(path)
	if !ok {
		return 0
	}
	return cur.(*atomic.Int32).Load()
}

func withUnifiedDelayOff(t *testing.T) {
	t.Helper()
	prev := adapter.UnifiedDelay.Load()
	adapter.UnifiedDelay.Store(false)
	t.Cleanup(func() { adapter.UnifiedDelay.Store(prev) })
}

func waitRequests(t *testing.T, fix *stormFixture, want int32, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if fix.requests.Load() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d requests; got %d", want, fix.requests.Load())
}

func TestStartupHealthChecksCoalesceEquivalentProbes(t *testing.T) {
	withUnifiedDelayOff(t)
	fix := newStormFixture(t, false)
	proxy := fix.proxy("node")
	members := []C.Proxy{proxy}
	expected, err := utils.NewUnsignedRanges[uint16]("204")
	if err != nil {
		t.Fatal(err)
	}
	url := fix.url("/generate_204")

	hcA := NewHealthCheck(members, url, 1000, 300, true, expected)
	hcB := NewHealthCheck(members, url, 1000, 300, true, expected)
	pdA, err := NewCompatibleProvider("group-a", members, hcA)
	if err != nil {
		t.Fatal(err)
	}
	pdB, err := NewCompatibleProvider("group-b", members, hcB)
	if err != nil {
		t.Fatal(err)
	}
	defer pdA.Close()
	defer pdB.Close()

	if err := pdA.Initial(); err != nil {
		t.Fatal(err)
	}
	if err := pdB.Initial(); err != nil {
		t.Fatal(err)
	}

	waitRequests(t, fix, 1, 2*time.Second)
	time.Sleep(150 * time.Millisecond)
	if got := fix.requests.Load(); got != 1 {
		t.Fatalf("equivalent startup probes were not coalesced: requests=%d dials=%d (want 1)", got, fix.dials.Load())
	}
	if !proxy.AliveForTestUrl(url) {
		t.Fatal("shared proxy should record the coalesced probe as alive")
	}
}

func TestDistinctProbeContractsAreNotMerged(t *testing.T) {
	withUnifiedDelayOff(t)
	fix := newStormFixture(t, false)
	proxy := fix.proxy("node")
	members := []C.Proxy{proxy}
	expected, err := utils.NewUnsignedRanges[uint16]("204")
	if err != nil {
		t.Fatal(err)
	}
	urlA := fix.url("/contract-a")
	urlB := fix.url("/contract-b")
	hcA := NewHealthCheck(members, urlA, 1000, 0, true, expected)
	hcB := NewHealthCheck(members, urlB, 1000, 0, true, expected)
	defer hcA.close()
	defer hcB.close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); hcA.check() }()
	go func() { defer wg.Done(); hcB.check() }()
	wg.Wait()

	if fix.pathCount("/contract-a") != 1 || fix.pathCount("/contract-b") != 1 {
		t.Fatalf("distinct URLs should each be probed once: a=%d b=%d total=%d",
			fix.pathCount("/contract-a"), fix.pathCount("/contract-b"), fix.requests.Load())
	}
}

func TestClosingOneGroupDoesNotCancelASharedInFlightProbe(t *testing.T) {
	withUnifiedDelayOff(t)
	fix := newStormFixture(t, true)
	proxy := fix.proxy("node")
	members := []C.Proxy{proxy}
	expected, err := utils.NewUnsignedRanges[uint16]("204")
	if err != nil {
		t.Fatal(err)
	}
	url := fix.url("/generate_204")
	hcA := NewHealthCheck(members, url, 2000, 0, true, expected)
	hcB := NewHealthCheck(members, url, 2000, 0, true, expected)
	defer hcB.close()

	doneB := make(chan struct{})
	go hcA.check()
	go func() {
		defer close(doneB)
		hcB.check()
	}()

	select {
	case <-fix.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("probe did not reach the fixture")
	}
	hcA.close()
	close(fix.release)
	select {
	case <-doneB:
	case <-time.After(2 * time.Second):
		t.Fatal("remaining group check did not finish after the first group closed")
	}
	if !proxy.AliveForTestUrl(url) {
		t.Fatalf("closing one group cancelled the shared probe; requests=%d", fix.requests.Load())
	}
	if got := fix.requests.Load(); got != 1 {
		t.Fatalf("shared in-flight probe should stay a single request, got %d", got)
	}
}
