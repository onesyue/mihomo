package adapter_test

import (
	"context"
	"io"
	"log"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/probestage"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
)

type localDialAdapter struct {
	*outbound.Base
	address string
	dials   *atomic.Int32
	mark    bool
}

func (a *localDialAdapter) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	a.dials.Add(1)
	if a.mark {
		probestage.Begin(ctx)
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", a.address)
	if err != nil {
		return nil, err
	}
	return outbound.NewConn(conn, a), nil
}

type coalesceFixture struct {
	server   *httptest.Server
	requests atomic.Int32
	entered  chan struct{}
	release  chan struct{}
	finished chan struct{}
	dials    atomic.Int32
	delay    time.Duration
}

func newCoalesceFixture(t *testing.T, opts ...func(*coalesceFixture)) *coalesceFixture {
	t.Helper()
	fix := &coalesceFixture{
		entered:  make(chan struct{}, 32),
		release:  make(chan struct{}),
		finished: make(chan struct{}, 32),
	}
	for _, opt := range opts {
		opt(fix)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fix.requests.Add(1)
		select {
		case fix.entered <- struct{}{}:
		default:
		}
		if fix.delay > 0 {
			select {
			case <-time.After(fix.delay):
			case <-r.Context().Done():
				select {
				case fix.finished <- struct{}{}:
				default:
				}
				return
			}
		}
		if cap(fix.release) == 0 && fix.release != nil {
			// unbuffered or closed-later hold: only wait if caller uses block via nil delay and a still-open hold flag
		}
		select {
		case <-fix.release:
		default:
			// release is initially open-for-data; tests that need a hold
			// leave it unclosed and send after entered. If the channel is
			// already closed, this receive returns immediately.
			if fix.delay == 0 && !closedChan(fix.release) && !tryNonBlockRelease(fix) {
				select {
				case <-fix.release:
				case <-r.Context().Done():
					select {
					case fix.finished <- struct{}{}:
					default:
					}
					return
				}
			}
		}
		w.WriteHeader(http.StatusNoContent)
		select {
		case fix.finished <- struct{}{}:
		default:
		}
	})
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Start()
	t.Cleanup(server.Close)
	fix.server = server
	return fix
}

func closedChan(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func tryNonBlockRelease(fix *coalesceFixture) bool {
	// If release was closed, receive succeeded in the select default? No.
	// Helper unused in hold path. Keep compile-stable.
	return false
}

func withDelay(d time.Duration) func(*coalesceFixture) {
	return func(f *coalesceFixture) { f.delay = d }
}

func (fix *coalesceFixture) hold() {
	// default constructor already uses an open unbuffered/buffered hold
}

func (fix *coalesceFixture) url() string {
	return "http://probe.fixture.invalid/generate_204"
}

func (fix *coalesceFixture) proxy(name string, mark bool) *adapter.Proxy {
	return adapter.NewProxy(&localDialAdapter{
		Base:    outbound.NewBase(outbound.BaseOption{Name: name, Type: C.Vless}),
		address: fix.server.Listener.Addr().String(),
		dials:   &fix.dials,
		mark:    mark,
	})
}

func withUnifiedDelayOff(t *testing.T) {
	t.Helper()
	prev := adapter.UnifiedDelay.Load()
	adapter.UnifiedDelay.Store(false)
	t.Cleanup(func() { adapter.UnifiedDelay.Store(prev) })
}

func expected204(t *testing.T) utils.IntRanges[uint16] {
	t.Helper()
	v, err := utils.NewUnsignedRanges[uint16]("204")
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestFirstWaiterShortDeadlineDoesNotStarveLaterWaiter(t *testing.T) {
	withUnifiedDelayOff(t)
	fix := newCoalesceFixture(t, withDelay(250*time.Millisecond))
	close(fix.release) // no extra hold; delay only
	proxy := fix.proxy("node", false)
	exp := expected204(t)
	url := fix.url()

	short, cancelShort := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancelShort()
	long, cancelLong := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelLong()

	var shortErr, longErr error
	var longDelay uint16
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, shortErr = proxy.URLTest(short, url, exp)
	}()
	time.Sleep(20 * time.Millisecond) // first waiter is the leader
	go func() {
		defer wg.Done()
		longDelay, longErr = proxy.URLTest(long, url, exp)
	}()
	wg.Wait()

	if shortErr == nil {
		t.Fatal("short waiter should have observed its own deadline")
	}
	if longErr != nil {
		t.Fatalf("later waiter still needed the result, got err=%v requests=%d", longErr, fix.requests.Load())
	}
	if longDelay == 0 || !proxy.AliveForTestUrl(url) {
		t.Fatalf("later waiter should receive the successful probe, delay=%d alive=%v", longDelay, proxy.AliveForTestUrl(url))
	}
	if got := fix.requests.Load(); got != 1 {
		t.Fatalf("equivalent contracts should share one probe, got %d", got)
	}
}

func TestFirstWaiterCancelLeavesLaterWaiterResult(t *testing.T) {
	withUnifiedDelayOff(t)
	fix := newCoalesceFixture(t)
	proxy := fix.proxy("node", false)
	exp := expected204(t)
	url := fix.url()

	leader, cancelLeader := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelLeader()
	later, cancelLater := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelLater()

	var laterDelay uint16
	var laterErr error
	doneLater := make(chan struct{})
	go func() { _, _ = proxy.URLTest(leader, url, exp) }()
	select {
	case <-fix.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("leader did not reach the fixture")
	}
	go func() {
		defer close(doneLater)
		laterDelay, laterErr = proxy.URLTest(later, url, exp)
	}()
	time.Sleep(30 * time.Millisecond)
	cancelLeader()
	close(fix.release)
	select {
	case <-doneLater:
	case <-time.After(2 * time.Second):
		t.Fatal("later waiter did not finish")
	}
	if laterErr != nil || laterDelay == 0 {
		t.Fatalf("cancelled first waiter aborted work still needed by the later waiter: delay=%d err=%v requests=%d", laterDelay, laterErr, fix.requests.Load())
	}
	if got := fix.requests.Load(); got != 1 {
		t.Fatalf("want 1 shared probe, got %d", got)
	}
}

func TestSameKeyStartsNewProbeAfterAllCancelled(t *testing.T) {
	withUnifiedDelayOff(t)
	fix := newCoalesceFixture(t)
	proxy := fix.proxy("node", false)
	exp := expected204(t)
	url := fix.url()

	ctx1, cancel1 := context.WithTimeout(context.Background(), 2*time.Second)
	errCh := make(chan error, 1)
	go func() { _, err := proxy.URLTest(ctx1, url, exp); errCh <- err }()
	select {
	case <-fix.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first probe did not start")
	}
	cancel1()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("cancelled first probe should return an error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled first probe did not return")
	}
	select {
	case <-fix.finished:
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled work did not bound-terminate")
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	close(fix.release)
	delay, err := proxy.URLTest(ctx2, url, exp)
	if err != nil || delay == 0 {
		t.Fatalf("same key after all waiters left should start a new probe: delay=%d err=%v requests=%d", delay, err, fix.requests.Load())
	}
	if got := fix.requests.Load(); got != 2 {
		t.Fatalf("expected a fresh probe after the abandoned flight, got %d", got)
	}
}

func TestConcurrentRelaunchAfterCancelDoesNotLeakOrStall(t *testing.T) {
	withUnifiedDelayOff(t)
	fix := newCoalesceFixture(t, withDelay(20*time.Millisecond))
	close(fix.release)
	proxy := fix.proxy("node", false)
	exp := expected204(t)
	url := fix.url()

	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			_, _ = proxy.URLTest(ctx, url, exp)
			cancel()
			ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
			defer cancel2()
			_, _ = proxy.URLTest(ctx2, url, exp)
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent cancel-and-rejoin stalled")
	}
	if fix.requests.Load() < 1 {
		t.Fatal("expected at least one probe")
	}
}

func TestExpectedStatusContractsAreNotMerged(t *testing.T) {
	withUnifiedDelayOff(t)
	fix := newCoalesceFixture(t)
	close(fix.release)
	proxy := fix.proxy("node", false)
	url := fix.url()
	want204 := expected204(t)
	want200, err := utils.NewUnsignedRanges[uint16]("200")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = proxy.URLTest(context.Background(), url, want204) }()
	go func() { defer wg.Done(); _, _ = proxy.URLTest(context.Background(), url, want200) }()
	wg.Wait()
	if got := fix.requests.Load(); got != 2 {
		t.Fatalf("different expected-status contracts must not share a probe, got %d", got)
	}
}

func TestNilEmptyAndStarExpectedShareOneContract(t *testing.T) {
	withUnifiedDelayOff(t)
	fix := newCoalesceFixture(t, withDelay(80*time.Millisecond))
	close(fix.release)
	proxy := fix.proxy("node", false)
	url := fix.url()
	star, err := utils.NewUnsignedRanges[uint16]("*")
	if err != nil {
		t.Fatal(err)
	}
	empty, err := utils.NewUnsignedRanges[uint16]("")
	if err != nil {
		t.Fatal(err)
	}
	if star.String() != "*" || empty.String() != "*" || utils.IntRanges[uint16](nil).String() != "*" {
		t.Fatalf("empty/default expected must stringify as *: star=%q empty=%q nil=%q", star.String(), empty.String(), utils.IntRanges[uint16](nil).String())
	}

	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); _, _ = proxy.URLTest(context.Background(), url, star) }()
	go func() { defer wg.Done(); _, _ = proxy.URLTest(context.Background(), url, empty) }()
	go func() { defer wg.Done(); _, _ = proxy.URLTest(context.Background(), url, nil) }()
	wg.Wait()
	if got := fix.requests.Load(); got != 1 {
		t.Fatalf("nil/empty/* expected-status are one contract, got %d probes", got)
	}
}

func TestReplacedProxyObjectDoesNotShareInFlight(t *testing.T) {
	withUnifiedDelayOff(t)
	fix := newCoalesceFixture(t)
	exp := expected204(t)
	url := fix.url()
	first := fix.proxy("node", false)
	second := fix.proxy("node", false)
	if first == second {
		t.Fatal("expected distinct proxy objects")
	}

	go func() { _, _ = first.URLTest(context.Background(), url, exp) }()
	select {
	case <-fix.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first generation did not start")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = second.URLTest(context.Background(), url, exp)
	}()
	select {
	case <-fix.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("second generation should start its own probe, not join the previous object")
	}
	close(fix.release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("second generation did not finish")
	}
	if got := fix.requests.Load(); got != 2 {
		t.Fatalf("replaced proxy objects must not share in-flight probes, got %d", got)
	}
}

func TestAllCancelBoundsWorkAndDoesNotLeak(t *testing.T) {
	withUnifiedDelayOff(t)
	fix := newCoalesceFixture(t)
	proxy := fix.proxy("node", false)
	exp := expected204(t)
	url := fix.url()
	before := runtime.NumGoroutine()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	errCh := make(chan error, 1)
	go func() { _, err := proxy.URLTest(ctx, url, exp); errCh <- err }()
	select {
	case <-fix.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("probe did not start")
	}
	cancel()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("cancelled waiter should return an error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled waiter did not return")
	}
	select {
	case <-fix.finished:
	case <-time.After(2 * time.Second):
		t.Fatal("work ignored cancellation and did not bound-terminate")
	}
	// Give the worker goroutine a moment to exit; it must not sit on the 30s HTTP client timeout.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before+5 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutines did not recede after cancel: before=%d now=%d", before, runtime.NumGoroutine())
}

func TestSharedProbeRecordsEachWaiterStageAndWritesHistoryOnce(t *testing.T) {
	withUnifiedDelayOff(t)
	fix := newCoalesceFixture(t, withDelay(80*time.Millisecond))
	close(fix.release)
	proxy := fix.proxy("node", true)
	exp := expected204(t)
	url := fix.url()

	ctxA, traceA := probestage.New(context.Background())
	ctxB, traceB := probestage.New(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = proxy.URLTest(ctxA, url, exp) }()
	time.Sleep(15 * time.Millisecond)
	go func() { defer wg.Done(); _, _ = proxy.URLTest(ctxB, url, exp) }()
	wg.Wait()

	if got := fix.requests.Load(); got != 1 {
		t.Fatalf("shared equivalent probes should be one request, got %d", got)
	}
	if traceA.FailureStage() != "tcp_connect" {
		t.Fatalf("leader recorder: got %q want tcp_connect", traceA.FailureStage())
	}
	if traceB.FailureStage() != "tcp_connect" {
		t.Fatalf("joiner recorder must keep its own stage: got %q want tcp_connect", traceB.FailureStage())
	}
	history := proxy.DelayHistoryForTestUrl(url)
	if len(history) != 1 {
		t.Fatalf("a shared in-flight probe should record delay history once, got %d", len(history))
	}
	// A later sequential test is a new flight and appends a second record.
	if _, err := proxy.URLTest(context.Background(), url, exp); err != nil {
		t.Fatal(err)
	}
	if got := len(proxy.DelayHistoryForTestUrl(url)); got != 2 {
		t.Fatalf("sequential URLTest should append a new history record, got %d", got)
	}
}
