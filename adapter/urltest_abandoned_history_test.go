package adapter_test

import (
	"context"
	"io"
	"log"
	"net"
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

// holdFirstDialAdapter lets the first DialContext ignore cancellation until
// the test unblocks it, simulating a slow-to-abort in-flight probe. Later
// dials complete normally against the fixture server.
type holdFirstDialAdapter struct {
	*outbound.Base
	address    string
	started    chan struct{}
	unblock    chan struct{}
	dials      atomic.Int32
	firstErrCh chan error
}

func (a *holdFirstDialAdapter) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	n := a.dials.Add(1)
	if n == 1 {
		close(a.started)
		<-a.unblock
		err := ctx.Err()
		if err == nil {
			err = context.Canceled
		}
		a.firstErrCh <- err
		return nil, err
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", a.address)
	if err != nil {
		return nil, err
	}
	return outbound.NewConn(conn, a), nil
}

// TestAbandonedFlightDoesNotClobberNewerHistory is a contract the candidate
// does not meet: doURLTest always writes DelayHistory and alive in a defer,
// even after the flight was abandoned and replaced. A late cancel/error write
// can overwrite a newer successful generation.
func TestAbandonedFlightDoesNotClobberNewerHistory(t *testing.T) {
	prev := adapter.UnifiedDelay.Load()
	adapter.UnifiedDelay.Store(false)
	t.Cleanup(func() { adapter.UnifiedDelay.Store(prev) })

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Start()
	t.Cleanup(server.Close)

	exp, err := utils.NewUnsignedRanges[uint16]("204")
	if err != nil {
		t.Fatal(err)
	}
	url := "http://probe.fixture.invalid/generate_204"

	dialer := &holdFirstDialAdapter{
		Base:       outbound.NewBase(outbound.BaseOption{Name: "node", Type: C.Vless}),
		address:    server.Listener.Addr().String(),
		started:    make(chan struct{}),
		unblock:    make(chan struct{}),
		firstErrCh: make(chan error, 1),
	}
	proxy := adapter.NewProxy(dialer)

	ctx1, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	errCh := make(chan error, 1)
	go func() {
		_, e := proxy.URLTest(ctx1, url, exp)
		errCh <- e
	}()

	select {
	case <-dialer.started:
	case <-time.After(2 * time.Second):
		t.Fatal("first flight did not start dialing")
	}

	cancel1()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("cancelled first waiter should return an error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled first waiter did not return")
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	delay, err := proxy.URLTest(ctx2, url, exp)
	if err != nil || delay == 0 {
		t.Fatalf("replacement flight should succeed, delay=%d err=%v", delay, err)
	}
	if !proxy.AliveForTestUrl(url) {
		t.Fatal("successful replacement flight should mark the URL alive")
	}
	if got := proxy.LastDelayForTestUrl(url); got == 0 || got == 0xffff {
		t.Fatalf("successful replacement last delay should be a real value, got %d", got)
	}
	historyAfterSuccess := proxy.DelayHistoryForTestUrl(url)
	if len(historyAfterSuccess) != 1 || historyAfterSuccess[0].Delay == 0 {
		t.Fatalf("expected one successful history record before the old flight returns, got %+v", historyAfterSuccess)
	}

	close(dialer.unblock)
	select {
	case <-dialer.firstErrCh:
	case <-time.After(2 * time.Second):
		t.Fatal("abandoned first dial did not return")
	}
	// Let the old doURLTest defer run.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if dialer.dials.Load() >= 2 {
			time.Sleep(20 * time.Millisecond)
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)

	if !proxy.AliveForTestUrl(url) {
		t.Fatal("abandoned flight overwrote newer alive=true with a cancel failure")
	}
	if got := proxy.LastDelayForTestUrl(url); got == 0 || got == 0xffff {
		t.Fatalf("abandoned flight overwrote newer last delay, got %d", got)
	}
	history := proxy.DelayHistoryForTestUrl(url)
	if len(history) == 0 {
		t.Fatal("history is empty after both flights")
	}
	last := history[len(history)-1]
	if last.Delay == 0 {
		t.Fatalf("abandoned flight appended or replaced history with a failure after a newer success: %+v", history)
	}
}

// TestCancelledFlightWithoutReplacementStillRecordsHistory keeps the
// pre-coalesce observability: if a probe is cancelled and no newer
// generation commits, the late (or completing) failure must still be
// written to DelayHistory and alive. Silently dropping that record would
// hide a cancelled result.
func TestCancelledFlightWithoutReplacementStillRecordsHistory(t *testing.T) {
	prev := adapter.UnifiedDelay.Load()
	adapter.UnifiedDelay.Store(false)
	t.Cleanup(func() { adapter.UnifiedDelay.Store(prev) })

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Start()
	t.Cleanup(server.Close)

	exp, err := utils.NewUnsignedRanges[uint16]("204")
	if err != nil {
		t.Fatal(err)
	}
	url := "http://probe.fixture.invalid/generate_204"

	dialer := &holdFirstDialAdapter{
		Base:       outbound.NewBase(outbound.BaseOption{Name: "node", Type: C.Vless}),
		address:    server.Listener.Addr().String(),
		started:    make(chan struct{}),
		unblock:    make(chan struct{}),
		firstErrCh: make(chan error, 1),
	}
	proxy := adapter.NewProxy(dialer)

	ctx1, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	errCh := make(chan error, 1)
	go func() {
		_, e := proxy.URLTest(ctx1, url, exp)
		errCh <- e
	}()

	select {
	case <-dialer.started:
	case <-time.After(2 * time.Second):
		t.Fatal("first flight did not start dialing")
	}

	cancel1()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("cancelled waiter should return an error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled waiter did not return")
	}

	close(dialer.unblock)
	select {
	case <-dialer.firstErrCh:
	case <-time.After(2 * time.Second):
		t.Fatal("abandoned dial did not return")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(proxy.DelayHistoryForTestUrl(url)) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	history := proxy.DelayHistoryForTestUrl(url)
	if len(history) == 0 {
		t.Fatal("cancelled probe with no replacement discarded DelayHistory")
	}
	if history[len(history)-1].Delay != 0 {
		t.Fatalf("cancelled probe with no replacement should record a failure, got %+v", history)
	}
	if proxy.AliveForTestUrl(url) {
		t.Fatal("cancelled probe with no replacement should not leave the URL marked alive")
	}
	if got := proxy.LastDelayForTestUrl(url); got != 0xffff {
		t.Fatalf("cancelled probe with no replacement last delay should be max uint16, got %d", got)
	}
}

// TestAbandonedFlightDoesNotClobberNewerHistoryForDifferentURL covers the
// shared global alive/history: a late abandoned failure for URL A must not
// append a global failure after a newer successful probe of URL B, and must
// not flip the proxy-level history tail. URL A's own history may still
// record the cancelled result because no newer generation of A committed.
func TestAbandonedFlightDoesNotClobberNewerHistoryForDifferentURL(t *testing.T) {
	prev := adapter.UnifiedDelay.Load()
	adapter.UnifiedDelay.Store(false)
	t.Cleanup(func() { adapter.UnifiedDelay.Store(prev) })

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Start()
	t.Cleanup(server.Close)

	exp, err := utils.NewUnsignedRanges[uint16]("204")
	if err != nil {
		t.Fatal(err)
	}
	urlA := "http://probe-a.fixture.invalid/generate_204"
	urlB := "http://probe-b.fixture.invalid/generate_204"

	dialer := &holdFirstDialAdapter{
		Base:       outbound.NewBase(outbound.BaseOption{Name: "node", Type: C.Vless}),
		address:    server.Listener.Addr().String(),
		started:    make(chan struct{}),
		unblock:    make(chan struct{}),
		firstErrCh: make(chan error, 1),
	}
	proxy := adapter.NewProxy(dialer)

	ctx1, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	errCh := make(chan error, 1)
	go func() {
		_, e := proxy.URLTest(ctx1, urlA, exp)
		errCh <- e
	}()

	select {
	case <-dialer.started:
	case <-time.After(2 * time.Second):
		t.Fatal("first flight did not start dialing")
	}

	cancel1()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("cancelled first waiter should return an error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled first waiter did not return")
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	delay, err := proxy.URLTest(ctx2, urlB, exp)
	if err != nil || delay == 0 {
		t.Fatalf("URL B replacement should succeed, delay=%d err=%v", delay, err)
	}
	if !proxy.AliveForTestUrl(urlB) {
		t.Fatal("successful URL B probe should mark URL B alive")
	}
	globalAfterSuccess := proxy.DelayHistory()
	if len(globalAfterSuccess) != 1 || globalAfterSuccess[0].Delay == 0 {
		t.Fatalf("expected one successful global history record before the old flight returns, got %+v", globalAfterSuccess)
	}

	close(dialer.unblock)
	select {
	case <-dialer.firstErrCh:
	case <-time.After(2 * time.Second):
		t.Fatal("abandoned first dial did not return")
	}
	time.Sleep(80 * time.Millisecond)

	if !proxy.AliveForTestUrl(urlB) {
		t.Fatal("abandoned URL A flight overwrote URL B alive state")
	}
	global := proxy.DelayHistory()
	if len(global) == 0 {
		t.Fatal("global history is empty after both flights")
	}
	if last := global[len(global)-1]; last.Delay == 0 {
		t.Fatalf("abandoned URL A flight appended a global failure after a newer URL B success: %+v", global)
	}
	historyA := proxy.DelayHistoryForTestUrl(urlA)
	if len(historyA) == 0 || historyA[len(historyA)-1].Delay != 0 {
		t.Fatalf("URL A cancel with no newer A generation should remain observable, got %+v", historyA)
	}
	if proxy.AliveForTestUrl(urlA) {
		t.Fatal("URL A cancel should not leave URL A marked alive")
	}
}

// TestAbandonedFlightDoesNotClobberNewerHistoryForDifferentStatus covers
// same-URL, distinct expected-status contracts that share URL-level state.
func TestAbandonedFlightDoesNotClobberNewerHistoryForDifferentStatus(t *testing.T) {
	prev := adapter.UnifiedDelay.Load()
	adapter.UnifiedDelay.Store(false)
	t.Cleanup(func() { adapter.UnifiedDelay.Store(prev) })

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Start()
	t.Cleanup(server.Close)

	exp204, err := utils.NewUnsignedRanges[uint16]("204")
	if err != nil {
		t.Fatal(err)
	}
	expAny, err := utils.NewUnsignedRanges[uint16]("200-204")
	if err != nil {
		t.Fatal(err)
	}
	url := "http://probe.fixture.invalid/generate_204"

	dialer := &holdFirstDialAdapter{
		Base:       outbound.NewBase(outbound.BaseOption{Name: "node", Type: C.Vless}),
		address:    server.Listener.Addr().String(),
		started:    make(chan struct{}),
		unblock:    make(chan struct{}),
		firstErrCh: make(chan error, 1),
	}
	proxy := adapter.NewProxy(dialer)

	ctx1, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	errCh := make(chan error, 1)
	go func() {
		_, e := proxy.URLTest(ctx1, url, exp204)
		errCh <- e
	}()

	select {
	case <-dialer.started:
	case <-time.After(2 * time.Second):
		t.Fatal("first flight did not start dialing")
	}

	cancel1()
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("cancelled first waiter should return an error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled first waiter did not return")
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	delay, err := proxy.URLTest(ctx2, url, expAny)
	if err != nil || delay == 0 {
		t.Fatalf("distinct-status replacement should succeed, delay=%d err=%v", delay, err)
	}
	historyAfterSuccess := proxy.DelayHistoryForTestUrl(url)
	if len(historyAfterSuccess) != 1 || historyAfterSuccess[0].Delay == 0 {
		t.Fatalf("expected one successful URL history record before the old flight returns, got %+v", historyAfterSuccess)
	}

	close(dialer.unblock)
	select {
	case <-dialer.firstErrCh:
	case <-time.After(2 * time.Second):
		t.Fatal("abandoned first dial did not return")
	}
	time.Sleep(80 * time.Millisecond)

	if !proxy.AliveForTestUrl(url) {
		t.Fatal("abandoned distinct-status flight overwrote newer alive=true")
	}
	history := proxy.DelayHistoryForTestUrl(url)
	if len(history) == 0 || history[len(history)-1].Delay == 0 {
		t.Fatalf("abandoned distinct-status flight clobbered shared URL history: %+v", history)
	}
}
