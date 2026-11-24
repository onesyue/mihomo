package adapter

import (
	"context"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
)

func newLinearizationProxy(t *testing.T) *Proxy {
	t.Helper()
	return NewProxy(outbound.NewBase(outbound.BaseOption{Name: "node", Type: C.Direct}))
}

func TestStaleAbandonedSnapshotDoesNotClobberNewerSameURLCommit(t *testing.T) {
	p := newLinearizationProxy(t)
	url := "http://probe.fixture.invalid/generate_204"
	assertFreshCommitLinearization(t, p, url, url, 12)
}

func TestStaleAbandonedSnapshotDoesNotClobberNewerGlobalHistory(t *testing.T) {
	p := newLinearizationProxy(t)
	urlA := "http://probe.fixture.invalid/a"
	urlB := "http://probe.fixture.invalid/b"
	assertFreshCommitLinearization(t, p, urlA, urlB, 15)

	// URL A had no newer generation, so an abandoned failure may still be
	// recorded there, but the proxy-level history tail must stay on B.
	historyA := p.DelayHistoryForTestUrl(urlA)
	if len(historyA) != 0 && historyA[len(historyA)-1].Delay != 0 {
		t.Fatalf("URL A should not look like a success, got %+v", historyA)
	}
}

func assertFreshCommitLinearization(t *testing.T, p *Proxy, urlA, urlB string, wantDelay uint16) {
	t.Helper()

	flightA := &urlTestFlight{seq: 1}
	flightB := &urlTestFlight{seq: 2}

	afterSample := make(chan struct{})
	afterLocked := make(chan struct{})
	allowA := make(chan struct{})
	aDone := make(chan struct{})

	afterSampleHook := urlTestCommitHook(func(got *Proxy, _ *urlTestFlight, seq uint64) {
		if got != p || seq != 1 {
			return
		}
		select {
		case <-afterSample:
		default:
			close(afterSample)
		}
		<-allowA
	})
	afterLockedHook := urlTestCommitHook(func(got *Proxy, _ *urlTestFlight, seq uint64) {
		if got != p || seq != 1 {
			return
		}
		select {
		case <-afterLocked:
		default:
			close(afterLocked)
		}
		<-allowA
	})
	urlTestAfterAbandonedSample.Store(&afterSampleHook)
	urlTestAfterCommitLocked.Store(&afterLockedHook)
	t.Cleanup(func() {
		urlTestAfterAbandonedSample.Store(nil)
		urlTestAfterCommitLocked.Store(nil)
		select {
		case <-allowA:
		default:
			close(allowA)
		}
	})

	go func() {
		defer close(aDone)
		p.commitURLTestResult(flightA, urlA, 0, context.Canceled, false)
	}()

	select {
	case <-afterSample:
		// Pre-fix window: A has a stale abandoned=false snapshot and does
		// not yet hold the write lock, so a newer flight can commit first.
		flightA.mu.Lock()
		flightA.abandoned = true
		flightA.mu.Unlock()
		p.commitURLTestResult(flightB, urlB, wantDelay, nil, true)
		close(allowA)
		<-aDone
	case <-afterLocked:
		// Write lock is already held and the snapshot used for the write
		// has been taken. Mutate abandoned and only start B after A
		// releases the lock, so this path cannot deadlock.
		flightA.mu.Lock()
		flightA.abandoned = true
		flightA.mu.Unlock()
		close(allowA)
		<-aDone
		p.commitURLTestResult(flightB, urlB, wantDelay, nil, true)
	case <-time.After(5 * time.Second):
		t.Fatal("commit A did not reach a scheduling hook")
	}

	if !p.AliveForTestUrl(urlB) {
		t.Fatal("stale abandoned=false snapshot overwrote a newer success")
	}
	if got := p.LastDelayForTestUrl(urlB); got != wantDelay {
		t.Fatalf("newer success last delay want %d got %d", wantDelay, got)
	}
	global := p.DelayHistory()
	if len(global) == 0 || global[len(global)-1].Delay != wantDelay {
		t.Fatalf("global history tail should be the newer success, got %+v", global)
	}
	if p.urlTestGlobalCommit != 2 {
		t.Fatalf("global commit seq want 2 got %d", p.urlTestGlobalCommit)
	}
	if p.urlTestCommit[urlB] != 2 {
		t.Fatalf("URL B commit seq want 2 got %d", p.urlTestCommit[urlB])
	}
	if p.urlTestGlobalCommit < p.urlTestCommit[urlB] {
		t.Fatalf("commit seq went backwards: global=%d urlB=%d", p.urlTestGlobalCommit, p.urlTestCommit[urlB])
	}

	// An even older abandoned generation must not regress the counters.
	older := &urlTestFlight{seq: 1, abandoned: true}
	p.commitURLTestResult(older, urlB, 0, context.Canceled, false)
	if p.urlTestGlobalCommit != 2 || p.urlTestCommit[urlB] != 2 {
		t.Fatalf("older abandoned commit regressed seq: global=%d urlB=%d", p.urlTestGlobalCommit, p.urlTestCommit[urlB])
	}
	if !p.AliveForTestUrl(urlB) || p.LastDelayForTestUrl(urlB) != wantDelay {
		t.Fatal("older abandoned commit overwrote the newer success")
	}
}
