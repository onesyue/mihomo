package adapter

import (
	"context"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/probestage"
	"github.com/metacubex/mihomo/common/utils"
)

type urlTestKey struct {
	url      string
	expected string
}

type deadlineWaiter struct {
	hasDeadline bool
	deadline    time.Time
}

type urlTestFlight struct {
	done chan struct{}
	t    uint16
	err  error
	seq  uint64

	mu         sync.Mutex
	waiters    int
	abandoned  bool
	cancelWork context.CancelFunc
	timer      *time.Timer
	timerGen   int
	deadlines  []deadlineWaiter
	shared     *probestage.Trace
}

// URLTest gets the delay for the specified URL.
// Equivalent in-flight tests on the same proxy object (same URL and expected
// status) share one dial and history write. A cancelled waiter does not abort
// work still needed by another waiter; the work lasts until the latest
// remaining deadline, or until every waiter has returned. Distinct URLs or
// expected-status contracts stay independent. After the flight is abandoned,
// the same key starts a new probe.
func (p *Proxy) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (uint16, error) {
	key := urlTestKey{url: url, expected: expectedStatus.String()}

	p.urlTestMu.Lock()
	if p.urlTests == nil {
		p.urlTests = make(map[urlTestKey]*urlTestFlight)
	}
	if flight, ok := p.urlTests[key]; ok && flight.tryJoin(ctx) {
		p.urlTestMu.Unlock()
		return flight.wait(ctx)
	}
	flight := p.startFlightLocked(ctx, key, url, expectedStatus)
	p.urlTestMu.Unlock()
	return flight.wait(ctx)
}

func (p *Proxy) startFlightLocked(ctx context.Context, key urlTestKey, url string, expectedStatus utils.IntRanges[uint16]) *urlTestFlight {
	base := context.WithoutCancel(ctx)
	sharedCtx, shared := probestage.StartShared(base)
	workCtx, cancel := context.WithCancel(sharedCtx)
	p.urlTestSeq++
	flight := &urlTestFlight{
		done:       make(chan struct{}),
		waiters:    1,
		cancelWork: cancel,
		shared:     shared,
		seq:        p.urlTestSeq,
	}
	flight.mu.Lock()
	flight.trackLocked(ctx)
	flight.mu.Unlock()
	p.urlTests[key] = flight
	go func() {
		t, err := p.doURLTest(workCtx, url, expectedStatus, flight)
		flight.t = t
		flight.err = err
		p.urlTestMu.Lock()
		if current, ok := p.urlTests[key]; ok && current == flight {
			delete(p.urlTests, key)
		}
		p.urlTestMu.Unlock()
		flight.mu.Lock()
		flight.abandoned = true
		flight.timerGen++
		if flight.timer != nil {
			flight.timer.Stop()
			flight.timer = nil
		}
		flight.mu.Unlock()
		cancel()
		close(flight.done)
	}()
	return flight
}

func (f *urlTestFlight) tryJoin(ctx context.Context) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.abandoned {
		return false
	}
	f.waiters++
	f.trackLocked(ctx)
	if t := probestage.FromContext(ctx); t != nil {
		f.shared.Mirror(t)
	}
	return true
}

func (f *urlTestFlight) trackLocked(ctx context.Context) {
	w := deadlineWaiter{}
	if deadline, ok := ctx.Deadline(); ok {
		w.hasDeadline = true
		w.deadline = deadline
	}
	f.deadlines = append(f.deadlines, w)
	f.rearmLocked()
}

func (f *urlTestFlight) untrackLocked(ctx context.Context) {
	hasDeadline := false
	deadline := time.Time{}
	if d, ok := ctx.Deadline(); ok {
		hasDeadline = true
		deadline = d
	}
	for i, w := range f.deadlines {
		if w.hasDeadline == hasDeadline && w.deadline.Equal(deadline) {
			f.deadlines = append(f.deadlines[:i], f.deadlines[i+1:]...)
			break
		}
	}
	f.rearmLocked()
}

func (f *urlTestFlight) rearmLocked() {
	f.timerGen++
	gen := f.timerGen
	if f.timer != nil {
		f.timer.Stop()
		f.timer = nil
	}
	if f.abandoned || f.cancelWork == nil {
		return
	}
	latest := time.Time{}
	allHaveDeadline := len(f.deadlines) > 0
	for _, w := range f.deadlines {
		if !w.hasDeadline {
			allHaveDeadline = false
			break
		}
		if latest.IsZero() || w.deadline.After(latest) {
			latest = w.deadline
		}
	}
	if !allHaveDeadline || latest.IsZero() {
		return
	}
	delay := time.Until(latest)
	if delay < 0 {
		delay = 0
	}
	f.timer = time.AfterFunc(delay, func() { f.onLatestDeadline(gen) })
}

func (f *urlTestFlight) onLatestDeadline(gen int) {
	f.mu.Lock()
	if gen != f.timerGen || f.abandoned || f.cancelWork == nil {
		f.mu.Unlock()
		return
	}
	f.abandoned = true
	workCancel := f.cancelWork
	if f.timer != nil {
		f.timer.Stop()
		f.timer = nil
	}
	f.mu.Unlock()
	workCancel()
}

func (f *urlTestFlight) wait(ctx context.Context) (uint16, error) {
	defer f.release(ctx)
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-f.done:
		return f.t, f.err
	}
}

func (f *urlTestFlight) release(ctx context.Context) {
	f.mu.Lock()
	f.waiters--
	f.untrackLocked(ctx)
	cancel := false
	if f.waiters == 0 && !f.abandoned && f.cancelWork != nil {
		f.abandoned = true
		cancel = true
		f.timerGen++
		if f.timer != nil {
			f.timer.Stop()
			f.timer = nil
		}
	}
	workCancel := f.cancelWork
	f.mu.Unlock()
	if cancel {
		workCancel()
	}
}
