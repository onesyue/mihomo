package adapter

import (
	"context"
	"sync"

	"github.com/metacubex/mihomo/common/utils"
)

type urlTestKey struct {
	url      string
	expected string
}

type urlTestFlight struct {
	done chan struct{}
	t    uint16
	err  error

	mu         sync.Mutex
	waiters    int
	abandoned  bool
	cancelWork context.CancelFunc
}

// URLTest gets the delay for the specified URL.
// Equivalent in-flight tests on the same proxy object (same URL and expected
// status) share one dial and history write. A cancelled waiter does not abort
// work still needed by another waiter; the work is cancelled when every waiter
// has returned or been cancelled.
func (p *Proxy) URLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16]) (uint16, error) {
	key := urlTestKey{url: url, expected: expectedStatus.String()}

	p.urlTestMu.Lock()
	if p.urlTests == nil {
		p.urlTests = make(map[urlTestKey]*urlTestFlight)
	}
	if flight, ok := p.urlTests[key]; ok {
		flight.mu.Lock()
		join := !flight.abandoned
		if join {
			flight.waiters++
		}
		flight.mu.Unlock()
		p.urlTestMu.Unlock()
		if join {
			return flight.wait(ctx)
		}
		p.urlTestMu.Lock()
	}

	workCtx, cancel := urlTestWorkContext(ctx)
	flight := &urlTestFlight{
		done:       make(chan struct{}),
		waiters:    1,
		cancelWork: cancel,
	}
	p.urlTests[key] = flight
	p.urlTestMu.Unlock()

	go func() {
		t, err := p.doURLTest(workCtx, url, expectedStatus)
		flight.t = t
		flight.err = err
		p.urlTestMu.Lock()
		if current, ok := p.urlTests[key]; ok && current == flight {
			delete(p.urlTests, key)
		}
		p.urlTestMu.Unlock()
		flight.mu.Lock()
		flight.abandoned = true
		flight.mu.Unlock()
		cancel()
		close(flight.done)
	}()

	return flight.wait(ctx)
}

func (f *urlTestFlight) wait(ctx context.Context) (uint16, error) {
	defer f.release()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-f.done:
		return f.t, f.err
	}
}

func (f *urlTestFlight) release() {
	f.mu.Lock()
	f.waiters--
	cancel := false
	if f.waiters == 0 && !f.abandoned && f.cancelWork != nil {
		f.abandoned = true
		cancel = true
	}
	workCancel := f.cancelWork
	f.mu.Unlock()
	if cancel {
		workCancel()
	}
}

func urlTestWorkContext(ctx context.Context) (context.Context, context.CancelFunc) {
	// Keep request-local values such as probe-stage recorders, but do not
	// bind the shared work to one waiter's cancellation.
	base := context.WithoutCancel(ctx)
	if deadline, ok := ctx.Deadline(); ok {
		return context.WithDeadline(base, deadline)
	}
	return context.WithCancel(base)
}
