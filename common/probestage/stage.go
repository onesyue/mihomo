// Package probestage records only closed stage enums for an existing URL test.
// It never dials, changes deadlines, or retains addresses, credentials or errors.
package probestage

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
)

type Stage uint32

const (
	Unknown Stage = iota
	TCPConnect
	TLSHandshake
	WSUpgrade
	VLESSFirstPacket
	TargetResponse
)

type key struct{}

type Trace struct {
	stage   atomic.Uint32
	mu      sync.Mutex
	mirrors []*Trace
}

func New(ctx context.Context) (context.Context, *Trace) {
	t := &Trace{}
	return context.WithValue(ctx, key{}, t), t
}

// FromContext returns the recorder bound to ctx, if any.
func FromContext(ctx context.Context) *Trace {
	t, _ := ctx.Value(key{}).(*Trace)
	return t
}

// StartShared returns a context whose recorder fans stages out to the
// caller's existing recorder (if any). Later waiters can Mirror onto the
// returned root without inheriting the first waiter's cancellation.
func StartShared(ctx context.Context) (context.Context, *Trace) {
	root := &Trace{}
	if existing := FromContext(ctx); existing != nil {
		root.Mirror(existing)
	}
	return context.WithValue(ctx, key{}, root), root
}

// Mirror attaches other as a destination for later Begin/Mark values and
// copies any stage already recorded on t. It is a no-op for nil or self.
func (t *Trace) Mirror(other *Trace) {
	if t == nil || other == nil || t == other {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	// One attachment per waiter, even if two calls share a caller context.
	t.mirrors = append(t.mirrors, other)
	other.assignAtLeast(Stage(t.stage.Load()))
}

// StopMirroring takes a final snapshot for this waiter. A callback running
// after the waiter leaves cannot assign a stage from another waiter's request.
func (t *Trace) StopMirroring(other *Trace) {
	if t == nil || other == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if i := slices.Index(t.mirrors, other); i >= 0 {
		other.assignAtLeast(Stage(t.stage.Load()))
		t.mirrors = slices.Delete(t.mirrors, i, i+1)
	}
}

func (t *Trace) assignAtLeast(s Stage) {
	if t == nil || s == Unknown {
		return
	}
	for {
		old := t.stage.Load()
		if old == 0 {
			if t.stage.CompareAndSwap(0, uint32(s)) {
				return
			}
			continue
		}
		if old >= uint32(s) {
			return
		}
		if t.stage.CompareAndSwap(old, uint32(s)) {
			return
		}
	}
}

func (t *Trace) propagate(s Stage) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, m := range t.mirrors {
		m.assignAtLeast(s)
	}
}

// Begin is called only for the supported, non-lazy VLESS WS+TLS path.
func Begin(ctx context.Context) {
	t := FromContext(ctx)
	if t == nil {
		return
	}
	if t.stage.CompareAndSwap(0, uint32(TCPConnect)) {
		t.propagate(TCPConnect)
		return
	}
	t.propagate(Stage(t.stage.Load()))
}

func Mark(ctx context.Context, s Stage) {
	t := FromContext(ctx)
	if t == nil {
		return
	}
	for {
		old := t.stage.Load()
		if old == 0 || old >= uint32(s) {
			return
		}
		if t.stage.CompareAndSwap(old, uint32(s)) {
			t.propagate(s)
			return
		}
	}
}

// ReachedTargetResponse starts tracing at the response wait when earlier
// transport stages were not instrumented. Joined URL tests share this evidence.
func (t *Trace) ReachedTargetResponse() {
	t.assignAtLeast(TargetResponse)
	t.propagate(TargetResponse)
}

func (t *Trace) FailureStage() string {
	switch Stage(t.stage.Load()) {
	case TCPConnect:
		return "tcp_connect"
	case TLSHandshake:
		return "tls_handshake"
	case WSUpgrade:
		return "ws_upgrade"
	case VLESSFirstPacket:
		return "vless_first_packet"
	case TargetResponse:
		return "target_response"
	default:
		return "unknown"
	}
}
