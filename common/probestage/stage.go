// Package probestage records only closed stage enums for an existing URL test.
// It never dials, changes deadlines, or retains addresses, credentials or errors.
package probestage

import (
	"context"
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
type Trace struct{ stage atomic.Uint32 }

func New(ctx context.Context) (context.Context, *Trace) {
	t := &Trace{}
	return context.WithValue(ctx, key{}, t), t
}

// Begin is called only for the supported, non-lazy VLESS WS+TLS path.
func Begin(ctx context.Context) {
	if t, ok := ctx.Value(key{}).(*Trace); ok {
		t.stage.CompareAndSwap(0, uint32(TCPConnect))
	}
}
func Mark(ctx context.Context, s Stage) {
	t, ok := ctx.Value(key{}).(*Trace)
	if !ok {
		return
	}
	for {
		old := t.stage.Load()
		if old == 0 || old >= uint32(s) {
			return
		}
		if t.stage.CompareAndSwap(old, uint32(s)) {
			return
		}
	}
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
