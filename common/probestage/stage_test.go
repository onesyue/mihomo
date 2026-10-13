package probestage

import (
	"context"
	"sync"
	"testing"
)

func TestTraceIsolationAndUnsupported(t *testing.T) {
	a, ta := New(context.Background())
	b, tb := New(context.Background())
	Mark(b, TLSHandshake)
	if tb.FailureStage() != "unknown" {
		t.Fatal("unsupported transport inferred")
	}
	Begin(a)
	Mark(a, TLSHandshake)
	if ta.FailureStage() != "tls_handshake" || tb.FailureStage() != "unknown" {
		t.Fatal("cross-request attribution")
	}
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); Mark(a, WSUpgrade); Mark(a, VLESSFirstPacket); _ = ta.FailureStage() }()
	}
	wg.Wait()
	Mark(a, TLSHandshake)
	if ta.FailureStage() != "vless_first_packet" {
		t.Fatal("stage regressed")
	}
	Mark(context.Background(), TargetResponse)
}
