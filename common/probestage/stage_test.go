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

func TestSharedMirrorKeepsSeparateRecorders(t *testing.T) {
	leaderCtx, leader := New(context.Background())
	sharedCtx, root := StartShared(leaderCtx)
	joinerCtx, joiner := New(context.Background())
	_ = joinerCtx
	Begin(sharedCtx)
	if leader.FailureStage() != "tcp_connect" {
		t.Fatalf("leader: %q", leader.FailureStage())
	}
	if joiner.FailureStage() != "unknown" {
		t.Fatal("joiner should not see stages before Mirror")
	}
	root.Mirror(joiner)
	if joiner.FailureStage() != "tcp_connect" {
		t.Fatalf("late joiner should inherit the closed stage, got %q", joiner.FailureStage())
	}
	Mark(sharedCtx, TLSHandshake)
	if leader.FailureStage() != "tls_handshake" || joiner.FailureStage() != "tls_handshake" {
		t.Fatalf("fan-out failed: leader=%q joiner=%q", leader.FailureStage(), joiner.FailureStage())
	}
	if FromContext(sharedCtx) == leader {
		t.Fatal("shared context must use the fan-out root, not alias the leader pointer")
	}
}
