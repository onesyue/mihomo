package adapter_test

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/probestage"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
)

func hy2StageProxy(address string, typ C.AdapterType) *adapter.Proxy {
	return adapter.NewProxy(&localDialAdapter{
		Base:    outbound.NewBase(outbound.BaseOption{Name: "test", Type: typ}),
		address: address,
		dials:   new(atomic.Int32),
	})
}

// A short waiter can observe a stalled HTTPS response while a later waiter
// finishes the same request successfully.
func TestHY2HTTPSPartialResponseSharedStage(t *testing.T) {
	withUnifiedDelayOff(t)
	release := make(chan struct{})
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = buf.WriteString("HTTP/1.1 204")
		if err := buf.Flush(); err != nil {
			t.Error(err)
			return
		}
		<-release
		_, _ = io.WriteString(conn, " No Content\r\nContent-Length: 0\r\n\r\n")
	}))
	defer server.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	if err := ca.AddCertificate(string(server.Certificate().Raw)); err != nil {
		t.Fatal(err)
	}
	defer ca.ResetCertificate()

	p := hy2StageProxy(server.Listener.Addr().String(), C.Hysteria2)
	start := func() (*probestage.Trace, context.CancelFunc, <-chan error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ctx, trace := probestage.New(ctx)
		result := make(chan error, 1)
		go func() {
			_, err := p.URLTest(ctx, server.URL, nil)
			result <- err
		}()
		return trace, cancel, result
	}
	waitForStage := func(trace *probestage.Trace) {
		t.Helper()
		until := time.Now().Add(3 * time.Second)
		for trace.FailureStage() != "target_response" {
			if time.Now().After(until) {
				t.Fatalf("missing response stage: %s", trace.FailureStage())
			}
			time.Sleep(time.Millisecond)
		}
	}
	leader, cancelLeader, first := start()
	defer cancelLeader()
	waitForStage(leader)
	joiner, cancelJoiner, second := start()
	defer cancelJoiner()
	waitForStage(joiner)
	cancelLeader()
	if err := <-first; err == nil {
		t.Fatal("cancelled waiter unexpectedly finished")
	}
	close(release)
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatalf("unexpected request count: %d", requests.Load())
	}
}

func TestHY2HTTPSStageBoundaries(t *testing.T) {
	withUnifiedDelayOff(t)
	var closeWithoutResponse atomic.Bool
	handle := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if closeWithoutResponse.Load() {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			conn.Close()
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	secure := httptest.NewTLSServer(handle)
	defer secure.Close()
	plain := httptest.NewServer(handle)
	defer plain.Close()
	if err := ca.AddCertificate(string(secure.Certificate().Raw)); err != nil {
		t.Fatal(err)
	}
	defer ca.ResetCertificate()
	badHost := "https://" + net.JoinHostPort("untrusted.invalid", "443")
	for _, tc := range []struct {
		name, url, address, wantStage string
		typ                           C.AdapterType
		closeEarly, wantError         bool
	}{
		{"untrusted target", badHost, secure.Listener.Addr().String(), "unknown", C.Hysteria2, false, true},
		{"no HTTP bytes", secure.URL, secure.Listener.Addr().String(), "unknown", C.Hysteria2, true, true},
		{"plain HTTP", plain.URL, plain.Listener.Addr().String(), "unknown", C.Hysteria2, false, false},
		{"other protocol", secure.URL, secure.Listener.Addr().String(), "unknown", C.Vless, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			closeWithoutResponse.Store(tc.closeEarly)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			ctx, trace := probestage.New(ctx)
			_, err := hy2StageProxy(tc.address, tc.typ).URLTest(ctx, tc.url, nil)
			if (err != nil) != tc.wantError || trace.FailureStage() != tc.wantStage {
				t.Fatalf("err=%v stage=%s", err, trace.FailureStage())
			}
		})
	}
}

// The first byte received after a cancelled waiter has returned belongs only
// to the active waiter, even though their calls shared one HTTPS request.
func TestHY2LateResponseDoesNotChangeCancelledWaiter(t *testing.T) {
	withUnifiedDelayOff(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-release:
			w.WriteHeader(http.StatusNoContent)
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	if err := ca.AddCertificate(string(server.Certificate().Raw)); err != nil {
		t.Fatal(err)
	}
	defer ca.ResetCertificate()
	p := hy2StageProxy(server.Listener.Addr().String(), C.Hysteria2)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	active, activeTrace := probestage.New(ctx)
	result := make(chan error, 1)
	go func() {
		_, err := p.URLTest(active, server.URL, nil)
		result <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	short, stop := context.WithCancel(ctx)
	short, shortTrace := probestage.New(short)
	stop()
	if _, err := p.URLTest(short, server.URL, nil); err != context.Canceled {
		t.Fatalf("cancelled waiter returned %v", err)
	}
	if got := shortTrace.FailureStage(); got != "unknown" {
		t.Fatalf("response not sent, stage=%s", got)
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if got := shortTrace.FailureStage(); got != "unknown" {
		t.Fatalf("cancelled waiter acquired a later stage: %s", got)
	}
	if got := activeTrace.FailureStage(); got != "target_response" {
		t.Fatalf("active waiter missed response: %s", got)
	}
}
