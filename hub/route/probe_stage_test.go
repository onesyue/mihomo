package route

import (
	"context"
	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/transport/vmess"
)

// Exercise the existing TCP/TLS/WS/VLESS/HTTP request, never a second probe.
func TestVLESSProbeFailureStages(t *testing.T) {
	for _, phase := range []string{"tcp_connect", "tls_handshake", "ws_upgrade", "vless_first_packet", "target_response", "success"} {
		t.Run(phase, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if phase == "ws_upgrade" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				c, err := vmess.StreamUpgradedWebsocketConn(w, r)
				if err != nil {
					t.Error(err)
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				if _, err := c.Read(make([]byte, 4096)); err != nil {
					return
				}
				if phase == "vless_first_packet" {
					_, _ = c.Write([]byte{99, 0})
					return
				}
				if phase == "target_response" {
					_, _ = c.Write([]byte{0, 0})
					return
				}
				time.Sleep(5 * time.Millisecond)
				_, _ = c.Write(append([]byte{0, 0}, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")...))
			})
			s := httptest.NewUnstartedServer(handler)
			if phase == "tls_handshake" {
				s.Start()
			} else {
				s.StartTLS()
			}
			addr := s.Listener.Addr().String()
			if phase == "tcp_connect" {
				s.Close()
			} else {
				defer s.Close()
			}
			host, portText, _ := net.SplitHostPort(addr)
			port, _ := strconv.Atoi(portText)
			p, err := outbound.NewVless(outbound.VlessOption{Name: "fixture", Server: host, Port: port,
				UUID: "00000000-0000-4000-8000-000000000001", TLS: true, SkipCertVerify: true, Network: "ws"})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("GET", "/delay?timeout=1000&url=http%3A%2F%2Ffixture.invalid%2F", nil)
			r = r.WithContext(context.WithValue(r.Context(), CtxKeyProxy, adapter.NewProxy(p)))
			w := httptest.NewRecorder()
			getProxyDelay(w, r)
			want := phase
			if phase == "success" {
				want = ""
				if w.Code != 200 {
					t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
				}
			}
			if got := w.Header().Get("X-Yue-Probe-Failure-Stage"); got != want {
				t.Fatalf("stage=%q want=%q status=%d body=%s", got, want, w.Code, w.Body.String())
			}
		})
	}
}

func TestVLESSProbeTimeoutStage(t *testing.T) {
	accepted := make(chan struct{})
	release := make(chan struct{})
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(accepted); <-release }))
	defer s.Close()
	defer close(release)
	host, portText, _ := net.SplitHostPort(s.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	p, err := outbound.NewVless(outbound.VlessOption{Name: "fixture", Server: host, Port: port, UUID: "00000000-0000-4000-8000-000000000001", TLS: true, SkipCertVerify: true, Network: "ws"})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/delay?timeout=500&url=http%3A%2F%2Ffixture.invalid%2F", nil)
	r = r.WithContext(context.WithValue(r.Context(), CtxKeyProxy, adapter.NewProxy(p)))
	w := httptest.NewRecorder()
	getProxyDelay(w, r)
	select {
	case <-accepted:
	default:
		t.Fatal("never reached WS request")
	}
	if w.Code != 504 || w.Header().Get("X-Yue-Probe-Failure-Stage") != "ws_upgrade" {
		t.Fatalf("wrong timeout: %d %v", w.Code, w.Header())
	}
	if w.Body.String() != "{\"message\":\"Timeout\"}\n" {
		t.Fatalf("legacy body changed: %q", w.Body.String())
	}
}
