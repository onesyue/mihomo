package mux

import (
	"io"
	"net"
	"testing"
	"time"
)

// YueLink fork regression (2026-09-22). On Go >= 1.27, x/net/http2 >= 0.54
// is a wrapper around net/http, which rejects a request with a nil Header
// ("http: nil Request.Header"). The upstream h2mux client built its CONNECT
// request without one, so every h2mux stream failed under the pinned
// toolchain. Exercise one real stream over an in-memory pipe.
func TestH2MuxStreamRoundTripsUnderNetHTTPWrapper(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	server := newH2MuxServer(serverSide)
	defer server.Close()
	client, err := newH2MuxClient(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	stream, err := client.Open(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := server.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	var inbound net.Conn
	select {
	case inbound = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("server never accepted the h2mux stream")
	}
	defer inbound.Close()
	buf := make([]byte, 4)
	_ = inbound.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(inbound, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("server read %q, %v", buf, err)
	}
}
