package dns

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	D "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// net/http detaches connection acquisition from request cancellation. A DNS
// query returning does not prove that its TLS handshake released the socket.
func TestDoHCancelledQueryReleasesSilentTLSConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan net.Conn, 1)
	closed := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c
		_, _ = io.Copy(io.Discard, c)
		close(closed)
	}()

	doh := newDoHClient("https://"+ln.Addr().String()+"/dns-query", nil, false,
		map[string]string{}, nil, "").(*dnsOverHTTPS)
	t.Cleanup(func() { _ = doh.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	returned := make(chan error, 1)
	go func() {
		m := new(D.Msg)
		m.SetQuestion("example.invalid.", D.TypeA)
		_, err := doh.ExchangeContext(ctx, m)
		returned <- err
	}()
	select {
	case c := <-accepted:
		t.Cleanup(func() { _ = c.Close() })
	case <-time.After(15 * time.Second):
		t.Fatal("DoH query did not reach the loopback TCP peer")
	}
	cancel()
	select {
	case err := <-returned:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled query did not return")
	}
	// Keep the resolver alive: CloseIdleConnections during fixture cleanup
	// would hide precisely the leak this assertion is intended to detect.
	select {
	case <-closed:
	case <-time.After(dialTimeout + 5*time.Second):
		t.Fatal("cancelled query left its TLS dial alive beyond the dial budget")
	}
}
