package outbound

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/pkg/cipher"
	"github.com/enfein/mieru/v3/pkg/protocol"
)

type mieruTerminalTimeout struct{}

func (mieruTerminalTimeout) Error() string     { return "closed transport timeout" }
func (mieruTerminalTimeout) Timeout() bool     { return true }
func (mieruTerminalTimeout) Temporary() bool   { return false }
func (mieruTerminalTimeout) Is(err error) bool { return err == net.ErrClosed }

type mieruTerminalConn struct {
	net.Conn
	reads  atomic.Int32
	closed atomic.Bool
}

func (c *mieruTerminalConn) Read([]byte) (int, error) {
	c.reads.Add(1)
	return 0, mieruTerminalTimeout{}
}
func (c *mieruTerminalConn) Close() error                  { c.closed.Store(true); return c.Conn.Close() }
func (*mieruTerminalConn) SetReadDeadline(time.Time) error { return nil }

type mieruFixtureDialer struct{ conn net.Conn }

func (d mieruFixtureDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}

func TestMieruUnderlayStopsAfterTerminalTimeout(t *testing.T) {
	raw, peer := net.Pipe()
	defer raw.Close()
	defer peer.Close()
	conn := &mieruTerminalConn{Conn: raw}
	block, err := cipher.BlockCipherFromPassword(make([]byte, 32), false)
	if err != nil {
		t.Fatal("create test cipher failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	underlay, err := protocol.NewStreamUnderlay(ctx, mieruFixtureDialer{conn}, nil, &apicommon.ClientDNSConfig{BypassDialerDNS: true}, "tcp", "127.0.0.1:1", 1400, block, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer underlay.Close()
	done := make(chan error, 1)
	go func() { done <- underlay.RunEventLoop(ctx) }()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("expected terminal close, got %v", err)
		}
		if conn.reads.Load() != 1 {
			t.Fatalf("terminal read retried %d times", conn.reads.Load())
		}
		if !conn.closed.Load() {
			t.Fatal("terminal underlay connection not closed")
		}
	case <-time.After(time.Second):
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("event loop ignored cancellation")
		}
		t.Fatalf("terminal timeout kept retrying: %d reads", conn.reads.Load())
	}
}
