package session

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/anytls/padding"
)

type createStreamResult struct {
	stream net.Conn
	err    error
}

type closeErrorConn struct {
	net.Conn
	err error
}

func (c closeErrorConn) Close() error { return errors.Join(c.Conn.Close(), c.err) }

func TestClientCloseRejectsLateDialResult(t *testing.T) {
	for _, disableReuse := range []bool{false, true} {
		t.Run(map[bool]string{false: "reusable", true: "single-use"}[disableReuse], func(t *testing.T) {
			conn, peer := net.Pipe()
			defer conn.Close()
			defer peer.Close()
			entered, release := make(chan struct{}), make(chan struct{})
			var p atomic.Pointer[padding.PaddingFactory]
			p.Store(padding.NewPaddingFactory(padding.DefaultPaddingScheme))
			client := NewClient(context.Background(), func(context.Context) (net.Conn, error) {
				close(entered)
				<-release
				return conn, nil // A dial may finish even after its context was canceled.
			}, &p, "test", time.Hour, time.Hour, 0, disableReuse)
			defer client.Close()
			result := make(chan createStreamResult, 1)
			go func() {
				stream, err := client.CreateStream(context.Background())
				result <- createStreamResult{stream: stream, err: err}
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("CreateStream never entered the gated dialer")
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			close(release)
			select {
			case got := <-result:
				if got.stream != nil || !errors.Is(got.err, io.ErrClosedPipe) {
					t.Errorf("closed client admitted a late session: stream=%v err=%v", got.stream != nil, got.err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("late dial result never settled")
			}
			client.sessionsLock.Lock()
			retained := len(client.sessions)
			client.sessionsLock.Unlock()
			if retained != 0 {
				t.Errorf("closed client retained %d late session(s)", retained)
			}
			if err := peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil && !errors.Is(err, io.ErrClosedPipe) {
				t.Fatal(err)
			}
			if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Errorf("late transport remained open after client close: %v", err)
			}
		})
	}
}

func TestClientCloseCancelsPendingDial(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	client := NewClient(context.Background(), func(ctx context.Context) (net.Conn, error) {
		close(entered)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
			return nil, errors.New("fixture released")
		}
	}, nil, "test", time.Hour, time.Hour, 0, false)
	defer client.Close()
	result := make(chan error, 1)
	go func() { _, err := client.CreateStream(context.Background()); result <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("CreateStream never entered the context-aware dialer")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("pending dial did not report cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client close did not cancel its pending transport dial")
	}
}

func TestClientCloseKeepsLateTransportCloseError(t *testing.T) {
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	closeErr := errors.New("late transport close failed")
	var client *Client
	client = NewClient(context.Background(), func(context.Context) (net.Conn, error) {
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
		return closeErrorConn{Conn: conn, err: closeErr}, nil
	}, nil, "test", time.Hour, time.Hour, 0, false)
	defer client.Close()
	stream, err := client.CreateStream(context.Background())
	if stream != nil || !errors.Is(err, io.ErrClosedPipe) || !errors.Is(err, closeErr) {
		t.Fatalf("late-close failure was lost: stream=%v err=%v", stream != nil, err)
	}
	if _, err := peer.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("late transport was not actually closed: %v", err)
	}
}

func TestClientDialFailureIsPreserved(t *testing.T) {
	dialErr := errors.New("transport dial failed")
	client := NewClient(context.Background(), func(context.Context) (net.Conn, error) {
		return nil, dialErr
	}, nil, "test", time.Hour, time.Hour, 0, false)
	defer client.Close()
	stream, err := client.CreateStream(context.Background())
	if stream != nil || !errors.Is(err, dialErr) {
		t.Fatalf("independent dial failure was lost: stream=%v err=%v", stream != nil, err)
	}
}

func TestClientSuccessfulDialRemainsUsableUntilClose(t *testing.T) {
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	drained := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, peer); close(drained) }()
	var p atomic.Pointer[padding.PaddingFactory]
	p.Store(padding.NewPaddingFactory(padding.DefaultPaddingScheme))
	client := NewClient(context.Background(), func(context.Context) (net.Conn, error) {
		return conn, nil
	}, &p, "test", time.Hour, time.Hour, 0, false)
	defer client.Close()
	stream, err := client.CreateStream(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := []byte("working session")
	if n, err := stream.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("successful dial was prematurely canceled: n=%d err=%v", n, err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("normal client shutdown did not close its live stream: %v", err)
	}
	select {
	case <-drained:
	case <-time.After(3 * time.Second):
		t.Fatal("normal shutdown did not release the transport")
	}
}
