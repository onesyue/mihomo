package shadowsocks

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	LC "github.com/metacubex/mihomo/listener/config"
)

type observedSSListener struct {
	net.Listener
	calls     atomic.Int32
	started   chan struct{}
	failed    chan struct{}
	retried   chan struct{}
	failOnce  sync.Once
	retryOnce sync.Once
}

func (l *observedSSListener) Accept() (net.Conn, error) {
	if l.calls.Add(1) == 1 {
		close(l.started)
	} else {
		l.retryOnce.Do(func() { close(l.retried) })
	}
	c, err := l.Listener.Accept()
	if err != nil {
		l.failOnce.Do(func() { close(l.failed) })
	}
	return c, err
}

type ssTestListenConfig struct{ listener net.Listener }

func (c ssTestListenConfig) Listen(context.Context, string, string) (net.Listener, error) {
	return c.listener, nil
}
func (ssTestListenConfig) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	panic("unexpected UDP listener")
}

func TestListenerCloseStopsAcceptLoop(t *testing.T) {
	saved := _listener
	defer func() { _listener = saved }()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	observed := &observedSSListener{Listener: raw, started: make(chan struct{}), failed: make(chan struct{}), retried: make(chan struct{})}
	listener, err := New(LC.ShadowsocksServer{Listen: raw.Addr().String(), Cipher: "DUMMY"}, ssTestListenConfig{observed}, nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-observed.started:
	case <-time.After(time.Second):
		t.Fatal("accept loop did not start")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-observed.failed:
	case <-time.After(time.Second):
		t.Fatal("close did not unblock Accept")
	}
	select {
	case <-observed.retried:
		t.Fatal("closed listener restarted Accept instead of stopping")
	case <-time.After(100 * time.Millisecond):
	}
	if conn, err := net.DialTimeout("tcp", raw.Addr().String(), time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("closed listener still accepts TCP")
	}
}
