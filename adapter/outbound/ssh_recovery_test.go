package outbound

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/ssh"
)

var errSSHTestWrite = errors.New("injected SSH write failure")

type sshFailWriteConn struct {
	net.Conn
	fail   atomic.Bool
	failed atomic.Bool
	once   sync.Once
	closed chan struct{}
}

func (c *sshFailWriteConn) Write(p []byte) (int, error) {
	if c.fail.Load() {
		c.failed.Store(true)
		return 0, errSSHTestWrite
	}
	return c.Conn.Write(p)
}
func (c *sshFailWriteConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

type sshRecoveryDialer struct{ connections chan *sshFailWriteConn }

func (d *sshRecoveryDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	wrapped := &sshFailWriteConn{Conn: c, closed: make(chan struct{})}
	d.connections <- wrapped
	return wrapped, nil
}
func (*sshRecoveryDialer) ListenPacket(context.Context, string, string, netip.AddrPort) (net.PacketConn, error) {
	return nil, errors.New("unexpected packet dial")
}

func TestSSHWriteFailureReleasesCachedClient(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
				server, channels, requests, err := ssh.NewServerConn(raw, cfg)
				if err != nil {
					return
				}
				defer server.Close()
				go func() {
					for ch := range channels {
						_ = ch.Reject(ssh.Prohibited, "unused")
					}
				}()
				for req := range requests {
					_ = req.Reply(true, nil)
				}
			}()
		}
	}()
	defer func() { _ = listener.Close(); <-serverDone }()
	d := &sshRecoveryDialer{connections: make(chan *sshFailWriteConn, 2)}
	proxy := &Ssh{Base: &Base{dialer: d}, config: &ssh.ClientConfig{User: "test", HostKeyCallback: ssh.InsecureIgnoreHostKey()}}
	defer proxy.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	first, err := proxy.connect(ctx, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn := <-d.connections
	defer conn.Close()
	if ok, _, err := first.SendRequest("probe", true, nil); err != nil || !ok {
		t.Fatalf("healthy request: ok=%t err=%v", ok, err)
	}
	conn.fail.Store(true)
	// The SSH transport caches its first write error and returns nil.
	// A request without a reply exposes the stuck cache without waiting for EOF.
	_, _, _ = first.SendRequest("probe", false, nil)
	if !conn.failed.Load() {
		t.Fatal("request did not reach the injected write failure")
	}
	select {
	case <-conn.closed:
	case <-time.After(time.Second):
		t.Fatal("write failure left the underlying connection and cached client alive")
	}
	// The existing Wait goroutine clears the cache after the connection closes.
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		proxy.cMutex.Lock()
		cleared := proxy.client == nil
		proxy.cMutex.Unlock()
		if cleared {
			break
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("closed SSH client was not evicted")
		}
	}
	second, err := proxy.connect(ctx, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if second == first {
		t.Fatal("reused broken SSH client")
	}
	secondConn := <-d.connections
	defer secondConn.Close()
	if ok, _, err := second.SendRequest("probe", true, nil); err != nil || !ok {
		t.Fatalf("reconnected request: ok=%t err=%v", ok, err)
	}
}
