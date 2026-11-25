package net

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestHandleContextListenerClosesConnectionAfterHandlerPanic(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	panicked := make(chan any, 1)
	listener := NewHandleContextListener(context.Background(), base, func(context.Context, net.Conn) (net.Conn, error) {
		panic("handshake failed")
	}, func(value any) { panicked <- value })
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		accepted <- err
	}()
	client, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	select {
	case <-panicked:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not run")
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("panic must close the accepted socket; Read returned %v", err)
	}
	_ = listener.Close()
	select {
	case err := <-accepted:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Accept did not finish on close")
	}
}
