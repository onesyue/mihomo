package session

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStreamCloseConcurrentIO(t *testing.T) {
	for _, local := range []bool{false, true} {
		for i := 0; i < 100; i++ {
			conn, peer := net.Pipe()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			drained := make(chan struct{})
			go func() { defer close(drained); io.Copy(io.Discard, peer) }()
			sess := NewServerSession(conn, nil, nil)
			s := newStream(1, sess)
			var hooks atomic.Int32
			var wg sync.WaitGroup
			wg.Add(4)
			go func() {
				defer wg.Done()
				_, err := s.Read(make([]byte, 1))
				if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
					t.Errorf("blocked reader after close: %v", err)
				}
			}()
			go func() {
				defer wg.Done()
				for j := 0; j < 100; j++ {
					if _, err := s.Write([]byte("data")); err != nil {
						if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
							t.Errorf("writer after close: %v", err)
						}
						return
					}
				}
			}()
			go func() {
				defer wg.Done()
				s.setDieHook(func() {
					hooks.Add(1)
					// Hook invocation must permit reentry after publishing closure.
					if _, err := s.Write([]byte("closed")); err == nil {
						t.Error("close hook observed an open stream")
					}
				})
			}()
			go func() {
				defer wg.Done()
				if local {
					s.closeLocally()
				} else {
					s.Close()
				}
			}()
			wg.Wait()
			s.closeLocally()
			if hooks.Load() != 1 {
				t.Fatalf("close callback count = %d, want 1", hooks.Load())
			}
			conn.Close()
			peer.Close()
			<-drained
		}
	}
}
