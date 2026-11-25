package dialer

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/reachhook"
)

type hookRecord struct {
	phase string
	dst   netip.AddrPort
	err   error
}

func TestReachHookObservesTCPConnects(t *testing.T) {
	var mu sync.Mutex
	var got []hookRecord
	reachhook.SetObserver(func(phase string, dst netip.AddrPort, _ time.Duration, err error) {
		mu.Lock()
		got = append(got, hookRecord{phase, dst, err})
		mu.Unlock()
	})
	defer reachhook.SetObserver(nil)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	okAddr := ln.Addr().String()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()
	c, err := DialContext(context.Background(), "tcp4", okAddr)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	ln.Close()

	// A closed port: refused, and still reported.
	_, _ = DialContext(context.Background(), "tcp4", okAddr)

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("observations = %+v", got)
	}
	want := netip.MustParseAddrPort(okAddr)
	if got[0].phase != reachhook.PhaseTCP || got[0].dst != want || got[0].err != nil {
		t.Fatalf("success observation = %+v", got[0])
	}
	if got[1].dst != want || got[1].err == nil {
		t.Fatalf("failure observation = %+v", got[1])
	}
}

func TestReachHookIsNoOpWithoutObserver(t *testing.T) {
	reachhook.SetObserver(nil)
	if reachhook.Enabled() {
		t.Fatal("observer unexpectedly installed")
	}
	// Must not panic or allocate an observer.
	reachhook.Observe(reachhook.PhaseTCP, netip.MustParseAddrPort("203.0.113.1:443"), time.Millisecond, nil)
}
