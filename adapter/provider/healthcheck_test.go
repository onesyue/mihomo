package provider

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/singledo"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
)

type gatedHealthProxy struct {
	C.Proxy
	entered chan struct{}
	release <-chan struct{}
	checks  atomic.Int32
}

func (p *gatedHealthProxy) Name() string { return "health-snapshot" }
func (p *gatedHealthProxy) URLTest(context.Context, string, utils.IntRanges[uint16]) (uint16, error) {
	p.checks.Add(1)
	if p.entered != nil {
		p.entered <- struct{}{}
		<-p.release
	}
	return 1, nil
}
func (*gatedHealthProxy) AliveForTestUrl(string) bool       { return true }
func (*gatedHealthProxy) LastDelayForTestUrl(string) uint16 { return 1 }

func TestHealthCheckRefreshKeepsOneProxySnapshot(t *testing.T) {
	release := make(chan struct{})
	old := &gatedHealthProxy{entered: make(chan struct{}, 24), release: release}
	next := &gatedHealthProxy{}
	proxies := make([]C.Proxy, 12) // exceed the errgroup's ten in-flight slots
	for i := range proxies {
		proxies[i] = old
	}
	hc := NewHealthCheck(proxies, "http://health.test/default", 1000, 0, false, nil)
	defer hc.close()
	hc.registerHealthCheckTask("http://health.test/extra", nil, "", 0)
	done := make(chan struct{})
	go func() { hc.check(); close(done) }()
	for range 10 {
		<-old.entered
	}
	// Updating must not wait for network checks, and all URLs in this check
	// must keep the snapshot it began with, including the extra URL below.
	hc.setProxies([]C.Proxy{next})
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("health check did not finish")
	}
	if old.checks.Load() != 24 || next.checks.Load() != 0 {
		t.Fatalf("mixed refresh snapshots: old=%d next=%d", old.checks.Load(), next.checks.Load())
	}
	hc.singleDo.Reset()
	hc.check()
	if next.checks.Load() != 2 {
		t.Fatalf("next check did not use refreshed proxies: %d", next.checks.Load())
	}
}

func TestHealthCheckConcurrentProviderRefresh(t *testing.T) {
	proxy := &gatedHealthProxy{}
	hc := NewHealthCheck(nil, "http://health.test/check", 1000, 0, false, nil)
	hc.singleDo = singledo.NewSingle[struct{}](0)
	defer hc.close()
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		<-start
		for range 2000 {
			hc.setProxies([]C.Proxy{proxy})
			hc.setProxies(nil)
		}
	})
	wg.Go(func() {
		<-start
		for range 2000 {
			hc.check()
		}
	})
	close(start)
	wg.Wait()
}
