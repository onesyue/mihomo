package outboundgroup

import (
	"sync"
	"sync/atomic"
	"testing"

	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/stretchr/testify/require"
)

type blockedHealthProvider struct {
	P.ProxyProvider
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (p *blockedHealthProvider) HealthCheck() { p.calls.Add(1); p.entered <- struct{}{}; <-p.release }
func TestHealthCheckConcurrentAdmissionAndCounterReset(t *testing.T) {
	provider := &blockedHealthProvider{entered: make(chan struct{}, 32), release: make(chan struct{})}
	group := NewGroupBase(GroupBaseOption{Name: "single-check", Providers: []P.ProxyProvider{provider}})
	group.failedTimes.Store(4)
	firstDone := make(chan struct{})
	go func() { defer close(firstDone); group.healthCheck() }()
	<-provider.entered
	var workers sync.WaitGroup
	for range 30 {
		workers.Go(func() { group.onDialSuccess(); group.healthCheck() })
	}
	workers.Wait()
	require.Equal(t, int32(1), provider.calls.Load(), "only one concurrent provider check may enter")
	require.Equal(t, int64(4), group.failedTimes.Load(), "success does not reset the active check's count")
	close(provider.release)
	<-firstDone
	require.Zero(t, group.failedTimes.Load())
	require.False(t, group.failedTesting.Load())
	group.healthCheck()
	require.Equal(t, int32(2), provider.calls.Load(), "a completed check releases admission")
}
