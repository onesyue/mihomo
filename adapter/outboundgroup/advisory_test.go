package outboundgroup

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/stretchr/testify/require"
)

type advisoryMeasuredProxy struct {
	*measuredProxy
	kind    C.AdapterType
	address string
	dials   atomic.Int32
	probes  atomic.Int32
}

func (p *advisoryMeasuredProxy) Type() C.AdapterType { return p.kind }
func (p *advisoryMeasuredProxy) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	p.dials.Add(1)
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", p.address)
	if err != nil {
		return nil, err
	}
	return outbound.NewConn(conn, outbound.NewBase(outbound.BaseOption{Name: p.name, Type: p.kind})), nil
}
func (p *advisoryMeasuredProxy) URLTest(context.Context, string, utils.IntRanges[uint16]) (uint16, error) {
	p.probes.Add(1)
	return 1, nil
}

type advisoryProvider struct{ *measuredProvider }

func (*advisoryProvider) Touch() {}
func newAdvisoryMember(name string, delay uint16) *advisoryMeasuredProxy {
	return &advisoryMeasuredProxy{measuredProxy: &measuredProxy{name: name, delay: delay, alive: true}, kind: C.Vless}
}

type testAdvisoryGroup interface {
	AdvisoryGroup
	Now() string
	ForceSet(string)
	DialContext(context.Context, *C.Metadata) (C.Conn, error)
}

func newAdvisoryGroup(t *testing.T, kind string, members ...C.Proxy) (testAdvisoryGroup, *advisoryProvider) {
	t.Helper()
	provider := &advisoryProvider{&measuredProvider{proxies: members, version: 1}}
	option := GroupCommonOption{Name: "auto", URL: "https://probe.invalid/", ExpectedStatus: "204"}
	if kind == "url-test" {
		group, err := NewURLTest(option, URLTestOption{Tolerance: 50}, members[0], []P.ProxyProvider{provider})
		require.NoError(t, err)
		return group, provider
	}
	group, err := NewFallback(option, FallbackOption{}, members[0], []P.ProxyProvider{provider})
	require.NoError(t, err)
	return group, provider
}
func advisoryLease(group AdvisoryGroup, names ...string) AdvisoryLease {
	return AdvisoryLease{Revision: group.Advisory().Revision, ExpectedGeneration: group.Advisory().Generation, Scope: "account-profile-network", Candidates: names, ExpiresAt: time.Now().Add(60 * time.Second).Unix()}
}
func resetAdvisorySelection(group testAdvisoryGroup) {
	if u, ok := group.(*URLTest); ok {
		u.fastSingle.Reset()
	}
}

func TestAdvisoryOrdinarySelectionAndManualIntent(t *testing.T) {
	for _, kind := range []string{"url-test", "fallback"} {
		t.Run(kind, func(t *testing.T) {
			first, legacy, advised := newAdvisoryMember("first", 10), newAdvisoryMember("legacy", 20), newAdvisoryMember("advised", 25)
			group, _ := newAdvisoryGroup(t, kind, first, legacy, advised)
			require.Equal(t, "first", group.Now())
			lease := advisoryLease(group, "advised")
			lease.ExpectedGeneration = group.Advisory().Generation
			require.NoError(t, group.SetAdvisory(t.Context(), lease))
			require.Equal(t, "first", group.Now(), "healthy incumbent must survive advice")
			first.alive = false
			first.delay = 65535
			resetAdvisorySelection(group)
			require.Equal(t, "advised", group.Now(), "ordinary automatic selection must consume eligible advice")
			require.Zero(t, advised.probes.Load())
			group.ForceSet("legacy")
			require.False(t, group.Advisory().Active)
			require.ErrorIs(t, group.SetAdvisory(t.Context(), lease), ErrAdvisoryManual)
			require.Equal(t, "legacy", group.Now())
			legacy.alive = false
			legacy.delay = 65535
			resetAdvisorySelection(group)
			_ = group.Now()
			require.ErrorIs(t, group.SetAdvisory(t.Context(), lease), ErrAdvisoryManual, "failed manual selection must not enable advice")
			group.ForceSet("")
			lease.ExpectedGeneration = group.Advisory().Generation
			require.NoError(t, group.SetAdvisory(t.Context(), lease))
			require.ErrorIs(t, group.ClearAdvisory(lease.Revision, "other-scope", lease.ExpectedGeneration), ErrAdvisoryScope)
			require.True(t, group.Advisory().Active)
			require.NoError(t, group.ClearAdvisory(lease.Revision, lease.Scope, lease.ExpectedGeneration))
			require.False(t, group.Advisory().Active)
		})
	}
}

func TestAdvisoryExpiryMembershipAndUnknown(t *testing.T) {
	for _, kind := range []string{"url-test", "fallback"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				first, legacy, advised := newAdvisoryMember("first", 10), newAdvisoryMember("legacy", 20), newAdvisoryMember("advised", 25)
				group, provider := newAdvisoryGroup(t, kind, first, legacy, advised)
				require.Equal(t, "first", group.Now())
				lease := advisoryLease(group, "advised")
				lease.ExpectedGeneration = group.Advisory().Generation
				require.NoError(t, group.SetAdvisory(t.Context(), lease))
				// Same-name replacement does not inherit its predecessor's evidence.
				replacement := newAdvisoryMember("advised", 25)
				provider.proxies = []C.Proxy{first, legacy, replacement}
				provider.version++
				first.alive = false
				first.delay = 65535
				resetAdvisorySelection(group)
				require.Equal(t, "legacy", group.Now())
				lease.ExpectedGeneration = group.Advisory().Generation
				require.NoError(t, group.SetAdvisory(t.Context(), lease))
				replacement.delay = 65535
				legacy.alive = false
				legacy.delay = 65535
				resetAdvisorySelection(group)
				// Unknown advice cannot become a measured choice. Existing fallback may
				// still select an unknown live member; compare exactly with no advice.
				withAdvice := group.Now()
				require.NoError(t, group.ClearAdvisory(lease.Revision, lease.Scope, lease.ExpectedGeneration))
				resetAdvisorySelection(group)
				require.Equal(t, group.Now(), withAdvice)
				lease.ExpectedGeneration = group.Advisory().Generation
				require.NoError(t, group.SetAdvisory(t.Context(), lease))
				time.Sleep(61 * time.Second)
				require.False(t, group.Advisory().Active)
				newGroup, _ := newAdvisoryGroup(t, kind, first, legacy, replacement)
				require.ErrorIs(t, newGroup.SetAdvisory(t.Context(), lease), ErrAdvisoryRevision)
			})
		})
	}
}

func TestAdvisoryValidation(t *testing.T) {
	member := newAdvisoryMember("member", 10)
	group, _ := newAdvisoryGroup(t, "fallback", member)
	tests := []struct {
		name   string
		change func(*AdvisoryLease)
	}{
		{"stale", func(l *AdvisoryLease) { l.Revision = "old" }},
		{"expired", func(l *AdvisoryLease) { l.ExpiresAt = time.Now().Unix() }},
		{"long", func(l *AdvisoryLease) { l.ExpiresAt = time.Now().Add(91 * time.Second).Unix() }},
		{"empty", func(l *AdvisoryLease) { l.Candidates = nil }},
		{"duplicate", func(l *AdvisoryLease) { l.Candidates = []string{"member", "member"} }},
		{"four", func(l *AdvisoryLease) { l.Candidates = []string{"a", "b", "c", "d"} }},
		{"foreign", func(l *AdvisoryLease) { l.Candidates = []string{"foreign"} }},
		{"scope", func(l *AdvisoryLease) { l.Scope = "bad\nscope" }},
		{"retry", func(l *AdvisoryLease) { l.Retry = true }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lease := advisoryLease(group, "member")
			tt.change(&lease)
			require.Error(t, group.SetAdvisory(t.Context(), lease))
			require.False(t, group.Advisory().Active)
		})
	}
	member.kind = C.Selector
	require.Error(t, group.SetAdvisory(t.Context(), advisoryLease(group, "member")))
}

func TestAdvisoryConcurrentSelectionAndLeaseMutation(t *testing.T) {
	for _, kind := range []string{"url-test", "fallback"} {
		t.Run(kind, func(t *testing.T) {
			a, b := newAdvisoryMember("a", 10), newAdvisoryMember("b", 20)
			group, _ := newAdvisoryGroup(t, kind, a, b)
			lease := advisoryLease(group, "b")
			var workers sync.WaitGroup
			for worker := 0; worker < 4; worker++ {
				workers.Go(func() {
					for range 100 {
						_ = group.Now()
						_ = group.SetAdvisory(t.Context(), lease)
						_ = group.Advisory()
						_ = group.ClearAdvisory(lease.Revision, lease.Scope, lease.ExpectedGeneration)
						group.ForceSet("a")
						group.ForceSet("")
					}
				})
			}
			workers.Wait()
		})
	}
}

func TestAdvisoryRealNewDialHasNoExtraProbeOrReplay(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	require.NoError(t, listener.(*net.TCPListener).SetDeadline(time.Now().Add(5*time.Second)))
	for _, kind := range []string{"url-test", "fallback"} {
		t.Run(kind, func(t *testing.T) {
			first, legacy, advised := newAdvisoryMember("first", 10), newAdvisoryMember("legacy", 20), newAdvisoryMember("advised", 25)
			for _, p := range []*advisoryMeasuredProxy{first, legacy, advised} {
				p.address = listener.Addr().String()
			}
			group, _ := newAdvisoryGroup(t, kind, first, legacy, advised)
			require.Equal(t, "first", group.Now())
			require.NoError(t, group.SetAdvisory(t.Context(), advisoryLease(group, "advised")))
			first.alive = false
			first.delay = 65535
			resetAdvisorySelection(group)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			conn, err := group.DialContext(ctx, &C.Metadata{Host: "application.test", DstPort: 443})
			require.NoError(t, err)
			defer conn.Close()
			peer, err := listener.Accept()
			require.NoError(t, err)
			defer peer.Close()
			require.NoError(t, peer.SetDeadline(time.Now().Add(time.Second)))
			_, err = conn.Write([]byte("once"))
			require.NoError(t, err)
			payload := make([]byte, 4)
			_, err = peer.Read(payload)
			require.NoError(t, err)
			require.Equal(t, "once", string(payload))
			require.EqualValues(t, 1, advised.dials.Load())
			require.Zero(t, legacy.dials.Load())
			require.Zero(t, first.dials.Load())
			for _, p := range []*advisoryMeasuredProxy{first, legacy, advised} {
				require.Zero(t, p.probes.Load(), fmt.Sprint(p.name))
			}
		})
	}
}

func TestAdvisoryRejectsPermissiveProbeStatus(t *testing.T) {
	for _, kind := range []string{"url-test", "fallback"} {
		t.Run(kind, func(t *testing.T) {
			member := newAdvisoryMember("member", 10)
			group, _ := newAdvisoryGroup(t, kind, member)
			if u, ok := group.(*URLTest); ok {
				u.expectedStatus = "*"
			} else {
				group.(*Fallback).expectedStatus = "200,204"
			}
			require.Error(t, group.SetAdvisory(t.Context(), advisoryLease(group, "member")))
		})
	}
}

type delayedAdvisoryProvider struct {
	*advisoryProvider
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *delayedAdvisoryProvider) Proxies() []C.Proxy {
	p.once.Do(func() { close(p.entered); <-p.release })
	return p.advisoryProvider.Proxies()
}

func TestAdvisoryTimedOutPendingMutationIsFenced(t *testing.T) {
	member := newAdvisoryMember("member", 10)
	pd := &delayedAdvisoryProvider{advisoryProvider: &advisoryProvider{&measuredProvider{proxies: []C.Proxy{member}, version: 1}}, entered: make(chan struct{}), release: make(chan struct{})}
	group, err := NewFallback(GroupCommonOption{Name: "auto", URL: "https://probe.invalid/", ExpectedStatus: "204"}, FallbackOption{}, member, []P.ProxyProvider{pd})
	require.NoError(t, err)
	lease := advisoryLease(group, "member")
	done := make(chan error, 1)
	// Intentionally do not cancel the server context: a lost transport cannot be
	// assumed to cancel an operation already admitted by the server.
	go func() { done <- group.SetAdvisory(context.Background(), lease) }()
	<-pd.entered
	select {
	case <-done:
		t.Fatal("blocked mutation returned early")
	case <-time.After(10 * time.Millisecond):
	}
	require.NoError(t, group.ClearAdvisory(lease.Revision, lease.Scope, lease.ExpectedGeneration))
	close(pd.release)
	require.ErrorIs(t, <-done, ErrAdvisoryGeneration)
	require.False(t, group.Advisory().Active)
}

func TestAdvisorySuccessorAndSameScopeRenewalFenceOldRequests(t *testing.T) {
	member := newAdvisoryMember("member", 10)
	group, _ := newAdvisoryGroup(t, "fallback", member)
	old := advisoryLease(group, "member")
	successor := old
	successor.Scope = "new-profile"
	require.NoError(t, group.SetAdvisory(t.Context(), successor))
	require.ErrorIs(t, group.SetAdvisory(t.Context(), old), ErrAdvisoryGeneration)
	require.Error(t, group.ClearAdvisory(old.Revision, old.Scope, old.ExpectedGeneration))
	require.Equal(t, successor.Scope, group.Advisory().Scope)
	renewal := advisoryLease(group, "member")
	renewal.Scope = successor.Scope
	require.NoError(t, group.SetAdvisory(t.Context(), renewal))
	require.ErrorIs(t, group.ClearAdvisory(successor.Revision, successor.Scope, successor.ExpectedGeneration), ErrAdvisoryGeneration)
	require.True(t, group.Advisory().Active)
	require.NoError(t, group.ClearAdvisory(renewal.Revision, renewal.Scope, renewal.ExpectedGeneration))
	require.False(t, group.Advisory().Active)
}

func TestAdvisoryCanceledMutationDoesNotInstall(t *testing.T) {
	member := newAdvisoryMember("member", 10)
	group, _ := newAdvisoryGroup(t, "url-test", member)
	lease := advisoryLease(group, "member")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, group.SetAdvisory(ctx, lease), context.Canceled)
	require.Equal(t, lease.ExpectedGeneration, group.Advisory().Generation)
	require.False(t, group.Advisory().Active)
}
