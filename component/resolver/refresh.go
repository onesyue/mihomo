package resolver

import (
	"context"
	"errors"
	"sync/atomic"
	"time"
)

const DNSRefreshTimeout = 3 * time.Second

var (
	ErrDNSRefreshBusy        = errors.New("DNS refresh is still in progress")
	ErrDNSRefreshUnsupported = errors.New("resolver does not support DNS refresh")
	ErrDNSRefreshSuperseded  = errors.New("DNS configuration changed during refresh")
	dnsRefreshPermit         = make(chan struct{}, 1)
	dnsRefreshGeneration     atomic.Uint64
	dnsRefreshResolvers      atomic.Pointer[dnsRefreshSnapshot]
)

type dnsRefreshSnapshot struct{ resolvers []Resolver }

// PublishDNSResolvers is the configuration executor's publication boundary.
// SystemResolver is initialized once before configuration publication begins.
// The refresh API reads this immutable snapshot, never the legacy globals.
func PublishDNSResolvers(primary, proxy, direct Resolver) {
	DefaultResolver, ProxyServerHostResolver, DirectHostResolver = primary, proxy, direct
	dnsRefreshResolvers.Store(&dnsRefreshSnapshot{resolvers: []Resolver{primary, proxy, direct, SystemResolver}})
}

// DNSRefresher invalidates DNS state without changing fake-IP or user flows.
// Implementations must check cancellation before starting each mutation phase.
type DNSRefresher interface{ RefreshDNS(context.Context) error }

// RefreshDNS reports completion only after every resolver has refreshed. A
// platform reset already entered may not be cancellable: in that case the
// caller returns promptly, but the single permit remains held until it exits.
// A successor is rejected while that task could still mutate DNS state.
// Failure may leave partially refreshed DNS state and never implies reachability.
func RefreshDNS(ctx context.Context) (uint64, error) {
	ctx, cancel := context.WithTimeout(ctx, DNSRefreshTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	select {
	case dnsRefreshPermit <- struct{}{}:
	default:
		return 0, ErrDNSRefreshBusy
	}
	snapshot := dnsRefreshResolvers.Load()
	if snapshot == nil {
		<-dnsRefreshPermit
		return 0, ErrDNSRefreshUnsupported
	}
	done := make(chan error, 1)
	go func() {
		var result error
		defer func() { <-dnsRefreshPermit; done <- result }()
		for _, r := range snapshot.resolvers {
			if err := ctx.Err(); err != nil {
				result = err
				return
			}
			if r == nil {
				continue
			}
			refresh, ok := r.(DNSRefresher)
			if !ok {
				result = ErrDNSRefreshUnsupported
				return
			}
			if err := refresh.RefreshDNS(ctx); err != nil {
				result = err
				return
			}
		}
		result = ctx.Err()
	}()

	select {
	case err := <-done:
		if err != nil {
			return 0, err
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if dnsRefreshResolvers.Load() != snapshot {
			return 0, ErrDNSRefreshSuperseded
		}
		return dnsRefreshGeneration.Add(1), nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}
