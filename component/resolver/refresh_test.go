package resolver

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type refreshResolver struct {
	Resolver
	refresh func(context.Context) error
}

func (r refreshResolver) RefreshDNS(ctx context.Context) error { return r.refresh(ctx) }

func installRefreshResolver(t *testing.T, r Resolver) {
	t.Helper()
	old := dnsRefreshResolvers.Swap(&dnsRefreshSnapshot{resolvers: []Resolver{r}})
	t.Cleanup(func() { dnsRefreshResolvers.Store(old) })
}

func TestRefreshDNSCompletionAndCancellation(t *testing.T) {
	var calls atomic.Int32
	installRefreshResolver(t, refreshResolver{refresh: func(ctx context.Context) error { calls.Add(1); return ctx.Err() }})
	first, err := RefreshDNS(t.Context())
	require.NoError(t, err)
	require.Positive(t, first)
	require.EqualValues(t, 1, calls.Load())
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = RefreshDNS(ctx)
	require.ErrorIs(t, err, context.Canceled)
	require.EqualValues(t, 1, calls.Load())
}

func TestRefreshDNSTimeoutRetainsPermitUntilWorkerStops(t *testing.T) {
	entered, release, stopped := make(chan struct{}), make(chan struct{}), make(chan struct{})
	installRefreshResolver(t, refreshResolver{refresh: func(context.Context) error {
		close(entered)
		<-release
		close(stopped)
		return nil
	}})
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { _, err := RefreshDNS(ctx); result <- err }()
	<-entered
	cancel()
	require.ErrorIs(t, <-result, context.Canceled)
	_, err := RefreshDNS(t.Context())
	require.ErrorIs(t, err, ErrDNSRefreshBusy)
	close(release)
	<-stopped
	require.Eventually(t, func() bool { return len(dnsRefreshPermit) == 0 }, time.Second, time.Millisecond)
}

func TestRefreshDNSErrorNeverAcknowledgesCompletion(t *testing.T) {
	failure := errors.New("refresh failed")
	installRefreshResolver(t, refreshResolver{refresh: func(context.Context) error { return failure }})
	generation, err := RefreshDNS(t.Context())
	require.ErrorIs(t, err, failure)
	require.Zero(t, generation)
}

func TestRefreshDNSDeadlineAndPublicationFence(t *testing.T) {
	t.Run("deadline", func(t *testing.T) {
		installRefreshResolver(t, refreshResolver{refresh: func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }})
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
		defer cancel()
		generation, err := RefreshDNS(ctx)
		require.ErrorIs(t, err, context.DeadlineExceeded)
		require.Zero(t, generation)
		require.Eventually(t, func() bool { return len(dnsRefreshPermit) == 0 }, time.Second, time.Millisecond)
	})
	t.Run("publication", func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		installRefreshResolver(t, refreshResolver{refresh: func(context.Context) error { close(entered); <-release; return nil }})
		result := make(chan error, 1)
		go func() { _, err := RefreshDNS(t.Context()); result <- err }()
		<-entered
		dnsRefreshResolvers.Store(&dnsRefreshSnapshot{})
		close(release)
		require.ErrorIs(t, <-result, ErrDNSRefreshSuperseded)
	})
}
