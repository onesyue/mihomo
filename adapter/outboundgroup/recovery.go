package outboundgroup

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/metacubex/mihomo/common/dialattempt"
	C "github.com/metacubex/mihomo/constant"
)

const recoveryBudget = 6 * time.Second

var errRecoveryInterrupted = errors.New("optional recovery interrupted")

func recoveryInterrupted(err error) error { return fmt.Errorf("%w: %w", errRecoveryInterrupted, err) }

type safeDialRetry interface{ SupportsSafeDialRetry() bool }

func supportsSafeDialRetry(proxy C.Proxy) bool {
	adapter, ok := proxy.Adapter().(safeDialRetry)
	return ok && adapter.SupportsSafeDialRetry()
}

// dialWithRecovery never sees application payload. Returned connections leave
// this operation permanently; first-write callbacks cannot re-enter it.
func (s *automaticSelection) dialWithRecovery(ctx context.Context, metadata *C.Metadata, primary C.Proxy, proxies func() []C.Proxy, testURL string) (C.Conn, error, C.Proxy) {
	legacy := func() (C.Conn, error, C.Proxy) { c, err := primary.DialContext(ctx, metadata); return c, err, primary }
	if !s.retryEnabled || metadata == nil || metadata.NetWork != C.TCP {
		return legacy()
	}
	s.mu.Lock()
	lease := s.lease
	if !s.active(time.Now()) || !lease.Retry {
		s.mu.Unlock()
		return legacy()
	}
	leaseCtx := s.leaseContext
	s.mu.Unlock()
	if !supportsSafeDialRetry(primary) {
		return legacy()
	}
	if err := ctx.Err(); err != nil {
		return nil, recoveryInterrupted(err), primary
	}
	deadline := minTime(time.Now().Add(recoveryBudget), time.Unix(lease.ExpiresAt, 0))
	operation, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	stop := context.AfterFunc(leaseCtx, cancel)
	defer stop()
	failure := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if leaseCtx.Err() != nil || !time.Now().Before(time.Unix(lease.ExpiresAt, 0)) {
			return context.Canceled
		}
		return operation.Err()
	}
	if err := failure(); err != nil {
		return nil, recoveryInterrupted(err), primary
	}
	remaining := time.Until(deadline)
	if callerDeadline, ok := operation.Deadline(); ok {
		remaining = time.Until(callerDeadline)
	}
	firstCtx, firstCancel := context.WithTimeout(operation, min(3*time.Second, remaining/2))
	conn, firstErr := primary.DialContext(firstCtx, metadata.Clone())
	firstCancel()
	if err := failure(); err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, recoveryInterrupted(err), primary
	}
	if firstErr == nil {
		return conn, nil, primary
	}
	if conn != nil {
		_ = conn.Close()
	}
	if errors.Is(firstErr, context.Canceled) || !dialattempt.ProvenBeforeApplicationData(firstErr) {
		return nil, firstErr, primary
	}
	current := proxies()
	s.mu.Lock()
	var alternate C.Proxy
	if s.lease == lease && s.active(time.Now()) {
		for _, candidate := range s.members {
			if candidate == primary || !proxyPresent(current, candidate) || !candidate.AliveForTestUrl(testURL) {
				continue
			}
			delay := candidate.LastDelayForTestUrl(testURL)
			if delay == 0 || delay == 65535 || !supportsSafeDialRetry(candidate) {
				continue
			}
			alternate = candidate
			break
		}
	}
	s.mu.Unlock()
	if err := failure(); err != nil {
		return nil, recoveryInterrupted(err), primary
	}
	if alternate == nil {
		return nil, firstErr, primary
	}
	conn, err := alternate.DialContext(operation, metadata.Clone())
	if contextErr := failure(); contextErr != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, recoveryInterrupted(contextErr), primary
	}
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, firstErr, primary
	}
	return conn, nil, alternate
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
