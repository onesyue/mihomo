package outboundgroup

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/dialattempt"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

type recoveryProxy struct {
	*measuredProxy
	safe  bool
	calls atomic.Int32
	dial  func(context.Context, *C.Metadata) (C.Conn, error)
}

func (p *recoveryProxy) Type() C.AdapterType         { return C.Vless }
func (p *recoveryProxy) Adapter() C.ProxyAdapter     { return p }
func (p *recoveryProxy) SupportsSafeDialRetry() bool { return p.safe }
func (p *recoveryProxy) DialContext(ctx context.Context, m *C.Metadata) (C.Conn, error) {
	p.calls.Add(1)
	return p.dial(ctx, m)
}
func newRecoveryProxy(name string) *recoveryProxy {
	return &recoveryProxy{measuredProxy: &measuredProxy{name: name, delay: 10, alive: true}, safe: true}
}
func setupRecovery(t *testing.T) (*automaticSelection, *recoveryProxy, *recoveryProxy, *recoveryProxy, AdvisoryLease) {
	t.Helper()
	a, b, c := newRecoveryProxy("a"), newRecoveryProxy("b"), newRecoveryProxy("c")
	s := newAutomaticSelection(true)
	lease := AdvisoryLease{Revision: s.revision, Scope: "test", Candidates: []string{"b", "c"}, ExpiresAt: time.Now().Add(time.Minute).Unix(), Retry: true}
	require.NoError(t, s.setAdvisory(t.Context(), lease, []C.Proxy{a, b, c}))
	t.Cleanup(func() { s.mu.Lock(); s.invalidateLeaseLocked(); s.mu.Unlock() })
	return &s, a, b, c, lease
}
func TestRecoveryProofAndAtMostTwoAttempts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		safe    bool
		network C.NetWork
		want    int32
	}{
		{"proof", dialattempt.BeforeApplicationData(errors.New("connect")), true, C.TCP, 1},
		{"generic", errors.New("handshake"), true, C.TCP, 0},
		{"unsupported", dialattempt.BeforeApplicationData(errors.New("connect")), false, C.TCP, 0},
		{"udp", dialattempt.BeforeApplicationData(errors.New("connect")), true, C.UDP, 0},
		{"canceled", dialattempt.BeforeApplicationData(context.Canceled), true, C.TCP, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, a, b, c, _ := setupRecovery(t)
			a.safe = tc.safe
			a.dial = func(context.Context, *C.Metadata) (C.Conn, error) { return nil, tc.err }
			b.dial = func(context.Context, *C.Metadata) (C.Conn, error) {
				return nil, dialattempt.BeforeApplicationData(errors.New("second"))
			}
			c.dial = func(context.Context, *C.Metadata) (C.Conn, error) { t.Fatal("third attempt"); return nil, nil }
			_, err, _ := s.dialWithRecovery(t.Context(), &C.Metadata{NetWork: tc.network}, a, func() []C.Proxy { return []C.Proxy{a, b, c} }, "probe")
			require.ErrorIs(t, err, tc.err)
			require.Equal(t, int32(1), a.calls.Load())
			require.Equal(t, tc.want, b.calls.Load())
			require.Zero(t, c.calls.Load())
		})
	}
}
func TestRecoveryAdmissionChangesPreventAlternate(t *testing.T) {
	for _, kind := range []string{"clear", "retired", "manual", "renew", "removed", "unhealthy", "unknown", "expired", "caller"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s, a, b, c, lease := setupRecovery(t)
				current := []C.Proxy{a, b, c}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				a.dial = func(context.Context, *C.Metadata) (C.Conn, error) {
					switch kind {
					case "clear":
						require.NoError(t, s.clearAdvisory(lease.Revision, lease.Scope, lease.ExpectedGeneration))
					case "retired":
						s.RetireAdvisory()
						require.ErrorIs(t, s.setAdvisory(t.Context(), lease, current), ErrAdvisoryRevision)
					case "manual":
						s.setSelected("a")
					case "renew":
						lease.ExpectedGeneration = s.advisory().Generation
						require.NoError(t, s.setAdvisory(t.Context(), lease, current))
					case "removed":
						current = []C.Proxy{a}
					case "unhealthy":
						b.alive = false
						c.alive = false
					case "unknown":
						b.delay = 0
						c.delay = 65535
					case "expired":
						time.Sleep(61 * time.Second)
					case "caller":
						cancel()
					}
					return nil, dialattempt.BeforeApplicationData(errors.New("connect"))
				}
				b.dial = func(context.Context, *C.Metadata) (C.Conn, error) { t.Fatal("stale alternate"); return nil, nil }
				c.dial = b.dial
				_, err, _ := s.dialWithRecovery(ctx, &C.Metadata{NetWork: C.TCP}, a, func() []C.Proxy { return current }, "probe")
				require.Error(t, err)
				require.Zero(t, b.calls.Load())
				require.Zero(t, c.calls.Load())
			})
		})
	}
}
func TestRecoveryDeadlineBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for _, budget := range []time.Duration{500 * time.Millisecond, 10 * time.Second} {
			s, a, b, c, _ := setupRecovery(t)
			ctx, cancel := context.WithTimeout(t.Context(), budget)
			a.dial = func(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
				<-ctx.Done()
				return nil, dialattempt.BeforeApplicationData(ctx.Err())
			}
			b.dial = func(ctx context.Context, _ *C.Metadata) (C.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
			start := time.Now()
			_, err, _ := s.dialWithRecovery(ctx, &C.Metadata{NetWork: C.TCP}, a, func() []C.Proxy { return []C.Proxy{a, b, c} }, "probe")
			cancel()
			require.ErrorIs(t, err, context.DeadlineExceeded)
			require.Equal(t, min(budget, recoveryBudget), time.Since(start))
			require.Equal(t, int32(1), b.calls.Load())
		}
	})
}
func TestRecoveryReturnedStreamDetachedAndLateConnectionClosed(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(map[bool]string{false: "returned", true: "late"}[late], func(t *testing.T) {
			s, a, b, c, lease := setupRecovery(t)
			left, right := net.Pipe()
			defer right.Close()
			defer left.Close()
			wrapped := outbound.NewConn(left, outbound.NewBase(outbound.BaseOption{Name: "b", Type: C.Vless}))
			a.dial = func(context.Context, *C.Metadata) (C.Conn, error) {
				return nil, dialattempt.BeforeApplicationData(errors.New("connect"))
			}
			b.dial = func(context.Context, *C.Metadata) (C.Conn, error) {
				if late {
					require.NoError(t, s.clearAdvisory(lease.Revision, lease.Scope, lease.ExpectedGeneration))
				}
				return wrapped, nil
			}
			conn, err, chosen := s.dialWithRecovery(t.Context(), &C.Metadata{NetWork: C.TCP}, a, func() []C.Proxy { return []C.Proxy{a, b, c} }, "probe")
			if late {
				require.ErrorIs(t, err, context.Canceled)
				require.Nil(t, conn)
				_, err = right.Write([]byte("x"))
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Same(t, b, chosen)
			require.NoError(t, s.clearAdvisory(lease.Revision, lease.Scope, lease.ExpectedGeneration))
			done := make(chan error, 1)
			go func() { _, err := right.Write([]byte("x")); done <- err }()
			buf := make([]byte, 1)
			_, err = conn.Read(buf)
			require.NoError(t, err)
			require.NoError(t, <-done)
		})
	}
}

func TestRecoveryDefaultOffPreservesCanceledDialAccounting(t *testing.T) {
	for _, kind := range []string{"url-test", "fallback"} {
		for _, mode := range []string{"default-off", "lease-off", "admitted"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					a, b := newRecoveryProxy("a"), newRecoveryProxy("b")
					a.dial = func(context.Context, *C.Metadata) (C.Conn, error) { return nil, context.Canceled }
					group, _ := newAdvisoryGroup(t, kind, a, b)
					var base *GroupBase
					var state *automaticSelection
					switch g := group.(type) {
					case *URLTest:
						base = g.GroupBase
						state = &g.automaticSelection
					case *Fallback:
						base = g.GroupBase
						state = &g.automaticSelection
					}
					require.Equal(t, "a", group.Now())
					state.retryEnabled = mode != "default-off"
					lease := advisoryLease(group, "b")
					lease.Retry = mode == "admitted"
					require.NoError(t, group.SetAdvisory(t.Context(), lease))
					t.Cleanup(func() { state.RetireAdvisory() })
					ctx, cancel := context.WithCancel(t.Context())
					cancel()
					_, err := group.DialContext(ctx, &C.Metadata{NetWork: C.TCP})
					require.ErrorIs(t, err, context.Canceled)
					synctest.Wait()
					base.failedTestMux.Lock()
					count := base.failedTimes.Load()
					base.failedTestMux.Unlock()
					if mode == "admitted" {
						require.Zero(t, count)
						require.Zero(t, a.calls.Load())
						require.ErrorIs(t, err, errRecoveryInterrupted)
					} else {
						require.Equal(t, int64(1), count)
						require.Equal(t, int32(1), a.calls.Load())
						require.NotErrorIs(t, err, errRecoveryInterrupted)
					}
				})
			})
		}
	}
}

type partialWriteFailure struct {
	C.Conn
	writes atomic.Int32
}

func (c *partialWriteFailure) NeedHandshake() bool { return true }
func (c *partialWriteFailure) Write([]byte) (int, error) {
	c.writes.Add(1)
	return 2, errors.New("partial application write")
}
func TestRecoveryNeverReplaysPartialFirstWrite(t *testing.T) {
	for _, kind := range []string{"url-test", "fallback"} {
		t.Run(kind, func(t *testing.T) {
			a, b := newRecoveryProxy("a"), newRecoveryProxy("b")
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			conn := &partialWriteFailure{Conn: outbound.NewConn(left, outbound.NewBase(outbound.BaseOption{Name: "a", Type: C.Vless}))}
			a.dial = func(context.Context, *C.Metadata) (C.Conn, error) { return conn, nil }
			b.dial = func(context.Context, *C.Metadata) (C.Conn, error) {
				t.Error("application data replayed")
				return nil, errors.New("unexpected alternate")
			}
			group, _ := newAdvisoryGroup(t, kind, a, b)
			require.Equal(t, "a", group.Now())
			var state *automaticSelection
			switch g := group.(type) {
			case *URLTest:
				state = &g.automaticSelection
			case *Fallback:
				state = &g.automaticSelection
			}
			state.retryEnabled = true
			t.Cleanup(state.RetireAdvisory)
			lease := advisoryLease(group, "b")
			lease.Retry = true
			require.NoError(t, group.SetAdvisory(t.Context(), lease))
			result, err := group.DialContext(t.Context(), &C.Metadata{NetWork: C.TCP})
			require.NoError(t, err)
			n, err := result.Write([]byte("application"))
			require.Equal(t, 2, n)
			require.Error(t, err)
			require.Equal(t, int32(1), conn.writes.Load())
			require.Equal(t, int32(1), a.calls.Load())
			require.Zero(t, b.calls.Load())
		})
	}
}
