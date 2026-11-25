package route

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/component/fakeip"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	dns "github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/tunnel/statistic"
	"github.com/stretchr/testify/require"
)

func TestDNSRefreshRoutePreservesFakeIP(t *testing.T) {
	pool, err := fakeip.New(fakeip.Options{IPNet: netip.MustParsePrefix("198.18.0.0/16"), Size: 100})
	require.NoError(t, err)
	ip := pool.Lookup("preserved.test")
	old := resolver.DefaultHostMapper
	resolver.DefaultHostMapper = dns.NewEnhancer(dns.EnhancerConfig{EnhancedMode: C.DNSFakeIP, FakeIPPool: pool})
	t.Cleanup(func() { resolver.DefaultHostMapper = old })
	w := httptest.NewRecorder()
	cacheRouter().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/dns/refresh", nil))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var response struct {
		Completed  bool
		Generation uint64
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	require.True(t, response.Completed)
	require.Positive(t, response.Generation)
	require.True(t, pool.Exist(ip))
	host, ok := pool.LookBack(ip)
	require.True(t, ok)
	require.Equal(t, "preserved.test", host)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	w = httptest.NewRecorder()
	cacheRouter().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/dns/refresh", nil).WithContext(ctx))
	require.Equal(t, http.StatusRequestTimeout, w.Code)
	require.Contains(t, w.Body.String(), `"completed":false`)
	expired, stop := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer stop()
	w = httptest.NewRecorder()
	cacheRouter().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/dns/refresh", nil).WithContext(expired))
	require.Equal(t, http.StatusGatewayTimeout, w.Code)
	require.Contains(t, w.Body.String(), `"completed":false`)
	// The existing admission-only cache flush remains compatible.
	w = httptest.NewRecorder()
	cacheRouter().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/dns/flush", nil))
	require.Equal(t, http.StatusNoContent, w.Code)
}

func TestDNSRefreshRoutePreservesTrackedTCPForThirtyEvents(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	require.NoError(t, err)
	peer, err := listener.Accept()
	require.NoError(t, err)
	defer peer.Close()
	tracker := statistic.NewTCPTracker(outbound.NewConn(client, outbound.NewDirect()), statistic.DefaultManager, &C.Metadata{}, nil, 0, 0, true)
	defer tracker.Close()
	require.NoError(t, tracker.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, peer.SetDeadline(time.Now().Add(5*time.Second)))
	for i := 0; i < 30; i++ {
		w := httptest.NewRecorder()
		cacheRouter().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/dns/refresh", nil))
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.Same(t, tracker, statistic.DefaultManager.Get(tracker.ID()))
		_, err = peer.Write([]byte{byte(i)})
		require.NoError(t, err)
		data := make([]byte, 1)
		_, err = tracker.Read(data)
		require.NoError(t, err)
		require.Equal(t, byte(i), data[0])
	}
}
