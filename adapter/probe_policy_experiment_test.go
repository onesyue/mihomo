//go:build reliability_experiment

package adapter_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/adapter/provider"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	coreDNS "github.com/metacubex/mihomo/dns"
	"github.com/metacubex/mihomo/tunnel/statistic"
	D "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// This fixture exercises the maintained core's real URLTest, automatic-group
// and provider consumers. Its adapter terminates at local fixture endpoints;
// it is not evidence about a public Reality/HY2 path or a Chinese carrier.
type probePolicyAdapter struct {
	*outbound.Base
	address   string
	bootstrap *coreDNS.Resolver
	dials     atomic.Int32
}

func (p *probePolicyAdapter) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	p.dials.Add(1)
	if p.bootstrap != nil {
		if _, err := p.bootstrap.LookupIPv4(ctx, "bootstrap.fixture.invalid"); err != nil {
			return nil, err
		}
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", p.address)
	if err != nil {
		return nil, err
	}
	return outbound.NewConn(conn, p), nil
}

type probeFixture struct {
	address   string
	url       string
	requests  atomic.Int32
	bootstrap *coreDNS.Resolver
}

func newProbeFixture(t *testing.T, scenario string) *probeFixture {
	t.Helper()
	fixture := &probeFixture{url: "http://probe.fixture.invalid/generate_204"}
	if scenario == "tcp_refused" {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		fixture.address = ln.Addr().String()
		require.NoError(t, ln.Close())
		return fixture
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.requests.Add(1)
		switch scenario {
		case "slow_204_2500ms":
			select {
			case <-time.After(2500 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case "portal_200":
			w.WriteHeader(http.StatusOK)
		case "redirect_302":
			w.Header().Set("Location", "http://must-not-follow.invalid/")
			w.WriteHeader(http.StatusFound)
		case "http_503":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "blackhole":
			<-r.Context().Done()
		default:
			// Preserve a measurable nonzero sample at the core's millisecond precision.
			select {
			case <-time.After(5 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}
	})
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	if scenario == "tls_bad_certificate" {
		server.StartTLS()
		fixture.url = "https://probe.fixture.invalid/generate_204"
	} else {
		server.Start()
	}
	fixture.address = server.Listener.Addr().String()
	t.Cleanup(server.Close)
	if scenario == "dns_bootstrap_nxdomain" {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		require.NoError(t, err)
		dnsServer := &D.Server{PacketConn: pc, Handler: D.HandlerFunc(func(w D.ResponseWriter, r *D.Msg) {
			response := new(D.Msg)
			response.SetRcode(r, D.RcodeNameError)
			_ = w.WriteMsg(response)
		})}
		go func() { _ = dnsServer.ActivateAndServe() }()
		t.Cleanup(func() { _ = dnsServer.Shutdown() })
		resolvers := coreDNS.NewResolver(coreDNS.Config{Main: []coreDNS.NameServer{{Net: "udp", Addr: pc.LocalAddr().String()}}})
		fixture.bootstrap = resolvers.Resolver
	}
	return fixture
}

type probeObservation struct {
	Milliseconds float64 `json:"ms"`
	Healthy      bool    `json:"healthy"`
	Requests     int32   `json:"requests"`
	Dials        int32   `json:"dials"`
}

func runProbeObservation(t *testing.T, fixture *probeFixture, consumer string, budget uint) probeObservation {
	t.Helper()
	transport := &probePolicyAdapter{Base: outbound.NewBase(outbound.BaseOption{Name: "fixture", Type: C.Vless}), address: fixture.address, bootstrap: fixture.bootstrap}
	proxy := adapter.NewProxy(transport)
	members := []C.Proxy{proxy}
	expected, err := utils.NewUnsignedRanges[uint16]("204")
	require.NoError(t, err)
	hc := provider.NewHealthCheck(members, fixture.url, budget, 180, true, expected)
	pd, err := provider.NewCompatibleProvider("fixture", members, hc)
	require.NoError(t, err)
	defer pd.Close()
	before := fixture.requests.Load()
	start := time.Now()
	if consumer == "provider" {
		pd.HealthCheck()
	} else {
		ctx, cancel := context.WithTimeout(t.Context(), time.Duration(budget)*time.Millisecond)
		defer cancel()
		options := outboundgroup.GroupCommonOption{Name: "auto", URL: fixture.url, ExpectedStatus: "204", TestTimeout: int(budget), MaxFailedTimes: 3}
		if consumer == "url-test" {
			group, err := outboundgroup.NewURLTest(options, outboundgroup.URLTestOption{Tolerance: 80}, proxy, []P.ProxyProvider{pd})
			require.NoError(t, err)
			_, _ = group.URLTest(ctx, fixture.url, expected)
			_ = group.Now()
		} else {
			group, err := outboundgroup.NewFallback(options, outboundgroup.FallbackOption{}, proxy, []P.ProxyProvider{pd})
			require.NoError(t, err)
			_, _ = group.URLTest(ctx, fixture.url, expected)
			_ = group.Now()
		}
	}
	return probeObservation{Milliseconds: float64(time.Since(start)) / float64(time.Millisecond), Healthy: proxy.AliveForTestUrl(fixture.url), Requests: fixture.requests.Load() - before, Dials: transport.dials.Load()}
}

type probeDistribution struct {
	Samples   []probeObservation `json:"samples"`
	MedianMS  float64            `json:"median_ms"`
	P95MS     float64            `json:"sample_p95_ms"`
	Unhealthy int                `json:"unhealthy"`
	Requests  int32              `json:"requests"`
	Dials     int32              `json:"dials"`
}

func summarizeProbe(samples []probeObservation) probeDistribution {
	result := probeDistribution{Samples: samples}
	times := make([]float64, 0, len(samples))
	for _, sample := range samples {
		times = append(times, sample.Milliseconds)
		if !sample.Healthy {
			result.Unhealthy++
		}
		result.Requests += sample.Requests
		result.Dials += sample.Dials
	}
	sort.Float64s(times)
	result.MedianMS = (times[len(times)/2-1] + times[len(times)/2]) / 2
	result.P95MS = times[int(math.Ceil(.95*float64(len(times))))-1]
	return result
}

func TestProbePolicyExperiment(t *testing.T) {
	// Frozen contract: control 3000ms, one candidate 2000ms. No executable
	// default changes. Thirty pairs per scenario and consumer; alternate order.
	oldUnified := adapter.UnifiedDelay.Load()
	adapter.UnifiedDelay.Store(true)
	defer adapter.UnifiedDelay.Store(oldUnified)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	require.NoError(t, err)
	peer, err := listener.Accept()
	require.NoError(t, err)
	defer peer.Close()
	tracked := statistic.NewTCPTracker(outbound.NewConn(client, outbound.NewDirect()), statistic.DefaultManager, &C.Metadata{}, nil, 0, 0, true)
	defer tracked.Close()
	assertStream := func() {
		require.Same(t, tracked, statistic.DefaultManager.Get(tracked.ID()))
		require.NoError(t, peer.SetWriteDeadline(time.Now().Add(time.Second)))
		_, err := peer.Write([]byte{1})
		require.NoError(t, err)
		require.NoError(t, tracked.SetReadDeadline(time.Now().Add(time.Second)))
		data := make([]byte, 1)
		_, err = tracked.Read(data)
		require.NoError(t, err)
		require.Equal(t, byte(1), data[0])
	}
	scenarios := []string{"immediate_204", "slow_204_2500ms", "portal_200", "redirect_302", "http_503", "tcp_refused", "tls_bad_certificate", "dns_bootstrap_nxdomain", "blackhole"}
	extraCandidateFailures := 0
	for _, scenario := range scenarios {
		for _, consumer := range []string{"url-test", "fallback", "provider"} {
			t.Run(scenario+"/"+consumer, func(t *testing.T) {
				fixture := newProbeFixture(t, scenario)
				control, candidate := make([]probeObservation, 0, 30), make([]probeObservation, 0, 30)
				for pair := 0; pair < 30; pair++ {
					var a, b probeObservation
					if pair%2 == 0 {
						a = runProbeObservation(t, fixture, consumer, 3000)
						b = runProbeObservation(t, fixture, consumer, 2000)
					} else {
						b = runProbeObservation(t, fixture, consumer, 2000)
						a = runProbeObservation(t, fixture, consumer, 3000)
					}
					control = append(control, a)
					candidate = append(candidate, b)
					if scenario != "immediate_204" && scenario != "slow_204_2500ms" {
						require.False(t, a.Healthy)
						require.False(t, b.Healthy)
					}
					assertStream()
				}
				a, b := summarizeProbe(control), summarizeProbe(candidate)
				require.LessOrEqual(t, b.Requests, a.Requests, "candidate cannot add requests")
				require.Equal(t, a.Dials, b.Dials, "one proxy dial per measurement")
				if b.Unhealthy > a.Unhealthy {
					extraCandidateFailures += b.Unhealthy - a.Unhealthy
				}
				record := struct {
					Scenario  string            `json:"scenario"`
					Consumer  string            `json:"consumer"`
					Control   probeDistribution `json:"control"`
					Candidate probeDistribution `json:"candidate"`
				}{scenario, consumer, a, b}
				raw, err := json.Marshal(record)
				require.NoError(t, err)
				t.Logf("PROBE_POLICY_PAIR %s", raw)
			})
		}
	}
	require.Positive(t, extraCandidateFailures, "slow valid204 must expose the shortened-timeout false-negative cost")
	t.Log(fmt.Sprintf("PROBE_POLICY_DECISION NO_CHANGE extra_candidate_failures=%d tracked_stream_closures=0", extraCandidateFailures))
}
