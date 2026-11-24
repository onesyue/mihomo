package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	stdatomic "sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/queue"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/common/xsync"
	"github.com/metacubex/mihomo/component/ca"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/http"
)

var UnifiedDelay = atomic.NewBool(false)

const (
	defaultHistoriesNum = 10
)

type internalProxyState struct {
	alive   atomic.Bool
	history *queue.Queue[C.DelayHistory]
}

type Proxy struct {
	C.ProxyAdapter
	alive   atomic.Bool
	history *queue.Queue[C.DelayHistory]
	extra   xsync.Map[string, *internalProxyState]

	urlTestMu sync.Mutex
	urlTests  map[urlTestKey]*urlTestFlight

	// urlTestWriteMu serializes DelayHistory/alive commits with generation
	// checks. Lock order: acquire urlTestWriteMu before flight.mu; never hold
	// flight.mu while acquiring urlTestMu or urlTestWriteMu; never hold
	// urlTestWriteMu while acquiring urlTestMu.
	urlTestWriteMu      sync.Mutex
	urlTestSeq          uint64
	urlTestGlobalCommit uint64
	urlTestCommit       map[string]uint64
}

// Adapter implements C.Proxy
func (p *Proxy) Adapter() C.ProxyAdapter {
	return p.ProxyAdapter
}

// AliveForTestUrl implements C.Proxy
func (p *Proxy) AliveForTestUrl(url string) bool {
	if state, ok := p.extra.Load(url); ok {
		return state.alive.Load()
	}

	return p.alive.Load()
}

// DialContext implements C.ProxyAdapter
func (p *Proxy) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	conn, err := p.ProxyAdapter.DialContext(ctx, metadata)
	return conn, err
}

// ListenPacketContext implements C.ProxyAdapter
func (p *Proxy) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	pc, err := p.ProxyAdapter.ListenPacketContext(ctx, metadata)
	return pc, err
}

// DelayHistory implements C.Proxy
func (p *Proxy) DelayHistory() []C.DelayHistory {
	queueM := p.history.Copy()
	histories := []C.DelayHistory{}
	for _, item := range queueM {
		histories = append(histories, item)
	}
	return histories
}

// DelayHistoryForTestUrl implements C.Proxy
func (p *Proxy) DelayHistoryForTestUrl(url string) []C.DelayHistory {
	var queueM []C.DelayHistory

	if state, ok := p.extra.Load(url); ok {
		queueM = state.history.Copy()
	}
	histories := []C.DelayHistory{}
	for _, item := range queueM {
		histories = append(histories, item)
	}
	return histories
}

// ExtraDelayHistories return all delay histories for each test URL
// implements C.Proxy
func (p *Proxy) ExtraDelayHistories() map[string]C.ProxyState {
	histories := map[string]C.ProxyState{}

	p.extra.Range(func(k string, v *internalProxyState) bool {
		testUrl := k
		state := v

		queueM := state.history.Copy()
		var history []C.DelayHistory

		for _, item := range queueM {
			history = append(history, item)
		}

		histories[testUrl] = C.ProxyState{
			Alive:   state.alive.Load(),
			History: history,
		}
		return true
	})
	return histories
}

// LastDelayForTestUrl return last history record of the specified URL. if proxy is not alive, return the max value of uint16.
// implements C.Proxy
func (p *Proxy) LastDelayForTestUrl(url string) (delay uint16) {
	var maxDelay uint16 = 0xffff

	alive := false
	var history C.DelayHistory

	if state, ok := p.extra.Load(url); ok {
		alive = state.alive.Load()
		history = state.history.Last()
	}

	if !alive || history.Delay == 0 {
		return maxDelay
	}
	return history.Delay
}

// MarshalJSON implements C.ProxyAdapter
func (p *Proxy) MarshalJSON() ([]byte, error) {
	inner, err := p.ProxyAdapter.MarshalJSON()
	if err != nil {
		return inner, err
	}

	mapping := map[string]any{}
	_ = json.Unmarshal(inner, &mapping)
	mapping["history"] = p.DelayHistory()
	mapping["extra"] = p.ExtraDelayHistories()
	mapping["alive"] = p.alive.Load()
	mapping["name"] = p.Name()
	mapping["udp"] = p.SupportUDP()
	mapping["uot"] = p.SupportUOT()

	proxyInfo := p.ProxyInfo()
	mapping["xudp"] = proxyInfo.XUDP
	mapping["tfo"] = proxyInfo.TFO
	mapping["mptcp"] = proxyInfo.MPTCP
	mapping["smux"] = proxyInfo.SMUX
	mapping["interface"] = proxyInfo.Interface
	mapping["routing-mark"] = proxyInfo.RoutingMark
	mapping["provider-name"] = proxyInfo.ProviderName
	mapping["dialer-proxy"] = proxyInfo.DialerProxy

	return json.Marshal(mapping)
}

func (p *Proxy) doURLTest(ctx context.Context, url string, expectedStatus utils.IntRanges[uint16], flight *urlTestFlight) (t uint16, err error) {
	var satisfied bool

	defer func() {
		p.commitURLTestResult(flight, url, t, err, satisfied)
	}()

	unifiedDelay := UnifiedDelay.Load()

	addr, err := urlToMetadata(url)
	if err != nil {
		return
	}

	start := time.Now()
	instance, err := p.DialContext(ctx, &addr)
	if err != nil {
		return
	}
	defer func() {
		_ = instance.Close()
	}()

	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return
	}
	req = req.WithContext(ctx)

	tlsConfig, err := ca.GetTLSConfig(ca.Option{})
	if err != nil {
		return
	}

	transport := &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return instance, nil
		},
		// from http.DefaultTransport
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsConfig,
	}

	client := http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	defer client.CloseIdleConnections()

	resp, err := client.Do(req)
	if err != nil {
		return
	}

	_ = resp.Body.Close()

	if unifiedDelay {
		second := time.Now()
		var ignoredErr error
		var secondResp *http.Response
		secondResp, ignoredErr = client.Do(req)
		if ignoredErr == nil {
			resp = secondResp
			_ = resp.Body.Close()
			start = second
		} else {
			if strings.HasPrefix(url, "http://") {
				// The second HEAD is best-effort: its error is ignored and the
				// first response is used. Logging it at error level made GUIs
				// show a red "delay test failed" banner for a node that passed.
				log.Debugln("%s failed to get the second response from %s: %v", p.Name(), url, ignoredErr)
				log.Debugln("It is recommended to use HTTPS for provider.health-check.url and group.url to ensure better reliability. Due to some proxy providers hijacking test addresses and not being compatible with repeated HEAD requests, using HTTP may result in failed tests.")
			}
		}
	}

	satisfied = resp != nil && (expectedStatus == nil || expectedStatus.Check(uint16(resp.StatusCode)))
	t = uint16(time.Since(start) / time.Millisecond)
	if t == 0 {
		// a zero delay means a failed test to callers, so report a test
		// that completed in under a millisecond as 1 ms
		t = 1
	}
	return
}

// Test-only commit hooks. Production leaves these nil. They must not be
// part of the public API. Stored atomically so tests can install them
// without racing leftover commits from other tests in the same package.
//
// urlTestAfterAbandonedSample is retained for tests that script the old
// stale-snapshot window (sample, drop flight.mu, then take the write lock).
// The production path must not call it.
// urlTestAfterCommitLocked runs once urlTestWriteMu is held and the
// snapshot that will govern the write has been taken under that lock.
type urlTestCommitHook func(p *Proxy, flight *urlTestFlight, seq uint64)

var (
	urlTestAfterAbandonedSample stdatomic.Pointer[urlTestCommitHook]
	urlTestAfterCommitLocked    stdatomic.Pointer[urlTestCommitHook]
)

// commitURLTestResult publishes DelayHistory and alive for one finished
// doURLTest generation. A still-current flight always writes (concurrent
// distinct-URL probes keep last-writer-wins). An abandoned flight writes
// only when no newer generation has already committed the relevant state,
// so a late cancel cannot clobber a newer success, while a cancelled
// probe with no replacement remains observable. The abandoned/seq
// snapshot is taken under urlTestWriteMu so the check and write are
// one critical section.
func (p *Proxy) commitURLTestResult(flight *urlTestFlight, url string, t uint16, err error, satisfied bool) {
	alive := err == nil
	record := C.DelayHistory{Time: time.Now()}
	if alive {
		record.Delay = t
	}

	// Take the write lock before reading abandoned/seq so a concurrent
	// release plus newer commit cannot publish between the snapshot and
	// this write. flight.mu is acquired only while urlTestWriteMu is held.
	p.urlTestWriteMu.Lock()
	defer p.urlTestWriteMu.Unlock()

	flight.mu.Lock()
	abandoned := flight.abandoned
	seq := flight.seq
	flight.mu.Unlock()

	if fn := urlTestAfterCommitLocked.Load(); fn != nil {
		(*fn)(p, flight, seq)
	}

	if p.urlTestCommit == nil {
		p.urlTestCommit = make(map[string]uint64)
	}

	writeGlobal := !abandoned || p.urlTestGlobalCommit < seq
	writeURL := !abandoned || p.urlTestCommit[url] < seq
	if !writeGlobal && !writeURL {
		return
	}

	if writeGlobal {
		p.alive.Store(alive)
		p.history.Put(record)
		if p.history.Len() > defaultHistoriesNum {
			p.history.Pop()
		}
		if seq > p.urlTestGlobalCommit {
			p.urlTestGlobalCommit = seq
		}
	}

	if !satisfied {
		record.Delay = 0
		alive = false
	}

	if writeURL {
		state, _ := p.extra.LoadOrStoreFn(url, func() *internalProxyState {
			return &internalProxyState{
				history: queue.New[C.DelayHistory](defaultHistoriesNum),
				alive:   atomic.NewBool(true),
			}
		})
		state.alive.Store(alive)
		state.history.Put(record)
		if state.history.Len() > defaultHistoriesNum {
			state.history.Pop()
		}
		if seq > p.urlTestCommit[url] {
			p.urlTestCommit[url] = seq
		}
	}
}

func NewProxy(adapter C.ProxyAdapter) *Proxy {
	return &Proxy{
		ProxyAdapter: adapter,
		history:      queue.New[C.DelayHistory](defaultHistoriesNum),
		alive:        atomic.NewBool(true),
	}
}

func urlToMetadata(rawURL string) (addr C.Metadata, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			err = fmt.Errorf("%s scheme not Support", rawURL)
			return
		}
	}

	err = addr.SetRemoteAddress(net.JoinHostPort(u.Hostname(), port))
	return
}
