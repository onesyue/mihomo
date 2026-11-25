package reachprobe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/reachhook"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type call struct{ kind, tid string }

type fakeProber struct {
	mu    sync.Mutex
	calls []call
	skip  bool
	err   error
	// during runs inside Run to simulate the dial hooks firing while the
	// probe is in flight.
	during func(t Target)
}

func (f *fakeProber) Run(_ context.Context, kind string, t Target) []StageResult {
	if f.during != nil {
		f.during(t)
	}
	f.mu.Lock()
	f.calls = append(f.calls, call{kind, t.TID})
	f.mu.Unlock()
	if f.skip {
		return nil
	}
	switch kind {
	case TaskEntry:
		return []StageResult{{Kind: ObsTCP, Phase: PhaseConnect, RTT: 40 * time.Millisecond, Err: f.err}}
	case TaskDNS:
		return []StageResult{{Kind: ObsDNS, Phase: PhaseDNS, IPVer: 4, RTT: 5 * time.Millisecond, Err: f.err}}
	case TaskDomain:
		return []StageResult{
			{Kind: ObsTLS, Phase: PhaseConnect, IPVer: 4, RTT: 20 * time.Millisecond},
			{Kind: ObsTLS, Phase: PhaseTLS, IPVer: 4, RTT: 30 * time.Millisecond, Err: f.err},
		}
	}
	return nil
}

func (f *fakeProber) snapshot() []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]call(nil), f.calls...)
}

func (f *fakeProber) reset() {
	f.mu.Lock()
	f.calls = nil
	f.mu.Unlock()
}

var epoch = time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)

func newTestProbe(t *testing.T, pr Prober) (*Probe, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: epoch}
	p := New(pr)
	p.now = clk.now
	t.Cleanup(p.Reset)
	return p, clk
}

// sampleList mirrors the reach targets v1 wire shape.
func sampleList(version string) TargetList {
	return TargetList{
		ListVersion:    version,
		IssuedAt:       epoch.Unix(),
		ExpiresAt:      epoch.Add(48 * time.Hour).Unix(),
		ProbeIntervalS: 86400,
		Targets: []Target{
			{TID: "e1", Kind: KindEntry, Addr: "203.0.113.10", Port: 443, Probe: ProbeTCP},
			{TID: "e2", Kind: KindEntry, Addr: "203.0.113.11", Port: 443, Probe: ProbeTCP},
			{TID: "e3", Kind: KindEntry, Addr: "203.0.113.12", Port: 443, Probe: ProbeTCP},
			{TID: "e4", Kind: KindEntry, Addr: "203.0.113.13", Port: 443, Probe: ProbeTCP},
			{TID: "e5", Kind: KindEntry, Addr: "2001:db8::5", Port: 443, Probe: ProbeTCP},
			{TID: "d1", Kind: KindDomain, Role: "cn-baseline", Host: "a.example", Port: 443, Probe: ProbeTLS},
			{TID: "d2", Kind: KindDomain, Role: "blocked", Host: "b.example", Port: 443, Probe: ProbeTLS},
			{TID: "d3", Kind: KindDomain, Role: "foreign", Host: "c.example", Port: 443, Probe: ProbeTLS},
		},
	}
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func drain(t *testing.T, p *Probe) []Batch {
	t.Helper()
	b, err := p.DrainBatches()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTargetListWireShape(t *testing.T) {
	// The exact server payload (sig already stripped by the host).
	raw := `{"list_version":"v1-20260923","issuedAt":1790000000,"expiresAt":` + fmt.Sprint(epoch.Add(time.Hour).Unix()) +
		`,"probe_interval_s":86400,"targets":[{"tid":"e1","kind":"entry","addr":"203.0.113.10","port":443,"probe":"tcp"},` +
		`{"tid":"d1","kind":"domain","role":"baseline","host":"www.example.com","port":443,"probe":"tls"},` +
		`{"tid":"x1","kind":"entry","addr":"203.0.113.20","port":443,"probe":"http3-future"}]}`
	var l TargetList
	if err := json.Unmarshal([]byte(raw), &l); err != nil {
		t.Fatal(err)
	}
	p, _ := newTestProbe(t, &fakeProber{})
	if err := p.SetTargets(l); err != nil {
		t.Fatalf("server list rejected: %v", err)
	}
	if p.list.activeInterval() != 24*time.Hour {
		t.Fatalf("probe_interval_s not honoured: %v", p.list.activeInterval())
	}
	// Unknown probe method: kept in the list (signature covers it) but never
	// matched or probed.
	reachhook.Observe(reachhook.PhaseTCP, ap("203.0.113.20:443"), time.Millisecond, nil)
	if b := drain(t, p); len(b) != 0 {
		t.Fatalf("unsupported target recorded: %+v", b)
	}
}

func TestPassiveAggregationAndDrain(t *testing.T) {
	p, _ := newTestProbe(t, nil)
	if err := p.SetTargets(sampleList("v1")); err != nil {
		t.Fatal(err)
	}
	p.SetNetworkType("wifi")
	if !reachhook.Enabled() {
		t.Fatal("SetTargets must install the passive hook")
	}
	for _, ms := range []int{10, 30, 20} {
		reachhook.Observe(reachhook.PhaseTCP, ap("203.0.113.10:443"), time.Duration(ms)*time.Millisecond, nil)
	}
	reachhook.Observe(reachhook.PhaseTCP, ap("203.0.113.10:443"), time.Second, syscall.ECONNRESET)
	reachhook.Observe(reachhook.PhaseTCP, ap("203.0.113.10:443"), time.Second, syscall.ECONNRESET)
	reachhook.Observe(reachhook.PhaseTCP, ap("203.0.113.10:443"), time.Second, context.DeadlineExceeded)
	reachhook.Observe(reachhook.PhaseTLS, ap("203.0.113.10:443"), 50*time.Millisecond, nil)
	// Losing legs of a dial race carry no path information.
	reachhook.Observe(reachhook.PhaseTCP, ap("203.0.113.10:443"), time.Millisecond, context.Canceled)
	// Hysteria2 on the same entry address, another (hopping) UDP port.
	reachhook.Observe(reachhook.PhaseQUIC, ap("203.0.113.10:20001"), 9*time.Millisecond, nil)
	reachhook.Observe(reachhook.PhaseTCP, ap("203.0.113.11:443"), 7*time.Millisecond, nil)

	batches := drain(t, p)
	if len(batches) != 1 {
		t.Fatalf("batches = %d, want 1", len(batches))
	}
	b := batches[0]
	if b.ListVersion != "v1" || b.NetworkType != "wifi" {
		t.Fatalf("batch header = %+v", b)
	}
	want := []Obs{
		{TID: "e1", Kind: ObsQUIC, Phase: PhaseConnect, Attempts: 1, OK: 1, RTTP50: 9, IPVer: 4},
		{TID: "e1", Kind: ObsTCP, Phase: PhaseConnect, Attempts: 6, OK: 3, ErrClass: ErrRST, RTTP50: 20, IPVer: 4},
		{TID: "e1", Kind: ObsTLS, Phase: PhaseTLS, Attempts: 1, OK: 1, RTTP50: 50, IPVer: 4},
		{TID: "e2", Kind: ObsTCP, Phase: PhaseConnect, Attempts: 1, OK: 1, RTTP50: 7, IPVer: 4},
	}
	if fmt.Sprint(b.Obs) != fmt.Sprint(want) {
		t.Fatalf("obs =\n%+v\nwant\n%+v", b.Obs, want)
	}
	if again := drain(t, p); len(again) != 0 {
		t.Fatalf("drain must clear the ring, got %d batches", len(again))
	}
}

func TestAttemptsCappedAtContractCeiling(t *testing.T) {
	p, _ := newTestProbe(t, nil)
	if err := p.SetTargets(sampleList("v1")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		var err error
		if i%100 == 0 { // 1% failures must not vanish in the scaling
			err = syscall.ECONNREFUSED
		}
		reachhook.Observe(reachhook.PhaseTCP, ap("203.0.113.10:443"), time.Millisecond, err)
	}
	o := drain(t, p)[0].Obs[0]
	if o.Attempts != MaxAttemptsPerObs || o.OK != MaxAttemptsPerObs-1 || o.ErrClass != ErrRefused {
		t.Fatalf("capped obs = %+v", o)
	}
	for _, c := range []struct{ a, ok, wa, wok uint32 }{
		{20, 7, 20, 7}, {40, 20, 20, 10}, {1000, 0, 20, 0}, {1000, 1000, 20, 20}, {1000, 1, 20, 1},
	} {
		if a, ok := scaleAttempts(c.a, c.ok); a != c.wa || ok != c.wok {
			t.Errorf("scaleAttempts(%d,%d) = %d,%d want %d,%d", c.a, c.ok, a, ok, c.wa, c.wok)
		}
	}
}

func TestUnlistedTargetsAreNeverRecorded(t *testing.T) {
	p, _ := newTestProbe(t, nil)
	// Nothing recorded before a list exists.
	reachhook.Observe(reachhook.PhaseTCP, ap("203.0.113.10:443"), time.Millisecond, nil)
	if err := p.SetTargets(sampleList("v1")); err != nil {
		t.Fatal(err)
	}
	reachhook.Observe(reachhook.PhaseTCP, ap("192.0.2.99:443"), time.Millisecond, nil)   // unknown address
	reachhook.Observe(reachhook.PhaseTCP, ap("198.51.100.7:443"), time.Millisecond, nil) // some website
	reachhook.Observe("udp-raw", ap("203.0.113.10:443"), time.Millisecond, nil)          // unknown hook phase
	if b := drain(t, p); len(b) != 0 {
		t.Fatalf("unlisted destinations were recorded: %+v", b)
	}
}

func TestExpiredListStopsRecordingAndIsRejected(t *testing.T) {
	p, clk := newTestProbe(t, &fakeProber{})
	l := sampleList("v1")
	if err := p.SetTargets(l); err != nil {
		t.Fatal(err)
	}
	clk.advance(49 * time.Hour)
	reachhook.Observe(reachhook.PhaseTCP, ap("203.0.113.10:443"), time.Millisecond, nil)
	if b := drain(t, p); len(b) != 0 {
		t.Fatalf("recorded against an expired list: %+v", b)
	}
	if started, reason := p.MaybeRunActive(ActiveOptions{NetworkType: "wifi"}); started || reason != "no_list" {
		t.Fatalf("active round on expired list: %v %q", started, reason)
	}
	if err := p.SetTargets(l); !errors.Is(err, ErrListExpired) {
		t.Fatalf("expired list accepted: %v", err)
	}
}

func TestListValidationRejectsWholeList(t *testing.T) {
	cases := map[string]func(*TargetList){
		"private addr":      func(l *TargetList) { l.Targets[0].Addr = "10.0.0.1" },
		"loopback":          func(l *TargetList) { l.Targets[0].Addr = "127.0.0.1" },
		"bad addr":          func(l *TargetList) { l.Targets[0].Addr = "not-an-ip" },
		"entry no addr":     func(l *TargetList) { l.Targets[0].Addr = "" },
		"dup tid":           func(l *TargetList) { l.Targets[1].TID = l.Targets[0].TID },
		"domain no host":    func(l *TargetList) { l.Targets[5].Host = "" },
		"bad host":          func(l *TargetList) { l.Targets[5].Host = "a b" },
		"domain ip host":    func(l *TargetList) { l.Targets[5].Host = "203.0.113.1" },
		"bad role":          func(l *TargetList) { l.Targets[5].Role = "a/b" },
		"zero port":         func(l *TargetList) { l.Targets[0].Port = 0 },
		"empty version":     func(l *TargetList) { l.ListVersion = "" },
		"negative interval": func(l *TargetList) { l.ProbeIntervalS = -1 },
		"empty":             func(l *TargetList) { l.Targets = nil },
		"tid charset":       func(l *TargetList) { l.Targets[0].TID = "a/b" },
		"too many": func(l *TargetList) {
			l.Targets = make([]Target, MaxTargets+1)
			for i := range l.Targets {
				l.Targets[i] = Target{TID: fmt.Sprint("t", i), Kind: KindEntry, Addr: "203.0.113.1", Port: 443, Probe: ProbeTCP}
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p, _ := newTestProbe(t, nil)
			l := sampleList("v1")
			mutate(&l)
			if err := p.SetTargets(l); err == nil {
				t.Fatal("malformed list accepted")
			}
			if reachhook.Enabled() {
				t.Fatal("a rejected list must not enable the hook")
			}
		})
	}
}

func TestWindowRollsEverySixHoursAndOnNewList(t *testing.T) {
	p, clk := newTestProbe(t, nil)
	if err := p.SetTargets(sampleList("v1")); err != nil {
		t.Fatal(err)
	}
	reachhook.Observe(reachhook.PhaseTCP, ap("203.0.113.10:443"), time.Millisecond, nil)
	clk.advance(WindowLength - time.Second)
	reachhook.Observe(reachhook.PhaseTCP, ap("203.0.113.10:443"), time.Millisecond, nil) // same window
	clk.advance(2 * time.Second)
	reachhook.Observe(reachhook.PhaseTCP, ap("203.0.113.10:443"), time.Millisecond, nil) // new window
	if err := p.SetTargets(sampleList("v2")); err != nil {
		t.Fatal(err)
	}
	reachhook.Observe(reachhook.PhaseTCP, ap("203.0.113.10:443"), time.Millisecond, nil) // v2 window

	b := drain(t, p)
	if len(b) != 3 {
		t.Fatalf("batches = %d, want 3: %+v", len(b), b)
	}
	if b[0].Obs[0].Attempts != 2 || b[1].Obs[0].Attempts != 1 || b[2].ListVersion != "v2" {
		t.Fatalf("window split wrong: %+v", b)
	}
	if b[0].WindowEnd-b[0].WindowStart < int64((WindowLength - time.Second).Seconds()) {
		t.Fatalf("first window too short: %+v", b[0])
	}
}

func TestRingIsBounded(t *testing.T) {
	var r ring
	big := Batch{ListVersion: "v1", NetworkType: "wifi"}
	for i := 0; i < 300; i++ {
		big.Obs = append(big.Obs, Obs{TID: fmt.Sprintf("tid-%03d", i), Kind: ObsTCP, Phase: PhaseConnect, Attempts: 1, OK: 1, IPVer: 4})
	}
	for i := 0; i < 40; i++ {
		big.WindowStart = int64(i)
		r.push(big)
		if r.size > RingCapacity {
			t.Fatalf("ring size %d exceeds %d", r.size, RingCapacity)
		}
	}
	if r.evicted == 0 {
		t.Fatal("expected oldest batches to be evicted")
	}
	items := r.drain()
	var last Batch
	if err := json.Unmarshal(items[len(items)-1], &last); err != nil || last.WindowStart != 39 {
		t.Fatalf("newest batch must survive: %v %+v", err, last.WindowStart)
	}
}

func TestWindowKeyCapBoundsMemory(t *testing.T) {
	w := newWindow("v1", epoch)
	for i := 0; i < maxWindowKeys+50; i++ {
		w.record(obsKey{tid: fmt.Sprint(i), kind: ObsTCP, phase: PhaseConnect, netType: "wifi", ipVer: 4}, true, "", 1, func(int) int { return 0 })
	}
	if len(w.aggs) != maxWindowKeys || w.dropped != 50 {
		t.Fatalf("keys=%d dropped=%d", len(w.aggs), w.dropped)
	}
}

func TestRTTReservoirIsBounded(t *testing.T) {
	var a obsAgg
	for i := 0; i < 10_000; i++ {
		a.add(true, "", uint32(i%100), func(n int) int { return n - 1 })
	}
	if len(a.rtts) != rttSampleSlots || a.attempts != 10_000 {
		t.Fatalf("rtts=%d attempts=%d", len(a.rtts), a.attempts)
	}
}

func TestActiveBudgetAndSelection(t *testing.T) {
	fp := &fakeProber{}
	p, clk := newTestProbe(t, fp)
	if err := p.SetTargets(sampleList("v1")); err != nil {
		t.Fatal(err)
	}
	// e1 carried traffic recently -> "in use" -> never actively probed.
	reachhook.Observe(reachhook.PhaseTCP, ap("203.0.113.10:443"), time.Millisecond, nil)

	ctx := context.Background()
	if ok, reason := p.runActiveSync(ctx, ActiveOptions{NetworkType: "wifi"}); !ok {
		t.Fatalf("first round refused: %s", reason)
	}
	calls := fp.snapshot()
	if len(calls) > MaxProbesPerRound {
		t.Fatalf("round ran %d probes, budget is %d", len(calls), MaxProbesPerRound)
	}
	entries := map[string]bool{}
	for _, c := range calls {
		if c.kind == TaskEntry {
			if c.tid == "e1" {
				t.Fatal("probed an in-use entry")
			}
			entries[c.tid] = true
		}
	}
	if len(entries) == 0 || len(entries) > MaxEntryAddrs {
		t.Fatalf("entry addresses probed = %d, want 1..%d", len(entries), MaxEntryAddrs)
	}

	// Budget: the list asks for one round a day; 6h later is still too soon.
	clk.advance(ActiveInterval + ActiveJitter)
	if ok, reason := p.runActiveSync(ctx, ActiveOptions{NetworkType: "wifi"}); ok || reason != "budget" {
		t.Fatalf("second round inside budget: %v %q", ok, reason)
	}
	clk.advance(24 * time.Hour)
	if ok, reason := p.runActiveSync(ctx, ActiveOptions{NetworkType: "wifi"}); !ok {
		t.Fatalf("round after interval refused: %s", reason)
	}

	b := drain(t, p)
	kinds := map[string]bool{}
	for _, batch := range b {
		for _, o := range batch.Obs {
			kinds[o.Kind+"/"+o.Phase] = true
		}
	}
	for _, k := range []string{"tcp/connect", "dns/dns", "tls/connect", "tls/tls"} {
		if !kinds[k] {
			t.Fatalf("missing %s in %v", k, kinds)
		}
	}
}

func TestMinimumIntervalWithoutServerHint(t *testing.T) {
	fp := &fakeProber{}
	p, clk := newTestProbe(t, fp)
	l := sampleList("v1")
	l.ProbeIntervalS = 60 // a server asking for more than the floor allows
	if err := p.SetTargets(l); err != nil {
		t.Fatal(err)
	}
	p.runActiveSync(context.Background(), ActiveOptions{NetworkType: "wifi"})
	clk.advance(ActiveInterval - time.Minute)
	if ok, reason := p.runActiveSync(context.Background(), ActiveOptions{NetworkType: "wifi"}); ok || reason != "budget" {
		t.Fatalf("6h floor not enforced: %v %q", ok, reason)
	}
}

func TestMeteredRunsOnlyDNSAndDomain(t *testing.T) {
	fp := &fakeProber{}
	p, _ := newTestProbe(t, fp)
	if err := p.SetTargets(sampleList("v1")); err != nil {
		t.Fatal(err)
	}
	p.nextActive = time.Time{}
	if ok, reason := p.runActiveSync(context.Background(), ActiveOptions{NetworkType: "cellular", Metered: true}); !ok {
		t.Fatalf("refused: %s", reason)
	}
	calls := fp.snapshot()
	if len(calls) == 0 {
		t.Fatal("metered round ran nothing")
	}
	for _, c := range calls {
		if c.kind == TaskEntry {
			t.Fatal("entry probe on a metered network")
		}
	}
}

func TestLowPowerSkipsAndSkipIsNotRecorded(t *testing.T) {
	fp := &fakeProber{skip: true}
	p, _ := newTestProbe(t, fp)
	if err := p.SetTargets(sampleList("v1")); err != nil {
		t.Fatal(err)
	}
	if ok, reason := p.runActiveSync(context.Background(), ActiveOptions{NetworkType: "wifi", LowPower: true}); ok || reason != "low_power" {
		t.Fatalf("low power not honoured: %v %q", ok, reason)
	}
	if len(fp.snapshot()) != 0 {
		t.Fatal("probes ran in low-power mode")
	}
	if ok, _ := p.runActiveSync(context.Background(), ActiveOptions{NetworkType: "wifi"}); !ok {
		t.Fatal("round refused")
	}
	if b := drain(t, p); len(b) != 0 {
		t.Fatalf("skipped probes were recorded: %+v", b)
	}
}

func TestPassiveSuppressedWhileActiveProbeInFlight(t *testing.T) {
	fp := &fakeProber{}
	fp.during = func(t Target) {
		if t.Address().IsValid() {
			reachhook.Observe(reachhook.PhaseTCP, netip.AddrPortFrom(t.Address(), t.Port), time.Millisecond, nil)
		}
	}
	p, _ := newTestProbe(t, fp)
	l := sampleList("v1")
	l.Targets = l.Targets[:2]
	if err := p.SetTargets(l); err != nil {
		t.Fatal(err)
	}
	if ok, reason := p.runActiveSync(context.Background(), ActiveOptions{NetworkType: "wifi"}); !ok {
		t.Fatal(reason)
	}
	for _, b := range drain(t, p) {
		for _, o := range b.Obs {
			if o.Attempts != 1 {
				t.Fatalf("active probe double-counted by the passive hook: %+v", o)
			}
		}
	}
}

func TestConcurrentRoundIsRefused(t *testing.T) {
	block := make(chan struct{})
	entered := make(chan struct{}, 1)
	fp := &fakeProber{}
	fp.during = func(Target) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-block
	}
	p, clk := newTestProbe(t, fp)
	if err := p.SetTargets(sampleList("v1")); err != nil {
		t.Fatal(err)
	}
	if ok, _ := p.MaybeRunActive(ActiveOptions{NetworkType: "wifi"}); !ok {
		t.Fatal("first round refused")
	}
	<-entered
	clk.advance(72 * time.Hour)
	if ok, reason := p.MaybeRunActive(ActiveOptions{NetworkType: "wifi"}); ok || reason != "busy" {
		t.Fatalf("overlapping round allowed: %v %q", ok, reason)
	}
	close(block)
}

func TestReplacedListDropsInFlightResults(t *testing.T) {
	fp := &fakeProber{}
	var p *Probe
	fp.during = func(Target) {
		l := sampleList("v2")
		for i := range l.Targets {
			l.Targets[i].TID += "-renamed"
		}
		_ = p.SetTargets(l)
	}
	p, _ = newTestProbe(t, fp)
	if err := p.SetTargets(sampleList("v1")); err != nil {
		t.Fatal(err)
	}
	p.runActiveSync(context.Background(), ActiveOptions{NetworkType: "wifi"})
	if b := drain(t, p); len(b) != 0 {
		t.Fatalf("result recorded under a list that no longer has its tid: %+v", b)
	}
}

func TestResetForgetsEverything(t *testing.T) {
	p, _ := newTestProbe(t, nil)
	if err := p.SetTargets(sampleList("v1")); err != nil {
		t.Fatal(err)
	}
	reachhook.Observe(reachhook.PhaseTCP, ap("203.0.113.10:443"), time.Millisecond, nil)
	p.Reset()
	if reachhook.Enabled() {
		t.Fatal("Reset must detach the hook")
	}
	if b := drain(t, p); len(b) != 0 {
		t.Fatalf("Reset kept observations: %+v", b)
	}
}

func TestDrainedPayloadCarriesNoAddresses(t *testing.T) {
	p, _ := newTestProbe(t, &fakeProber{})
	l := sampleList("v1")
	if err := p.SetTargets(l); err != nil {
		t.Fatal(err)
	}
	reachhook.Observe(reachhook.PhaseTCP, ap("203.0.113.10:443"), time.Millisecond, nil)
	p.runActiveSync(context.Background(), ActiveOptions{NetworkType: "wifi"})
	raw := string(p.Drain())
	for _, tg := range l.Targets {
		if (tg.Addr != "" && strings.Contains(raw, tg.Addr)) || (tg.Host != "" && strings.Contains(raw, tg.Host)) {
			t.Fatalf("payload leaks %s/%s: %s", tg.Addr, tg.Host, raw)
		}
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{context.DeadlineExceeded, ErrTimeout},
		{fmt.Errorf("wrap: %w", syscall.ECONNRESET), ErrRST},
		{syscall.ECONNREFUSED, ErrRefused},
		{errors.New("1.2.3.4:443 connect error: read tcp: connection reset by peer"), ErrRST},
		{errors.New("x connect error: dial tcp: i/o timeout"), ErrTimeout},
		{errors.New("remote error: tls: handshake failure"), ErrTLSAlert},
		{errors.New("reality verification failed"), ErrTLSAlert},
		{errPoisonedDNS, ErrPoisoned},
		{errors.New("something else"), ErrOther},
	}
	for _, c := range cases {
		if got := Classify(c.err); got != c.want {
			t.Errorf("Classify(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

func TestBogonClassification(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "0.0.0.0", "10.1.2.3", "192.168.1.1", "::1", "fe80::1"} {
		if !isBogon(netip.MustParseAddr(s)) {
			t.Errorf("%s not treated as bogon", s)
		}
	}
	for _, s := range []string{"203.0.113.1", "8.8.8.8", "2001:4860::8888"} {
		if isBogon(netip.MustParseAddr(s)) {
			t.Errorf("%s treated as bogon", s)
		}
	}
	if !fakeIPRange.Contains(netip.MustParseAddr("198.18.0.7")) {
		t.Fatal("fake-ip range")
	}
}
