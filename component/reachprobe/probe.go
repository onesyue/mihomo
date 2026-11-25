package reachprobe

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/reachhook"
)

// Budget of the active probe round.
const (
	WindowLength      = 6 * time.Hour
	ActiveInterval    = 6 * time.Hour // floor; a list's probe_interval_s may raise it
	ActiveJitter      = 30 * time.Minute
	MaxProbesPerRound = 8
	MaxEntryAddrs     = 3
	InUseHorizon      = time.Hour // an entry address seen passively this recently is "in use"
	ProbeTimeout      = 5 * time.Second
)

// Task kinds of an active round.
const (
	TaskEntry  = "entry"  // handshake against an entry address (probe method from the list)
	TaskDNS    = "dns"    // resolve a domain target with the physical network's DNS
	TaskDomain = "domain" // TCP + TLS(SNI) against a domain target, no HTTP
)

// StageResult is one measured stage of one probe.
type StageResult struct {
	Kind  string // ObsTCP | ObsTLS | ObsQUIC | ObsDNS
	Phase string // PhaseConnect | PhaseTLS | PhaseDNS
	IPVer uint8  // 4 or 6; 0 = derive from the target address
	RTT   time.Duration
	Err   error
}

// Prober runs single active probes. Every socket must bypass the tunnel
// (component/dialer: Android protect(fd), desktop interface binding; iOS
// extension sockets are outside the tunnel by construction). Returning no
// stages means "could not run" (e.g. no node config owns the address); such
// probes are not recorded.
type Prober interface {
	Run(ctx context.Context, taskKind string, t Target) []StageResult
}

// ActiveOptions is what the host knows and the core does not.
type ActiveOptions struct {
	// NetworkType is the contract value (wifi|cellular|ethernet|other|unknown).
	NetworkType string `json:"network_type"`
	// Metered: only DNS/domain probes (cellular, or unknown on a phone).
	Metered bool `json:"metered"`
	// LowPower: skip the round entirely (battery saver / low power mode).
	LowPower bool `json:"low_power"`
}

// Probe is the process-wide measurement state.
type Probe struct {
	mu sync.Mutex

	now    func() time.Time
	rnd    *rand.Rand
	prober Prober

	list    *TargetList
	entries map[netip.Addr]*Target // entry targets by address
	netType string

	win      *window
	ring     ring
	lastSeen map[netip.Addr]time.Time
	inflight map[netip.Addr]int

	nextActive time.Time
	running    atomic.Bool
	hooked     bool
}

// New returns an idle Probe. It records nothing until SetTargets succeeds.
func New(prober Prober) *Probe {
	return &Probe{
		now:      time.Now,
		rnd:      rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), 0x7975652d72656163)),
		prober:   prober,
		lastSeen: map[netip.Addr]time.Time{},
		inflight: map[netip.Addr]int{},
	}
}

// SetTargets installs a verified target list and starts passive recording.
func (p *Probe) SetTargets(l TargetList) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if err := l.validate(now); err != nil {
		return err
	}
	if p.list != nil && p.list.ListVersion != l.ListVersion {
		p.closeWindowLocked(now) // observations never straddle two lists
	}
	p.list = &l
	p.entries = make(map[netip.Addr]*Target, len(l.Targets))
	for i := range l.Targets {
		t := &l.Targets[i]
		if t.Kind == KindEntry && t.supported() {
			if _, dup := p.entries[t.addr]; !dup {
				p.entries[t.addr] = t
			}
		}
	}
	if !p.hooked {
		p.hooked = true
		reachhook.SetObserver(p.observePassive)
	}
	return nil
}

// SetNetworkType records the host's current network type. Passive
// observations are attributed to it.
func (p *Probe) SetNetworkType(nt string) {
	p.mu.Lock()
	p.netType = normaliseNet(nt)
	p.mu.Unlock()
}

func normaliseNet(nt string) string {
	switch nt {
	case "wifi", "cellular", "ethernet", "other":
		return nt
	}
	return "unknown"
}

// Reset drops the list, every observation and the ring, and detaches the
// hook. Used when the user turns diagnostics off.
func (p *Probe) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.hooked {
		reachhook.SetObserver(nil)
		p.hooked = false
	}
	p.list, p.entries, p.win = nil, nil, nil
	p.ring = ring{}
	p.lastSeen = map[netip.Addr]time.Time{}
	p.nextActive = time.Time{}
}

// Drain closes the open window and returns every buffered batch as one JSON
// document {"batches":[...]}, clearing the buffer.
func (p *Probe) Drain() []byte {
	p.mu.Lock()
	p.closeWindowLocked(p.now())
	items := p.ring.drain()
	p.mu.Unlock()
	out := []byte(`{"batches":[`)
	for i, it := range items {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, it...)
	}
	return append(out, "]}"...)
}

// DrainBatches is Drain for in-process callers.
func (p *Probe) DrainBatches() ([]Batch, error) {
	var doc struct {
		Batches []Batch `json:"batches"`
	}
	err := json.Unmarshal(p.Drain(), &doc)
	return doc.Batches, err
}

func (p *Probe) closeWindowLocked(now time.Time) {
	if p.win == nil {
		return
	}
	if len(p.win.aggs) > 0 {
		for _, b := range p.win.close(now) {
			p.ring.push(b)
		}
	}
	p.win = nil
}

// listLocked returns the current list if it is still valid.
func (p *Probe) listLocked(now time.Time) *TargetList {
	if p.list == nil || p.list.ExpiresAt <= now.Unix() {
		return nil
	}
	return p.list
}

func ipVerOf(a netip.Addr) uint8 {
	if a.Is6() {
		return 6
	}
	return 4
}

func (p *Probe) recordLocked(now time.Time, tid string, r StageResult, netType string) {
	if p.win != nil && (now.Sub(p.win.start) >= WindowLength || p.win.listVersion != p.list.ListVersion) {
		p.closeWindowLocked(now)
	}
	if p.win == nil {
		p.win = newWindow(p.list.ListVersion, now)
	}
	ms := min(max(r.RTT.Milliseconds(), 0), 60_000)
	p.win.record(obsKey{tid: tid, kind: r.Kind, phase: r.Phase, netType: netType, ipVer: r.IPVer},
		r.Err == nil, Classify(r.Err), uint32(ms), p.rnd.IntN)
}

// passiveStage maps a hook phase to the contract's (kind, phase).
func passiveStage(hookPhase string) (kind, phase string, ok bool) {
	switch hookPhase {
	case reachhook.PhaseTCP:
		return ObsTCP, PhaseConnect, true
	case reachhook.PhaseTLS:
		return ObsTLS, PhaseTLS, true
	case reachhook.PhaseQUIC:
		return ObsQUIC, PhaseConnect, true
	}
	return "", "", false
}

// observePassive is the reachhook observer. An address that is not an
// entry target of the current list returns before anything is stored.
// Entries match by address alone: the same entry address serves VLESS on
// TCP and Hysteria2 on UDP (with port hopping), and the list names one port.
func (p *Probe) observePassive(hookPhase string, dst netip.AddrPort, rtt time.Duration, err error) {
	if err != nil && isCancellation(err) {
		return
	}
	kind, phase, ok := passiveStage(hookPhase)
	if !ok {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if p.listLocked(now) == nil {
		return
	}
	t := p.entries[dst.Addr()]
	if t == nil {
		return
	}
	if p.inflight[t.addr] > 0 {
		return // our own active probe; recorded by runTask instead
	}
	p.lastSeen[t.addr] = now
	p.recordLocked(now, t.TID, StageResult{Kind: kind, Phase: phase, IPVer: ipVerOf(t.addr), RTT: rtt, Err: err}, p.netTypeLocked())
}

func (p *Probe) netTypeLocked() string {
	if p.netType == "" {
		return "unknown"
	}
	return p.netType
}

type task struct {
	kind   string // TaskEntry | TaskDNS | TaskDomain
	target Target
}

// planLocked chooses at most MaxProbesPerRound probes. A metered network
// runs only DNS/domain probes. Entry probes pick up to MaxEntryAddrs random
// entry addresses that have not carried traffic within InUseHorizon.
func (p *Probe) planLocked(now time.Time, metered bool) []task {
	var entries, domains []*Target
	for i := range p.list.Targets {
		t := &p.list.Targets[i]
		if !t.supported() {
			continue
		}
		switch t.Kind {
		case KindEntry:
			if metered {
				continue
			}
			if seen, ok := p.lastSeen[t.addr]; ok && now.Sub(seen) < InUseHorizon {
				continue
			}
			entries = append(entries, t)
		case KindDomain:
			domains = append(domains, t)
		}
	}
	p.rnd.Shuffle(len(entries), func(i, j int) { entries[i], entries[j] = entries[j], entries[i] })
	p.rnd.Shuffle(len(domains), func(i, j int) { domains[i], domains[j] = domains[j], domains[i] })

	var plan []task
	addrs := map[netip.Addr]struct{}{}
	for _, t := range entries {
		if len(plan) >= MaxProbesPerRound {
			break
		}
		if _, ok := addrs[t.addr]; !ok && len(addrs) >= MaxEntryAddrs {
			continue
		}
		addrs[t.addr] = struct{}{}
		plan = append(plan, task{kind: TaskEntry, target: *t})
	}
	for _, t := range domains {
		if len(plan)+2 > MaxProbesPerRound {
			break
		}
		plan = append(plan, task{kind: TaskDNS, target: *t}, task{kind: TaskDomain, target: *t})
	}
	return plan
}

// MaybeRunActive starts one active round in the background if the budget
// allows. It never blocks on the probes themselves.
func (p *Probe) MaybeRunActive(opts ActiveOptions) (started bool, reason string) {
	plan, reason := p.claimRound(opts)
	if plan == nil {
		return false, reason
	}
	go p.runPlan(context.Background(), plan, normaliseNet(opts.NetworkType))
	return true, "started"
}

// runActiveSync is MaybeRunActive that waits for the round (tests).
func (p *Probe) runActiveSync(ctx context.Context, opts ActiveOptions) (bool, string) {
	plan, reason := p.claimRound(opts)
	if plan == nil {
		return false, reason
	}
	p.runPlan(ctx, plan, normaliseNet(opts.NetworkType))
	return true, "started"
}

func (p *Probe) claimRound(opts ActiveOptions) ([]task, string) {
	if opts.LowPower {
		return nil, "low_power"
	}
	if p.prober == nil {
		return nil, "no_prober"
	}
	if !p.running.CompareAndSwap(false, true) {
		return nil, "busy"
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	list := p.listLocked(now)
	if list == nil {
		p.running.Store(false)
		return nil, "no_list"
	}
	if now.Before(p.nextActive) {
		p.running.Store(false)
		return nil, "budget"
	}
	plan := p.planLocked(now, opts.Metered)
	if len(plan) == 0 {
		p.running.Store(false)
		return nil, "nothing_to_probe"
	}
	p.nextActive = now.Add(list.activeInterval() + time.Duration(p.rnd.Int64N(int64(ActiveJitter))))
	return plan, ""
}

func (p *Probe) runPlan(ctx context.Context, plan []task, netType string) {
	defer p.running.Store(false)
	for _, tk := range plan {
		if ctx.Err() != nil {
			return
		}
		p.runTask(ctx, tk, netType)
	}
}

func (p *Probe) runTask(parent context.Context, tk task, netType string) {
	t := tk.target
	pinned := t.addr.IsValid()
	if pinned {
		p.mu.Lock()
		p.inflight[t.addr]++
		p.mu.Unlock()
		defer func() {
			p.mu.Lock()
			if p.inflight[t.addr]--; p.inflight[t.addr] <= 0 {
				delete(p.inflight, t.addr)
			}
			p.mu.Unlock()
		}()
	}

	ctx, cancel := context.WithTimeout(parent, ProbeTimeout)
	defer cancel()
	stages := p.prober.Run(ctx, tk.kind, t)
	if len(stages) == 0 || parent.Err() != nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	list := p.listLocked(now)
	if list == nil || !stillListed(list, t) {
		return // the list was replaced or expired mid-round
	}
	for _, s := range stages {
		if s.IPVer == 0 {
			if !pinned {
				continue // a domain stage must say which family it used
			}
			s.IPVer = ipVerOf(t.addr)
		}
		if s.Err != nil && errors.Is(s.Err, context.Canceled) {
			continue
		}
		p.recordLocked(now, t.TID, s, netType)
	}
}

func stillListed(l *TargetList, t Target) bool {
	for i := range l.Targets {
		c := &l.Targets[i]
		if c.TID == t.TID {
			return c.Kind == t.Kind && c.Addr == t.Addr && c.Host == t.Host && c.Port == t.Port && c.Probe == t.Probe
		}
	}
	return false
}
