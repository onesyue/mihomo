package reachprobe

import (
	"encoding/json"
	"slices"
	"sort"
	"time"
)

// Observation kinds (protocol) and phases (stage) of reach_probe_v1.
const (
	ObsTCP  = "tcp"
	ObsTLS  = "tls"
	ObsQUIC = "quic"
	ObsDNS  = "dns"

	PhaseDNS     = "dns"
	PhaseConnect = "connect"
	PhaseTLS     = "tls"
)

// MaxAttemptsPerObs is the contract's per-row attempts ceiling. One device's
// connections inside one window are strongly correlated, so a busy device
// is reported as at most this many trials with its success ratio preserved
// instead of dominating the server's per-entry estimate.
const MaxAttemptsPerObs = 20

// Obs is one aggregated observation row of the upload contract.
type Obs struct {
	TID      string `json:"tid"`
	Kind     string `json:"kind"`
	Phase    string `json:"phase"`
	Attempts uint32 `json:"attempts"`
	OK       uint32 `json:"ok"`
	ErrClass string `json:"err_class,omitempty"`
	RTTP50   uint32 `json:"rtt_p50_ms"`
	IPVer    uint8  `json:"ip_ver"`
}

// Batch is one closed aggregation window for one (list version, network
// type). The host turns each batch into one POST /api/client/reach body.
type Batch struct {
	ListVersion string `json:"list_version"`
	NetworkType string `json:"network_type"`
	WindowStart int64  `json:"window_start"`
	WindowEnd   int64  `json:"window_end"`
	Obs         []Obs  `json:"obs"`
}

type obsKey struct {
	tid, kind, phase, netType string
	ipVer                     uint8
}

type obsAgg struct {
	attempts uint32
	ok       uint32
	errs     [len(errClasses)]uint32
	rtts     []uint32 // reservoir of successful handshake RTTs (ms)
	okSeen   uint32
}

func (a *obsAgg) add(ok bool, errClass string, rttMS uint32, rnd func(n int) int) {
	a.attempts++
	if !ok {
		a.errs[errClassIndex(errClass)]++
		return
	}
	a.ok++
	a.okSeen++
	if len(a.rtts) < rttSampleSlots {
		a.rtts = append(a.rtts, rttMS)
		return
	}
	// Reservoir sampling keeps the median unbiased with bounded memory.
	if j := rnd(int(a.okSeen)); j < rttSampleSlots {
		a.rtts[j] = rttMS
	}
}

func (a *obsAgg) p50() uint32 {
	if len(a.rtts) == 0 {
		return 0
	}
	s := slices.Clone(a.rtts)
	slices.Sort(s)
	return s[(len(s)-1)/2]
}

func (a *obsAgg) dominantErr() string {
	if a.ok == a.attempts {
		return ""
	}
	best, bestN := "", uint32(0)
	for i, n := range a.errs {
		if n > bestN {
			best, bestN = errClasses[i], n
		}
	}
	return best
}

// window is the open aggregation window.
type window struct {
	listVersion string
	start       time.Time
	aggs        map[obsKey]*obsAgg
	dropped     uint32
}

func newWindow(listVersion string, start time.Time) *window {
	return &window{listVersion: listVersion, start: start, aggs: map[obsKey]*obsAgg{}}
}

func (w *window) record(k obsKey, ok bool, errClass string, rttMS uint32, rnd func(int) int) {
	a := w.aggs[k]
	if a == nil {
		if len(w.aggs) >= maxWindowKeys {
			w.dropped++
			return
		}
		a = &obsAgg{}
		w.aggs[k] = a
	}
	a.add(ok, errClass, rttMS, rnd)
}

// close turns the window into one batch per network type, deterministic
// order (tests and server-side dedupe both benefit).
func (w *window) close(end time.Time) []Batch {
	byNet := map[string][]Obs{}
	for k, a := range w.aggs {
		attempts, ok := scaleAttempts(a.attempts, a.ok)
		byNet[k.netType] = append(byNet[k.netType], Obs{
			TID: k.tid, Kind: k.kind, Phase: k.phase,
			Attempts: attempts, OK: ok, ErrClass: a.dominantErr(),
			RTTP50: a.p50(), IPVer: k.ipVer,
		})
	}
	nets := make([]string, 0, len(byNet))
	for n := range byNet {
		nets = append(nets, n)
	}
	sort.Strings(nets)
	out := make([]Batch, 0, len(nets))
	for _, n := range nets {
		obs := byNet[n]
		sort.Slice(obs, func(i, j int) bool {
			a, b := obs[i], obs[j]
			if a.TID != b.TID {
				return a.TID < b.TID
			}
			if a.Kind != b.Kind {
				return a.Kind < b.Kind
			}
			if a.Phase != b.Phase {
				return a.Phase < b.Phase
			}
			return a.IPVer < b.IPVer
		})
		out = append(out, Batch{
			ListVersion: w.listVersion, NetworkType: n,
			WindowStart: w.start.Unix(), WindowEnd: end.Unix(), Obs: obs,
		})
	}
	return out
}

// scaleAttempts caps attempts at MaxAttemptsPerObs keeping ok/attempts, and
// never turns a mixed result into an all-success or all-failure row.
func scaleAttempts(attempts, ok uint32) (uint32, uint32) {
	if attempts <= MaxAttemptsPerObs {
		return attempts, ok
	}
	scaled := uint32((uint64(ok)*MaxAttemptsPerObs + uint64(attempts)/2) / uint64(attempts))
	if ok > 0 && ok < attempts {
		scaled = min(max(scaled, 1), MaxAttemptsPerObs-1)
	}
	return MaxAttemptsPerObs, scaled
}

// ring keeps encoded batches, oldest first, within RingCapacity bytes.
type ring struct {
	items   [][]byte
	size    int
	evicted uint32
}

func (r *ring) push(b Batch) {
	enc, err := json.Marshal(b)
	if err != nil || len(enc) > RingCapacity {
		r.evicted++
		return
	}
	r.items = append(r.items, enc)
	r.size += len(enc)
	for r.size > RingCapacity && len(r.items) > 0 {
		r.size -= len(r.items[0])
		r.items[0] = nil
		r.items = r.items[1:]
		r.evicted++
	}
}

func (r *ring) drain() [][]byte {
	out := r.items
	r.items, r.size = nil, 0
	return out
}
