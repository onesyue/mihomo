// Package reachprobe is the YueLink fork's mainland reachability measurement
// client. It aggregates the results of real outbound handshakes (passive,
// fed by component/reachhook) and of a tightly budgeted active probe round,
// but only for targets on a signed list the host has verified and handed in.
// Nothing outside that list is ever recorded: an unmatched handshake is
// dropped at the hook. Results live in a fixed-size ring the host drains.
//
// Privacy boundary: observations carry the list's opaque target id, never an
// IP address, hostname, UUID or any user identifier.
package reachprobe

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"time"
)

// Limits that bound memory regardless of what the host hands in.
const (
	MaxTargets     = 512
	maxTIDLen      = 64
	maxVersionLen  = 64
	maxHostLen     = 253
	maxRoleLen     = 32
	RingCapacity   = 100 * 1024 // bytes of encoded batches kept for the host
	maxWindowKeys  = 400        // distinct (tid,kind,phase,net,ipver) per window
	rttSampleSlots = 32
)

// Target kinds and probe methods of the signed list (reach targets v1).
const (
	KindEntry  = "entry"
	KindDomain = "domain"

	ProbeTCP   = "tcp"   // TCP connect only
	ProbeTLS   = "tls"   // TCP connect + TLS handshake with SNI, no HTTP
	ProbeVLESS = "vless" // real VLESS/REALITY handshake with the owning node config
	ProbeHY2   = "hy2"   // real Hysteria2 QUIC+auth handshake with the owning node config
)

// Target is one entry of the signed target list. Entry targets carry addr;
// domain targets carry host.
type Target struct {
	TID   string `json:"tid"`
	Kind  string `json:"kind"`
	Addr  string `json:"addr,omitempty"`
	Host  string `json:"host,omitempty"`
	Role  string `json:"role,omitempty"`
	Port  uint16 `json:"port"`
	Probe string `json:"probe"`

	addr netip.Addr
}

// Address returns the parsed entry address (invalid for domain targets).
func (t *Target) Address() netip.Addr { return t.addr }

// TargetList is the verified payload of GET /api/client/reach/targets with
// the signature removed.
type TargetList struct {
	ListVersion    string   `json:"list_version"`
	IssuedAt       int64    `json:"issuedAt,omitempty"`
	ExpiresAt      int64    `json:"expiresAt"`
	ProbeIntervalS int64    `json:"probe_interval_s,omitempty"`
	Targets        []Target `json:"targets"`
}

var (
	idPattern   = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)
	hostPattern = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)

	ErrListExpired = errors.New("reachprobe: target list expired")
)

// supported reports whether this client knows how to use t. Unknown kinds or
// probe methods from a newer server are ignored (never probed, never
// matched) rather than rejecting the whole list, so an old client keeps
// measuring the targets it understands.
func (t *Target) supported() bool {
	switch t.Kind {
	case KindEntry:
		switch t.Probe {
		case ProbeTCP, ProbeTLS, ProbeVLESS, ProbeHY2:
			return true
		}
	case KindDomain:
		switch t.Probe {
		case ProbeTCP, ProbeTLS:
			return true
		}
	}
	return false
}

// validate normalises the list in place. A malformed value in a field this
// client understands rejects the whole list: the host verified a signature
// over exactly this content, so a partial accept would silently diverge from
// what the server signed.
func (l *TargetList) validate(now time.Time) error {
	if l.ListVersion == "" || len(l.ListVersion) > maxVersionLen || !idPattern.MatchString(l.ListVersion) {
		return errors.New("reachprobe: bad list_version")
	}
	if l.ExpiresAt <= now.Unix() {
		return ErrListExpired
	}
	if l.ProbeIntervalS < 0 {
		return errors.New("reachprobe: bad probe_interval_s")
	}
	if len(l.Targets) == 0 || len(l.Targets) > MaxTargets {
		return fmt.Errorf("reachprobe: target count %d outside 1..%d", len(l.Targets), MaxTargets)
	}
	seen := make(map[string]struct{}, len(l.Targets))
	for i := range l.Targets {
		t := &l.Targets[i]
		if t.TID == "" || len(t.TID) > maxTIDLen || !idPattern.MatchString(t.TID) {
			return fmt.Errorf("reachprobe: bad tid at %d", i)
		}
		if _, dup := seen[t.TID]; dup {
			return fmt.Errorf("reachprobe: duplicate tid %q", t.TID)
		}
		seen[t.TID] = struct{}{}
		if t.Port == 0 {
			return fmt.Errorf("reachprobe: bad port for %q", t.TID)
		}
		if len(t.Role) > maxRoleLen || (t.Role != "" && !idPattern.MatchString(t.Role)) {
			return fmt.Errorf("reachprobe: bad role for %q", t.TID)
		}
		switch t.Kind {
		case KindEntry:
			addr, err := netip.ParseAddr(t.Addr)
			if err != nil || !addr.Unmap().IsGlobalUnicast() || addr.Unmap().IsPrivate() {
				return fmt.Errorf("reachprobe: bad addr for %q", t.TID)
			}
			t.addr = addr.Unmap()
		case KindDomain:
			if t.Host == "" || len(t.Host) > maxHostLen || !hostPattern.MatchString(t.Host) {
				return fmt.Errorf("reachprobe: bad host for %q", t.TID)
			}
			if _, err := netip.ParseAddr(t.Host); err == nil {
				return fmt.Errorf("reachprobe: domain target %q carries an address", t.TID)
			}
		}
	}
	return nil
}

// activeInterval is the minimum spacing of active rounds for this list: the
// server's probe_interval_s, never below ActiveInterval.
func (l *TargetList) activeInterval() time.Duration {
	if d := time.Duration(l.ProbeIntervalS) * time.Second; d > ActiveInterval {
		return d
	}
	return ActiveInterval
}
