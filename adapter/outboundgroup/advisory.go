package outboundgroup

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
)

const MaxAdvisoryTTL = 90 * time.Second

var (
	ErrAdvisoryRevision      = errors.New("automatic group revision changed")
	ErrAdvisoryGeneration    = errors.New("advisory mutation generation changed")
	ErrAdvisoryScope         = errors.New("advisory scope changed")
	ErrAdvisoryManual        = errors.New("automatic group has an explicit selection")
	ErrAdvisoryRetryDisabled = errors.New("experimental dial retry is disabled")
)

// AdvisoryLease is local availability advice, never a replacement proxy list.
// ExpiresAt is an absolute UTC Unix timestamp in seconds. Scope is an opaque
// caller-provided context binding. The core does not infer a physical network
// generation or treat the scope as evidence of path quality.
type AdvisoryLease struct {
	Revision           string   `json:"revision"`
	Scope              string   `json:"scope"`
	Candidates         []string `json:"candidates"`
	ExpiresAt          int64    `json:"expires_at"`
	Retry              bool     `json:"retry"`
	ExpectedGeneration uint64   `json:"expected_generation"`
}

type AdvisoryStatus struct {
	AdvisoryLease
	Active     bool   `json:"active"`
	Generation uint64 `json:"generation"`
}

// AdvisoryGroup is implemented only by automatic groups with direct members.
// Reconfiguration creates a fresh revision and an empty in-memory lease.
type AdvisoryGroup interface {
	Advisory() AdvisoryStatus
	SetAdvisory(context.Context, AdvisoryLease) error
	ClearAdvisory(revision, scope string, expectedGeneration uint64) error
}

type automaticSelection struct {
	mu         sync.Mutex
	revision   string
	generation uint64
	selected   string
	manual     bool
	lease      *AdvisoryLease
	members    []C.Proxy
	incumbent  C.Proxy
}

func newAutomaticSelection() automaticSelection {
	return automaticSelection{revision: utils.NewUUIDV4().String()}
}

func (s *automaticSelection) setSelected(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.generation++
	s.selected = name
	s.manual = name != ""
	s.lease, s.members = nil, nil
}

func (s *automaticSelection) selectedName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.selected
}

func (s *automaticSelection) advisory() AdvisoryStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := AdvisoryStatus{AdvisoryLease: AdvisoryLease{Revision: s.revision}, Generation: s.generation}
	if s.active(time.Now()) {
		status.AdvisoryLease = *s.lease
		status.Candidates = append([]string(nil), s.lease.Candidates...)
		status.Active = true
	}
	return status
}

func (s *automaticSelection) active(now time.Time) bool {
	return !s.manual && s.lease != nil && now.Before(time.Unix(s.lease.ExpiresAt, 0))
}

func (s *automaticSelection) setAdvisory(ctx context.Context, lease AdvisoryLease, proxies []C.Proxy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if lease.Revision != s.revision {
		return ErrAdvisoryRevision
	}
	if s.manual {
		return ErrAdvisoryManual
	}
	if lease.Retry {
		return ErrAdvisoryRetryDisabled
	}
	if lease.ExpectedGeneration != s.generation {
		return ErrAdvisoryGeneration
	}
	now := time.Now()
	expires := time.Unix(lease.ExpiresAt, 0)
	if !expires.After(now) || expires.After(now.Add(MaxAdvisoryTTL)) {
		return errors.New("advisory expiry must be within the next 90 seconds")
	}
	if len(lease.Scope) < 1 || len(lease.Scope) > 128 {
		return errors.New("invalid advisory scope")
	}
	for _, c := range lease.Scope {
		if c < 33 || c > 126 {
			return errors.New("invalid advisory scope")
		}
	}
	if len(lease.Candidates) < 1 || len(lease.Candidates) > 3 {
		return errors.New("advisory requires 1 to 3 candidates")
	}
	members := make([]C.Proxy, 0, len(lease.Candidates))
	seen := make(map[string]bool, len(lease.Candidates))
	for _, name := range lease.Candidates {
		if seen[name] {
			return errors.New("duplicate advisory candidate")
		}
		seen[name] = true
		var member C.Proxy
		for _, p := range proxies {
			if p.Name() == name {
				member = p
				break
			}
		}
		if member == nil || (member.Type() != C.Vless && member.Type() != C.Hysteria2) {
			return fmt.Errorf("candidate %q is not a supported direct member", name)
		}
		members = append(members, member)
	}
	lease.Candidates = append([]string(nil), lease.Candidates...)
	if err := ctx.Err(); err != nil {
		return err
	}
	s.generation++
	s.lease, s.members = &lease, members
	return nil
}

func (s *automaticSelection) clearAdvisory(revision, scope string, expectedGeneration uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if revision != s.revision {
		return ErrAdvisoryRevision
	}
	if scope == "" {
		return errors.New("advisory scope is required")
	}
	if s.lease != nil && s.lease.Scope == scope && s.lease.ExpectedGeneration == expectedGeneration {
		s.lease, s.members = nil, nil
		s.generation++
		return nil
	}
	if s.generation == expectedGeneration {
		// Fence a PUT whose transport timed out before its mutation ran. Preserve
		// a different installed lease; this cleanup owns only its captured attempt.
		s.generation++
		return nil
	}
	if s.lease != nil && s.lease.Scope != scope {
		return ErrAdvisoryScope
	}
	return ErrAdvisoryGeneration
}

// advised returns only the original live member objects. A provider replacing
// an object with the same name cannot inherit evidence for its predecessor.
// The caller holds s.mu and already checked that its incumbent is unavailable.
func (s *automaticSelection) advised(proxies []C.Proxy, testURL string) C.Proxy {
	if !s.active(time.Now()) {
		return nil
	}
	for _, member := range s.members {
		for _, p := range proxies {
			if p != member {
				continue
			}
			delay := p.LastDelayForTestUrl(testURL)
			if p.AliveForTestUrl(testURL) && delay > 0 && delay < 65535 {
				return p
			}
		}
	}
	return nil
}

func proxyPresent(proxies []C.Proxy, member C.Proxy) bool {
	for _, p := range proxies {
		if p == member {
			return true
		}
	}
	return false
}

func (u *URLTest) Advisory() AdvisoryStatus { return u.automaticSelection.advisory() }
func (u *URLTest) SetAdvisory(ctx context.Context, lease AdvisoryLease) error {
	if strings.TrimSpace(u.expectedStatus) != "204" {
		return errors.New("advisory requires an exact 204 baseline")
	}
	if err := u.automaticSelection.setAdvisory(ctx, lease, u.GetProxies(false)); err != nil {
		return err
	}
	u.fastSingle.Reset()
	return nil
}
func (u *URLTest) ClearAdvisory(revision, scope string, expectedGeneration uint64) error {
	if err := u.automaticSelection.clearAdvisory(revision, scope, expectedGeneration); err != nil {
		return err
	}
	u.fastSingle.Reset()
	return nil
}
func (f *Fallback) Advisory() AdvisoryStatus { return f.automaticSelection.advisory() }
func (f *Fallback) SetAdvisory(ctx context.Context, lease AdvisoryLease) error {
	if strings.TrimSpace(f.expectedStatus) != "204" {
		return errors.New("advisory requires an exact 204 baseline")
	}
	return f.automaticSelection.setAdvisory(ctx, lease, f.GetProxies(false))
}
func (f *Fallback) ClearAdvisory(revision, scope string, expectedGeneration uint64) error {
	return f.automaticSelection.clearAdvisory(revision, scope, expectedGeneration)
}
