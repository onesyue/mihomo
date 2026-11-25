package common

import (
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/geodata"
)

// dnsGeoSource switches a first-use rule to a complete database installed by the
// client's background refresher, which may run in a different process. A rule
// probes the filesystem at most once per minute while it is using its bundled seed.
type dnsGeoSource struct {
	seed      bool
	live      atomic.Pointer[string]
	nextProbe atomic.Int64
}

func (s *dnsGeoSource) probe(name string) string {
	if !s.seed || s.live.Load() != nil {
		return ""
	}
	now := time.Now().Unix()
	next := s.nextProbe.Load()
	if now < next || !s.nextProbe.CompareAndSwap(next, now+60) {
		return ""
	}
	actual, _ := geodata.FindDNSGeoFile(name)
	return actual
}
