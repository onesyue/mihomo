package mmdb

import (
	"net"
	"testing"
)

// Fork regression: a failed MMDB load leaves the sync.Once-consumed instance
// at its zero value. Lookup on that zero value must degrade to "no match",
// never dereference the nil embedded reader (which panics the whole app under
// c-archive embedding).
func TestZeroValueReadersDoNotPanic(t *testing.T) {
	ip := net.ParseIP("1.2.3.4")
	if got := (IPReader{}).LookupCode(ip); len(got) != 0 {
		t.Fatalf("zero IPReader LookupCode = %v, want empty", got)
	}
	asn, org := (ASNReader{}).LookupASN(ip)
	if asn != "" || org != "" {
		t.Fatalf("zero ASNReader LookupASN = %q,%q, want empty", asn, org)
	}
}
