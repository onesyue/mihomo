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

// Fork regression, same class: on an ipinfo-typed ASN database, a lookup miss
// leaves IPInfo zero-valued and the old `result.ASN[2:]` sliced the empty
// string — index out of range, unrecovered under c-archive embedding. The
// strip helper must degrade to "no match" for anything shorter than the "AS"
// prefix.
func TestIpinfoASNPrefixStripDoesNotPanic(t *testing.T) {
	cases := map[string]string{
		"":        "", // lookup miss — the panic case
		"A":       "",
		"AS":      "",
		"AS12345": "12345",
	}
	for in, want := range cases {
		if got := stripIpinfoASNPrefix(in); got != want {
			t.Fatalf("stripIpinfoASNPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}
