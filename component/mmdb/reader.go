package mmdb

import (
	"fmt"
	"net"
	"strings"

	"github.com/metacubex/mihomo/log"
	"github.com/oschwald/maxminddb-golang"
)

type geoip2Country struct {
	Country struct {
		IsoCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

type IPReader struct {
	*maxminddb.Reader
	databaseType
}

type ASNReader struct {
	*maxminddb.Reader
}

type GeoLite2 struct {
	AutonomousSystemNumber       uint32 `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

type IPInfo struct {
	ASN  string `maxminddb:"asn"`
	Name string `maxminddb:"name"`
}

func (r IPReader) LookupCode(ipAddress net.IP) []string {
	// Fork guard: 3dbff728 downgraded MMDB load failure from Fatalln to
	// Errorln+return, which leaves the sync.Once-consumed instance at its zero
	// value — databaseType zero == typeMaxmind, and the embedded *Reader is
	// nil. Without this check the first GEOIP rule evaluated on such a process
	// dereferences the nil reader and panics the whole embedding app
	// (c-archive: no recover() anywhere in tunnel/ or listener/).
	if r.Reader == nil {
		return []string{}
	}
	switch r.databaseType {
	case typeMaxmind:
		var country geoip2Country
		_ = r.Lookup(ipAddress, &country)
		if country.Country.IsoCode == "" {
			return []string{}
		}
		return []string{strings.ToLower(country.Country.IsoCode)}

	case typeSing:
		var code string
		_ = r.Lookup(ipAddress, &code)
		if code == "" {
			return []string{}
		}
		return []string{code}

	case typeMetaV0:
		var record any
		_ = r.Lookup(ipAddress, &record)
		switch record := record.(type) {
		case string:
			return []string{record}
		case []any: // lookup returned type of slice is []any
			result := make([]string, 0, len(record))
			for _, item := range record {
				result = append(result, item.(string))
			}
			return result
		}
		return []string{}

	default:
		panic(fmt.Sprint("unknown geoip database type:", r.databaseType))
	}
}

func (r ASNReader) LookupASN(ip net.IP) (string, string) {
	// Fork guard: same zero-value hazard as IPReader.LookupCode — a failed
	// ASN database load leaves this reader nil, and r.Metadata below would
	// dereference it before any switch arm runs.
	if r.Reader == nil {
		return "", ""
	}
	switch r.Metadata.DatabaseType {
	case "GeoLite2-ASN", "DBIP-ASN-Lite (compat=GeoLite2-ASN)":
		var result GeoLite2
		_ = r.Lookup(ip, &result)
		return fmt.Sprint(result.AutonomousSystemNumber), result.AutonomousSystemOrganization
	case "ipinfo generic_asn_free.mmdb":
		var result IPInfo
		_ = r.Lookup(ip, &result)
		// Fork guard (same class as 01acf232): a lookup miss leaves result
		// zero-valued, and slicing the empty ASN ("AS12345" → "12345") panics
		// with index out of range. Under c-archive embedding nothing recovers,
		// so the first IP absent from an ipinfo ASN database would take down
		// the host app. Degrade to "no match" instead.
		return stripIpinfoASNPrefix(result.ASN), result.Name
	default:
		log.Warnln("Unsupported ASN type: %s", r.Metadata.DatabaseType)
	}
	return "", ""
}

// stripIpinfoASNPrefix turns ipinfo's "AS12345" into "12345". Anything too
// short to carry the "AS" prefix — above all the empty string a lookup miss
// produces — yields "" instead of an out-of-range slice.
func stripIpinfoASNPrefix(asn string) string {
	if len(asn) < 2 {
		return ""
	}
	return asn[2:]
}
