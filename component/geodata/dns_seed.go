package geodata

import (
	"bytes"
	"compress/gzip"
	"embed"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/component/geodata/router"
	C "github.com/metacubex/mihomo/constant"
	"google.golang.org/protobuf/proto"
)

// Each file holds one complete upstream protobuf group, including regexes and attributes.
//
//go:embed dnsseed/*.pb.gz
var dnsSeeds embed.FS

const dnsGeoMirror = "https://geo.yuetong.app/geox/"

var dnsSeedUsed atomic.Bool

// DNSSeedPublished returns the age reference for the standalone core's normal updater.
func DNSSeedPublished() (time.Time, bool) {
	return time.Date(2026, 11, 25, 4, 59, 59, 0, time.UTC), dnsSeedUsed.Load()
}

// FindDNSGeoFile uses the core's sorted, case-insensitive filename convention
// without changing the mutable legacy asset names. The result is a basename.
func FindDNSGeoFile(name string) (string, error) {
	entries, err := os.ReadDir(C.Path.HomeDir())
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.EqualFold(entry.Name(), name) {
			return entry.Name(), nil
		}
	}
	return "", nil
}

func dnsGeoFileMissing(name string) bool {
	file, err := FindDNSGeoFile(name)
	return err == nil && file == ""
}

// UseDNSGeoSiteSeed admits the four exact default policies and the official source.
func UseDNSGeoSiteSeed(country string) bool {
	if GeoSiteUrl() != dnsGeoMirror+"geosite.dat" || !dnsGeoFileMissing("GeoSite.dat") {
		return false
	}
	switch strings.ToLower(country) {
	case "cn", "private", "geolocation-!cn", "gfw":
		return true
	default:
		return false
	}
}

func UseDNSGeoIPSeed(country string) bool {
	return GeodataMode() && strings.EqualFold(country, "cn") && GeoIpUrl() == dnsGeoMirror+"geoip.dat" && dnsGeoFileMissing("GeoIP.dat")
}

func readDNSSeed(name string, entry proto.Message) error {
	raw, err := dnsSeeds.ReadFile("dnsseed/" + name + ".pb.gz")
	if err != nil {
		return err
	}
	r, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return proto.Unmarshal(data, entry)
}

func readSeedSite(name string) ([]*router.Domain, error) {
	var site router.GeoSite
	if err := readDNSSeed("site-"+name, &site); err != nil {
		return nil, err
	}
	if !strings.EqualFold(site.CountryCode, name) || len(site.Domain) == 0 {
		return nil, fmt.Errorf("invalid bundled DNS GeoSite group %q", name)
	}
	return site.Domain, nil
}

func readSeedIP(name string) ([]*router.CIDR, error) {
	var geoIP router.GeoIP
	if err := readDNSSeed("ip-"+name, &geoIP); err != nil {
		return nil, err
	}
	if !strings.EqualFold(geoIP.CountryCode, name) || len(geoIP.Cidr) == 0 {
		return nil, fmt.Errorf("invalid bundled DNS GeoIP group %q", name)
	}
	return geoIP.Cidr, nil
}
