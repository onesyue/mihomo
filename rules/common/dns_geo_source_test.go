package common

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/geodata/router"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// Flutter writes through a private temporary file and renames only after SHA-256 verification.
// The active rule must adopt it without requiring a native updater event or a restart.
func TestDNSSeedAdoptsExternallyInstalledFullFile(t *testing.T) {
	oldHome, oldSource := C.Path.HomeDir(), geodata.GeoSiteUrl()
	dir := t.TempDir()
	C.SetHomeDir(dir)
	geodata.SetGeoSiteUrl("https://geo.yuetong.app/geox/geosite.dat")
	geodata.ClearGeoSiteCache()
	t.Cleanup(func() { geodata.ClearGeoSiteCache(); geodata.SetGeoSiteUrl(oldSource); C.SetHomeDir(oldHome) })
	rule, err := NewDNSGEOSITE("private", "dns.nameserver-policy", true)
	require.NoError(t, err)
	require.True(t, rule.MatchDomain("office-printer"))
	require.False(t, rule.MatchDomain("new.example.com"))
	data, err := proto.Marshal(&router.GeoSiteList{Entry: []*router.GeoSite{{CountryCode: "PRIVATE", Domain: []*router.Domain{{Type: router.Domain_Full, Value: "new.example.com"}}}}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "gEosIte.dAt"), data, 0600))
	rule.dnsSource.nextProbe.Store(0)
	require.True(t, rule.MatchDomain("new.example.com"))
	require.False(t, rule.MatchDomain("office-printer"))
	require.Equal(t, "gEosIte.dAt", *rule.dnsSource.live.Load())
}

func TestDNSSeedAdoptsMixedCaseIPv4AndIPv6(t *testing.T) {
	oldHome, oldSource, oldMode := C.Path.HomeDir(), geodata.GeoIpUrl(), geodata.GeodataMode()
	dir := t.TempDir()
	C.SetHomeDir(dir)
	geodata.SetGeodataMode(true)
	geodata.SetGeoIpUrl("https://geo.yuetong.app/geox/geoip.dat")
	geodata.ClearGeoIPCache()
	t.Cleanup(func() {
		geodata.ClearGeoIPCache()
		geodata.SetGeoIpUrl(oldSource)
		geodata.SetGeodataMode(oldMode)
		C.SetHomeDir(oldHome)
	})
	rule, err := NewDNSGEOIP("cn", "dns.fallback-filter.geoip", false, true, true)
	require.NoError(t, err)
	filter := rule.DnsFallbackFilter()
	v4, v6 := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("2001:4860:4860::8888")
	require.True(t, filter.MatchIp(v4))
	require.True(t, filter.MatchIp(v6))
	full := &router.GeoIPList{Entry: []*router.GeoIP{{CountryCode: "CN", Cidr: []*router.CIDR{{Ip: v4.AsSlice(), Prefix: 32}, {Ip: v6.AsSlice(), Prefix: 128}}}}}
	data, err := proto.Marshal(full)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "gEOIp.DaT"), data, 0600))
	rule.dnsSource.nextProbe.Store(0)
	require.False(t, filter.MatchIp(v4))
	require.False(t, filter.MatchIp(v6))
	require.Equal(t, "gEOIp.DaT", *rule.dnsSource.live.Load())
}
