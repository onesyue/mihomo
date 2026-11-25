package config

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

const seedPolicy = `dns:
  enable: true
  use-bundled-geo-seed: true
  nameserver: [1.1.1.1]
  nameserver-policy:
    'fixture.example': 4.4.4.4
    'geosite:geolocation-!cn': 9.9.9.9
    'geosite:cn': 1.1.1.1
    'geosite:private': 1.1.1.1
  fallback: [8.8.8.8]
  fallback-filter:
    geoip: true
    geoip-code: CN
    geosite: [gfw]
    ipcidr: [240.0.0.0/4]
    domain: ['+.extra.example']
`

func TestDNSGeoSeedExactOfflineAndLiveUpdate(t *testing.T) {
	oldHome, oldMode, oldSite, oldIP := C.Path.HomeDir(), geodata.GeodataMode(), geodata.GeoSiteUrl(), geodata.GeoIpUrl()
	oldSiteName, oldIPName := C.GeositeName, C.GeoipName
	dir := t.TempDir()
	C.SetHomeDir(dir)
	geodata.ClearGeoIPCache()
	geodata.ClearGeoSiteCache()
	geodata.SetGeodataMode(true)
	geodata.SetGeoIpUrl("https://geo.yuetong.app/geox/geoip.dat")
	geodata.SetGeoSiteUrl("https://geo.yuetong.app/geox/geosite.dat")
	t.Cleanup(func() {
		C.SetHomeDir(oldHome)
		C.GeositeName, C.GeoipName = oldSiteName, oldIPName
		geodata.SetGeodataMode(oldMode)
		geodata.SetGeoIpUrl(oldIP)
		geodata.SetGeoSiteUrl(oldSite)
		geodata.ClearGeoIPCache()
		geodata.ClearGeoSiteCache()
	})
	raw, err := UnmarshalRawConfig([]byte(seedPolicy))
	require.NoError(t, err)
	cfg, err := parseDNS(raw, nil)
	require.NoError(t, err)
	require.Equal(t, "fixture.example", cfg.NameServerPolicy[0].Domain)
	foreign, china, private := cfg.NameServerPolicy[1].Matcher, cfg.NameServerPolicy[2].Matcher, cfg.NameServerPolicy[3].Matcher
	require.True(t, foreign.MatchDomain("a.13mei6.buzz"))
	require.False(t, foreign.MatchDomain("a.13mei9.buzz"))
	require.True(t, china.MatchDomain("www.baidu.com"))
	require.False(t, china.MatchDomain("unlisted.invalid"))
	require.True(t, private.MatchDomain("office-printer2"))
	require.False(t, private.MatchDomain("office-printer2.unlistedexample"))
	require.Len(t, cfg.FallbackDomainFilter, 2)
	require.True(t, cfg.FallbackDomainFilter[0].MatchDomain("a.extra.example"))
	gfw := cfg.FallbackDomainFilter[1]
	require.True(t, gfw.MatchDomain("www.youtube.com"))
	require.False(t, gfw.MatchDomain("unlisted.invalid"))
	require.Len(t, cfg.FallbackIPFilter, 2)
	country := cfg.FallbackIPFilter[0]
	for ip, want := range map[string]bool{"223.5.5.5": false, "2400:3200::1": false, "8.8.8.8": true, "2001:4860:4860::8888": true, "10.1.1.1": false, "127.0.0.1": false, "169.254.1.2": false, "224.0.0.1": false, "::": false, "::1": false, "ff02::1": false, "fe80::10": false, "fc00::1": false} {
		require.Equal(t, want, country.MatchIp(netip.MustParseAddr(ip)), ip)
	}
	require.False(t, country.MatchIp(netip.Addr{}))
	require.True(t, cfg.FallbackIPFilter[1].MatchIp(netip.MustParseAddr("241.1.2.3")))
	require.NoFileExists(t, filepath.Join(dir, "GeoSite.dat"))
	require.NoFileExists(t, filepath.Join(dir, "GeoIP.dat"))
	require.True(t, geodata.GeoSiteEnable())
	require.True(t, geodata.GeoIpEnable())
	require.False(t, geodata.UseDNSGeoSiteSeed("!cn"))
	require.False(t, geodata.UseDNSGeoSiteSeed("cn@ads"))
	require.False(t, geodata.UseDNSGeoIPSeed("US"))
	geodata.SetGeoSiteUrl("")
	geodata.SetGeoIpUrl("")
	_, err = parseDNS(raw, nil)
	require.ErrorContains(t, err, "unsupported protocol scheme")
	geodata.SetGeoIpUrl("https://geo.yuetong.app/geox/geoip.dat")
	geodata.SetGeoSiteUrl("https://geo.yuetong.app/geox/geosite.dat")
	var sites router.GeoSiteList
	for _, name := range []string{"cn", "private", "geolocation-!cn", "gfw"} {
		sites.Entry = append(sites.Entry, &router.GeoSite{CountryCode: name, Domain: []*router.Domain{{Type: router.Domain_Full, Value: "updated.invalid"}}})
	}
	write := func(name string, obj proto.Message) {
		b, err := proto.Marshal(obj)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), b, 0600))
	}
	write("GeoSite.dat", &sites)
	write("GeoIP.dat", &router.GeoIPList{Entry: []*router.GeoIP{{CountryCode: "cn", Cidr: []*router.CIDR{{Ip: []byte{8, 8, 8, 8}, Prefix: 32}}}}})
	geodata.ClearGeoSiteCache()
	geodata.ClearGeoIPCache()
	require.True(t, gfw.MatchDomain("updated.invalid"))
	require.False(t, gfw.MatchDomain("www.youtube.com"))
	require.False(t, country.MatchIp(netip.MustParseAddr("8.8.8.8")))
	require.True(t, country.MatchIp(netip.MustParseAddr("223.5.5.5")))
	raw.DNS.UseBundledGeoSeed = false
	standard, err := parseDNS(raw, nil)
	require.NoError(t, err)
	require.True(t, standard.FallbackDomainFilter[1].MatchDomain("updated.invalid"))
}
