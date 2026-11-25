package geodata

import (
	"fmt"
	"strings"

	"github.com/metacubex/mihomo/common/singleflight"
	"github.com/metacubex/mihomo/component/geodata/router"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

var (
	geoMode        bool
	geoLoaderName  = "memconservative"
	geoSiteMatcher = "succinct"
)

//  geoLoaderName = "standard"

func GeodataMode() bool {
	return geoMode
}

func LoaderName() string {
	return geoLoaderName
}

func SiteMatcherName() string {
	return geoSiteMatcher
}

func SetGeodataMode(newGeodataMode bool) {
	geoMode = newGeodataMode
}

func SetLoader(newLoader string) {
	if newLoader == "memc" {
		newLoader = "memconservative"
	}
	geoLoaderName = newLoader
}

func SetSiteMatcher(newMatcher string) {
	switch newMatcher {
	case "mph", "hybrid":
		geoSiteMatcher = "mph"
	default:
		geoSiteMatcher = "succinct"
	}
}

func Verify(name string) error {
	switch name {
	case C.GeositeName:
		_, err := LoadGeoSiteMatcher("CN")
		return err
	case C.GeoipName:
		_, err := LoadGeoIPMatcher("CN")
		return err
	default:
		return fmt.Errorf("not support name")
	}
}

var loadGeoSiteMatcherListSF = singleflight.Group[[]*router.Domain]{StoreResult: true}
var loadGeoSiteMatcherSF = singleflight.Group[router.DomainMatcher]{StoreResult: true}

func LoadGeoSiteMatcher(countryCode string) (router.DomainMatcher, error) {
	return LoadDNSGeoSiteMatcher(countryCode, false, "")
}

// LoadDNSGeoSiteMatcher permits the app's signed first-use seed only for selected DNS predicates.
func LoadDNSGeoSiteMatcher(countryCode string, seed bool, file string) (router.DomainMatcher, error) {
	if countryCode == "" {
		return nil, fmt.Errorf("country code could not be empty")
	}
	if file != "" && !strings.EqualFold(file, "GeoSite.dat") {
		return nil, fmt.Errorf("invalid DNS GeoSite basename")
	}

	not := false
	if countryCode[0] == '!' {
		not = true
		countryCode = countryCode[1:]
		if countryCode == "" {
			return nil, fmt.Errorf("country code could not be empty")
		}
	}
	countryCode = strings.ToLower(countryCode)

	parts := strings.Split(countryCode, "@")
	listName := strings.TrimSpace(parts[0])
	attrVal := parts[1:]
	attrs := parseAttrs(attrVal)

	if listName == "" {
		return nil, fmt.Errorf("empty listname in rule: %s", countryCode)
	}

	listKey := listName
	if seed {
		listKey = "dns-seed\x00" + listName
	} else if file != "" {
		listKey = "dns-live\x00" + file + "\x00" + listName
	}
	matcherName := listKey
	if !attrs.IsEmpty() {
		matcherName += "@" + attrs.String()
	}
	matcher, err, shared := loadGeoSiteMatcherSF.Do(matcherName, func() (router.DomainMatcher, error) {
		log.Infoln("Load GeoSite rule: %s", countryCode)
		domains, err, shared := loadGeoSiteMatcherListSF.Do(listKey, func() ([]*router.Domain, error) {
			geoLoader, err := GetGeoDataLoader(geoLoaderName)
			if err != nil {
				return nil, err
			}
			if seed {
				actual, err := FindDNSGeoFile("GeoSite.dat")
				if err != nil {
					return nil, err
				}
				if actual == "" {
					return readSeedSite(listName)
				}
				return geoLoader.LoadSiteByPath(actual, listName)
			}
			if file != "" {
				return geoLoader.LoadSiteByPath(file, listName)
			}
			return geoLoader.LoadGeoSite(listName)
		})
		if err != nil {
			if !shared {
				loadGeoSiteMatcherListSF.Forget(listKey) // don't store the error result
			}
			return nil, err
		}

		if attrs.IsEmpty() {
			if strings.Contains(countryCode, "@") {
				log.Warnln("empty attribute list: %s", countryCode)
			}
		} else {
			filteredDomains := make([]*router.Domain, 0, len(domains))
			hasAttrMatched := false
			for _, domain := range domains {
				if attrs.Match(domain) {
					hasAttrMatched = true
					filteredDomains = append(filteredDomains, domain)
				}
			}
			if !hasAttrMatched {
				log.Warnln("attribute match no rule: geosite: %s", countryCode)
			}
			domains = filteredDomains
		}

		/**
		linear: linear algorithm
		matcher, err := router.NewDomainMatcher(domains)
		mph：minimal perfect hash algorithm
		*/
		if geoSiteMatcher == "mph" {
			return router.NewMphMatcherGroup(domains)
		} else {
			return router.NewSuccinctMatcherGroup(domains)
		}
	})
	if err != nil {
		if !shared {
			loadGeoSiteMatcherSF.Forget(matcherName) // don't store the error result
		}
		return nil, err
	}
	if not {
		matcher = router.NewNotDomainMatcherGroup(matcher)
	}

	return matcher, nil
}

var loadGeoIPMatcherSF = singleflight.Group[router.IPMatcher]{StoreResult: true}

func LoadGeoIPMatcher(country string) (router.IPMatcher, error) {
	return LoadDNSGeoIPMatcher(country, false, "")
}

// LoadDNSGeoIPMatcher uses the normal country matcher and keeps seed entries out of other rules' caches.
func LoadDNSGeoIPMatcher(country string, seed bool, file string) (router.IPMatcher, error) {
	if len(country) == 0 {
		return nil, fmt.Errorf("country code could not be empty")
	}
	if file != "" && !strings.EqualFold(file, "GeoIP.dat") {
		return nil, fmt.Errorf("invalid DNS GeoIP basename")
	}

	not := false
	if country[0] == '!' {
		not = true
		country = country[1:]
	}
	country = strings.ToLower(country)

	key := country
	if seed {
		key = "dns-seed\x00" + key
	} else if file != "" {
		key = "dns-live\x00" + file + "\x00" + key
	}
	matcher, err, shared := loadGeoIPMatcherSF.Do(key, func() (router.IPMatcher, error) {
		log.Infoln("Load GeoIP rule: %s", country)
		geoLoader, err := GetGeoDataLoader(geoLoaderName)
		if err != nil {
			return nil, err
		}
		var cidrList []*router.CIDR
		if seed {
			actual, lookupErr := FindDNSGeoFile("GeoIP.dat")
			if lookupErr != nil {
				return nil, lookupErr
			}
			if actual == "" {
				cidrList, err = readSeedIP(country)
			} else {
				cidrList, err = geoLoader.LoadIPByPath(actual, country)
			}
		} else if file != "" {
			cidrList, err = geoLoader.LoadIPByPath(file, country)
		} else {
			cidrList, err = geoLoader.LoadGeoIP(country)
		}
		if err != nil {
			return nil, err
		}
		return router.NewGeoIPMatcher(cidrList)
	})
	if err != nil {
		if !shared {
			loadGeoIPMatcherSF.Forget(key) // don't store the error result
			log.Warnln("Load GeoIP rule: %s", country)
		}
		return nil, err
	}
	if not {
		matcher = router.NewNotIpMatcherGroup(matcher)
	}
	return matcher, nil
}

func ClearGeoSiteCache() {
	loadGeoSiteMatcherListSF.Reset()
	loadGeoSiteMatcherSF.Reset()
}

func ClearGeoIPCache() {
	loadGeoIPMatcherSF.Reset()
}
