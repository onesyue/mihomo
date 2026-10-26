package outboundgroup

import (
	"fmt"
	"testing"
	"testing/synctest"

	C "github.com/metacubex/mihomo/constant"
)

func TestStickySessionsFindsAndKeepsHealthyMember(t *testing.T) {
	for healthyIndex := range 8 {
		t.Run(fmt.Sprintf("healthy=%d", healthyIndex), func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				proxies := make([]C.Proxy, 8)
				for i := range proxies {
					proxies[i] = &measuredProxy{name: fmt.Sprintf("member-%d", i), alive: i == healthyIndex}
				}
				selectProxy := strategyStickySessions("https://probe.invalid/")
				metadata := &C.Metadata{Host: "example.com"}
				// The fake clock does not advance within this selection. Repeated
				// hash attempts may hit the same unavailable member every time.
				if got := selectProxy(proxies, metadata, true); got != proxies[healthyIndex] {
					t.Fatalf("selected %s, want sole healthy %s", got.Name(), proxies[healthyIndex].Name())
				}
				for _, proxy := range proxies {
					proxy.(*measuredProxy).alive = true
				}
				if got := selectProxy(proxies, metadata, true); got != proxies[healthyIndex] {
					t.Fatalf("healthy sticky member changed to %s", got.Name())
				}
			})
		})
	}
}

func TestStickySessionsAllUnavailableUsesFirstMember(t *testing.T) {
	t.Parallel()
	proxies := []C.Proxy{&measuredProxy{name: "first"}, &measuredProxy{name: "second"}}
	selectProxy := strategyStickySessions("https://probe.invalid/")
	if got := selectProxy(proxies, nil, true); got != proxies[0] {
		t.Fatalf("all unavailable = %s, want first member", got.Name())
	}
}
