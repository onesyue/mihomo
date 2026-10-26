package outboundgroup

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
)

func TestFallbackReplacesUnavailableSelection(t *testing.T) {
	for _, removed := range []bool{false, true} {
		name := "failed"
		if removed {
			name = "removed"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			first := &measuredProxy{name: "first"}
			healthy := &measuredProxy{name: "healthy", alive: true}
			selected := &measuredProxy{name: "selected", alive: true}
			provider := &measuredProvider{proxies: []C.Proxy{first, healthy, selected}, version: 1}
			group, err := NewFallback(GroupCommonOption{Name: "fallback", URL: "https://probe.invalid/"},
				FallbackOption{}, first, []P.ProxyProvider{provider})
			if err != nil {
				t.Fatal(err)
			}
			group.ForceSet(selected.Name())
			if got := group.Now(); got != selected.Name() {
				t.Fatalf("healthy fixed selection = %s, want %s", got, selected.Name())
			}
			if removed {
				provider.proxies = []C.Proxy{first, healthy}
				provider.version++
			} else {
				selected.alive = false
			}
			if got := group.Now(); got != healthy.Name() {
				t.Fatalf("selection after %s fixed member = %s, want %s", name, got, healthy.Name())
			}
			first.alive = true
			if got := group.Now(); got != first.Name() {
				t.Fatalf("recovered first member = %s, want %s", got, first.Name())
			}
			first.alive = false
			healthy.alive = false
			if got := group.Now(); got != first.Name() {
				t.Fatalf("all unavailable = %s, want existing first-member fallback %s", got, first.Name())
			}
		})
	}
}
