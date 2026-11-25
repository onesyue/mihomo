package route

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"

	"github.com/metacubex/chi"
	"github.com/metacubex/http"
)

func registeredRoutes(t *testing.T) []string {
	t.Helper()
	var routes []string
	r, ok := upgradeRouter().(chi.Routes)
	if !ok {
		t.Fatal("upgradeRouter is not a chi router")
	}
	_ = chi.Walk(r, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		routes = append(routes, method+" "+route)
		return nil
	})
	return routes
}

// YueLink SEC1: the privileged core offers no /upgrade endpoint at all.
// Routes are inspected, never executed: the handlers download and replace
// the running binary.
func TestUpgradeRouterDisabledWhenHardened(t *testing.T) {
	prev := C.Hardened
	t.Cleanup(func() { C.Hardened = prev })

	C.Hardened = true
	if got := registeredRoutes(t); len(got) != 0 {
		t.Fatalf("hardened core registers upgrade routes: %v", got)
	}
	// Control: the walk does see routes when not hardened, so an empty
	// result above is not a blind walker.
	C.Hardened = false
	if got := registeredRoutes(t); len(got) == 0 {
		t.Fatal("route walker saw nothing on the ordinary router")
	}
}
