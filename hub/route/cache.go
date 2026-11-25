package route

import (
	"context"
	"errors"
	"github.com/metacubex/mihomo/component/resolver"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

func cacheRouter() http.Handler {
	r := chi.NewRouter()
	r.Post("/fakeip/flush", flushFakeIPPool)
	r.Post("/dns/flush", flushDnsCache)
	r.Post("/dns/refresh", refreshDNS)
	return r
}

func flushFakeIPPool(w http.ResponseWriter, r *http.Request) {
	err := resolver.FlushFakeIP()
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	render.NoContent(w, r)
}

func flushDnsCache(w http.ResponseWriter, r *http.Request) {
	resolver.ClearCache()
	render.NoContent(w, r)
}

// refreshDNS acknowledges completed invalidation, never DNS reachability.
func refreshDNS(w http.ResponseWriter, r *http.Request) {
	generation, err := resolver.RefreshDNS(r.Context())
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			status = http.StatusGatewayTimeout
		case errors.Is(err, context.Canceled):
			status = http.StatusRequestTimeout
		case errors.Is(err, resolver.ErrDNSRefreshSuperseded):
			status = http.StatusConflict
		case errors.Is(err, resolver.ErrDNSRefreshBusy):
			status = http.StatusServiceUnavailable
		case errors.Is(err, resolver.ErrDNSRefreshUnsupported):
			status = http.StatusNotImplemented
		}
		render.Status(r, status)
		render.JSON(w, r, map[string]any{"completed": false, "message": err.Error()})
		return
	}
	render.JSON(w, r, map[string]any{"completed": true, "generation": generation})
}
