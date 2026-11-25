package route

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/common/probestage"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

var (
	SwitchProxiesCallback func(sGroup string, sProxy string)
)

func proxyRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getProxies)

	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProxyName, findProxyByName)
		r.Get("/", getProxy)
		r.Get("/delay", getProxyDelay)
		r.Get("/advisory", getProxyAdvisory)
		r.Put("/advisory", putProxyAdvisory)
		r.Delete("/advisory", deleteProxyAdvisory)
		r.Put("/", updateProxy)
		r.Delete("/", unfixedProxy)
	})
	return r
}

func parseProxyName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := getEscapeParam(r, "name")
		ctx := context.WithValue(r.Context(), CtxKeyProxyName, name)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func findProxyByName(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.Context().Value(CtxKeyProxyName).(string)
		proxy, exist := tunnel.GetProxy(name)
		if !exist {
			render.Status(r, http.StatusNotFound)
			render.JSON(w, r, ErrNotFound)
			return
		}

		ctx := context.WithValue(r.Context(), CtxKeyProxy, proxy)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func getProxies(w http.ResponseWriter, r *http.Request) {
	proxies := tunnel.Proxies()
	render.JSON(w, r, render.M{
		"proxies": proxies,
	})
}

func getProxy(w http.ResponseWriter, r *http.Request) {
	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)
	if selector, ok := proxy.Adapter().(*outboundgroup.Selector); ok && isSelectionResource(r) {
		revision := selector.SelectionRevision()
		w.Header().Set("ETag", selectorETag(revision))
		w.Header().Set("Cache-Control", "no-store")
		render.JSON(w, r, render.M{"name": proxy.Name(), "revision": revision})
		return
	}
	render.JSON(w, r, proxy)
}

func isSelectionResource(r *http.Request) bool {
	return r.URL.Query().Get("yuelink-selection") == "1"
}

func selectorETag(revision string) string { return `"yue-selector-` + revision + `"` }

// Accept strong entity tags and the existence wildcard. Weak tags never satisfy
// If-Match. Quoted entity tags may contain commas, so compare whole elements.
func matchesSelectorETag(values []string, current string) bool {
	value := strings.TrimSpace(strings.Join(values, ","))
	if value == "*" {
		return true
	}
	matched := false
	for value != "" {
		if value[0] == ',' {
			value = strings.TrimSpace(value[1:])
			continue
		}
		weak := strings.HasPrefix(value, "W/")
		if weak {
			value = value[2:]
		}
		if len(value) < 2 || value[0] != '"' {
			return false
		}
		end := strings.IndexByte(value[1:], '"')
		if end < 0 {
			return false
		}
		end += 2
		for i := 1; i < end-1; i++ {
			if value[i] < 0x21 || value[i] == 0x7f {
				return false
			}
		}
		if !weak && value[:end] == current {
			matched = true
		}
		value = strings.TrimSpace(value[end:])
		if value != "" && value[0] != ',' {
			return false
		}
	}
	return matched
}

func updateProxy(w http.ResponseWriter, r *http.Request) {
	req := struct {
		Name string `json:"name"`
	}{}
	if err := render.DecodeJSON(r.Body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)
	selector, ok := proxy.Adapter().(outboundgroup.SelectAble)
	if !ok {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("Must be a Selector"))
		return
	}

	save := func() { cachefile.Cache().SetSelected(proxy.Name(), req.Name) }
	scoped := isSelectionResource(r)
	var conditions []string
	if scoped {
		if _, ok := selector.(*outboundgroup.Selector); !ok {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError("Must be a Selector"))
			return
		}
		conditions = r.Header.Values("If-Match")
		if len(conditions) == 0 {
			render.Status(r, http.StatusPreconditionRequired)
			render.JSON(w, r, newError("If-Match required"))
			return
		}
	}
	var err error
	if fixed, ok := selector.(*outboundgroup.Selector); ok {
		var matches func(string) bool
		if len(conditions) > 0 {
			matches = func(rev string) bool { return matchesSelectorETag(conditions, selectorETag(rev)) }
		}
		var revision string
		revision, err = fixed.UpdateSelection(req.Name, matches, save)
		if scoped && err == nil {
			w.Header().Set("ETag", selectorETag(revision))
		}
	} else if err = selector.Set(req.Name); err == nil {
		save()
	}
	if errors.Is(err, outboundgroup.ErrSelectionChanged) {
		render.Status(r, http.StatusPreconditionFailed)
		render.JSON(w, r, newError("Selector revision changed"))
		return
	}
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(fmt.Sprintf("Selector update error: %s", err.Error())))
		return
	}
	if SwitchProxiesCallback != nil {
		// refresh tray menu
		go SwitchProxiesCallback(proxy.Name(), req.Name)
	}
	render.NoContent(w, r)
}

func getProxyDelay(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	url := query.Get("url")
	timeout, err := strconv.ParseInt(query.Get("timeout"), 10, 16)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	expectedStatus, err := utils.NewUnsignedRanges[uint16](query.Get("expected"))
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*time.Duration(timeout))
	defer cancel()

	ctx, stages := probestage.New(ctx)
	delay, err := proxy.URLTest(ctx, url, expectedStatus)
	if err != nil || delay == 0 || ctx.Err() != nil {
		w.Header().Set("X-Yue-Probe-Failure-Stage", classifyProbeFailure(stages.FailureStage(), err))
	}
	if ctx.Err() != nil {
		render.Status(r, http.StatusGatewayTimeout)
		render.JSON(w, r, ErrRequestTimeout)
		return
	}

	if err != nil || delay == 0 {
		render.Status(r, http.StatusServiceUnavailable)
		if err != nil && delay != 0 {
			render.JSON(w, r, err)
		} else {
			render.JSON(w, r, newError("An error occurred in the delay test"))
		}
		return
	}

	render.JSON(w, r, render.M{
		"delay": delay,
	})
}

func unfixedProxy(w http.ResponseWriter, r *http.Request) {
	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)
	if selectAble, ok := proxy.Adapter().(outboundgroup.SelectAble); ok && proxy.Type() != C.Selector {
		selectAble.ForceSet("")
		cachefile.Cache().SetSelected(proxy.Name(), "")
		render.NoContent(w, r)
		return
	}
	render.Status(r, http.StatusBadRequest)
	render.JSON(w, r, ErrBadRequest)
}
