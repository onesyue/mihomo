package route

import (
	"encoding/json"
	"io"

	"github.com/metacubex/mihomo/component/reachprobe"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

// YueLink reachability measurement (component/reachprobe). Same
// authentication as every other controller route; on iOS this is how the
// app reaches the probe living in the packet-tunnel extension, which never
// makes HTTP requests of its own.
//
//	PUT    /yue/reach/targets  verified target list (the host checked the ed25519 signature)
//	PUT    /yue/reach/network  {"network_type":"wifi|cellular|ethernet|other|unknown"}
//	POST   /yue/reach/active   {"network_type","metered","low_power"} -> {"started","reason"}
//	POST   /yue/reach/drain    -> {"batches":[...]}, clears the ring
//	DELETE /yue/reach          forget everything (diagnostics turned off)
const reachMaxBody = 256 << 10

func reachRouter() http.Handler {
	return reachRouterFor(reachprobe.Default)
}

func reachRouterFor(p *reachprobe.Probe) http.Handler {
	r := chi.NewRouter()
	r.Put("/targets", func(w http.ResponseWriter, r *http.Request) {
		var list reachprobe.TargetList
		if !decodeReachBody(w, r, &list) {
			return
		}
		if err := p.SetTargets(list); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, newError(err.Error()))
			return
		}
		render.NoContent(w, r)
	})
	r.Put("/network", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			NetworkType string `json:"network_type"`
		}
		if !decodeReachBody(w, r, &body) {
			return
		}
		p.SetNetworkType(body.NetworkType)
		render.NoContent(w, r)
	})
	r.Post("/active", func(w http.ResponseWriter, r *http.Request) {
		var opts reachprobe.ActiveOptions
		if !decodeReachBody(w, r, &opts) {
			return
		}
		started, reason := p.MaybeRunActive(opts)
		render.JSON(w, r, render.M{"started": started, "reason": reason})
	})
	r.Post("/drain", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(p.Drain())
	})
	r.Delete("/", func(w http.ResponseWriter, r *http.Request) {
		p.Reset()
		render.NoContent(w, r)
	})
	return r
}

func decodeReachBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, reachMaxBody+1))
	if err == nil && len(body) > reachMaxBody {
		err = io.ErrShortBuffer
	}
	if err == nil {
		err = json.Unmarshal(body, dst)
	}
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return false
	}
	return true
}
