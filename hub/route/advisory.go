package route

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"
)

func advisoryGroup(w http.ResponseWriter, r *http.Request) (outboundgroup.AdvisoryGroup, bool) {
	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)
	group, ok := proxy.Adapter().(outboundgroup.AdvisoryGroup)
	if !ok {
		render.Status(r, http.StatusNotImplemented)
		render.JSON(w, r, newError("proxy is not a supported automatic group"))
		return nil, false
	}
	current, exists := tunnel.GetProxy(proxy.Name())
	if !exists || current.Adapter() != proxy.Adapter() {
		render.Status(r, http.StatusConflict)
		render.JSON(w, r, newError("automatic group revision changed"))
		return nil, false
	}
	return group, true
}

func getProxyAdvisory(w http.ResponseWriter, r *http.Request) {
	group, ok := advisoryGroup(w, r)
	if !ok {
		return
	}
	render.JSON(w, r, group.Advisory())
}

func decodeAdvisory(w http.ResponseWriter, r *http.Request, value any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return false
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return false
	}
	return true
}

func advisoryError(w http.ResponseWriter, r *http.Request, err error) {
	status := http.StatusUnprocessableEntity
	if errors.Is(err, outboundgroup.ErrAdvisoryRevision) || errors.Is(err, outboundgroup.ErrAdvisoryManual) || errors.Is(err, outboundgroup.ErrAdvisoryScope) || errors.Is(err, outboundgroup.ErrAdvisoryGeneration) {
		status = http.StatusConflict
	}
	if errors.Is(err, outboundgroup.ErrAdvisoryRetryDisabled) {
		status = http.StatusNotImplemented
	}
	if errors.Is(err, context.Canceled) {
		status = http.StatusRequestTimeout
	}
	if errors.Is(err, context.DeadlineExceeded) {
		status = http.StatusGatewayTimeout
	}
	render.Status(r, status)
	render.JSON(w, r, newError(err.Error()))
}

func putProxyAdvisory(w http.ResponseWriter, r *http.Request) {
	var lease outboundgroup.AdvisoryLease
	if !decodeAdvisory(w, r, &lease) {
		return
	}
	group, ok := advisoryGroup(w, r)
	if !ok {
		return
	}
	if err := group.SetAdvisory(r.Context(), lease); err != nil {
		advisoryError(w, r, err)
		return
	}
	if _, ok = advisoryGroup(w, r); !ok {
		return
	}
	render.JSON(w, r, group.Advisory())
}

func deleteProxyAdvisory(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Revision           string `json:"revision"`
		Scope              string `json:"scope"`
		ExpectedGeneration uint64 `json:"expected_generation"`
	}
	if !decodeAdvisory(w, r, &request) {
		return
	}
	group, ok := advisoryGroup(w, r)
	if !ok {
		return
	}
	if err := group.ClearAdvisory(request.Revision, request.Scope, request.ExpectedGeneration); err != nil {
		advisoryError(w, r, err)
		return
	}
	render.JSON(w, r, group.Advisory())
}
