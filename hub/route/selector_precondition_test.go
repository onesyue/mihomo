package route

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	stdhttp "net/http"
	stdtest "net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/adapter/provider"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/stretchr/testify/require"
)

func selectorFixture(t *testing.T) (http.Handler, map[string]C.Proxy) {
	t.Helper()
	oldHome := C.Path.HomeDir()
	C.SetHomeDir(t.TempDir())
	t.Cleanup(func() { C.SetHomeDir(oldHome) })
	members := []C.Proxy{
		adapter.NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: "one"})),
		adapter.NewProxy(outbound.NewBase(outbound.BaseOption{Name: "two", Type: C.Vless})),
	}
	pd, err := provider.NewCompatibleProvider("fixture", members, provider.NewHealthCheck(members, "https://probe.invalid", 1000, 0, true, nil))
	require.NoError(t, err)
	groups := map[string]C.Proxy{"one": members[0]}
	for _, name := range []string{"first", "other"} {
		group, err := outboundgroup.NewSelector(outboundgroup.GroupCommonOption{Name: name}, outboundgroup.SelectorOption{}, members[0], []P.ProxyProvider{pd})
		require.NoError(t, err)
		groups[name] = adapter.NewProxy(group)
	}
	automatic, err := outboundgroup.NewFallback(outboundgroup.GroupCommonOption{Name: "auto"}, outboundgroup.FallbackOption{}, members[0], []P.ProxyProvider{pd})
	require.NoError(t, err)
	groups["auto"] = adapter.NewProxy(automatic)
	previous, providers := tunnel.Proxies(), tunnel.Providers()
	tunnel.UpdateProxies(groups, nil)
	t.Cleanup(func() { tunnel.UpdateProxies(previous, providers) })
	return proxyRouter(), groups
}

func selectorPut(router http.Handler, path, member string, tags ...string) *httptest.ResponseRecorder {
	if len(tags) > 0 {
		path += "?yuelink-selection=1"
	}
	req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(fmt.Sprintf(`{"name":%q}`, member)))
	for _, tag := range tags {
		req.Header.Add("If-Match", tag)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestSelectorPreconditions(t *testing.T) {
	router, groups := selectorFixture(t)
	snapshot := func(path string) (string, string) {
		rec := reachDo(t, router, http.MethodGet, path, "")
		require.Equal(t, http.StatusOK, rec.Code)
		var result struct {
			Now string `json:"now"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
		require.Empty(t, rec.Header().Get("ETag"), "legacy resource has no selection validator")
		scoped := reachDo(t, router, http.MethodGet, path+"?yuelink-selection=1", "")
		require.Equal(t, http.StatusOK, scoped.Code)
		return scoped.Header().Get("ETag"), result.Now
	}
	first, current := snapshot("/first")
	other, _ := snapshot("/other")
	require.Regexp(t, `^"yue-selector-[A-Z2-7]+"$`, first)
	require.Equal(t, "one", current)
	require.NotEqual(t, first, other)
	require.Empty(t, reachDo(t, router, http.MethodGet, "/one", "").Header().Get("ETag"))
	for _, tag := range []string{"", other, "W/" + first, first + " extra", `"other`, `"abc,` + first} {
		require.Equal(t, http.StatusPreconditionFailed, selectorPut(router, "/first", "two", tag).Code, tag)
	}
	require.Equal(t, http.StatusBadRequest, selectorPut(router, "/first", "missing", first).Code)
	tag, now := snapshot("/first")
	require.Equal(t, first, tag)
	require.Equal(t, "one", now)
	success := selectorPut(router, "/first", "one", `"one,two"`, first)
	require.Equal(t, http.StatusNoContent, success.Code)
	same := success.Header().Get("ETag")
	require.NotEmpty(t, same)
	require.NotEqual(t, first, same, "choosing the same member must fence an older accepted write")
	require.Equal(t, http.StatusPreconditionFailed, selectorPut(router, "/first", "two", first).Code)
	require.Equal(t, http.StatusNoContent, selectorPut(router, "/other", "two", other).Code)
	legacy := selectorPut(router, "/first", "two")
	require.Equal(t, http.StatusNoContent, legacy.Code)
	require.Empty(t, legacy.Header().Get("ETag"))
	require.Equal(t, http.StatusPreconditionFailed, selectorPut(router, "/first", "one", same).Code)
	tag, now = snapshot("/first")
	require.NotEqual(t, same, tag)
	require.Equal(t, "two", now)
	groups["first"].Adapter().(*outboundgroup.Selector).ForceSet("one")
	require.Equal(t, http.StatusPreconditionFailed, selectorPut(router, "/first", "two", tag).Code)
	require.Equal(t, http.StatusNoContent, selectorPut(router, "/first", "one", "*").Code)
}

func TestSelectorPreconditionsConcurrentWriters(t *testing.T) {
	router, _ := selectorFixture(t)
	tag := reachDo(t, router, http.MethodGet, "/first?yuelink-selection=1", "").Header().Get("ETag")
	const total = 16
	start := make(chan struct{})
	statuses := make(chan int, total)
	for i := 0; i < total; i++ {
		go func() { <-start; statuses <- selectorPut(router, "/first", "two", tag).Code }()
	}
	close(start)
	success := 0
	for i := 0; i < total; i++ {
		status := <-statuses
		if status == http.StatusNoContent {
			success++
		} else {
			require.Equal(t, http.StatusPreconditionFailed, status)
		}
	}
	require.Equal(t, 1, success)
}

type acceptedSelectorBody struct {
	reader   io.Reader
	once     sync.Once
	accepted chan struct{}
}

func (b *acceptedSelectorBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.accepted) })
	return b.reader.Read(p)
}

func TestSelectorPreconditionsFenceResolvedRequestOnReplacement(t *testing.T) {
	router, _ := selectorFixture(t)
	old := reachDo(t, router, http.MethodGet, "/first?yuelink-selection=1", "").Header().Get("ETag")
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	b := &acceptedSelectorBody{reader: reader, accepted: make(chan struct{})}
	req := httptest.NewRequest(http.MethodPut, "/first?yuelink-selection=1", b)
	req.Header.Set("If-Match", old)
	answer := make(chan int, 1)
	go func() { rec := httptest.NewRecorder(); router.ServeHTTP(rec, req); answer <- rec.Code }()
	<-b.accepted
	_, newGroups := selectorFixture(t)
	_, err := io.WriteString(writer, `{"name":"two"}`)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	require.Equal(t, http.StatusPreconditionFailed, <-answer)
	require.Equal(t, "one", newGroups["first"].Adapter().(*outboundgroup.Selector).Now())
	fresh := reachDo(t, router, http.MethodGet, "/first?yuelink-selection=1", "").Header().Get("ETag")
	require.NotEqual(t, old, fresh)
	require.Equal(t, http.StatusPreconditionFailed, selectorPut(router, "/first", "two", old).Code)
}

func TestSelectorControlResourceExcludesHealthHistory(t *testing.T) {
	router, groups := selectorFixture(t)
	path := "/first?yuelink-selection=1"
	before := reachDo(t, router, http.MethodGet, path, "")
	require.Equal(t, "no-store", before.Header().Get("Cache-Control"))
	var state map[string]string
	require.NoError(t, json.Unmarshal(before.Body.Bytes(), &state))
	require.Len(t, state, 2)
	require.Equal(t, "first", state["name"])
	require.Equal(t, selectorETag(state["revision"]), before.Header().Get("ETag"))
	legacy := reachDo(t, router, http.MethodGet, "/first", "")
	require.Empty(t, legacy.Header().Get("ETag"))
	target := stdtest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) { w.WriteHeader(204) }))
	defer target.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := groups["first"].URLTest(ctx, target.URL, nil)
	require.NoError(t, err)
	require.NotEqual(t, legacy.Body.String(), reachDo(t, router, http.MethodGet, "/first", "").Body.String())
	after := reachDo(t, router, http.MethodGet, path, "")
	require.Equal(t, before.Body.String(), after.Body.String())
	require.Equal(t, before.Header().Get("ETag"), after.Header().Get("ETag"))
	require.Equal(t, http.StatusPreconditionRequired, reachDo(t, router, http.MethodPut, path, `{"name":"two"}`).Code)
	for _, path := range []string{"/auto", "/one"} {
		legacy := reachDo(t, router, http.MethodGet, path, "")
		optional := reachDo(t, router, http.MethodGet, path+"?yuelink-selection=1", "")
		require.Equal(t, http.StatusOK, optional.Code)
		require.Equal(t, legacy.Body.String(), optional.Body.String())
		require.Empty(t, optional.Header().Get("ETag"))
	}
	require.Equal(t, http.StatusBadRequest, selectorPut(router, "/auto", "two", before.Header().Get("ETag")).Code)
	require.Equal(t, http.StatusNoContent, selectorPut(router, "/auto", "two").Code)
	require.Equal(t, "two", groups["auto"].Adapter().(*outboundgroup.Fallback).Now())
}
