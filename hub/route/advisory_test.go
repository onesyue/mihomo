package route

import (
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/adapter/provider"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/stretchr/testify/require"
)

func TestAdvisoryRoutesBindGroupRevisionAndScope(t *testing.T) {
	for _, groupName := range []string{"auto", "自动选择 🌐"} {
		t.Run(groupName, func(t *testing.T) { testAdvisoryRoutesBindGroupRevisionAndScope(t, groupName) })
	}
}

func testAdvisoryRoutesBindGroupRevisionAndScope(t *testing.T, groupName string) {
	t.Helper()
	routePath := "/" + url.PathEscape(groupName) + "/advisory"
	member := adapter.NewProxy(outbound.NewBase(outbound.BaseOption{Name: "member", Type: C.Vless}))
	members := []C.Proxy{member}
	hc := provider.NewHealthCheck(members, "https://probe.invalid/", 1000, 0, true, nil)
	pd, err := provider.NewCompatibleProvider("fixture", members, hc)
	require.NoError(t, err)
	defer pd.Close()
	group, err := outboundgroup.NewFallback(outboundgroup.GroupCommonOption{Name: groupName, URL: "https://probe.invalid/", ExpectedStatus: "204"}, outboundgroup.FallbackOption{}, member, []P.ProxyProvider{pd})
	require.NoError(t, err)
	previous, previousProviders := tunnel.Proxies(), tunnel.Providers()
	tunnel.UpdateProxies(map[string]C.Proxy{groupName: adapter.NewProxy(group), "member": member}, nil)
	t.Cleanup(func() { tunnel.UpdateProxies(previous, previousProviders) })
	router := proxyRouter()
	get := reachDo(t, router, http.MethodGet, routePath, "")
	require.Equal(t, http.StatusOK, get.Code)
	var status outboundgroup.AdvisoryStatus
	require.NoError(t, json.Unmarshal(get.Body.Bytes(), &status))
	require.NotEmpty(t, status.Revision)
	require.False(t, status.Active)
	lease := outboundgroup.AdvisoryLease{Revision: status.Revision, Scope: "profile-network-1", ExpectedGeneration: status.Generation, Candidates: []string{"member"}, ExpiresAt: time.Now().Add(60 * time.Second).Unix()}
	body, err := json.Marshal(lease)
	require.NoError(t, err)
	put := reachDo(t, router, http.MethodPut, routePath, string(body))
	require.Equal(t, http.StatusOK, put.Code, put.Body.String())
	clearBody := `{"revision":"` + status.Revision + `","scope":"another-scope"}`
	require.Equal(t, http.StatusConflict, reachDo(t, router, http.MethodDelete, routePath, clearBody).Code)
	require.True(t, group.Advisory().Active)
	clearBody = `{"revision":"` + status.Revision + `","scope":"profile-network-1"}`
	require.Equal(t, http.StatusOK, reachDo(t, router, http.MethodDelete, routePath, clearBody).Code)
	require.False(t, group.Advisory().Active)
	require.Equal(t, http.StatusConflict, reachDo(t, router, http.MethodDelete, routePath, clearBody).Code, "a completed clear fences old attempts")
	require.Equal(t, http.StatusBadRequest, reachDo(t, router, http.MethodPut, routePath, string(body)+` {}`).Code)
	require.Equal(t, http.StatusNotImplemented, reachDo(t, router, http.MethodGet, "/member/advisory", "").Code)
	group.ForceSet("member")
	require.Equal(t, http.StatusConflict, reachDo(t, router, http.MethodPut, routePath, string(body)).Code)
	group.ForceSet("")
	lease.Retry = true
	body, err = json.Marshal(lease)
	require.NoError(t, err)
	require.Equal(t, http.StatusNotImplemented, reachDo(t, router, http.MethodPut, routePath, string(body)).Code)
	lease.Retry = false
	lease.Revision = "retired"
	body, err = json.Marshal(lease)
	require.NoError(t, err)
	require.Equal(t, http.StatusConflict, reachDo(t, router, http.MethodPut, routePath, string(body)).Code)
}
