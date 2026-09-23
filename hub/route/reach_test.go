package route

import (
	"encoding/json"
	"github.com/metacubex/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/reachprobe"

	"github.com/metacubex/http"
)

func reachDo(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestReachRoutes(t *testing.T) {
	p := reachprobe.New(nil)
	defer p.Reset()
	h := reachRouterFor(p)

	exp := time.Now().Add(time.Hour).Unix()
	good := `{"list_version":"v1","expiresAt":` + jsonInt(exp) + `,"probe_interval_s":86400,"targets":[{"tid":"e1","kind":"entry","addr":"203.0.113.10","port":443,"probe":"tcp"},{"tid":"d1","kind":"domain","role":"baseline","host":"www.example.com","port":443,"probe":"tls"}]}`
	if rec := reachDo(t, h, "PUT", "/targets", good); rec.Code != http.StatusNoContent {
		t.Fatalf("PUT targets = %d %s", rec.Code, rec.Body)
	}
	bad := strings.Replace(good, "203.0.113.10", "10.0.0.1", 1)
	if rec := reachDo(t, h, "PUT", "/targets", bad); rec.Code != http.StatusBadRequest {
		t.Fatalf("private target accepted: %d", rec.Code)
	}
	if rec := reachDo(t, h, "PUT", "/targets", "{"); rec.Code != http.StatusBadRequest {
		t.Fatalf("garbage accepted: %d", rec.Code)
	}
	if rec := reachDo(t, h, "PUT", "/targets", strings.Repeat(" ", reachMaxBody+1)); rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body accepted: %d", rec.Code)
	}
	if rec := reachDo(t, h, "PUT", "/network", `{"network_type":"cellular"}`); rec.Code != http.StatusNoContent {
		t.Fatalf("PUT network = %d", rec.Code)
	}
	rec := reachDo(t, h, "POST", "/active", `{"network_type":"wifi","metered":false,"low_power":true}`)
	var act struct {
		Started bool   `json:"started"`
		Reason  string `json:"reason"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &act); err != nil || act.Started || act.Reason != "low_power" {
		t.Fatalf("POST active = %s", rec.Body)
	}
	rec = reachDo(t, h, "POST", "/drain", "")
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"batches":[]}` {
		t.Fatalf("POST drain = %d %s", rec.Code, rec.Body)
	}
	if rec := reachDo(t, h, "DELETE", "/", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE = %d", rec.Code)
	}
}

func jsonInt(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}
