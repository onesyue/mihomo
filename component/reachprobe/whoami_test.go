package reachprobe

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchWhoamiURLGate(t *testing.T) {
	for _, u := range []string{"", "http://x/reach/whoami", "https:///reach/whoami", "https://x/reach/who", "https://a:b@x/reach/whoami"} {
		if _, _, err := FetchWhoami(context.Background(), u, ""); err != ErrWhoamiURL {
			t.Errorf("%q: err = %v", u, err)
		}
	}
}

// The request leaves through component/dialer and returns the body; TLS is
// verified against the core's CA pool, so a self-signed test server must
// fail — proof that verification is on.
func TestFetchWhoamiVerifiesTLS(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"cc":"CN"}`))
	}))
	srv.TLS = &tls.Config{}
	srv.StartTLS()
	defer srv.Close()
	_, _, err := FetchWhoami(context.Background(), srv.URL+"/api/ops/client/reach/whoami", "YueLink/test")
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "certificate") {
		t.Fatalf("self-signed server accepted: %v", err)
	}
}
