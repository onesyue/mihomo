package convert_test

import (
	"encoding/json"
	"net/url"
	"reflect"
	"testing"

	"github.com/gofrs/uuid/v5"
	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/common/convert"
)

func TestXHTTPShareLinkExtraHeaders(t *testing.T) {
	for _, tt := range []struct {
		name    string
		headers any
		present bool
	}{
		{"custom headers", map[string]any{"X-Route": "test", "Host": "cdn.example"}, true},
		{"empty headers", map[string]any{}, false},
		{"wrong header container", "not-a-map", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			id, err := uuid.NewV4()
			if err != nil {
				t.Fatal("generate fixture identifier failed")
			}
			extra, err := json.Marshal(map[string]any{"headers": tt.headers, "noGRPCHeader": true})
			if err != nil {
				t.Fatal(err)
			}
			query := url.Values{"type": {"xhttp"}, "security": {"tls"}, "path": {"/tunnel"}, "extra": {string(extra)}}
			link := url.URL{Scheme: "vless", User: url.User(id.String()), Host: "example.com:443", RawQuery: query.Encode()}
			proxies, err := convert.ConvertsV2Ray([]byte(link.String()))
			if err != nil || len(proxies) != 1 {
				t.Fatal("fixture conversion failed")
			}
			opts, ok := proxies[0]["xhttp-opts"].(map[string]any)
			if !ok {
				t.Fatal("missing XHTTP options")
			}
			headers, present := opts["headers"]
			if present != tt.present {
				t.Fatal("header presence was not preserved")
			}
			if tt.present && !reflect.DeepEqual(headers, tt.headers) {
				t.Fatal("header values changed")
			}
			if opts["path"] != "/tunnel" || opts["no-grpc-header"] != true {
				t.Fatal("other XHTTP fields changed")
			}
			if _, err := adapter.ParseProxy(proxies[0]); err != nil {
				t.Fatal("converted proxy is unusable")
			}
		})
	}
}
