package reachprobe

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/dialer"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

const (
	whoamiSuffix  = "/reach/whoami"
	whoamiMaxBody = 4 << 10
	whoamiTimeout = 8 * time.Second
)

// ErrWhoamiURL rejects anything that is not an https .../reach/whoami URL:
// this is a single-purpose fetch, not a generic HTTP client for the host.
var ErrWhoamiURL = errors.New("reachprobe: whoami url must be https and end in " + whoamiSuffix)

// FetchWhoami performs GET rawURL over the physical network, bypassing the
// tunnel exactly like proxy dials (component/dialer). The geo endpoint must
// see the user's real network address — through the tunnel it would see a
// node and answer UNKNOWN. Returns the status and at most 4 KiB of body.
//
// Not used on iOS: the packet-tunnel extension makes no HTTP requests; the
// app fetches whoami itself while the tunnel is down.
func FetchWhoami(ctx context.Context, rawURL, userAgent string) (int, []byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		!strings.HasSuffix(u.Path, whoamiSuffix) {
		return 0, nil, ErrWhoamiURL
	}
	tlsCfg, err := ca.GetTLSConfig(ca.Option{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}})
	if err != nil {
		return 0, nil, err
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:     tlsCfg,
		ForceAttemptHTTP2:   true,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: whoamiTimeout,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: whoamiTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	if ua := strings.TrimSpace(userAgent); ua != "" && len(ua) <= 256 && !strings.ContainsAny(ua, "\r\n") {
		req.Header.Set("User-Agent", ua)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, whoamiMaxBody))
	return resp.StatusCode, body, err
}
