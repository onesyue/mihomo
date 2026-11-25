package route

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/resolver"
)

func TestClassifyProbeFailureDNSDoesNotCopyTheName(t *testing.T) {
	const secret = "k-secret.example.invalid"
	wrapped := fmt.Errorf("%s connect error: %w", secret, resolver.ErrIPNotFound)
	dnsErr := fmt.Errorf("dial %s: %w", secret, &net.DNSError{Err: "no such host", Name: secret, IsNotFound: true})

	cases := []struct {
		stage string
		err   error
		want  string
	}{
		{stage: "", err: nil, want: "unknown"},
		{stage: "unknown", err: errors.New("timeout"), want: "unknown"},
		{stage: "unknown", err: wrapped, want: "dns"},
		{stage: "tcp_connect", err: dnsErr, want: "dns"},
		{stage: "tcp_connect", err: errors.New("connection refused"), want: "tcp_connect"},
		{stage: "tcp_connect", err: fmt.Errorf("%s: %w", secret, resolver.ErrIPv6Disabled), want: "tcp_connect"},
		{stage: "unknown", err: fmt.Errorf("%s: %w", secret, resolver.ErrIPVersion), want: "unknown"},
		{stage: "tcp_connect", err: fmt.Errorf("%s: %w", secret, context.DeadlineExceeded), want: "tcp_connect"},
		{stage: "tls_handshake", err: dnsErr, want: "tls_handshake"},
		{stage: "vless_first_packet", err: wrapped, want: "vless_first_packet"},
	}
	for _, tc := range cases {
		got := classifyProbeFailure(tc.stage, tc.err)
		if got != tc.want {
			t.Fatalf("stage %q err %v: got %q want %q", tc.stage, tc.err, got, tc.want)
		}
		if strings.Contains(got, secret) || strings.Contains(got, "no such host") {
			t.Fatalf("stage copied the error: %q", got)
		}
	}
}
