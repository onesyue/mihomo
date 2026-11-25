package route

import (
	"errors"
	"net"

	"github.com/metacubex/mihomo/component/resolver"
)

// classifyProbeFailure keeps the closed stage from an in-flight URL test and
// reports dns when the entry name never resolved.
//
// probestage.Begin marks tcp_connect before dial on the VLESS WebSocket path,
// so a DNS failure of that entry would otherwise look like a TCP failure.
// A stage past tcp_connect means the dial already passed name resolution.
// The returned value is only the closed enum; the error text, which can
// contain the dial address, is never copied.
func classifyProbeFailure(stage string, err error) string {
	if stage == "" {
		stage = "unknown"
	}
	if (stage == "unknown" || stage == "tcp_connect") && entryDNSFailure(err) {
		return "dns"
	}
	return stage
}

func entryDNSFailure(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	return errors.Is(err, resolver.ErrIPNotFound)
}
