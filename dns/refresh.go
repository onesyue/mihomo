package dns

import (
	"context"
	"fmt"

	"github.com/metacubex/mihomo/component/resolver"
)

// RefreshDNS invalidates DNS caches and reusable upstream transports. It does
// not query the network or claim DNS availability. OS discovery is invalidated
// synchronously and is performed on the next lookup. Old in-flight answers
// cannot populate the new cache generation or join its singleflight requests.
func (r *Resolver) RefreshDNS(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	r.ClearCache()
	// Also fence requests that started during transport retirement.
	defer r.ClearCache()
	clients := append(append([]dnsClient{}, r.main...), r.fallback...)
	for _, policy := range r.policy {
		switch p := policy.(type) {
		case domainTriePolicy:
			p.Foreach(func(_ string, data []dnsClient) bool { clients = append(clients, data...); return true })
		case domainMatcherPolicy:
			clients = append(clients, p.dnsClients...)
		default:
			return resolver.ErrDNSRefreshUnsupported
		}
	}
	for _, c := range clients {
		if err := ctx.Err(); err != nil {
			return err
		}
		for {
			u, ok := c.(interface{ Unwrap() dnsClient })
			if !ok {
				break
			}
			c = u.Unwrap()
		}
		// DHCP discovery has an independent asynchronous lifetime. Refuse to report
		// completion until that transport exposes a generation-aware refresh API.
		if _, ok := c.(*dhcpClient); ok {
			return fmt.Errorf("DHCP: %w", resolver.ErrDNSRefreshUnsupported)
		}
		c.ResetConnection()
	}
	if err := r.defaultResolver.RefreshDNS(ctx); err != nil {
		return err
	}
	return ctx.Err()
}

func (rs Resolvers) RefreshDNS(ctx context.Context) error {
	for _, r := range []*Resolver{rs.Resolver, rs.ProxyResolver, rs.DirectResolver} {
		if err := r.RefreshDNS(ctx); err != nil {
			return err
		}
	}
	return ctx.Err()
}
