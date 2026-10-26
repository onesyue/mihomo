package tunnel

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

type retirementProxy struct {
	C.Proxy
	retired int
	closed  int
}

func (p *retirementProxy) Adapter() C.ProxyAdapter { return p }
func (p *retirementProxy) RetireAdvisory()         { p.retired++ }
func (p *retirementProxy) Close() error            { p.closed++; return nil }
func TestProxyPublicationRetiresOnlyReplacedAdvice(t *testing.T) {
	oldProxies, oldProviders := proxies, providers
	t.Cleanup(func() { proxies, providers = oldProxies, oldProviders })
	kept, replaced, removed := &retirementProxy{}, &retirementProxy{}, &retirementProxy{}
	proxies = map[string]C.Proxy{"kept": kept, "replaced": replaced, "removed": removed}
	successor := &retirementProxy{}
	UpdateProxies(map[string]C.Proxy{"kept": kept, "replaced": successor}, nil)
	require.Zero(t, kept.retired)
	require.Equal(t, 1, replaced.retired)
	require.Equal(t, 1, removed.retired)
	require.Zero(t, successor.retired)
	require.Zero(t, kept.closed+replaced.closed+removed.closed+successor.closed)
}
