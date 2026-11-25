//go:build !(android && cmfa)

package dns

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSystemRefreshDiscardsDiscoveryImmediately(t *testing.T) {
	c := newSystemClient()
	server := "192.0.2.1"
	var reads int
	var readErr error
	c.readConfig = func() ([]string, error) { reads++; return []string{server}, readErr }
	first, err := c.getDnsClients()
	require.NoError(t, err)
	require.Len(t, first, 1)
	require.Equal(t, "udp://192.0.2.1:53", first[0].Address())
	server = "192.0.2.2"
	cached, err := c.getDnsClients()
	require.NoError(t, err)
	require.Equal(t, first, cached)
	require.Equal(t, 1, reads)
	c.ResetConnection()
	fresh, err := c.getDnsClients()
	require.NoError(t, err)
	require.Len(t, fresh, 1)
	require.Equal(t, 2, reads)
	require.Equal(t, "udp://192.0.2.2:53", fresh[0].Address())
	readErr = errors.New("discovery unavailable")
	c.ResetConnection()
	fresh, err = c.getDnsClients()
	require.ErrorIs(t, err, readErr)
	require.Empty(t, fresh)
}
