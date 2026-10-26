package dns

import (
	"context"
	"net"
	"testing"
	"time"

	D "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// A DNS query already holding a reusable connection must not put it back into
// the pool after refresh. The peer observes closure after its response arrives.
func TestDoTRefreshRetiresInflightConnection(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	require.NoError(t, peer.SetDeadline(time.Now().Add(3*time.Second)))
	c := &dnsOverTLS{}
	c.connections.PushBack(client)
	entered, release := make(chan struct{}), make(chan struct{})
	peerResult := make(chan error, 1)
	go func() {
		conn := &D.Conn{Conn: peer}
		query, err := conn.ReadMsg()
		if err != nil {
			peerResult <- err
			return
		}
		close(entered)
		<-release
		reply := new(D.Msg)
		reply.SetReply(query)
		if err = conn.WriteMsg(reply); err != nil {
			peerResult <- err
			return
		}
		_, err = peer.Read(make([]byte, 1))
		peerResult <- err
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		query := new(D.Msg)
		query.SetQuestion("refresh.test.", D.TypeA)
		_, err := c.ExchangeContext(ctx, query)
		result <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		close(release)
		t.Fatal(ctx.Err())
	}
	c.ResetConnection()
	close(release)
	require.NoError(t, <-result)
	require.Error(t, <-peerResult)
	c.access.Lock()
	remaining := c.connections.Len()
	c.access.Unlock()
	require.Zero(t, remaining)
}
