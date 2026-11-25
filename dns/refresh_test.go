package dns

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/component/trie"
	D "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type refreshClient struct{ resets atomic.Int32 }

func (c *refreshClient) Address() string                                         { return "fixture" }
func (c *refreshClient) ResetConnection()                                        { c.resets.Add(1) }
func (c *refreshClient) ExchangeContext(context.Context, *D.Msg) (*D.Msg, error) { panic("unused") }

func TestRefreshDNSIncludesPolicyAndBootstrap(t *testing.T) {
	main, fallback, policy, bootstrap := new(refreshClient), new(refreshClient), new(refreshClient), new(refreshClient)
	tr := trie.New[[]dnsClient]()
	require.NoError(t, tr.Insert("example.test", []dnsClient{policy}))
	r := &Resolver{main: []dnsClient{main}, fallback: []dnsClient{fallback}, policy: []dnsPolicy{domainTriePolicy{tr}}, defaultResolver: &Resolver{main: []dnsClient{bootstrap}}}
	require.NoError(t, r.RefreshDNS(t.Context()))
	for _, c := range []*refreshClient{main, fallback, policy, bootstrap} {
		require.EqualValues(t, 1, c.resets.Load())
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, r.RefreshDNS(ctx), context.Canceled)
	for _, c := range []*refreshClient{main, fallback, policy, bootstrap} {
		require.EqualValues(t, 1, c.resets.Load())
	}
}

func TestRefreshDNSRejectsUnfencedDHCP(t *testing.T) {
	r := NewResolverFromClient(newDHCPClient("fixture"))
	require.ErrorIs(t, r.RefreshDNS(t.Context()), resolver.ErrDNSRefreshUnsupported)
}

func TestRefreshDNSRealConsumerFencesInflightAnswers(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	entered, release := make(chan struct{}), make(chan struct{})
	var requests atomic.Int32
	server := &D.Server{PacketConn: pc, Handler: D.HandlerFunc(func(w D.ResponseWriter, req *D.Msg) {
		n := requests.Add(1)
		if n == 1 {
			close(entered)
			<-release
		}
		answer := new(D.Msg)
		answer.SetReply(req)
		ip := net.IPv4(192, 0, 2, byte(n))
		answer.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: req.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: ip}}
		_ = w.WriteMsg(answer)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	r := NewResolver(Config{Main: []NameServer{{Net: "udp", Addr: pc.LocalAddr().String()}}})
	query := new(D.Msg)
	query.SetQuestion("refresh.test.", D.TypeA)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	oldDone := make(chan error, 1)
	go func() { _, err := r.ExchangeContext(ctx, query.Copy()); oldDone <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	require.NoError(t, r.RefreshDNS(ctx))
	fresh, err := r.ExchangeContext(ctx, query.Copy())
	require.NoError(t, err)
	require.Equal(t, "192.0.2.2", fresh.Answer[0].(*D.A).A.String())
	close(release)
	require.NoError(t, <-oldDone)
	fresh, err = r.ExchangeContext(ctx, query.Copy())
	require.NoError(t, err)
	require.Equal(t, "192.0.2.2", fresh.Answer[0].(*D.A).A.String())
	require.EqualValues(t, 2, requests.Load())
	// Thirty refreshes must invalidate actual answers without restarting a stream.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	streamDone := make(chan error, 1)
	go func() {
		for i := 0; i < 30; i++ {
			_, err := b.Write([]byte{byte(i)})
			if err != nil {
				streamDone <- err
				return
			}
		}
		streamDone <- nil
	}()
	require.NoError(t, a.SetReadDeadline(time.Now().Add(5*time.Second)))
	for i := 0; i < 30; i++ {
		require.NoError(t, r.RefreshDNS(ctx))
		_, err := r.ExchangeContext(ctx, query.Copy())
		require.NoError(t, err)
		data := make([]byte, 1)
		_, err = a.Read(data)
		require.NoError(t, err)
		require.Equal(t, byte(i), data[0])
	}
	require.NoError(t, <-streamDone)
	require.EqualValues(t, 32, requests.Load())
}
