package inbound_test

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/listener/inbound"
	"github.com/stretchr/testify/require"
)

// Keep the actual TLS, Salamander, authentication and HTTP/HTTPS transports.
// This UDP relay only models a router dropping oversized DF datagrams in both
// directions. The limits are the UDP budgets of 1280-byte IPv4/IPv6 paths.
func TestInboundHysteria2_MinimumPathMTU(t *testing.T) {
	for _, test := range []struct {
		name    string
		maximum int
	}{{"IPv4", 1252}, {"IPv6", 1232}} {
		t.Run(test.name, func(t *testing.T) {
			testInboundHysteria2(t, inbound.Hysteria2Option{
				Certificate: tlsCertificate, PrivateKey: tlsPrivateKey,
				Obfs: "salamander", ObfsPassword: userUUID,
			}, outbound.Hysteria2Option{
				Fingerprint: tlsFingerprint, Obfs: "salamander", ObfsPassword: userUUID,
			}, test.maximum)
		})
	}
}

func boundedHysteriaDatagramRelay(t *testing.T, destination netip.AddrPort, maximum int) netip.AddrPort {
	t.Helper()
	front, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	back, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(destination))
	require.NoError(t, err)
	var peer *net.UDPAddr
	var peerLock sync.Mutex
	var dropped atomic.Int64
	var running sync.WaitGroup
	running.Add(2)
	go func() {
		defer running.Done()
		buffer := make([]byte, 65535)
		for {
			n, address, err := front.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			if n > maximum {
				dropped.Add(1)
				continue
			}
			peerLock.Lock()
			peer = address
			peerLock.Unlock()
			if _, err = back.Write(buffer[:n]); err != nil {
				return
			}
		}
	}()
	go func() {
		defer running.Done()
		buffer := make([]byte, 65535)
		for {
			n, err := back.Read(buffer)
			if err != nil {
				return
			}
			if n > maximum {
				dropped.Add(1)
				continue
			}
			peerLock.Lock()
			address := peer
			peerLock.Unlock()
			if address != nil {
				if _, err = front.WriteToUDP(buffer[:n], address); err != nil {
					return
				}
			}
		}
	}()
	t.Cleanup(func() {
		_ = front.Close()
		_ = back.Close()
		running.Wait()
		t.Logf("maximum wire UDP=%d, oversized datagrams dropped=%d", maximum, dropped.Load())
	})
	return front.LocalAddr().(*net.UDPAddr).AddrPort()
}

// A listener is either ready or returns a startup error. Closing it immediately
// must not race a deferred native Service.Start assigning its QUIC listener.
func TestInboundHysteria2StartupImmediateClose(t *testing.T) {
	for range 20 {
		listener, err := inbound.NewHysteria2(&inbound.Hysteria2Option{
			BaseOption:  inbound.BaseOption{NameStr: "hysteria2_startup", Listen: "127.0.0.1", Port: "0"},
			Certificate: tlsCertificate, PrivateKey: tlsPrivateKey, Users: map[string]string{"test": userUUID},
		})
		require.NoError(t, err)
		tunnel := NewHttpTestTunnel()
		require.NoError(t, listener.Listen(tunnel))
		require.NoError(t, listener.Close())
		require.NoError(t, tunnel.Close())
	}
}
