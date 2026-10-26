//go:build reliability_protocol

package outboundgroup

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	A "github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/dialattempt"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/sing-quic/hysteria2"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	mtls "github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

const protocolProbe = "http://fixture.invalid/health"
const fixtureUUID = "00000000-0000-4000-8000-000000000001"

type fixtureProvider struct {
	*advisoryProvider
	checks atomic.Int32
}

func (p *fixtureProvider) HealthCheck() { p.checks.Add(1) }

type countingProtocolProxy struct {
	C.Proxy
	dials atomic.Int32
}

func (p *countingProtocolProxy) DialContext(ctx context.Context, m *C.Metadata) (C.Conn, error) {
	p.dials.Add(1)
	return p.Proxy.DialContext(ctx, m)
}
func startRealityFixture(t *testing.T) C.Proxy {
	t.Helper()
	path := os.Getenv("YUELINK_REALITY_FIXTURE")
	require.NotEmpty(t, path, "build testdata/realityfixture and supply its binary")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	cmd := exec.CommandContext(ctx, path)
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = stdin.Close()
		err := cmd.Wait()
		cancel()
		require.NoError(t, err, "helper: %s", stderr.String())
		if t.Failed() {
			t.Logf("helper diagnostics: %s", stderr.String())
		}
	})
	var config struct {
		Address   string `json:"address"`
		PublicKey string `json:"public_key"`
		ShortID   string `json:"short_id"`
	}
	require.NoError(t, json.NewDecoder(stdout).Decode(&config))
	host, port, err := net.SplitHostPort(config.Address)
	require.NoError(t, err)
	number, err := strconv.Atoi(port)
	require.NoError(t, err)
	native, err := A.ParseProxy(map[string]any{"name": "reality", "type": "vless", "server": host, "port": number, "uuid": fixtureUUID, "tls": true, "servername": "fixture.invalid", "client-fingerprint": "chrome", "reality-opts": map[string]any{"public-key": config.PublicKey, "short-id": config.ShortID}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = native.Close() })
	return native
}
func measureProtocol(t *testing.T, p C.Proxy) {
	t.Helper()
	status, err := utils.NewUnsignedRanges[uint16]("204")
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	_, err = p.URLTest(ctx, protocolProbe, status)
	require.NoError(t, err)
	require.True(t, p.AliveForTestUrl(protocolProbe))
	require.Positive(t, p.LastDelayForTestUrl(protocolProbe))
}
func protocolEcho(t *testing.T, c C.Conn) {
	t.Helper()
	require.NoError(t, c.SetDeadline(time.Now().Add(3*time.Second)))
	payload := []byte("application-data-once\n")
	_, err := c.Write(payload)
	require.NoError(t, err)
	reply := make([]byte, len(payload))
	_, err = io.ReadFull(c, reply)
	require.NoError(t, err)
	require.Equal(t, payload, reply)
}
func newProtocolGroup(t *testing.T, kind string, retry bool, members ...C.Proxy) testAdvisoryGroup {
	t.Helper()
	provider := &fixtureProvider{advisoryProvider: &advisoryProvider{&measuredProvider{proxies: members, version: 1}}}
	option := GroupCommonOption{Name: "auto", URL: protocolProbe, ExpectedStatus: "204", AdvisoryRetry: retry}
	if kind == "url-test" {
		g, e := NewURLTest(option, URLTestOption{Tolerance: 50}, members[0], []P.ProxyProvider{provider})
		require.NoError(t, e)
		return g
	}
	g, e := NewFallback(option, FallbackOption{}, members[0], []P.ProxyProvider{provider})
	require.NoError(t, e)
	return g
}
func deadVLESS(t *testing.T) C.Proxy {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, e)
	port := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())
	v, e := A.ParseProxy(map[string]any{"name": "refused", "type": "vless", "server": "127.0.0.1", "port": port, "uuid": fixtureUUID})
	require.NoError(t, e)
	return &measuredProxy{Proxy: v, name: "refused", delay: 1, alive: true}
}
func TestProtocolRealityRecoveryThirtyPairs(t *testing.T) {
	reality := &countingProtocolProxy{Proxy: startRealityFixture(t)}
	measureProtocol(t, reality)
	existing, err := reality.DialContext(t.Context(), &C.Metadata{NetWork: C.TCP, Host: "echo.invalid", DstPort: 443})
	require.NoError(t, err)
	defer existing.Close()
	protocolEcho(t, existing)
	for _, kind := range []string{"url-test", "fallback"} {
		t.Run(kind, func(t *testing.T) {
			failed := &countingProtocolProxy{Proxy: deadVLESS(t)}
			control := newProtocolGroup(t, kind, false, failed, reality)
			candidate := newProtocolGroup(t, kind, true, failed, reality)
			require.Equal(t, "refused", candidate.Now(), "establish the healthy incumbent before advising a recovery candidate")
			lease := advisoryLease(candidate, "reality")
			lease.Retry = true
			require.NoError(t, candidate.SetAdvisory(t.Context(), lease))
			before := reality.dials.Load()
			controlMS := make([]float64, 0, 30)
			candidateMS := make([]float64, 0, 30)
			for pair := range 30 {
				for arm := range 2 {
					experimental := (pair+arm)%2 == 1
					group := control
					if experimental {
						group = candidate
					}
					ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
					started := time.Now()
					conn, err := group.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "echo.invalid", DstPort: 443})
					cancel()
					if experimental {
						require.NoError(t, err)
						protocolEcho(t, conn)
						candidateMS = append(candidateMS, float64(time.Since(started))/float64(time.Millisecond))
						require.NoError(t, conn.Close())
					} else {
						require.Error(t, err)
						require.True(t, dialattempt.ProvenBeforeApplicationData(err))
						require.Nil(t, conn)
						controlMS = append(controlMS, float64(time.Since(started))/float64(time.Millisecond))
					}
				}
				protocolEcho(t, existing)
			}
			require.Equal(t, int32(30), reality.dials.Load()-before)
			require.Equal(t, int32(60), failed.dials.Load())
			sample, err := json.Marshal(map[string]any{"consumer": kind, "pairs": 30, "control_success": 0, "candidate_success": 30, "primary_dials": failed.dials.Load(), "alternate_dials": reality.dials.Load() - before, "existing_stream_failures": 0, "control_failure_ms": controlMS, "candidate_first_echo_ms": candidateMS})
			require.NoError(t, err)
			t.Logf("RECOVERY_PAIR %s", sample)
		})
	}
}

type hyFixtureHandler struct{ connections atomic.Int32 }

func (h *hyFixtureHandler) NewConnection(_ context.Context, c net.Conn, _ M.Metadata) error {
	h.connections.Add(1)
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	r := bufio.NewReader(c)
	prefix, e := r.Peek(4)
	if e != nil {
		return e
	}
	if string(prefix) == "HEAD" {
		for {
			req, e := http.ReadRequest(r)
			if e != nil {
				return e
			}
			_ = req.Body.Close()
			time.Sleep(3 * time.Millisecond)
			_, e = c.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"))
			if e != nil {
				return e
			}
		}
	}
	_, e = io.Copy(c, r)
	return e
}
func (*hyFixtureHandler) NewPacketConnection(_ context.Context, c N.PacketConn, _ M.Metadata) error {
	return c.Close()
}

// The server API and digest pin follow Link TestSubscriptionHysteria2ObfsRoundTrip.
// This fixture adds fault boundaries; the existing obfuscation round trips are reused.
func startHYFixture(t *testing.T) (C.Proxy, *hyFixtureHandler) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, e)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"fixture.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, e)
	keyDER, e := x509.MarshalECPrivateKey(key)
	require.NoError(t, e)
	cert, e := mtls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	require.NoError(t, e)
	handler := &hyFixtureHandler{}
	service, e := hysteria2.NewService[string](hysteria2.ServiceOptions{Context: t.Context(), Logger: logger.NOP(), TLSConfig: &mtls.Config{Certificates: []mtls.Certificate{cert}}, Handler: handler, UDPTimeout: time.Second, IgnoreClientBandwidth: true})
	require.NoError(t, e)
	service.UpdateUsers([]string{"fixture"}, []string{"test-password"})
	socket, e := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, e)
	require.NoError(t, service.Start(socket))
	t.Cleanup(func() { _ = service.Close(); _ = socket.Close() })
	native, e := outbound.NewHysteria2(outbound.Hysteria2Option{Name: "hy2", Server: "127.0.0.1", Port: socket.LocalAddr().(*net.UDPAddr).Port, Password: "test-password", SNI: "fixture.invalid", Fingerprint: fmt.Sprintf("%x", sha256.Sum256(der))})
	require.NoError(t, e)
	t.Cleanup(func() { _ = native.Close() })
	return A.NewProxy(native), handler
}
func TestProtocolHY2PortFailureAndTCPBaseline(t *testing.T) {
	hy, handler := startHYFixture(t)
	measureProtocol(t, hy)
	reality := startRealityFixture(t)
	measureProtocol(t, reality)
	existing, e := hy.DialContext(t.Context(), &C.Metadata{NetWork: C.TCP, Host: "echo.invalid", DstPort: 443})
	require.NoError(t, e)
	defer existing.Close()
	protocolEcho(t, existing)
	blackhole, e := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, e)
	defer blackhole.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 2048)
		for {
			if _, _, err := blackhole.ReadFrom(buffer); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = blackhole.Close(); <-done })
	bad, e := outbound.NewHysteria2(outbound.Hysteria2Option{Name: "blocked-udp", Server: "127.0.0.1", Port: blackhole.LocalAddr().(*net.UDPAddr).Port, Password: "test-password", SkipCertVerify: true})
	require.NoError(t, e)
	defer bad.Close()
	blocked := A.NewProxy(bad)
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	_, e = blocked.URLTest(ctx, protocolProbe, nil)
	cancel()
	require.Error(t, e)
	require.False(t, blocked.AliveForTestUrl(protocolProbe))
	require.False(t, supportsSafeDialRetry(blocked), "HY2 remains outside retry proof")
	for _, kind := range []string{"url-test", "fallback"} {
		t.Run(kind, func(t *testing.T) {
			group := newProtocolGroup(t, kind, false, blocked, reality, hy)
			lease := advisoryLease(group, "reality")
			require.NoError(t, group.SetAdvisory(t.Context(), lease))
			require.Equal(t, "reality", group.Now())
			c, e := group.DialContext(t.Context(), &C.Metadata{NetWork: C.TCP, Host: "echo.invalid", DstPort: 443})
			require.NoError(t, e)
			protocolEcho(t, c)
			_ = c.Close()
			protocolEcho(t, existing)
		})
	}
	require.GreaterOrEqual(t, handler.connections.Load(), int32(2))
	// A target-only UDP failure does not grant TCP retry or close a shared HY2 session.
	packet, e := hy.ListenPacketContext(t.Context(), &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: 443})
	require.NoError(t, e)
	require.NoError(t, packet.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
	_, e = packet.WriteTo([]byte("unreplayed-quic"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})
	require.NoError(t, e)
	_, _, e = packet.ReadFrom(make([]byte, 128))
	require.Error(t, e)
	_ = packet.Close()
	protocolEcho(t, existing)
}
