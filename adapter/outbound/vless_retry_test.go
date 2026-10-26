package outbound

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/dialattempt"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/require"
)

func TestVLESSRetryProofNativeConnectOnly(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())
	options := VlessOption{Name: "proof", Server: "127.0.0.1", Port: port, UUID: "00000000-0000-4000-8000-000000000001"}
	v, err := NewVless(options)
	require.NoError(t, err)
	defer v.Close()
	require.True(t, v.SupportsSafeDialRetry())
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, err = v.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "fixture.invalid", DstPort: 443})
	require.Error(t, err)
	require.True(t, dialattempt.ProvenBeforeApplicationData(err))
	for _, change := range []func(*VlessOption){func(o *VlessOption) { o.TFO = true }, func(o *VlessOption) { o.MPTCP = true }, func(o *VlessOption) { o.DialerProxy = "chain" }, func(o *VlessOption) { o.DialerForAPI = v.dialer }, func(o *VlessOption) { o.Network = "ws" }, func(o *VlessOption) { o.Network = "grpc" }, func(o *VlessOption) { o.Network = "xhttp" }} {
		copy := options
		change(&copy)
		testAdapter := &Vless{option: &copy}
		require.False(t, testAdapter.SupportsSafeDialRetry())
	}
	wrapped := NewAutoCloseProxyAdapter(v)
	require.True(t, wrapped.(interface{ SupportsSafeDialRetry() bool }).SupportsSafeDialRetry())
}
func TestVLESSTLSFailureDoesNotCarryConnectProof(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := listener.Accept()
		if e == nil {
			defer c.Close()
			_, _ = c.Write([]byte("invalid TLS reply"))
		}
	}()
	v, err := NewVless(VlessOption{Name: "tls", Server: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, UUID: "00000000-0000-4000-8000-000000000001", TLS: true, SkipCertVerify: true})
	require.NoError(t, err)
	defer v.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, err = v.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Host: "fixture.invalid", DstPort: 443})
	require.Error(t, err)
	require.False(t, dialattempt.ProvenBeforeApplicationData(err))
	<-done
}
