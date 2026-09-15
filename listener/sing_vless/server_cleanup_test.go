package sing_vless

import (
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"

	LC "github.com/metacubex/mihomo/listener/config"
)

func TestDecryptionCleanupAfterCertificateFailure(t *testing.T) {
	// A real decryption instance is allocated before TLS certificate loading.
	// Returning nil, err must close that instance without dereferencing the
	// named listener result, which has already become nil at this point.
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	config := LC.VlessServer{
		Decryption:  "mlkem768x25519plus.native.600s." + key,
		Certificate: filepath.Join(t.TempDir(), "missing.crt"),
		PrivateKey:  filepath.Join(t.TempDir(), "missing.key"),
	}
	listener, err := New(config, nil, nil)
	if listener != nil {
		_ = listener.Close()
		t.Fatal("invalid certificate unexpectedly started a listener")
	}
	if err == nil || !strings.Contains(err.Error(), "missing.crt") {
		t.Fatalf("expected certificate error, got %v", err)
	}
}
