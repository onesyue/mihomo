package age

import (
	"bytes"
	"testing"
)

func TestDecryptBytesEmptyProviderKey(t *testing.T) {
	secret, public, err := GenX25519KeyPair()
	if err != nil {
		t.Fatal("generate test identity failed")
	}
	plaintext := []byte("test provider data")
	ciphertext, err := EncryptBytes(plaintext, public)
	if err != nil {
		t.Fatal("encrypt test provider failed")
	}
	saved := append([]string(nil), globalSecretKeys...)
	defer SetGlobalSecretKeys(saved...)
	for _, tt := range []struct {
		name      string
		local     []string
		global    []string
		wantError bool
	}{
		{name: "empty local uses global", local: []string{""}, global: []string{secret}},
		{name: "empty local before valid local", local: []string{"", secret}},
		{name: "invalid nonempty local still fails", local: []string{"invalid-identity"}, global: []string{secret}, wantError: true},
		{name: "empty local without global still fails", local: []string{""}, wantError: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			SetGlobalSecretKeys(tt.global...)
			got, err := DecryptBytes(ciphertext, tt.local...)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected identity failure")
				}
				return
			}
			if err != nil {
				t.Fatal("valid identity did not decrypt provider")
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatal("decrypted provider bytes changed")
			}
		})
	}
}
