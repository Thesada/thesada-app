package secrets

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"testing"
)

// testKEK returns a valid base64 32-byte KEK for tests.
func testKEK(t *testing.T) string {
	t.Helper()
	b := make([]byte, keyLen)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		t.Fatalf("rand KEK: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestNewKeyring(t *testing.T) {
	if _, err := NewKeyring(testKEK(t)); err != nil {
		t.Fatalf("valid KEK rejected: %v", err)
	}
	cases := map[string]string{
		"empty":      "",
		"not base64": "not!base64!",
		"too short":  base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"too long":   base64.StdEncoding.EncodeToString(make([]byte, 48)),
	}
	for name, kek := range cases {
		if _, err := NewKeyring(kek); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestDEKWrapRoundTrip(t *testing.T) {
	kr, err := NewKeyring(testKEK(t))
	if err != nil {
		t.Fatal(err)
	}
	aad := []byte("tenant-abc")
	dek, err := kr.GenerateDEK()
	if err != nil {
		t.Fatal(err)
	}
	if len(dek) != keyLen {
		t.Fatalf("DEK is %d bytes, want %d", len(dek), keyLen)
	}
	wrapped, err := kr.WrapDEK(dek, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wrapped, dek) {
		t.Fatal("wrapped DEK contains the plaintext DEK")
	}
	got, err := kr.UnwrapDEK(wrapped, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("unwrapped DEK != original")
	}
}

func TestDEKWrapRejectsWrongAADAndTamper(t *testing.T) {
	kr, _ := NewKeyring(testKEK(t))
	dek, _ := kr.GenerateDEK()
	wrapped, _ := kr.WrapDEK(dek, []byte("tenant-abc"))

	if _, err := kr.UnwrapDEK(wrapped, []byte("tenant-xyz")); err == nil {
		t.Error("unwrap with wrong AAD succeeded")
	}
	tampered := bytes.Clone(wrapped)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := kr.UnwrapDEK(tampered, []byte("tenant-abc")); err == nil {
		t.Error("unwrap of tampered blob succeeded")
	}
	// A DEK wrapped under a different KEK must not open under this one.
	other, _ := NewKeyring(testKEK(t))
	otherWrapped, _ := other.WrapDEK(dek, []byte("tenant-abc"))
	if _, err := kr.UnwrapDEK(otherWrapped, []byte("tenant-abc")); err == nil {
		t.Error("unwrap under wrong KEK succeeded")
	}
}

func TestSecretRoundTrip(t *testing.T) {
	kr, _ := NewKeyring(testKEK(t))
	dek, _ := kr.GenerateDEK()
	aad := []byte("tenant-abc/dev-1/wifi.password")
	plain := []byte("hunter2-correct-horse")

	ct, err := EncryptSecret(dek, plain, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, plain) {
		t.Fatal("ciphertext contains plaintext")
	}
	got, err := DecryptSecret(dek, ct, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("decrypted %q, want %q", got, plain)
	}
}

func TestSecretRejectsWrongDEKAADTamper(t *testing.T) {
	kr, _ := NewKeyring(testKEK(t))
	dek, _ := kr.GenerateDEK()
	aad := []byte("tenant-abc/dev-1/wifi.password")
	ct, _ := EncryptSecret(dek, []byte("secret"), aad)

	otherDEK, _ := kr.GenerateDEK()
	if _, err := DecryptSecret(otherDEK, ct, aad); err == nil {
		t.Error("decrypt with wrong DEK succeeded")
	}
	// Wrong AAD = a ciphertext moved to another field/device must not open.
	if _, err := DecryptSecret(dek, ct, []byte("tenant-abc/dev-1/mqtt.password")); err == nil {
		t.Error("decrypt with wrong AAD succeeded")
	}
	tampered := bytes.Clone(ct)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := DecryptSecret(dek, tampered, aad); err == nil {
		t.Error("decrypt of tampered ciphertext succeeded")
	}
}

// Encrypting the same value twice must yield different blobs (fresh nonce),
// so equal secrets are not detectable by equal ciphertext.
func TestNonceIsFreshPerCall(t *testing.T) {
	kr, _ := NewKeyring(testKEK(t))
	dek, _ := kr.GenerateDEK()
	aad := []byte("aad")
	a, _ := EncryptSecret(dek, []byte("same"), aad)
	b, _ := EncryptSecret(dek, []byte("same"), aad)
	if bytes.Equal(a, b) {
		t.Fatal("two encryptions of the same plaintext produced identical blobs")
	}
}

// Empty plaintext is a legitimate value (a secret being cleared); it must
// round-trip rather than panic or return a degenerate blob.
func TestEmptyPlaintextRoundTrips(t *testing.T) {
	kr, _ := NewKeyring(testKEK(t))
	dek, _ := kr.GenerateDEK()
	ct, err := EncryptSecret(dek, []byte{}, []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptSecret(dek, ct, []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d bytes, want 0", len(got))
	}
}
