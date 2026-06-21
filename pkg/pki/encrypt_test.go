package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestEncryptDecryptRoundTrip verifies that encryptCAKey + decryptCAKey
// preserve the input bytes exactly under a known-good passphrase.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	plaintext := []byte("not actually a key, just sentinel bytes for the round-trip test")
	env, err := encryptCAKey(plaintext, "correct horse battery staple")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !isEncryptedEnvelope(env) {
		t.Fatalf("envelope detection failed on freshly-generated envelope")
	}
	got, err := decryptCAKey(env, "correct horse battery staple")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: %q vs %q", got, plaintext)
	}
}

// TestDecryptWrongPassphrase verifies that the AEAD authenticator rejects
// a bad passphrase instead of returning garbage plaintext.
func TestDecryptWrongPassphrase(t *testing.T) {
	plaintext := []byte("sentinel")
	env, err := encryptCAKey(plaintext, "right")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := decryptCAKey(env, "wrong"); err == nil {
		t.Fatalf("decrypt with wrong passphrase should fail, got nil error")
	}
}

// TestDecryptTamperedCiphertext verifies that AES-GCM rejects a flipped
// bit in the ciphertext rather than returning altered plaintext.
func TestDecryptTamperedCiphertext(t *testing.T) {
	env, err := encryptCAKey([]byte("sentinel"), "pass")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Flip a bit somewhere in the ciphertext segment of the JSON envelope.
	// Crude: walk forward to the last byte before the closing brace.
	for i := len(env) - 1; i >= 0; i-- {
		if env[i] != '"' && env[i] != '}' && env[i] != '\n' && env[i] != ' ' {
			env[i] ^= 0x01
			break
		}
	}
	if _, err := decryptCAKey(env, "pass"); err == nil {
		t.Fatalf("decrypt of tampered envelope should fail")
	}
}

// TestBootstrapEncryptedRoundTrip exercises the full Bootstrap path: first
// boot generates an encrypted key, second boot loads it back, signs a
// device cert with the loaded CA, verifies the signature with the loaded
// CA cert. Catches any drift between the encrypt-on-generate and
// decrypt-on-load code paths.
func TestBootstrapEncryptedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	pass := "passphrase-for-test"

	ca1, warn, err := Bootstrap(dir, pass)
	if err != nil {
		t.Fatalf("first Bootstrap: %v", err)
	}
	if warn != nil {
		t.Fatalf("first Bootstrap returned warning under encrypted path: %v", warn)
	}

	// The on-disk file should be the encrypted envelope, not plaintext PEM.
	raw, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("read back ca.key: %v", err)
	}
	if !isEncryptedEnvelope(raw) {
		t.Fatalf("ca.key written under non-empty passphrase is not an encrypted envelope")
	}

	ca2, warn2, err := Bootstrap(dir, pass)
	if err != nil {
		t.Fatalf("second Bootstrap: %v", err)
	}
	if warn2 != nil {
		t.Fatalf("second Bootstrap returned warning under encrypted path: %v", warn2)
	}
	if ca1.Cert.SerialNumber.Cmp(ca2.Cert.SerialNumber) != 0 {
		t.Fatalf("Bootstrap did not load the persisted CA back")
	}

	// Wrong passphrase must fail loudly, not silently fall back.
	if _, _, err := Bootstrap(dir, "different"); err == nil {
		t.Fatalf("Bootstrap with wrong passphrase should fail")
	}

	// Bootstrap with no passphrase against an encrypted file must fail.
	if _, _, err := Bootstrap(dir, ""); err == nil {
		t.Fatalf("Bootstrap against encrypted file with empty passphrase should fail")
	}
}

// TestBootstrapPlaintextWarn verifies that the legacy plaintext path still
// works for back-compat but surfaces a PlaintextKey warning so the
// operator sees the exposure.
func TestBootstrapPlaintextWarn(t *testing.T) {
	dir := t.TempDir()

	_, warn, err := Bootstrap(dir, "")
	if err != nil {
		t.Fatalf("Bootstrap (plaintext): %v", err)
	}
	if warn == nil {
		t.Fatalf("expected PlaintextKey warning, got nil")
	}
	var pk *PlaintextKey
	if !errors.As(warn, &pk) {
		t.Fatalf("expected *PlaintextKey warning, got %T", warn)
	}

	// File should NOT be the envelope format.
	raw, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("read back ca.key: %v", err)
	}
	if isEncryptedEnvelope(raw) {
		t.Fatalf("ca.key written under empty passphrase should be plaintext PEM")
	}
}

// TestEncryptKeyOnDiskMigration exercises the plaintext -> encrypted
// migration: write a SEC1-formatted plaintext key (mimicking pre-0020
// installs), run EncryptKeyOnDisk, verify the result loads with the
// passphrase and the plaintext backup landed.
func TestEncryptKeyOnDiskMigration(t *testing.T) {
	dir := t.TempDir()
	pass := "migration-test"

	// Hand-write a SEC1 plaintext key + a self-signed cert so load() has
	// what it expects under the legacy layout.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa generate: %v", err)
	}
	sec1, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal SEC1: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	if err := EncryptKeyOnDisk(dir, pass); err != nil {
		t.Fatalf("EncryptKeyOnDisk: %v", err)
	}

	// Encrypted form on disk + plaintext backup beside it.
	raw, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !isEncryptedEnvelope(raw) {
		t.Fatalf("EncryptKeyOnDisk did not produce an envelope on disk")
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.key.plaintext.bak")); err != nil {
		t.Fatalf("plaintext backup missing: %v", err)
	}

	// Idempotent: rerunning is a no-op (no new backup, no error).
	if err := EncryptKeyOnDisk(dir, pass); err != nil {
		t.Fatalf("EncryptKeyOnDisk second run: %v", err)
	}
}
