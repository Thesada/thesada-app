// encrypt.go - CA private-key encryption at rest.
//
// Without a passphrase the CA private key sits as plaintext PEM on disk
// (mode 0600, parent dir 0700). Anyone with filesystem read access -
// operator with sudo, the nightly backup process, a container escape, a
// sidecar that mounts the same volume - walks away with the CA. CA
// compromise = forge client certs for any device CN in any tenant,
// bypass dynsec ACL, impersonate devices.
//
// When THESADA_CA_KEY_PASSPHRASE is set, Bootstrap writes the CA key as
// an encrypted envelope instead. The passphrase is never persisted; it
// lives in env (sourced from a sealed-secrets / systemd Credential /
// kubernetes Secret etc) and is consumed at boot. The encrypted file is
// safe to back up - a stolen backup is not enough to forge certs without
// the passphrase. It does NOT defend against a live-server compromise
// (the decrypted key is in memory after boot) - that is the long-term
// KMS path documented in docs/security.md.
//
// Envelope: JSON file starting with the magic "THESADA-CAKEY-V1". scrypt
// derives a 32-byte key from the passphrase + a random salt; AES-256-GCM
// encrypts the PKCS#8-marshaled CA private key. Parameters live in the
// envelope so we can rotate to argon2id or stronger scrypt params later
// without breaking on-disk format compatibility.
package pki

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/scrypt"
)

// envelopeMagic prefixes every encrypted-CA-key file so plaintext PEM
// loaders can detect the new format and fail loudly instead of trying to
// PEM-decode a JSON blob.
const envelopeMagic = "THESADA-CAKEY-V1"

// scrypt parameters: ~64 MiB / ~200 ms on commodity hardware as of
// 2026. Rotate by bumping these + the envelope version when commodity
// CPUs make these too cheap. Decryption reads N/R/P from the envelope
// so older files keep loading.
const (
	scryptN = 1 << 15 // 32768
	scryptR = 8
	scryptP = 1
)

// caKeyEnvelope is the on-disk shape of the encrypted CA key. JSON for
// human inspectability and forward-compatible field add.
type caKeyEnvelope struct {
	Magic      string `json:"magic"`
	KDF        string `json:"kdf"`
	ScryptN    int    `json:"scrypt_n"`
	ScryptR    int    `json:"scrypt_r"`
	ScryptP    int    `json:"scrypt_p"`
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// encryptCAKey wraps the marshaled CA private key bytes in an envelope
// encrypted under a scrypt-derived AES-256-GCM key. The plaintext bytes
// are PKCS#8 ("PRIVATE KEY") so the format survives a future swap of
// EC P-256 for Ed25519 without breaking the envelope shape.
// in: PKCS#8 plaintext key bytes, passphrase. out: JSON envelope bytes, error.
func encryptCAKey(plaintext []byte, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("encryptCAKey: empty passphrase")
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}
	dk, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, 32)
	if err != nil {
		return nil, fmt.Errorf("scrypt: %w", err)
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)

	env := caKeyEnvelope{
		Magic:      envelopeMagic,
		KDF:        "scrypt",
		ScryptN:    scryptN,
		ScryptR:    scryptR,
		ScryptP:    scryptP,
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: ct,
	}
	return json.MarshalIndent(env, "", "  ")
}

// decryptCAKey reverses encryptCAKey. Reads the envelope, re-derives the
// AES-GCM key with the envelope's scrypt parameters, decrypts, and
// returns the plaintext PKCS#8 bytes. A bad passphrase or tampered
// envelope surface as the AES-GCM authentication error, not a plaintext
// returned with garbage bytes.
// in: envelope JSON bytes, passphrase. out: PKCS#8 plaintext, error.
func decryptCAKey(envBytes []byte, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, errors.New("decryptCAKey: empty passphrase")
	}
	var env caKeyEnvelope
	if err := json.Unmarshal(envBytes, &env); err != nil {
		return nil, fmt.Errorf("envelope unmarshal: %w", err)
	}
	if env.Magic != envelopeMagic {
		return nil, fmt.Errorf("envelope magic mismatch: %q", env.Magic)
	}
	if env.KDF != "scrypt" {
		return nil, fmt.Errorf("envelope KDF unsupported: %q", env.KDF)
	}
	dk, err := scrypt.Key([]byte(passphrase), env.Salt, env.ScryptN, env.ScryptR, env.ScryptP, 32)
	if err != nil {
		return nil, fmt.Errorf("scrypt: %w", err)
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	pt, err := gcm.Open(nil, env.Nonce, env.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return pt, nil
}

// isEncryptedEnvelope returns true if the file bytes look like one of
// our JSON envelopes (the magic prefix is present). Used by load() to
// switch between plaintext-PEM and envelope decryption paths.
// in: raw file bytes. out: true if envelope.
func isEncryptedEnvelope(b []byte) bool {
	// Quick check: file starts with '{' and contains the magic. Avoids
	// trying to JSON-parse a multi-KB PEM blob.
	if len(b) == 0 || b[0] != '{' {
		return false
	}
	return bytesContainsString(b, envelopeMagic)
}

// EncryptKeyOnDisk rewrites the CA key file from plaintext PEM to the
// THESADA-CAKEY-V1 encrypted envelope. The plaintext form is preserved
// as <keyPath>.plaintext.bak so the operator can roll back if anything
// goes wrong before deleting it once the encrypted load is verified.
// Idempotent: an already-encrypted file is left alone and the function
// returns nil. An empty passphrase is rejected so this cannot
// accidentally generate a re-savable plaintext output.
// in: CA directory, passphrase. out: error (nil on success or no-op).
func EncryptKeyOnDisk(dir, passphrase string) error {
	if passphrase == "" {
		return errors.New("EncryptKeyOnDisk: THESADA_CA_KEY_PASSPHRASE is empty")
	}
	cleanDir, err := sanitizeCADir(dir)
	if err != nil {
		return err
	}
	keyPath := filepath.Join(cleanDir, "ca.key")
	raw, err := os.ReadFile(keyPath) // #nosec G304 -- path is sanitizeCADir(operator env)
	if err != nil {
		return fmt.Errorf("read CA key: %w", err)
	}
	if isEncryptedEnvelope(raw) {
		return nil
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return errors.New("CA key: no PEM block found")
	}
	// Re-marshal to PKCS#8 if the on-disk form is SEC1 so the encrypted
	// envelope always carries the same inner format.
	var pkcs8 []byte
	switch block.Type {
	case "PRIVATE KEY":
		pkcs8 = block.Bytes
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse SEC1 key: %w", err)
		}
		pkcs8, err = x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return fmt.Errorf("marshal PKCS8: %w", err)
		}
	default:
		return fmt.Errorf("unsupported PEM type: %q", block.Type)
	}
	envelope, err := encryptCAKey(pkcs8, passphrase)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	backup := filepath.Join(cleanDir, "ca.key.plaintext.bak")
	if err := os.WriteFile(backup, raw, 0600); err != nil { // #nosec G306,G703 -- path is sanitizeCADir(operator env)
		return fmt.Errorf("write backup: %w", err)
	}
	if err := os.WriteFile(keyPath, envelope, 0600); err != nil { // #nosec G306,G703 -- path is sanitizeCADir(operator env)
		return fmt.Errorf("write encrypted CA key: %w", err)
	}
	return nil
}

// sanitizeCADir cleans and validates a CA-directory path. The path comes
// from THESADA_CA_DIR (operator-controlled env, not user input) but we
// still reject relative paths and paths containing ".." so an accidental
// misconfiguration (env var pointing at "/tmp/.." or similar) fails loud
// at the call site instead of writing somewhere unexpected.
// in: raw dir. out: cleaned absolute dir, error.
func sanitizeCADir(dir string) (string, error) {
	if dir == "" {
		return "", errors.New("CA dir is empty")
	}
	cleaned := filepath.Clean(dir)
	if !filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("CA dir must be absolute: %q", dir)
	}
	return cleaned, nil
}

// bytesContainsString is a small substring check that avoids importing
// strings just for one Contains call here.
func bytesContainsString(b []byte, s string) bool {
	if len(s) > len(b) {
		return false
	}
	limit := len(b) - len(s)
	for i := 0; i <= limit; i++ {
		match := true
		for j := 0; j < len(s); j++ {
			if b[i+j] != s[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
