// Package secrets is the envelope-encryption core for device-config
// secrets (wifi.password, mqtt.password, telegram.bot_token, web.password,
// ap_password). It never touches the database or HTTP layer - it only
// turns key material into sealed blobs and back, so it is unit-testable in
// isolation and reusable by the storage, provisioning, and rotation layers.
//
// Two-level key hierarchy (envelope encryption):
//
//	root KEK  (THESADA_DEVICE_CONFIG_KEK, one per deployment, never in the DB)
//	  └─ wraps per-tenant DEK  (random, stored wrapped in the DB)
//	       └─ encrypts each secret value
//
// The root KEK is real 32-byte key material, not a passphrase, so no KDF
// is needed to use it (unlike the CA-key envelope in pkg/pki, which
// stretches a human passphrase with scrypt). Generate one with
// `openssl rand -base64 32` and source it from a systemd Credential /
// sealed secret, the same way THESADA_CA_KEY_PASSPHRASE is handled.
//
// Both wrap and encrypt use AES-256-GCM. Callers pass additional
// authenticated data (AAD) that binds a ciphertext to its identity - the
// tenant for a wrapped DEK, the tenant/device/field for a secret value -
// so an attacker with DB write cannot move one row's ciphertext onto
// another row and have it decrypt. A wrong key, tampered blob, or wrong
// AAD all surface as the GCM authentication error, never as garbage
// plaintext.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// keyLen is the byte length of both the root KEK and every DEK: 32 bytes
// selects AES-256.
const keyLen = 32

// Keyring holds the deployment root KEK in memory. It is the only place
// the root key material lives after Load; per-tenant DEKs are wrapped
// under it and stored in the DB, never the KEK itself.
type Keyring struct {
	kek []byte // exactly keyLen bytes
}

// NewKeyring decodes the base64 root KEK from THESADA_DEVICE_CONFIG_KEK and
// validates its length. An empty value is rejected here; callers that want
// the secrets feature to be optional check for the empty string before
// calling (mirrors the CAKeyPassphrase-empty path) and skip wiring the
// keyring at all.
// in: standard-base64 KEK string. out: *Keyring, error.
func NewKeyring(b64KEK string) (*Keyring, error) {
	if b64KEK == "" {
		return nil, errors.New("secrets: THESADA_DEVICE_CONFIG_KEK is empty")
	}
	kek, err := base64.StdEncoding.DecodeString(b64KEK)
	if err != nil {
		return nil, fmt.Errorf("secrets: decode KEK: %w", err)
	}
	if len(kek) != keyLen {
		return nil, fmt.Errorf("secrets: KEK is %d bytes, want %d (try `openssl rand -base64 32`)", len(kek), keyLen)
	}
	return &Keyring{kek: kek}, nil
}

// GenerateDEK returns a fresh random 32-byte data-encryption key. One DEK
// is minted per tenant at tenant-create and wrapped with WrapDEK before it
// touches the DB.
// in: none. out: 32-byte DEK, error.
func (k *Keyring) GenerateDEK() ([]byte, error) {
	dek := make([]byte, keyLen)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("secrets: generate DEK: %w", err)
	}
	return dek, nil
}

// WrapDEK seals a DEK under the root KEK. aad should be the owning tenant
// identity (e.g. the tenant id), binding the wrapped DEK to its row so it
// cannot be replayed under another tenant. The returned blob is
// nonce||ciphertext, safe to store in a single column.
// in: 32-byte DEK, AAD. out: sealed blob, error.
func (k *Keyring) WrapDEK(dek, aad []byte) ([]byte, error) {
	if len(dek) != keyLen {
		return nil, fmt.Errorf("secrets: DEK is %d bytes, want %d", len(dek), keyLen)
	}
	return seal(k.kek, dek, aad)
}

// UnwrapDEK reverses WrapDEK. The same aad passed to WrapDEK must be
// supplied or the GCM open fails.
// in: sealed blob, AAD. out: 32-byte DEK, error.
func (k *Keyring) UnwrapDEK(wrapped, aad []byte) ([]byte, error) {
	dek, err := open(k.kek, wrapped, aad)
	if err != nil {
		return nil, err
	}
	if len(dek) != keyLen {
		return nil, fmt.Errorf("secrets: unwrapped DEK is %d bytes, want %d", len(dek), keyLen)
	}
	return dek, nil
}

// EncryptSecret seals a single secret value under a tenant DEK. aad binds
// the ciphertext to the secret's identity (e.g. tenant/device/field) so it
// cannot be moved to another field or device. Returns nonce||ciphertext.
// in: 32-byte DEK, plaintext value, AAD. out: sealed blob, error.
func EncryptSecret(dek, plaintext, aad []byte) ([]byte, error) {
	if len(dek) != keyLen {
		return nil, fmt.Errorf("secrets: DEK is %d bytes, want %d", len(dek), keyLen)
	}
	return seal(dek, plaintext, aad)
}

// DecryptSecret reverses EncryptSecret. The same aad must be supplied.
// in: 32-byte DEK, sealed blob, AAD. out: plaintext value, error.
func DecryptSecret(dek, ciphertext, aad []byte) ([]byte, error) {
	if len(dek) != keyLen {
		return nil, fmt.Errorf("secrets: DEK is %d bytes, want %d", len(dek), keyLen)
	}
	return open(dek, ciphertext, aad)
}

// seal encrypts plaintext under a 32-byte key with AES-256-GCM and returns
// nonce||ciphertext. A fresh random nonce is generated per call, so
// encrypting the same plaintext twice yields different blobs.
// in: 32-byte key, plaintext, AAD. out: nonce||ciphertext, error.
func seal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("secrets: nonce: %w", err)
	}
	// Seal appends the ciphertext to its first arg, so the returned slice is
	// nonce followed by ciphertext - everything open needs in one blob.
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// open reverses seal: splits the nonce prefix off the blob and
// authenticates+decrypts the remainder.
// in: 32-byte key, nonce||ciphertext, AAD. out: plaintext, error.
func open(key, blob, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, fmt.Errorf("secrets: sealed blob is %d bytes, shorter than nonce (%d)", len(blob), ns)
	}
	nonce, ct := blob[:ns], blob[ns:]
	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("secrets: decrypt: %w", err)
	}
	return pt, nil
}

// newGCM builds an AES-256-GCM AEAD from a 32-byte key.
// in: 32-byte key. out: cipher.AEAD, error.
func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != keyLen {
		return nil, fmt.Errorf("secrets: key is %d bytes, want %d", len(key), keyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secrets: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secrets: gcm: %w", err)
	}
	return gcm, nil
}
