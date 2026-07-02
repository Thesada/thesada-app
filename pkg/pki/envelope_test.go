package pki

// Envelope-validation contracts: encrypt/decrypt must reject empty
// passphrases and malformed/foreign envelopes rather than fall through to a
// weak or garbage result.

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEncryptCAKey_RejectsEmptyPassphrase(t *testing.T) {
	if _, err := encryptCAKey([]byte("key"), ""); err == nil || !strings.Contains(err.Error(), "empty passphrase") {
		t.Fatalf("err = %v, want empty-passphrase rejection", err)
	}
}

func TestDecryptCAKey_RejectsEmptyPassphrase(t *testing.T) {
	if _, err := decryptCAKey([]byte("{}"), ""); err == nil || !strings.Contains(err.Error(), "empty passphrase") {
		t.Fatalf("err = %v, want empty-passphrase rejection", err)
	}
}

func TestDecryptCAKey_RejectsMalformedJSON(t *testing.T) {
	if _, err := decryptCAKey([]byte("not json"), "pass"); err == nil || !strings.Contains(err.Error(), "unmarshal") {
		t.Fatalf("err = %v, want unmarshal error", err)
	}
}

func TestDecryptCAKey_RejectsWrongMagic(t *testing.T) {
	b, _ := json.Marshal(caKeyEnvelope{Magic: "SOMETHING-ELSE", KDF: "scrypt"})
	if _, err := decryptCAKey(b, "pass"); err == nil || !strings.Contains(err.Error(), "magic mismatch") {
		t.Fatalf("err = %v, want magic mismatch", err)
	}
}

func TestDecryptCAKey_RejectsUnsupportedKDF(t *testing.T) {
	b, _ := json.Marshal(caKeyEnvelope{Magic: envelopeMagic, KDF: "argon2id"})
	if _, err := decryptCAKey(b, "pass"); err == nil || !strings.Contains(err.Error(), "KDF unsupported") {
		t.Fatalf("err = %v, want unsupported KDF", err)
	}
}
