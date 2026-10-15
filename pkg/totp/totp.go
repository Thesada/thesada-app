// Package totp is RFC 6238 TOTP with a 30 second step, 6 digits, and SHA-1.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"time"
)

const (
	step    = 30 * time.Second
	digits  = 6
	keySize = 20
	skew    = 1
)

// NewKey returns a fresh shared secret and its base32 form for an otpauth URL.
// in: none. out: raw key, base32, error.
func NewKey() (raw []byte, encoded string, err error) {
	raw = make([]byte, keySize)
	if _, err = rand.Read(raw); err != nil {
		return nil, "", fmt.Errorf("totp: random key: %w", err)
	}
	encoded = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	return raw, encoded, nil
}

// DecodeKey parses a base32 secret written by NewKey.
// in: base32 secret. out: raw key, error.
func DecodeKey(encoded string) ([]byte, error) {
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("totp: decode secret: %w", err)
	}
	return raw, nil
}

// Code is the 6 digit token for key at the given time.
// in: raw key, time. out: 6-digit code.
func Code(key []byte, at time.Time) string {
	counter := uint64(at.Unix()) / uint64(step/time.Second)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", digits, bin%1_000_000)
}

// Check decodes the base32 secret and verifies the code.
// A decode failure is an error, not a rejected code.
// in: base32 secret, code, time. out: accepted, error.
func Check(encoded, code string, at time.Time) (bool, error) {
	raw, err := DecodeKey(encoded)
	if err != nil {
		return false, err
	}
	return Verify(raw, code, at), nil
}

// Verify accepts the current step and one step either side.
// in: raw key, code, time. out: true when the code matches.
func Verify(key []byte, code string, at time.Time) bool {
	if len(code) != digits {
		return false
	}
	for delta := -skew; delta <= skew; delta++ {
		got := Code(key, at.Add(time.Duration(delta)*step))
		if hmac.Equal([]byte(got), []byte(code)) {
			return true
		}
	}
	return false
}
