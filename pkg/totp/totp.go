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
func NewKey() (raw []byte, encoded string, err error) {
	raw = make([]byte, keySize)
	if _, err = rand.Read(raw); err != nil {
		return nil, "", err
	}
	encoded = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	return raw, encoded, nil
}

// DecodeKey parses a base32 secret written by NewKey.
func DecodeKey(encoded string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encoded)
}

// Code is the 6 digit token for key at the given time.
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

// Verify accepts the current step and one step either side.
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
