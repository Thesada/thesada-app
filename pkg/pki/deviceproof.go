package pki

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Device claim proof-of-possession.
//
// A factory-fresh device mints an Ed25519 keypair on first boot and prints the
// public half in its claim QR. Claiming it means proving the device still
// holds the private half: the app issues a challenge, the device signs it, and
// this verifies the signature against the advertised public key.
//
// Why this exists rather than trusting the QR alone: a QR is a photograph. It
// can be copied off a shelf, a box, or a support ticket screenshot. Without a
// signature, anyone who has seen the code can claim the device.

// DeviceIDPrefix is the fixed prefix the firmware puts on a generated id.
const DeviceIDPrefix = "thesada-"

// deviceIDHexLen is the MAC half of the id: six bytes, lowercase hex.
const deviceIDHexLen = 12

var (
	ErrBadPublicKey = errors.New("pki: device public key malformed")
	ErrBadSignature = errors.New("pki: device signature malformed")
	ErrBadDeviceID  = errors.New("pki: device id malformed")
	ErrProofFailed  = errors.New("pki: device proof did not verify")
)

// ParseDevicePublicKey decodes the lowercase-hex Ed25519 public key the
// firmware reports via chip.info and identity.info.
//
// Hex is required to be lowercase because that is what the firmware emits;
// accepting mixed case would mean two spellings of one key, and the key is
// used as an identity, so one spelling is the point.
// in: hex string. out: key, error.
func ParseDevicePublicKey(pubHex string) (ed25519.PublicKey, error) {
	if pubHex != strings.ToLower(pubHex) {
		return nil, fmt.Errorf("%w: not lowercase hex", ErrBadPublicKey)
	}
	raw, err := hex.DecodeString(pubHex)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadPublicKey, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d",
			ErrBadPublicKey, len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// ValidDeviceID reports whether id has the shape the firmware generates:
// the fixed prefix plus twelve lowercase hex digits of the factory MAC.
//
// A hand-edited name from an older config.json must not pass - those are
// operator labels, not identities, and they are not unique across units.
// in: id. out: true when well-formed.
func ValidDeviceID(id string) bool {
	if !strings.HasPrefix(id, DeviceIDPrefix) {
		return false
	}
	h := strings.TrimPrefix(id, DeviceIDPrefix)
	if len(h) != deviceIDHexLen {
		return false
	}
	for _, c := range h {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// VerifyDeviceProof checks that sig is a valid Ed25519 signature by pubHex
// over challenge, and that deviceID is well-formed.
//
// The challenge must be bound to a single claim attempt and expire, or a
// captured signature is replayable forever. Freshness and single-use are the
// caller's job - this function is deliberately stateless so it stays pure and
// testable, and the caller owns the storage that makes a challenge one-shot.
// in: device id, lowercase-hex public key, challenge bytes, signature bytes.
// out: nil when the proof holds.
func VerifyDeviceProof(deviceID, pubHex string, challenge, sig []byte) error {
	if !ValidDeviceID(deviceID) {
		return ErrBadDeviceID
	}
	pub, err := ParseDevicePublicKey(pubHex)
	if err != nil {
		return err
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: got %d bytes, want %d",
			ErrBadSignature, len(sig), ed25519.SignatureSize)
	}
	if len(challenge) == 0 {
		// An empty challenge verifies against a signature over nothing, which
		// proves possession of the key but not participation in THIS claim.
		return fmt.Errorf("%w: empty challenge", ErrProofFailed)
	}
	if !ed25519.Verify(pub, challenge, sig) {
		return ErrProofFailed
	}
	return nil
}
