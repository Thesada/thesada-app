package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv, hex.EncodeToString(pub)
}

const goodID = "thesada-dcb4d91acd28"

// --- ValidDeviceID ----------------------------------------------------------

func TestValidDeviceIDAcceptsGeneratedShape(t *testing.T) {
	for _, id := range []string{goodID, "thesada-000000000000", "thesada-ffffffffffff"} {
		if !ValidDeviceID(id) {
			t.Fatalf("%q should be valid", id)
		}
	}
}

// Operator labels from a hand-edited config.json are not identities and are
// not unique across units. They must never pass as a claimable device id.
func TestValidDeviceIDRejectsLegacyNames(t *testing.T) {
	for _, id := range []string{"thesada-node", "thesada-owb-debug", "node", "", "thesada-"} {
		if ValidDeviceID(id) {
			t.Fatalf("%q should be rejected", id)
		}
	}
}

func TestValidDeviceIDRejectsWrongLengthAndCase(t *testing.T) {
	for _, id := range []string{
		"thesada-dcb4d91acd2",   // 11
		"thesada-dcb4d91acd280", // 13
		"thesada-DCB4D91ACD28",  // uppercase
		"thesada-dcb4d91acdzz",  // non-hex
	} {
		if ValidDeviceID(id) {
			t.Fatalf("%q should be rejected", id)
		}
	}
}

// --- ParseDevicePublicKey ---------------------------------------------------

func TestParseDevicePublicKeyRoundTrips(t *testing.T) {
	pub, _, pubHex := testKey(t)
	got, err := ParseDevicePublicKey(pubHex)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatal("parsed key differs from original")
	}
}

// The firmware emits lowercase. Accepting uppercase would give one key two
// spellings, and the key is used as an identity.
func TestParseDevicePublicKeyRejectsUppercase(t *testing.T) {
	_, _, pubHex := testKey(t)
	if _, err := ParseDevicePublicKey(strings.ToUpper(pubHex)); !errors.Is(err, ErrBadPublicKey) {
		t.Fatalf("uppercase hex must be rejected, got %v", err)
	}
}

func TestParseDevicePublicKeyRejectsWrongSize(t *testing.T) {
	for _, h := range []string{"", "aabb", strings.Repeat("ab", 31), strings.Repeat("ab", 33)} {
		if _, err := ParseDevicePublicKey(h); !errors.Is(err, ErrBadPublicKey) {
			t.Fatalf("%d-char hex must be rejected, got %v", len(h), err)
		}
	}
}

func TestParseDevicePublicKeyRejectsNonHex(t *testing.T) {
	if _, err := ParseDevicePublicKey(strings.Repeat("zz", 32)); !errors.Is(err, ErrBadPublicKey) {
		t.Fatalf("non-hex must be rejected, got %v", err)
	}
}

// --- VerifyDeviceProof ------------------------------------------------------

func TestVerifyDeviceProofAcceptsGenuineSignature(t *testing.T) {
	_, priv, pubHex := testKey(t)
	challenge := []byte("claim-challenge-0001")
	if err := VerifyDeviceProof(goodID, pubHex, challenge, ed25519.Sign(priv, challenge)); err != nil {
		t.Fatalf("genuine proof must verify: %v", err)
	}
}

// The whole point: possessing the QR is not possessing the key.
func TestVerifyDeviceProofRejectsWrongKey(t *testing.T) {
	_, priv, _ := testKey(t)
	_, _, otherHex := testKey(t)
	challenge := []byte("claim-challenge-0001")
	err := VerifyDeviceProof(goodID, otherHex, challenge, ed25519.Sign(priv, challenge))
	if !errors.Is(err, ErrProofFailed) {
		t.Fatalf("signature from a different key must fail, got %v", err)
	}
}

// A signature captured from one claim attempt must not satisfy another.
func TestVerifyDeviceProofRejectsSignatureOverDifferentChallenge(t *testing.T) {
	_, priv, pubHex := testKey(t)
	sig := ed25519.Sign(priv, []byte("challenge-A"))
	err := VerifyDeviceProof(goodID, pubHex, []byte("challenge-B"), sig)
	if !errors.Is(err, ErrProofFailed) {
		t.Fatalf("replayed signature must fail, got %v", err)
	}
}

// An empty challenge would let a signature over nothing count as
// participation in this claim.
func TestVerifyDeviceProofRejectsEmptyChallenge(t *testing.T) {
	_, priv, pubHex := testKey(t)
	if err := VerifyDeviceProof(goodID, pubHex, nil, ed25519.Sign(priv, nil)); !errors.Is(err, ErrProofFailed) {
		t.Fatalf("empty challenge must fail, got %v", err)
	}
}

func TestVerifyDeviceProofRejectsMalformedInputs(t *testing.T) {
	_, priv, pubHex := testKey(t)
	challenge := []byte("claim-challenge-0001")
	sig := ed25519.Sign(priv, challenge)

	if err := VerifyDeviceProof("thesada-node", pubHex, challenge, sig); !errors.Is(err, ErrBadDeviceID) {
		t.Fatalf("legacy device id must be rejected, got %v", err)
	}
	if err := VerifyDeviceProof(goodID, "nothex", challenge, sig); !errors.Is(err, ErrBadPublicKey) {
		t.Fatalf("bad key must be rejected, got %v", err)
	}
	if err := VerifyDeviceProof(goodID, pubHex, challenge, sig[:10]); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("truncated signature must be rejected, got %v", err)
	}
}

// A flipped bit anywhere in the signature must fail closed.
func TestVerifyDeviceProofRejectsTamperedSignature(t *testing.T) {
	_, priv, pubHex := testKey(t)
	challenge := []byte("claim-challenge-0001")
	sig := ed25519.Sign(priv, challenge)
	sig[0] ^= 0x01
	if err := VerifyDeviceProof(goodID, pubHex, challenge, sig); !errors.Is(err, ErrProofFailed) {
		t.Fatalf("tampered signature must fail, got %v", err)
	}
}

// RFC 8032 section 7.1 TEST 2. Both sides of this system implement Ed25519
// from that spec - Go's crypto/ed25519 here, libsodium's
// crypto_sign_ed25519_detached on the device - so a known-answer vector is
// what proves they interoperate. A live signing oracle would prove the same
// thing at the cost of a command that signs attacker-chosen bytes with the
// device key, which is the claim attack itself.
func TestVerifyDeviceProofAcceptsRFC8032Vector(t *testing.T) {
	const (
		pubHex = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
		msgHex = "72"
		sigHex = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
			"085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
	)
	msg, err := hex.DecodeString(msgHex)
	if err != nil {
		t.Fatalf("decode msg: %v", err)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if err := VerifyDeviceProof(goodID, pubHex, msg, sig); err != nil {
		t.Fatalf("RFC 8032 vector must verify: %v", err)
	}
}
