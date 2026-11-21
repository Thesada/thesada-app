// Package webauthntest is a software WebAuthn authenticator for tests: one
// P-256 key, "none" attestation, a sign counter the test can rewind.
package webauthntest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

const credIDLen = 16

const (
	flagUserPresent  = 0x01
	flagUserVerified = 0x04
	flagAttested     = 0x40
)

// Authenticator holds one credential for one relying party.
type Authenticator struct {
	RPID    string
	Origin  string
	Counter uint32
	credID  []byte
	key     *ecdsa.PrivateKey
}

// New makes an authenticator with a fresh key and credential id.
// in: RP ID, origin the browser would report. out: authenticator, error.
func New(rpID, origin string) (*Authenticator, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	id := make([]byte, credIDLen)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	return &Authenticator{RPID: rpID, Origin: origin, credID: id, key: key}, nil
}

type options struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
	} `json:"publicKey"`
}

// Register answers creation options the way navigator.credentials.create would.
// in: options JSON from the server. out: credential JSON, error.
func (a *Authenticator) Register(optionsJSON []byte) ([]byte, error) {
	challenge, err := challengeOf(optionsJSON)
	if err != nil {
		return nil, err
	}
	clientData, err := a.clientData("webauthn.create", challenge)
	if err != nil {
		return nil, err
	}
	cose, err := webauthncbor.Marshal(map[int]interface{}{
		1: 2, 3: -7, -1: 1,
		-2: pad32(a.key.X.Bytes()), -3: pad32(a.key.Y.Bytes()),
	})
	if err != nil {
		return nil, err
	}
	attested := make([]byte, 0, 18+len(a.credID)+len(cose))
	attested = append(attested, make([]byte, 16)...) // zero AAGUID
	attested = binary.BigEndian.AppendUint16(attested, credIDLen)
	attested = append(attested, a.credID...)
	attested = append(attested, cose...)
	authData := append(a.authData(flagUserPresent|flagUserVerified|flagAttested), attested...)
	attObj, err := webauthncbor.Marshal(map[string]interface{}{
		"fmt": "none", "attStmt": map[string]interface{}{}, "authData": authData,
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]interface{}{
		"id": b64(a.credID), "rawId": b64(a.credID), "type": "public-key",
		"response": map[string]interface{}{
			"attestationObject": b64(attObj), "clientDataJSON": b64(clientData),
			"transports": []string{"usb"},
		},
		"clientExtensionResults": map[string]interface{}{},
	})
}

// Login answers request options the way navigator.credentials.get would.
// The counter goes up by one first, set Counter to replay an old value.
// in: options JSON from the server. out: credential JSON, error.
func (a *Authenticator) Login(optionsJSON []byte) ([]byte, error) {
	challenge, err := challengeOf(optionsJSON)
	if err != nil {
		return nil, err
	}
	a.Counter++
	clientData, err := a.clientData("webauthn.get", challenge)
	if err != nil {
		return nil, err
	}
	authData := a.authData(flagUserPresent | flagUserVerified)
	digest := sha256.Sum256(clientData)
	signed := sha256.Sum256(append(append([]byte{}, authData...), digest[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, signed[:])
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]interface{}{
		"id": b64(a.credID), "rawId": b64(a.credID), "type": "public-key",
		"response": map[string]interface{}{
			"authenticatorData": b64(authData), "clientDataJSON": b64(clientData),
			"signature": b64(sig),
		},
		"clientExtensionResults": map[string]interface{}{},
	})
}

func (a *Authenticator) authData(flags byte) []byte {
	rp := sha256.Sum256([]byte(a.RPID))
	out := append([]byte{}, rp[:]...)
	out = append(out, flags)
	return binary.BigEndian.AppendUint32(out, a.Counter)
}

func (a *Authenticator) clientData(kind, challenge string) ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"type": kind, "challenge": challenge, "origin": a.Origin, "crossOrigin": false,
	})
}

func challengeOf(optionsJSON []byte) (string, error) {
	var o options
	if err := json.Unmarshal(optionsJSON, &o); err != nil {
		return "", err
	}
	if o.PublicKey.Challenge == "" {
		return "", fmt.Errorf("webauthntest: options carry no challenge")
	}
	return o.PublicKey.Challenge, nil
}

func pad32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	return append(make([]byte, 32-len(b)), b...)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
