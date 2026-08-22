package service

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"time"
)

// Enrollment decision rules, kept pure and separate from the storage in
// enrollment.go.
//
// These endpoints are unauthenticated and reachable from the public internet,
// so every rule below is load-bearing rather than defensive tidiness. Keeping
// them as functions over plain values means they are tested against the
// adversarial cases directly, not inferred from a passing integration run.

// ChallengeTTL bounds how long a proof-of-possession nonce stays usable. Short
// enough that a captured challenge is stale before it is useful, long enough
// to survive a device rebooting between announce and verify.
const ChallengeTTL = 5 * time.Minute

// EnrollmentTTL bounds how long an unclaimed row survives. Anyone can create
// rows here, so they must age out on their own.
const EnrollmentTTL = 24 * time.Hour

// HashClaimToken returns the stored form of a claim token. The token is the
// bearer credential for certificate delivery, so the database holds only a
// digest - a read of this table must not yield something replayable.
// in: plaintext token. out: lowercase hex SHA-256.
func HashClaimToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ClaimTokenMatches compares a presented token against a stored hash in
// constant time. A byte-by-byte early exit here leaks the token one character
// at a time to anyone who can measure the endpoint.
// in: presented plaintext token, stored hex hash. out: true on match.
func ClaimTokenMatches(presented, storedHash string) bool {
	if presented == "" || storedHash == "" {
		return false
	}
	return subtle.ConstantTimeCompare(
		[]byte(HashClaimToken(presented)), []byte(storedHash)) == 1
}

// ChallengeUsable reports whether a stored challenge may still be answered.
//
// An absent challenge is not an error state: it means the challenge was
// already consumed. Treating "consumed" and "expired" identically is what
// makes the nonce single-use, and it keeps the endpoint from telling an
// attacker which of the two happened.
// in: stored challenge, its expiry, now. out: true when answerable.
func ChallengeUsable(challenge string, expiresAt *time.Time, now time.Time) bool {
	if challenge == "" || expiresAt == nil {
		return false
	}
	return now.Before(*expiresAt)
}

// ProofAllowed reports whether a caller may still prove possession on a row.
//
// Announcing is always allowed - see the announce handler for why refusing it
// would turn the endpoint into an enumeration oracle. Proving is not: once a
// certificate has been delivered the row is sealed, or a leaked claim token
// could be redeemed a second time. Recovering from there is an explicit
// re-pair, which clears the row.
// in: cert_delivered_at. out: true when the proof may be judged.
func ProofAllowed(certDeliveredAt *time.Time) bool {
	return certDeliveredAt == nil
}

// PubkeyStable asserts a presented pubkey belongs to the row it was loaded
// against - the check that catches a lookup returning somebody else's row.
// It does NOT bind a device_id to a unit; guessed-id squatters land on their
// own row and get nothing (docs/invariants.md, enrollment oracle table).
// in: stored pubkey (empty when new), presented pubkey.
// out: true when the presented key is the row's key.
func PubkeyStable(stored, presented string) bool {
	if presented == "" {
		return false
	}
	if stored == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(presented)) == 1
}

// ClaimTokenFrozen reports whether the claim token may still be rotated.
//
// Rotation is normal before proof: the device mints a fresh token per portal
// session. After proof it is fatal. Announce is unauthenticated, device_id is
// readable from the soft-AP BSSID and the pubkey is public by construction, so
// an attacker in radio range could re-announce with a token of their choosing;
// if verified_at survived that, they could then poll the cert endpoint and be
// handed the device's certificate AND private key.
// in: verified_at. out: true when the stored token must not change.
func ClaimTokenFrozen(verifiedAt *time.Time) bool {
	return verifiedAt != nil
}

// DeliverAllowed reports whether the certificate may be handed to the device.
//
// All four conditions are required, and the order they are written here is not
// the order they matter: verified proves the caller holds the device key,
// claimed proves a human authorised it, and not-yet-delivered makes the whole
// exchange one-shot.
// in: verified_at, claimed_at, cert_delivered_at. out: true when deliverable.
func DeliverAllowed(verifiedAt, claimedAt, certDeliveredAt *time.Time) bool {
	if verifiedAt == nil || claimedAt == nil {
		return false
	}
	return certDeliveredAt == nil
}

// ClaimAllowed reports whether a user may claim this enrollment.
//
// First claim wins. A device that is already claimed stays claimed even if the
// claim token leaks afterwards, so the race is decided once rather than
// continuously.
// in: verified_at, claimed_at. out: true when claimable.
func ClaimAllowed(verifiedAt, claimedAt *time.Time) bool {
	return verifiedAt != nil && claimedAt == nil
}

// ClaimRetryAllowed reports whether an already-claimed row may be claimed
// again by the tenant that holds it. Only the same tenant, so first-claim-wins
// still decides the race; this only lets a half-finished claim be replayed.
// in: claimed_at, claimed_by_tenant, claiming tenant. out: true when replayable.
func ClaimRetryAllowed(claimedAt *time.Time, claimedByTenant *string, tenantID string) bool {
	if claimedAt == nil || claimedByTenant == nil || tenantID == "" {
		return false
	}
	return *claimedByTenant == tenantID
}

// DeviceTopicPrefix builds the MQTT topic prefix for a claimed device.
//
// One function, two callers that MUST agree: the claim path writes this into
// the broker ACL, and the enrollment API hands the same string to the device.
// If they ever disagree the device publishes on a topic its own ACL denies,
// and the only symptom is silence. Two copies of this format string would
// drift eventually; one cannot.
// in: topic root (empty falls back to "thesada"), tenant id, device id.
// out: prefix.
func DeviceTopicPrefix(root, tenantID, deviceID string) string {
	if root == "" {
		root = "thesada"
	}
	return root + "/" + tenantID + "/" + deviceID
}

// DeviceCertCN builds the certificate CN, which is also the dynsec username
// via use_identity_as_username - same drift argument as DeviceTopicPrefix.
// in: tenant id, device id. out: CN.
func DeviceCertCN(tenantID, deviceID string) string {
	return fmt.Sprintf("thesada-%s-%s", tenantID, deviceID)
}
