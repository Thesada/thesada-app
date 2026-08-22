package service

import (
	"strings"
	"testing"
	"time"
)

func ptr(t time.Time) *time.Time { return &t }

// --- HashClaimToken / ClaimTokenMatches -------------------------------------

func TestHashClaimTokenIsStableAndHex(t *testing.T) {
	h := HashClaimToken("token-abc")
	if h != HashClaimToken("token-abc") {
		t.Fatal("hash must be deterministic")
	}
	if len(h) != 64 || strings.ToLower(h) != h {
		t.Fatalf("want 64 lowercase hex chars, got %q", h)
	}
	if h == HashClaimToken("token-abd") {
		t.Fatal("different tokens must not collide")
	}
}

func TestClaimTokenMatchesAcceptsCorrectToken(t *testing.T) {
	if !ClaimTokenMatches("token-abc", HashClaimToken("token-abc")) {
		t.Fatal("correct token must match its stored hash")
	}
}

func TestClaimTokenMatchesRejectsWrongToken(t *testing.T) {
	stored := HashClaimToken("token-abc")
	for _, bad := range []string{"token-abd", "token-ab", "token-abcd", "TOKEN-ABC"} {
		if ClaimTokenMatches(bad, stored) {
			t.Fatalf("%q must not match", bad)
		}
	}
}

// An empty presented token must never satisfy an empty or absent stored hash.
// Without this, a row written with no token would accept every caller.
func TestClaimTokenMatchesRejectsEmpty(t *testing.T) {
	if ClaimTokenMatches("", HashClaimToken("token-abc")) {
		t.Fatal("empty token must not match")
	}
	if ClaimTokenMatches("token-abc", "") {
		t.Fatal("empty stored hash must not match")
	}
	if ClaimTokenMatches("", "") {
		t.Fatal("empty against empty must not match")
	}
}

// A presented value that is already the hash must not authenticate. Otherwise
// a database read hands the reader a working credential.
func TestClaimTokenMatchesRejectsPresentedHash(t *testing.T) {
	stored := HashClaimToken("token-abc")
	if ClaimTokenMatches(stored, stored) {
		t.Fatal("presenting the stored hash must not authenticate")
	}
}

// --- ChallengeUsable --------------------------------------------------------

func TestChallengeUsableAcceptsFreshChallenge(t *testing.T) {
	now := time.Now()
	if !ChallengeUsable("nonce", ptr(now.Add(time.Minute)), now) {
		t.Fatal("unexpired challenge must be usable")
	}
}

func TestChallengeUsableRejectsExpired(t *testing.T) {
	now := time.Now()
	if ChallengeUsable("nonce", ptr(now.Add(-time.Second)), now) {
		t.Fatal("expired challenge must be rejected")
	}
	// Exactly at expiry is expired: the boundary fails closed.
	if ChallengeUsable("nonce", ptr(now), now) {
		t.Fatal("challenge at its expiry instant must be rejected")
	}
}

// A consumed challenge is cleared, which is what makes the nonce single-use.
func TestChallengeUsableRejectsConsumed(t *testing.T) {
	now := time.Now()
	if ChallengeUsable("", ptr(now.Add(time.Minute)), now) {
		t.Fatal("cleared challenge must be rejected")
	}
	if ChallengeUsable("nonce", nil, now) {
		t.Fatal("challenge with no expiry must be rejected")
	}
}

// --- ProofAllowed -----------------------------------------------------------

// Rebooting mid-provisioning is normal and must not lock a device out.
func TestProofAllowedPermitsRetryBeforeDelivery(t *testing.T) {
	if !ProofAllowed(nil) {
		t.Fatal("a device that has no cert yet must be able to prove itself")
	}
}

// The one-shot rule: a leaked claim token must not be redeemable twice.
func TestProofAllowedRefusesAfterDelivery(t *testing.T) {
	if ProofAllowed(ptr(time.Now())) {
		t.Fatal("proof must be refused once a cert has been delivered")
	}
}

// --- PubkeyStable -----------------------------------------------------------

func TestPubkeyStableAcceptsFirstAnnounce(t *testing.T) {
	if !PubkeyStable("", "aabb") {
		t.Fatal("first announce has nothing to compare against")
	}
}

func TestPubkeyStableAcceptsSameKey(t *testing.T) {
	if !PubkeyStable("aabb", "aabb") {
		t.Fatal("re-announce with the same key must be allowed")
	}
}

// The squatter regression. The previous rule let an unproven key be replaced,
// on the theory that the real device would win the race by signing first. It
// would not: producing a signature needs A private key, not THE private key,
// so whoever announced last before verifying pinned their own. A key never
// moves on a row now - (device_id, pubkey_hex) is the row identity, and a
// squatter lands on its own row instead of overwriting the device's.
func TestPubkeyStableRefusesSubstitutedKeyWithoutProof(t *testing.T) {
	if PubkeyStable("real-device-key", "squatter-key") {
		t.Fatal("a stored key must never be replaced by a different one")
	}
}

func TestPubkeyStableRejectsEmptyPresentedKey(t *testing.T) {
	if PubkeyStable("aabb", "") {
		t.Fatal("an empty presented key must be refused")
	}
	if PubkeyStable("", "") {
		t.Fatal("an empty presented key must be refused even on first announce")
	}
}

// --- claimTokenMatches ------------------------------------------------------

// A remote caller who guesses a device_id can announce and verify - with its
// own keypair, on its own row. A token off the device's portal QR picks the
// real row, and a token nobody wrote picks nothing.
func TestClaimTokenMatchesSelectsOnlyItsOwnRow(t *testing.T) {
	now := time.Now()
	rows := []Enrollment{
		{
			DeviceID:       "thesada-aabbccddeeff",
			PubkeyHex:      "squatter",
			ClaimTokenHash: HashClaimToken("squatter-token"),
			VerifiedAt:     &now,
		},
		{
			DeviceID:       "thesada-aabbccddeeff",
			PubkeyHex:      "real",
			ClaimTokenHash: HashClaimToken("real-token"),
			VerifiedAt:     &now,
		},
	}
	got := claimTokenMatches(rows, "real-token")
	if len(got) != 1 || got[0].PubkeyHex != "real" {
		t.Fatalf("real token must select the real row, got %+v", got)
	}
	if got := claimTokenMatches(rows, "some-other-token"); len(got) != 0 {
		t.Fatalf("an unknown token must select nothing, got %+v", got)
	}
	if got := claimTokenMatches(nil, "real-token"); len(got) != 0 {
		t.Fatal("no rows must select nothing")
	}
}

// The takeover this replaced: a squatter announces the SAME token off a
// photographed QR with a keypair ground to sort first. Returning the first
// match handed that row to whoever asked. Every match has to come back so the
// caller can refuse instead of picking.
func TestClaimTokenMatchesReturnsEveryDuplicate(t *testing.T) {
	now := time.Now()
	rows := []Enrollment{
		{PubkeyHex: "0000", ClaimTokenHash: HashClaimToken("shared"), VerifiedAt: &now},
		{PubkeyHex: "ffff", ClaimTokenHash: HashClaimToken("shared"), VerifiedAt: &now},
	}
	got := claimTokenMatches(rows, "shared")
	if len(got) != 2 {
		t.Fatalf("both rows carry the token, got %d matches", len(got))
	}
}

// An empty token must not match a row, however the row was written.
func TestClaimTokenMatchesRejectsEmptyToken(t *testing.T) {
	rows := []Enrollment{{PubkeyHex: "real", ClaimTokenHash: HashClaimToken("t")}}
	if got := claimTokenMatches(rows, ""); len(got) != 0 {
		t.Fatalf("empty token must match nothing, got %+v", got)
	}
}

// --- ClaimRetryAllowed ------------------------------------------------------

// A claim that reached the database but failed at the broker has to be
// replayable, or the user is told the device is already claimed while it holds
// a certificate and no broker client.
func TestClaimRetryAllowedForTheHoldingTenant(t *testing.T) {
	now := time.Now()
	tenant := "acme"
	if !ClaimRetryAllowed(&now, &tenant, "acme") {
		t.Fatal("the tenant holding the claim must be able to replay it")
	}
}

// Replay is not a second chance at somebody else's row: first claim still wins.
func TestClaimRetryRefusedForEveryoneElse(t *testing.T) {
	now := time.Now()
	tenant := "acme"
	cases := []struct {
		name      string
		claimedAt *time.Time
		holder    *string
		tenantID  string
	}{
		{"other tenant", &now, &tenant, "evilcorp"},
		{"unclaimed row", nil, nil, "acme"},
		{"claimed with no tenant", &now, nil, "acme"},
		{"no tenant on the session", &now, &tenant, ""},
	}
	for _, c := range cases {
		if ClaimRetryAllowed(c.claimedAt, c.holder, c.tenantID) {
			t.Fatalf("%s must not be replayable", c.name)
		}
	}
}

// --- ClaimTokenFrozen -------------------------------------------------------

// Rotation per portal session is normal before proof.
func TestClaimTokenNotFrozenBeforeProof(t *testing.T) {
	if ClaimTokenFrozen(nil) {
		t.Fatal("token must be rotatable before verification")
	}
}

// The key-theft path: announce is unauthenticated, device_id is readable from
// the soft-AP BSSID and the pubkey is public. Without the freeze an attacker
// re-announces their own token against a verified row, then redeems the
// certificate and private key with it.
func TestClaimTokenFrozenAfterProof(t *testing.T) {
	now := time.Now()
	if !ClaimTokenFrozen(&now) {
		t.Fatal("token must be frozen once the device has proved possession")
	}
}

// --- DeliverAllowed ---------------------------------------------------------

func TestDeliverAllowedRequiresVerifiedAndClaimed(t *testing.T) {
	now := time.Now()
	if !DeliverAllowed(ptr(now), ptr(now), nil) {
		t.Fatal("verified and claimed must be deliverable")
	}
	if DeliverAllowed(nil, ptr(now), nil) {
		t.Fatal("unverified must not be deliverable - no proof of key possession")
	}
	if DeliverAllowed(ptr(now), nil, nil) {
		t.Fatal("unclaimed must not be deliverable - no human authorised it")
	}
	if DeliverAllowed(nil, nil, nil) {
		t.Fatal("neither verified nor claimed must not be deliverable")
	}
}

// One-shot: the second poll after a successful delivery gets nothing.
func TestDeliverAllowedRefusesSecondDelivery(t *testing.T) {
	now := time.Now()
	if DeliverAllowed(ptr(now), ptr(now), ptr(now)) {
		t.Fatal("a delivered cert must not be delivered again")
	}
}

// --- ClaimAllowed -----------------------------------------------------------

// Claiming before the device proved key possession would let anyone who
// photographed a QR bind someone else's hardware into their tenant.
func TestClaimAllowedRequiresVerified(t *testing.T) {
	now := time.Now()
	if ClaimAllowed(nil, nil) {
		t.Fatal("unverified enrollment must not be claimable")
	}
	if !ClaimAllowed(ptr(now), nil) {
		t.Fatal("verified and unclaimed must be claimable")
	}
}

func TestClaimAllowedIsFirstClaimWins(t *testing.T) {
	now := time.Now()
	if ClaimAllowed(ptr(now), ptr(now)) {
		t.Fatal("an already claimed enrollment must not be claimable again")
	}
}

// --- DeviceTopicPrefix ------------------------------------------------------

// The claim path writes this into the broker ACL and the enrollment API hands
// the same string to the device. Disagreement means every publish is denied
// and the only symptom is silence.
func TestDeviceTopicPrefixShape(t *testing.T) {
	got := DeviceTopicPrefix("thesada", "acme", "thesada-0123456789ab")
	if got != "thesada/acme/thesada-0123456789ab" {
		t.Fatalf("unexpected prefix %q", got)
	}
}

func TestDeviceTopicPrefixDefaultsRoot(t *testing.T) {
	if got := DeviceTopicPrefix("", "acme", "dev"); got != "thesada/acme/dev" {
		t.Fatalf("empty root must fall back to thesada, got %q", got)
	}
}

func TestDeviceTopicPrefixHonoursCustomRoot(t *testing.T) {
	if got := DeviceTopicPrefix("iot", "acme", "dev"); got != "iot/acme/dev" {
		t.Fatalf("custom root must be used, got %q", got)
	}
}
