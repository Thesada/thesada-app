//go:build integration

// EnrollmentService integration tests. The pure rules are covered in
// enrollment_policy_test.go; what needs a real database is the SQL that
// enforces them under concurrency - the row identity that stops a squatter,
// the FOR UPDATE that makes the first claim win, and the sweeps that clear
// rows any caller on the internet can create.
//
//	go test -tags integration -run TestEnrollment ./pkg/service/...
package service_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

// enrollDeviceID is a well-formed id: the fixed prefix plus twelve lowercase
// hex digits of a factory MAC.
const enrollDeviceID = "thesada-aabbccddeeff"

// newDeviceKey mints an Ed25519 keypair the way first boot does and returns
// the public half in the lowercase hex the firmware reports.
func newDeviceKey(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return hex.EncodeToString(pub), priv
}

// seedUser inserts a user out-of-band and returns its id, for owner_user_id.
func seedUser(t *testing.T, env *servicetest.Env, tenantID, email string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := env.Super.QueryRow(context.Background(),
		`INSERT INTO users (tenant_id, email) VALUES ($1, $2) RETURNING id`,
		tenantID, email).Scan(&id); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

// announceAndVerify walks one keypair through the device half of the flow.
func announceAndVerify(t *testing.T, e *service.EnrollmentService, deviceID, pubHex string, priv ed25519.PrivateKey, token string) {
	t.Helper()
	ctx := context.Background()
	challenge, err := e.Announce(ctx, deviceID, pubHex, token)
	if err != nil {
		t.Fatalf("announce: %v", err)
	}
	if err := e.Verify(ctx, deviceID, pubHex, ed25519.Sign(priv, []byte(challenge))); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// TestEnrollmentHappyPath walks announce, verify, claim and seal, and asserts
// the claim writes both halves it is responsible for: the owner and the
// topic prefix the broker ACL is built from.
func TestEnrollmentHappyPath(t *testing.T) {
	env := servicetest.Start(t)
	enroll := env.Services.Enrollments
	ctx := context.Background()

	const tenant = "enroll-happy"
	env.SeedTenant(t, tenant)
	owner := seedUser(t, env, tenant, "owner@enroll-happy.test")

	const happyToken = "claim-token-happy"
	pubHex, priv := newDeviceKey(t)
	announceAndVerify(t, enroll, enrollDeviceID, pubHex, priv, happyToken)

	prefix := service.DeviceTopicPrefix("thesada", tenant, enrollDeviceID)
	devicePk, err := enroll.ClaimInto(ctx, enrollDeviceID, pubHex, tenant, owner, prefix)
	if err != nil {
		t.Fatalf("ClaimInto: %v", err)
	}

	var gotOwner *uuid.UUID
	var gotPrefix *string
	if err := env.Super.QueryRow(ctx,
		`SELECT owner_user_id, mqtt_topic_prefix FROM devices WHERE id = $1`,
		devicePk).Scan(&gotOwner, &gotPrefix); err != nil {
		t.Fatalf("read device row: %v", err)
	}
	if gotOwner == nil || *gotOwner != owner {
		t.Fatalf("owner_user_id = %v, want %v", gotOwner, owner)
	}
	if gotPrefix == nil || *gotPrefix != prefix {
		t.Fatalf("mqtt_topic_prefix = %v, want %q", gotPrefix, prefix)
	}

	if got, err := enroll.MarkDelivered(ctx, enrollDeviceID, pubHex, happyToken); err != nil || got != tenant {
		t.Fatalf("MarkDelivered = %q, %v; want %q, nil", got, err, tenant)
	}
	// Sealing is terminal - a second ack must not re-open delivery.
	if _, err := enroll.MarkDelivered(ctx, enrollDeviceID, pubHex, happyToken); !errors.Is(err, service.ErrEnrollNotReady) {
		t.Fatalf("second MarkDelivered = %v, want ErrEnrollNotReady", err)
	}
	// Sealing needs the row's own token: the pubkey is public, so without the
	// token anyone who read a key could seal a row before its device collects.
	if _, err := enroll.MarkDelivered(ctx, enrollDeviceID, pubHex, "not-the-token"); !errors.Is(err, service.ErrEnrollNotFound) {
		t.Fatalf("MarkDelivered with a foreign token = %v, want ErrEnrollNotFound", err)
	}
}

// TestEnrollmentFailedVerifyBurnsTheChallenge - the burn must COMMIT on a bad
// proof. Rolled into the verify transaction it would be undone by the error,
// handing the nonce back to grind signatures against.
func TestEnrollmentFailedVerifyBurnsTheChallenge(t *testing.T) {
	env := servicetest.Start(t)
	enroll := env.Services.Enrollments
	ctx := context.Background()

	pubHex, priv := newDeviceKey(t)
	challenge, err := enroll.Announce(ctx, enrollDeviceID, pubHex, "burn-token")
	if err != nil {
		t.Fatalf("announce: %v", err)
	}

	if err := enroll.Verify(ctx, enrollDeviceID, pubHex,
		[]byte("not a signature")); !errors.Is(err, service.ErrEnrollBadProof) {
		t.Fatalf("bad-proof Verify = %v, want ErrEnrollBadProof", err)
	}
	var gone *string
	if err := env.Super.QueryRow(ctx,
		`SELECT challenge FROM device_enrollments
		  WHERE device_id = $1 AND pubkey_hex = $2`,
		enrollDeviceID, pubHex).Scan(&gone); err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	if gone != nil {
		t.Fatal("challenge survived a failed verify - the burn rolled back")
	}
	// The spent nonce must not be redeemable, even with a now-valid signature.
	if err := enroll.Verify(ctx, enrollDeviceID, pubHex,
		ed25519.Sign(priv, []byte(challenge))); !errors.Is(err, service.ErrEnrollBadProof) {
		t.Fatalf("replayed challenge Verify = %v, want ErrEnrollBadProof", err)
	}
	// A fresh announce recovers the device.
	announceAndVerify(t, enroll, enrollDeviceID, pubHex, priv, "burn-token")
}

// TestEnrollmentVerifyIgnoresARotatedToken - the burn commits in its own
// transaction, so an Announce can land between it and the verified update.
// Rotation is legal until verified_at is set, so without re-qualifying the row
// a caller that guessed the id gets its own claim token frozen by somebody
// else's proof, and can then claim the device.
func TestEnrollmentVerifyIgnoresARotatedToken(t *testing.T) {
	env := servicetest.Start(t)
	enroll := env.Services.Enrollments
	ctx := context.Background()

	pubHex, priv := newDeviceKey(t)
	challenge, err := enroll.Announce(ctx, enrollDeviceID, pubHex, "real-token")
	if err != nil {
		t.Fatalf("announce: %v", err)
	}

	// Stand in for the racing Announce, in the one window it can land: after
	// the burn commits, before the row is marked verified.
	restore := service.SetVerifyBurnHook(func() {
		if _, err := env.Super.Exec(ctx,
			`UPDATE device_enrollments
			    SET claim_token_hash = $3, challenge = $4,
			        challenge_expires_at = now() + interval '5 minutes'
			  WHERE device_id = $1 AND pubkey_hex = $2`,
			enrollDeviceID, pubHex, service.HashClaimToken("attacker-token"),
			"a-different-challenge"); err != nil {
			t.Errorf("simulate racing announce: %v", err)
		}
	})
	defer restore()

	if err := enroll.Verify(ctx, enrollDeviceID, pubHex,
		ed25519.Sign(priv, []byte(challenge))); !errors.Is(err, service.ErrEnrollBadProof) {
		t.Fatalf("Verify across a rotation = %v, want ErrEnrollBadProof", err)
	}

	var verifiedAt *time.Time
	if err := env.Super.QueryRow(ctx,
		`SELECT verified_at FROM device_enrollments
		  WHERE device_id = $1 AND pubkey_hex = $2`,
		enrollDeviceID, pubHex).Scan(&verifiedAt); err != nil {
		t.Fatalf("read verified_at: %v", err)
	}
	if verifiedAt != nil {
		t.Fatal("a rotated claim token was frozen by somebody else's proof")
	}
}

// TestEnrollmentClaimIntoRequiresOwner - the spec makes the claiming user the
// owner. A claim with no user must fail rather than write a NULL that nothing
// later fills in.
func TestEnrollmentClaimIntoRequiresOwner(t *testing.T) {
	env := servicetest.Start(t)
	enroll := env.Services.Enrollments

	const tenant = "enroll-noowner"
	env.SeedTenant(t, tenant)
	pubHex, priv := newDeviceKey(t)
	announceAndVerify(t, enroll, enrollDeviceID, pubHex, priv, "tok")

	_, err := enroll.ClaimInto(context.Background(), enrollDeviceID, pubHex, tenant, uuid.Nil, "p")
	if !errors.Is(err, service.ErrEnrollNoOwner) {
		t.Fatalf("ClaimInto with no owner = %v, want ErrEnrollNoOwner", err)
	}
}

// TestEnrollmentSquatterCannotLockOutDevice is the shared-credential regression.
//
// device_ids come from sequential factory MACs, so a remote caller can guess
// one, announce with its OWN keypair and satisfy the proof with it - producing
// a signature needs a private key, not THE private key. When the row was keyed
// on device_id alone that pinned the attacker's key and froze the claim token,
// and the real hardware could never enroll again. Rows keyed on
// (device_id, pubkey_hex) put the squatter on its own inert row instead.
func TestEnrollmentSquatterCannotLockOutDevice(t *testing.T) {
	env := servicetest.Start(t)
	enroll := env.Services.Enrollments
	ctx := context.Background()

	const tenant = "enroll-squat"
	env.SeedTenant(t, tenant)
	owner := seedUser(t, env, tenant, "owner@enroll-squat.test")

	// The squatter goes first and completes the whole proof.
	squatPub, squatPriv := newDeviceKey(t)
	announceAndVerify(t, enroll, enrollDeviceID, squatPub, squatPriv, "squatter-token")

	// The real device boots later. It must still be able to announce and prove
	// itself: against the old rule this failed with ErrEnrollKeyChange.
	realPub, realPriv := newDeviceKey(t)
	announceAndVerify(t, enroll, enrollDeviceID, realPub, realPriv, "real-token")

	// Each token selects its own row on the claim form, and neither selects
	// the other's.
	got, err := enroll.FindForClaim(ctx, enrollDeviceID, "real-token")
	if err != nil {
		t.Fatalf("find by real token: %v", err)
	}
	if got.PubkeyHex != realPub {
		t.Fatalf("real token selected pubkey %q, want the device's own", got.PubkeyHex)
	}
	if got, err := enroll.FindForClaim(ctx, enrollDeviceID, "squatter-token"); err != nil ||
		got.PubkeyHex != squatPub {
		t.Fatalf("squatter token must select the squatter row, got %+v (%v)", got, err)
	}

	// Knowing only the device_id buys nothing: there is no lookup without a
	// token, and a guessed one selects no row at all.
	if _, err := enroll.FindForClaim(ctx, enrollDeviceID, "guessed-token"); !errors.Is(err, service.ErrEnrollNotFound) {
		t.Fatalf("unknown token = %v, want ErrEnrollNotFound", err)
	}

	// The device-facing lookup keys on the row, and the token has to belong to
	// the row it named. Neither party can reach across.
	if _, err := enroll.FindByDeviceKey(ctx, enrollDeviceID, realPub, "squatter-token"); !errors.Is(err, service.ErrEnrollNotFound) {
		t.Fatalf("foreign token against the real row = %v, want ErrEnrollNotFound", err)
	}
	if _, err := enroll.FindByDeviceKey(ctx, enrollDeviceID, squatPub, "real-token"); !errors.Is(err, service.ErrEnrollNotFound) {
		t.Fatalf("real token against the squatter row = %v, want ErrEnrollNotFound", err)
	}

	// The owner claims the row its QR points at, and gets the real hardware.
	prefix := service.DeviceTopicPrefix("thesada", tenant, enrollDeviceID)
	if _, err := enroll.ClaimInto(ctx, enrollDeviceID, realPub, tenant, owner, prefix); err != nil {
		t.Fatalf("owner must be able to claim the real row: %v", err)
	}
	if _, err := enroll.MarkDelivered(ctx, enrollDeviceID, realPub, "real-token"); err != nil {
		t.Fatalf("MarkDelivered on the real row: %v", err)
	}
	// The squatter's row is untouched by any of it and still unclaimed.
	sq, err := enroll.FindForClaim(ctx, enrollDeviceID, "squatter-token")
	if err != nil {
		t.Fatalf("squatter row lookup: %v", err)
	}
	if sq.ClaimedAt != nil || sq.CertDeliveredAt != nil {
		t.Fatalf("squatter row must stay inert, got %+v", sq)
	}
}

// newDeviceKeyBelow mints a keypair whose hex sorts before want, the way an
// attacker grinds one to land first under ORDER BY pubkey_hex.
func newDeviceKeyBelow(t *testing.T, want string) (string, ed25519.PrivateKey) {
	t.Helper()
	for i := 0; i < 64; i++ {
		pub, priv := newDeviceKey(t)
		if pub < want {
			return pub, priv
		}
	}
	t.Fatal("could not mint a key that sorts first")
	return "", nil
}

// TestEnrollmentSameTokenSquatterCannotTakeTheCert is the takeover regression.
//
// The QR carries device_id, pubkey and claim token together, so a squatter who
// photographed one can announce the SAME token under its own keypair, ground
// so the hex sorts first. While the device-facing lookups picked a row by
// claim token alone and returned the first match, that squatter row answered
// the real device's certificate poll: the app signed thesada-<squatter tenant>
// -<device_id> and handed the real hardware a certificate and private key for
// somebody else's tenant.
func TestEnrollmentSameTokenSquatterCannotTakeTheCert(t *testing.T) {
	env := servicetest.Start(t)
	enroll := env.Services.Enrollments
	ctx := context.Background()

	const realTenant, squatTenant = "enroll-same-real", "enroll-same-squat"
	env.SeedTenant(t, realTenant)
	env.SeedTenant(t, squatTenant)
	owner := seedUser(t, env, realTenant, "owner@enroll-same.test")
	squatter := seedUser(t, env, squatTenant, "squatter@enroll-same.test")

	// One token, off one QR, held by both parties.
	const qrToken = "qr-token-off-the-label"
	realPub, realPriv := newDeviceKey(t)
	squatPub, squatPriv := newDeviceKeyBelow(t, realPub)

	announceAndVerify(t, enroll, enrollDeviceID, squatPub, squatPriv, qrToken)
	// The real device still completes its own announce and verify while that
	// row exists: the proof is judged against the key the caller named, so the
	// squatter cannot burn the real device's challenge or its verified_at.
	announceAndVerify(t, enroll, enrollDeviceID, realPub, realPriv, qrToken)

	// The squatter claims the row it holds. That is the accepted model - it
	// gets a certificate for a phantom device inside its own tenant.
	if _, err := enroll.ClaimInto(ctx, enrollDeviceID, squatPub, squatTenant, squatter,
		service.DeviceTopicPrefix("thesada", squatTenant, enrollDeviceID)); err != nil {
		t.Fatalf("squatter claim: %v", err)
	}

	// The real device polls for its certificate with its own token. It must
	// reach its OWN row - unclaimed, so "keep polling" - and never the
	// squatter's claimed one.
	e, err := enroll.FindByDeviceKey(ctx, enrollDeviceID, realPub, qrToken)
	if err != nil {
		t.Fatalf("real device cert poll: %v", err)
	}
	if e.PubkeyHex != realPub {
		t.Fatalf("cert poll reached pubkey %q, want the device's own", e.PubkeyHex)
	}
	if e.ClaimedByTenant != nil {
		t.Fatalf("the real device's row must still be unclaimed, got tenant %q", *e.ClaimedByTenant)
	}

	// The owner claims. Only one row under this id is still claimable, so the
	// form resolves to the hardware in front of them.
	prefix := service.DeviceTopicPrefix("thesada", realTenant, enrollDeviceID)
	forClaim, err := enroll.FindForClaim(ctx, enrollDeviceID, qrToken)
	if err != nil {
		t.Fatalf("owner claim lookup: %v", err)
	}
	if forClaim.PubkeyHex != realPub {
		t.Fatalf("claim form selected pubkey %q, want the real device's", forClaim.PubkeyHex)
	}
	if _, err := enroll.ClaimInto(ctx, enrollDeviceID, forClaim.PubkeyHex, realTenant, owner, prefix); err != nil {
		t.Fatalf("owner claim: %v", err)
	}

	// And now the certificate the device collects is bound to its owner's
	// tenant, which is the whole point.
	e, err = enroll.FindByDeviceKey(ctx, enrollDeviceID, realPub, qrToken)
	if err != nil {
		t.Fatalf("cert poll after claim: %v", err)
	}
	if e.ClaimedByTenant == nil || *e.ClaimedByTenant != realTenant {
		t.Fatalf("cert poll resolved to tenant %v, want %q", e.ClaimedByTenant, realTenant)
	}
	if got, err := enroll.MarkDelivered(ctx, enrollDeviceID, realPub, qrToken); err != nil || got != realTenant {
		t.Fatalf("MarkDelivered = %q, %v; want %q, nil", got, err, realTenant)
	}
}

// TestEnrollmentAmbiguousClaimIsRefused - the claim form carries no pubkey, so
// when two rows share a token nothing on the request says which one the user
// meant. Refusing is the only honest answer: a success page for a row the user
// did not mean is how the squatter's device ends up in their tenant.
func TestEnrollmentAmbiguousClaimIsRefused(t *testing.T) {
	env := servicetest.Start(t)
	enroll := env.Services.Enrollments
	ctx := context.Background()

	const tenant = "enroll-ambiguous"
	env.SeedTenant(t, tenant)
	owner := seedUser(t, env, tenant, "owner@enroll-ambiguous.test")

	const qrToken = "shared-qr-token"
	realPub, realPriv := newDeviceKey(t)
	squatPub, squatPriv := newDeviceKeyBelow(t, realPub)
	announceAndVerify(t, enroll, enrollDeviceID, squatPub, squatPriv, qrToken)
	announceAndVerify(t, enroll, enrollDeviceID, realPub, realPriv, qrToken)

	if _, err := enroll.FindForClaim(ctx, enrollDeviceID, qrToken); !errors.Is(err, service.ErrEnrollAmbiguous) {
		t.Fatalf("ambiguous claim = %v, want ErrEnrollAmbiguous", err)
	}
	// Refused means nothing moved: no row may be claimed by a lookup that
	// could not tell them apart.
	var claimed int
	if err := env.Super.QueryRow(ctx,
		`SELECT count(*) FROM device_enrollments WHERE device_id = $1 AND claimed_at IS NOT NULL`,
		enrollDeviceID).Scan(&claimed); err != nil {
		t.Fatalf("count claimed: %v", err)
	}
	if claimed != 0 {
		t.Fatalf("%d rows were claimed by a refused lookup, want 0", claimed)
	}

	// The device-facing path is not ambiguous at all - it names a row - so the
	// real device keeps enrolling while the duplicate sits there.
	if e, err := enroll.FindByDeviceKey(ctx, enrollDeviceID, realPub, qrToken); err != nil || e.PubkeyHex != realPub {
		t.Fatalf("device lookup must stay unambiguous, got %+v (%v)", e, err)
	}

	// Once only one row can still be claimed the form resolves again, so the
	// duplicate is not a permanent lockout.
	if _, err := enroll.ClaimInto(ctx, enrollDeviceID, squatPub, tenant, owner,
		service.DeviceTopicPrefix("thesada", tenant, enrollDeviceID)); err != nil {
		t.Fatalf("claim the duplicate: %v", err)
	}
	got, err := enroll.FindForClaim(ctx, enrollDeviceID, qrToken)
	if err != nil || got.PubkeyHex != realPub {
		t.Fatalf("claim lookup after the duplicate is claimed = %+v (%v), want the real row", got, err)
	}
}

// TestEnrollmentClaimRetryIsIdempotent - the claim handler provisions the
// broker after ClaimInto returns, and tells the user to retry when that fails.
// The retry has to reach the same row: refusing it left the device claimed,
// holding a certificate, with no broker client and no way back.
func TestEnrollmentClaimRetryIsIdempotent(t *testing.T) {
	env := servicetest.Start(t)
	enroll := env.Services.Enrollments
	ctx := context.Background()

	const tenant, other = "enroll-retry", "enroll-retry-other"
	env.SeedTenant(t, tenant)
	env.SeedTenant(t, other)
	owner := seedUser(t, env, tenant, "owner@enroll-retry.test")
	colleague := seedUser(t, env, tenant, "colleague@enroll-retry.test")
	stranger := seedUser(t, env, other, "stranger@enroll-retry.test")

	pubHex, priv := newDeviceKey(t)
	announceAndVerify(t, enroll, enrollDeviceID, pubHex, priv, "retry-token")
	prefix := service.DeviceTopicPrefix("thesada", tenant, enrollDeviceID)

	first, err := enroll.ClaimInto(ctx, enrollDeviceID, pubHex, tenant, owner, prefix)
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	var claimedAt time.Time
	if err := env.Super.QueryRow(ctx,
		`SELECT claimed_at FROM device_enrollments WHERE device_id = $1 AND pubkey_hex = $2`,
		enrollDeviceID, pubHex).Scan(&claimedAt); err != nil {
		t.Fatalf("read claimed_at: %v", err)
	}

	again, err := enroll.ClaimInto(ctx, enrollDeviceID, pubHex, tenant, owner, prefix)
	if err != nil {
		t.Fatalf("retry after a broker failure must succeed, got %v", err)
	}
	if again != first {
		t.Fatalf("retry returned device %v, want the row the first claim made (%v)", again, first)
	}
	var stillClaimedAt time.Time
	if err := env.Super.QueryRow(ctx,
		`SELECT claimed_at FROM device_enrollments WHERE device_id = $1 AND pubkey_hex = $2`,
		enrollDeviceID, pubHex).Scan(&stillClaimedAt); err != nil {
		t.Fatalf("re-read claimed_at: %v", err)
	}
	if !stillClaimedAt.Equal(claimedAt) {
		t.Fatalf("retry moved claimed_at from %v to %v", claimedAt, stillClaimedAt)
	}

	// A replay is not a second chance at the row: first claim still wins, for
	// another tenant and for another user inside the holding tenant.
	if _, err := enroll.ClaimInto(ctx, enrollDeviceID, pubHex, other, stranger,
		service.DeviceTopicPrefix("thesada", other, enrollDeviceID)); !errors.Is(err, service.ErrEnrollNotReady) {
		t.Fatalf("another tenant = %v, want ErrEnrollNotReady", err)
	}
	if _, err := enroll.ClaimInto(ctx, enrollDeviceID, pubHex, tenant, colleague, prefix); !errors.Is(err, service.ErrEnrollNotReady) {
		t.Fatalf("another user = %v, want ErrEnrollNotReady", err)
	}
	var devices int
	if err := env.Super.QueryRow(ctx,
		`SELECT count(*) FROM devices WHERE device_id = $1`, enrollDeviceID).Scan(&devices); err != nil {
		t.Fatalf("count devices: %v", err)
	}
	if devices != 1 {
		t.Fatalf("devices rows for the id = %d, want 1", devices)
	}
}

// TestEnrollmentAnnounceIsNotAnOracle - the ledger says every refusal on this
// surface looks the same, so announce must not refuse on state at all. A
// sealed id, an unknown id and a fresh one all hand back a challenge; the
// sealed row reveals itself only at verify, to a caller that signed.
func TestEnrollmentAnnounceIsNotAnOracle(t *testing.T) {
	env := servicetest.Start(t)
	enroll := env.Services.Enrollments
	ctx := context.Background()

	const tenant = "enroll-oracle"
	env.SeedTenant(t, tenant)
	owner := seedUser(t, env, tenant, "owner@enroll-oracle.test")

	pubHex, priv := newDeviceKey(t)
	announceAndVerify(t, enroll, enrollDeviceID, pubHex, priv, "sealed-token")
	prefix := service.DeviceTopicPrefix("thesada", tenant, enrollDeviceID)
	if _, err := enroll.ClaimInto(ctx, enrollDeviceID, pubHex, tenant, owner, prefix); err != nil {
		t.Fatalf("ClaimInto: %v", err)
	}
	if _, err := enroll.MarkDelivered(ctx, enrollDeviceID, pubHex, "sealed-token"); err != nil {
		t.Fatalf("MarkDelivered: %v", err)
	}

	// Same keypair, sealed row: still a challenge.
	challenge, err := enroll.Announce(ctx, enrollDeviceID, pubHex, "sealed-token")
	if err != nil || challenge == "" {
		t.Fatalf("announce on a sealed row = %q, %v; want a challenge and no error", challenge, err)
	}
	// The refusal happens at verify, after the caller proved it holds the key.
	if err := enroll.Verify(ctx, enrollDeviceID, pubHex,
		ed25519.Sign(priv, []byte(challenge))); !errors.Is(err, service.ErrEnrollSealed) {
		t.Fatalf("verify on a sealed row = %v, want ErrEnrollSealed", err)
	}

	// A fabricated id is indistinguishable: a challenge, same as the real one.
	if c, err := enroll.Announce(ctx, "thesada-000000000000", pubHex, "whatever"); err != nil || c == "" {
		t.Fatalf("announce for an unknown id = %q, %v; want a challenge and no error", c, err)
	}

	// The stored token does not move on a verified row, however loudly a
	// re-announce asks - otherwise whoever learned the pubkey could swap in a
	// token of their own and redeem the certificate with it.
	if _, err := enroll.Announce(ctx, enrollDeviceID, pubHex, "attacker-token"); err != nil {
		t.Fatalf("re-announce: %v", err)
	}
	if _, err := enroll.FindForClaim(ctx, enrollDeviceID, "attacker-token"); !errors.Is(err, service.ErrEnrollNotFound) {
		t.Fatalf("a frozen row must not accept a rotated token, got %v", err)
	}
	if _, err := enroll.FindForClaim(ctx, enrollDeviceID, "sealed-token"); err != nil {
		t.Fatalf("the original token must still select the row: %v", err)
	}
}

// TestEnrollmentFirstClaimWins pins the FOR UPDATE. Two users racing to claim
// one row must not both succeed: the loser would find claimed_at already set
// but a devices row in the winner's tenant.
func TestEnrollmentFirstClaimWins(t *testing.T) {
	env := servicetest.Start(t)
	enroll := env.Services.Enrollments
	ctx := context.Background()

	const tA, tB = "enroll-race-a", "enroll-race-b"
	env.SeedTenant(t, tA)
	env.SeedTenant(t, tB)
	userA := seedUser(t, env, tA, "a@enroll-race.test")
	userB := seedUser(t, env, tB, "b@enroll-race.test")

	pubHex, priv := newDeviceKey(t)
	announceAndVerify(t, enroll, enrollDeviceID, pubHex, priv, "race-token")

	type result struct {
		tenant string
		err    error
	}
	results := make([]result, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, c := range []struct {
		tenant string
		user   uuid.UUID
	}{{tA, userA}, {tB, userB}} {
		wg.Add(1)
		go func(i int, tenant string, user uuid.UUID) {
			defer wg.Done()
			<-start
			_, err := enroll.ClaimInto(ctx, enrollDeviceID, pubHex, tenant, user,
				service.DeviceTopicPrefix("thesada", tenant, enrollDeviceID))
			results[i] = result{tenant: tenant, err: err}
		}(i, c.tenant, c.user)
	}
	close(start)
	wg.Wait()

	var won, lost int
	for _, r := range results {
		switch {
		case r.err == nil:
			won++
		case errors.Is(r.err, service.ErrEnrollNotReady):
			lost++
		default:
			t.Fatalf("claim for %s failed unexpectedly: %v", r.tenant, r.err)
		}
	}
	if won != 1 || lost != 1 {
		t.Fatalf("want exactly one winner, got won=%d lost=%d", won, lost)
	}

	// Exactly one devices row exists for the id, in the winning tenant.
	var devices int
	if err := env.Super.QueryRow(ctx,
		`SELECT count(*) FROM devices WHERE device_id = $1`, enrollDeviceID).Scan(&devices); err != nil {
		t.Fatalf("count devices: %v", err)
	}
	if devices != 1 {
		t.Fatalf("devices rows for the id = %d, want 1", devices)
	}
}

// TestEnrollmentResetStartsAFreshCycle - revoking used to leave the row sealed,
// so the hardware could never enroll again. The spec: "next POST starts a fresh
// cycle".
func TestEnrollmentResetStartsAFreshCycle(t *testing.T) {
	env := servicetest.Start(t)
	enroll := env.Services.Enrollments
	ctx := context.Background()

	const tenant = "enroll-reset"
	env.SeedTenant(t, tenant)
	owner := seedUser(t, env, tenant, "owner@enroll-reset.test")

	pubHex, priv := newDeviceKey(t)
	announceAndVerify(t, enroll, enrollDeviceID, pubHex, priv, "cycle-one")
	prefix := service.DeviceTopicPrefix("thesada", tenant, enrollDeviceID)
	if _, err := enroll.ClaimInto(ctx, enrollDeviceID, pubHex, tenant, owner, prefix); err != nil {
		t.Fatalf("ClaimInto: %v", err)
	}
	if _, err := enroll.MarkDelivered(ctx, enrollDeviceID, pubHex, "cycle-one"); err != nil {
		t.Fatalf("MarkDelivered: %v", err)
	}

	// Sealed: proving possession again is refused.
	challenge, err := enroll.Announce(ctx, enrollDeviceID, pubHex, "cycle-one")
	if err != nil {
		t.Fatalf("announce: %v", err)
	}
	if err := enroll.Verify(ctx, enrollDeviceID, pubHex,
		ed25519.Sign(priv, []byte(challenge))); !errors.Is(err, service.ErrEnrollSealed) {
		t.Fatalf("verify before reset = %v, want ErrEnrollSealed", err)
	}

	// The revoke paths call this. It clears every row under the id, squatter
	// litter included.
	n, err := enroll.Reset(ctx, enrollDeviceID)
	if err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if n != 1 {
		t.Fatalf("Reset removed %d rows, want 1", n)
	}

	// A whole new cycle, including a freshly minted keypair after an
	// identity.reset on the device.
	newPub, newPriv := newDeviceKey(t)
	announceAndVerify(t, enroll, enrollDeviceID, newPub, newPriv, "cycle-two")
	if _, err := enroll.ClaimInto(ctx, enrollDeviceID, newPub, tenant, owner, prefix); err != nil {
		t.Fatalf("re-claim after reset: %v", err)
	}

	// Reset on an id with no rows is a no-op, not an error - the revoke paths
	// call it for every device, enrolled or not.
	if n, err := enroll.Reset(ctx, "thesada-000000000000"); err != nil || n != 0 {
		t.Fatalf("Reset of an unknown id = %d, %v; want 0, nil", n, err)
	}
}

// TestEnrollmentPrune - announce is unauthenticated, so these rows are the one
// thing in the schema any caller on the internet can create. They have to age
// out on their own; a claimed row is the record of a real device and stays.
func TestEnrollmentPrune(t *testing.T) {
	env := servicetest.Start(t)
	enroll := env.Services.Enrollments
	ctx := context.Background()

	const tenant = "enroll-prune"
	env.SeedTenant(t, tenant)
	owner := seedUser(t, env, tenant, "owner@enroll-prune.test")

	// Fresh unclaimed: survives.
	freshPub, _ := newDeviceKey(t)
	if _, err := enroll.Announce(ctx, "thesada-111111111111", freshPub, "fresh"); err != nil {
		t.Fatalf("announce fresh: %v", err)
	}

	// Stale unclaimed: goes.
	stalePub, _ := newDeviceKey(t)
	if _, err := enroll.Announce(ctx, "thesada-222222222222", stalePub, "stale"); err != nil {
		t.Fatalf("announce stale: %v", err)
	}

	// Stale but claimed: stays, because it is the record of a real device.
	claimedPub, claimedPriv := newDeviceKey(t)
	announceAndVerify(t, enroll, enrollDeviceID, claimedPub, claimedPriv, "claimed")
	if _, err := enroll.ClaimInto(ctx, enrollDeviceID, claimedPub, tenant, owner,
		service.DeviceTopicPrefix("thesada", tenant, enrollDeviceID)); err != nil {
		t.Fatalf("ClaimInto: %v", err)
	}

	aged := time.Now().Add(-service.EnrollmentTTL - time.Hour)
	if _, err := env.Super.Exec(ctx,
		`UPDATE device_enrollments SET last_seen_at = $1 WHERE device_id <> $2`,
		aged, "thesada-111111111111"); err != nil {
		t.Fatalf("age rows: %v", err)
	}

	n, err := enroll.Prune(ctx)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("Prune deleted %d rows, want 1 (the stale unclaimed one)", n)
	}
	var left []string
	rows, err := env.Super.Query(ctx, `SELECT device_id FROM device_enrollments ORDER BY device_id`)
	if err != nil {
		t.Fatalf("list rows: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		left = append(left, id)
	}
	if len(left) != 2 || left[0] != "thesada-111111111111" || left[1] != enrollDeviceID {
		t.Fatalf("surviving rows = %v, want the claimed one and the fresh one", left)
	}
}
