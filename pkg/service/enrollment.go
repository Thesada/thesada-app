package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/db"
	"thesada.app/app/pkg/pki"
)

// ---------------------------------------------------------------------------
// EnrollmentService - devices that exist but belong to nobody yet
// ---------------------------------------------------------------------------

// EnrollmentService stores devices that have announced themselves but have not
// been claimed into a tenant.
//
// Every method runs through db.WithAdminAudit. That is not laziness about
// tenant scoping: device_enrollments has no tenant column, because an
// unclaimed device genuinely belongs to nobody (see 0028). The audit line is
// the compensating control - every touch of this table is logged with a
// reason.
type EnrollmentService struct {
	cfg   *config.Config
	pools db.Pools
}

// Errors callers distinguish. Handlers deliberately collapse several of these
// into one response so the endpoint does not become an oracle.
var (
	ErrEnrollNotFound  = errors.New("enrollment: no such device")
	ErrEnrollSealed    = errors.New("enrollment: certificate already delivered")
	ErrEnrollKeyChange = errors.New("enrollment: public key does not match the one on file")
	ErrEnrollNotReady  = errors.New("enrollment: not verified and claimed")
	ErrEnrollBadProof  = errors.New("enrollment: proof did not verify")
	// ErrEnrollNoOwner means a claim arrived without a user to attribute it
	// to. The spec makes the owner part of the claim, so this fails rather than
	// writing a NULL that nothing later fills in.
	ErrEnrollNoOwner = errors.New("enrollment: claim needs an owner")
	// ErrEnrollAmbiguous means several rows carry the presented claim token
	// and nothing on the request says which one the caller meant.
	ErrEnrollAmbiguous = errors.New("enrollment: more than one row matches that claim token")
)

// Enrollment is one unclaimed-or-claimed device announcement.
type Enrollment struct {
	DeviceID           string
	PubkeyHex          string
	ClaimTokenHash     string
	Challenge          *string
	ChallengeExpiresAt *time.Time
	VerifiedAt         *time.Time
	ClaimedByTenant    *string
	ClaimedAt          *time.Time
	CertDeliveredAt    *time.Time
	FirstSeenAt        time.Time
	LastSeenAt         time.Time
}

const enrollmentColumns = `device_id, pubkey_hex, claim_token_hash, challenge,
	challenge_expires_at, verified_at, claimed_by_tenant, claimed_at,
	cert_delivered_at, first_seen_at, last_seen_at`

func scanEnrollment(row pgx.Row) (*Enrollment, error) {
	var e Enrollment
	err := row.Scan(&e.DeviceID, &e.PubkeyHex, &e.ClaimTokenHash, &e.Challenge,
		&e.ChallengeExpiresAt, &e.VerifiedAt, &e.ClaimedByTenant, &e.ClaimedAt,
		&e.CertDeliveredAt, &e.FirstSeenAt, &e.LastSeenAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrEnrollNotFound
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// newNonce returns n random bytes as lowercase hex.
func newNonce(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("enrollment: nonce: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// scanEnrollments reads every row for one device_id. Plural on purpose: rows
// are keyed on (device_id, pubkey_hex), so a guessable id yields as many rows
// as there are keypairs that claimed it. See migration 0028.
// in: rows. out: enrollments, error.
func scanEnrollments(rows pgx.Rows) ([]Enrollment, error) {
	defer rows.Close()
	var out []Enrollment
	for rows.Next() {
		e, err := scanEnrollment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}

// claimTokenMatches returns every row whose stored hash matches token - all of
// them, because claim_token_hash has no unique constraint. Every candidate is
// compared in constant time, so the walk says nothing about which one matched.
// in: candidate rows, presented plaintext token. out: matching rows.
func claimTokenMatches(rows []Enrollment, token string) []*Enrollment {
	var out []*Enrollment
	for i := range rows {
		if ClaimTokenMatches(token, rows[i].ClaimTokenHash) {
			out = append(out, &rows[i])
		}
	}
	return out
}

// Announce records an announcement for (device_id, pubkey) and issues a fresh
// challenge to sign. Succeeds for any well-formed pair - refusal would be a
// device-id oracle; the token hash freezes once verified (docs/invariants.md).
// in: ctx, device id, lowercase-hex pubkey, plaintext claim token.
// out: challenge to be signed, error.
func (s *EnrollmentService) Announce(ctx context.Context, deviceID, pubkeyHex, claimToken string) (string, error) {
	if !pki.ValidDeviceID(deviceID) {
		return "", ErrEnrollNotFound
	}
	if _, err := pki.ParseDevicePublicKey(pubkeyHex); err != nil {
		return "", err
	}
	challenge, err := newNonce(32)
	if err != nil {
		return "", err
	}
	expires := time.Now().Add(ChallengeTTL)
	tokenHash := HashClaimToken(claimToken)

	err = db.WithAdminAudit(ctx, s.pools.Admin, "device enrollment announce", func(tx pgx.Tx) error {
		existing, err := scanEnrollment(tx.QueryRow(ctx,
			`SELECT `+enrollmentColumns+` FROM device_enrollments
			  WHERE device_id = $1 AND pubkey_hex = $2 FOR UPDATE`,
			deviceID, pubkeyHex))
		switch {
		case errors.Is(err, ErrEnrollNotFound):
			// ON CONFLICT rather than a bare INSERT: FOR UPDATE cannot lock a
			// row that does not exist yet, so two first announces for the same
			// pair can both reach here.
			_, err = tx.Exec(ctx,
				`INSERT INTO device_enrollments
				   (device_id, pubkey_hex, claim_token_hash, challenge, challenge_expires_at)
				 VALUES ($1, $2, $3, $4, $5)
				 ON CONFLICT (device_id, pubkey_hex) DO UPDATE
				   SET challenge            = EXCLUDED.challenge,
				       challenge_expires_at = EXCLUDED.challenge_expires_at,
				       last_seen_at         = now()`,
				deviceID, pubkeyHex, tokenHash, challenge, expires)
			return err
		case err != nil:
			return err
		}
		// Assertion, not a gate: the row was selected by pubkey, so this
		// cannot fire unless a future edit widens that WHERE clause.
		if !PubkeyStable(existing.PubkeyHex, pubkeyHex) {
			return ErrEnrollKeyChange
		}
		// Rotation is normal before proof - the device mints a fresh token per
		// portal session. After proof the stored hash stands, and the refusal
		// is silent: answering differently would tell an unauthenticated
		// caller that this device_id is real and already verified.
		storedToken := existing.ClaimTokenHash
		if !ClaimTokenFrozen(existing.VerifiedAt) {
			storedToken = tokenHash
		}
		_, err = tx.Exec(ctx,
			`UPDATE device_enrollments
			    SET claim_token_hash = $3, challenge = $4,
			        challenge_expires_at = $5, last_seen_at = now()
			  WHERE device_id = $1 AND pubkey_hex = $2`,
			deviceID, pubkeyHex, storedToken, challenge, expires)
		return err
	})
	if err != nil {
		return "", err
	}
	return challenge, nil
}

// Verify consumes the challenge on (device_id, pubkey) if sig is a valid
// signature over it by that same pubkey. The burn commits in its own
// transaction before the signature is judged: one tx would roll the burn
// back on a bad proof and hand the nonce back to the caller.
// in: ctx, device id, lowercase-hex pubkey, signature bytes. out: error.
func (s *EnrollmentService) Verify(ctx context.Context, deviceID, pubkeyHex string, sig []byte) error {
	if !pki.ValidDeviceID(deviceID) {
		return ErrEnrollBadProof
	}
	if _, err := pki.ParseDevicePublicKey(pubkeyHex); err != nil {
		return ErrEnrollBadProof
	}
	challenge := ""
	err := db.WithAdminAudit(ctx, s.pools.Admin, "device enrollment verify", func(tx pgx.Tx) error {
		e, err := scanEnrollment(tx.QueryRow(ctx,
			`SELECT `+enrollmentColumns+` FROM device_enrollments
			  WHERE device_id = $1 AND pubkey_hex = $2 FOR UPDATE`,
			deviceID, pubkeyHex))
		if errors.Is(err, ErrEnrollNotFound) {
			// An unannounced pair and a bad signature are one answer: neither
			// caller proved anything about this device.
			return ErrEnrollBadProof
		}
		if err != nil {
			return err
		}
		if !ProofAllowed(e.CertDeliveredAt) {
			return ErrEnrollSealed
		}
		if e.Challenge != nil {
			challenge = *e.Challenge
		}
		if !ChallengeUsable(challenge, e.ChallengeExpiresAt, time.Now()) {
			return ErrEnrollBadProof
		}
		_, err = tx.Exec(ctx,
			`UPDATE device_enrollments
			    SET challenge = NULL, challenge_expires_at = NULL, last_seen_at = now()
			  WHERE device_id = $1 AND pubkey_hex = $2`, deviceID, pubkeyHex)
		return err
	})
	if err != nil {
		return err
	}
	if err := pki.VerifyDeviceProof(deviceID, pubkeyHex, []byte(challenge), sig); err != nil {
		return ErrEnrollBadProof
	}
	// A crash here loses a valid proof but never the burn: the device
	// re-announces for a fresh challenge, single-use holds.
	return db.WithAdminAudit(ctx, s.pools.Admin, "device enrollment verified", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE device_enrollments SET verified_at = now()
			  WHERE device_id = $1 AND pubkey_hex = $2`, deviceID, pubkeyHex)
		return err
	})
}

// FindByDeviceKey returns the enrollment for (device_id, pubkey) when the
// presented claim token matches THAT row. A device always knows its own public
// key, and the token is not unique, so the token must not select the row.
// in: ctx, device id, lowercase-hex pubkey, presented token. out: enrollment, error.
func (s *EnrollmentService) FindByDeviceKey(ctx context.Context, deviceID, pubkeyHex, claimToken string) (*Enrollment, error) {
	if !pki.ValidDeviceID(deviceID) || claimToken == "" {
		return nil, ErrEnrollNotFound
	}
	if _, err := pki.ParseDevicePublicKey(pubkeyHex); err != nil {
		return nil, ErrEnrollNotFound
	}
	var out *Enrollment
	err := db.WithAdminAudit(ctx, s.pools.Admin, "device enrollment read", func(tx pgx.Tx) error {
		e, err := scanEnrollment(tx.QueryRow(ctx,
			`SELECT `+enrollmentColumns+` FROM device_enrollments
			  WHERE device_id = $1 AND pubkey_hex = $2`, deviceID, pubkeyHex))
		if err != nil {
			return err
		}
		if !ClaimTokenMatches(claimToken, e.ClaimTokenHash) {
			return ErrEnrollNotFound
		}
		out = e
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// FindForClaim returns the row the human claim form is about: the sole match
// for (device_id, claim_token), or the sole claimable one when several rows
// carry that token. Ambiguity is refused, never resolved by ordering.
// in: ctx, device id, presented plaintext token. out: enrollment, error.
func (s *EnrollmentService) FindForClaim(ctx context.Context, deviceID, claimToken string) (*Enrollment, error) {
	if !pki.ValidDeviceID(deviceID) || claimToken == "" {
		return nil, ErrEnrollNotFound
	}
	// The only lookup left that a token resolves on its own: the form has no
	// pubkey to offer. Resolving it by ordering handed a user somebody else's
	// row under a success page.
	var out *Enrollment
	err := db.WithAdminAudit(ctx, s.pools.Admin, "device enrollment claim lookup", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+enrollmentColumns+` FROM device_enrollments
			  WHERE device_id = $1 ORDER BY pubkey_hex`, deviceID)
		if err != nil {
			return err
		}
		candidates, err := scanEnrollments(rows)
		if err != nil {
			return err
		}
		matches := claimTokenMatches(candidates, claimToken)
		switch len(matches) {
		case 0:
			return ErrEnrollNotFound
		case 1:
			out = matches[0]
			return nil
		}
		// Several rows carry this token, so somebody announced with a token
		// read off the same QR. A claimed or unverified row cannot be claimed
		// anyway; if that narrows the set to one the user still gets their
		// device, and otherwise nobody gets a silently chosen one.
		var claimable []*Enrollment
		for _, m := range matches {
			if ClaimAllowed(m.VerifiedAt, m.ClaimedAt) {
				claimable = append(claimable, m)
			}
		}
		if len(claimable) != 1 {
			return ErrEnrollAmbiguous
		}
		out = claimable[0]
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MarkDelivered seals one enrollment row, ONLY from the device's explicit
// acknowledgement: sealing at hand-over would brick a device that never got
// the bytes, ack-seal makes that a retried re-sign (docs/invariants.md).
// in: ctx, device id, row pubkey, presented token. out: claimed tenant, error.
func (s *EnrollmentService) MarkDelivered(ctx context.Context, deviceID, pubkeyHex, claimToken string) (string, error) {
	var tenant string
	err := db.WithAdminAudit(ctx, s.pools.Admin, "device enrollment deliver", func(tx pgx.Tx) error {
		e, err := scanEnrollment(tx.QueryRow(ctx,
			`SELECT `+enrollmentColumns+` FROM device_enrollments
			  WHERE device_id = $1 AND pubkey_hex = $2 FOR UPDATE`,
			deviceID, pubkeyHex))
		if err != nil {
			return err
		}
		// The pubkey is public - it is on the QR and on chip.info - so sealing
		// needs the token as well. Otherwise anyone who has read a key can
		// seal the row before the device collects its certificate.
		if !ClaimTokenMatches(claimToken, e.ClaimTokenHash) {
			return ErrEnrollNotFound
		}
		if !DeliverAllowed(e.VerifiedAt, e.ClaimedAt, e.CertDeliveredAt) {
			return ErrEnrollNotReady
		}
		if e.ClaimedByTenant == nil {
			return ErrEnrollNotReady
		}
		tenant = *e.ClaimedByTenant
		_, err = tx.Exec(ctx,
			`UPDATE device_enrollments
			    SET cert_delivered_at = now(), last_seen_at = now()
			  WHERE device_id = $1 AND pubkey_hex = $2`, deviceID, pubkeyHex)
		return err
	})
	return tenant, err
}

// ClaimInto binds a verified enrollment to a tenant AND creates the devices
// row in ONE admin-pool transaction - a split has no recovery when the second
// half fails (docs/invariants.md). Dynsec runs after, idempotent, by the
// caller; a claim already held by this tenant and user replays, not refuses.
// in: ctx, device id, row pubkey, tenant id, claiming user, mqtt topic prefix.
// out: device pk, error.
func (s *EnrollmentService) ClaimInto(ctx context.Context, deviceID, pubkeyHex, tenantID string, ownerUserID uuid.UUID, topicPrefix string) (uuid.UUID, error) {
	if ownerUserID == uuid.Nil {
		return uuid.Nil, ErrEnrollNoOwner
	}
	var devicePk uuid.UUID
	err := db.WithAdminAudit(ctx, s.pools.Admin, "device enrollment claim into tenant", func(tx pgx.Tx) error {
		e, err := scanEnrollment(tx.QueryRow(ctx,
			`SELECT `+enrollmentColumns+` FROM device_enrollments
			  WHERE device_id = $1 AND pubkey_hex = $2 FOR UPDATE`,
			deviceID, pubkeyHex))
		if err != nil {
			return err
		}
		if ClaimRetryAllowed(e.ClaimedAt, e.ClaimedByTenant, tenantID) {
			// The claim itself already landed; what failed was the broker
			// provisioning the caller runs after this returns. Hand back the
			// same devices row so that step can be retried. A row owned by
			// somebody else is not this user's claim to replay.
			err := tx.QueryRow(ctx,
				`SELECT id FROM devices
				  WHERE tenant_id = $1 AND device_id = $2 AND owner_user_id = $3`,
				tenantID, deviceID, ownerUserID).Scan(&devicePk)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrEnrollNotReady
			}
			return err
		}
		if !ClaimAllowed(e.VerifiedAt, e.ClaimedAt) {
			return ErrEnrollNotReady
		}
		// owner_user_id is written here and nowhere else on this path: the spec
		// makes the claiming user the owner, and no later step revisits it.
		// The prefix must be written now too. It is otherwise only ever set
		// from the MQTT ingest path, and a device that has never published
		// would leave it NULL - which yields an ACL that does not match what
		// the device actually publishes on.
		if err := tx.QueryRow(ctx,
			`INSERT INTO devices (tenant_id, device_id, owner_user_id, mqtt_topic_prefix)
			 VALUES ($1, $2, $3, $4)
			 ON CONFLICT (tenant_id, device_id)
			   DO UPDATE SET owner_user_id     = EXCLUDED.owner_user_id,
			                 mqtt_topic_prefix = EXCLUDED.mqtt_topic_prefix
			 RETURNING id`,
			tenantID, deviceID, ownerUserID, topicPrefix).Scan(&devicePk); err != nil {
			return err
		}
		_, err = tx.Exec(ctx,
			`UPDATE device_enrollments
			    SET claimed_by_tenant = $3, claimed_at = now()
			  WHERE device_id = $1 AND pubkey_hex = $2`, deviceID, pubkeyHex, tenantID)
		return err
	})
	return devicePk, err
}

// Reset deletes every enrollment row for a device_id so it can start over.
//
// Wired into all three revoke paths. Without it a revoked device is bricked:
// cert_delivered_at stays set, so the row stays sealed and the device can
// never prove itself again. The spec requires the opposite - "next POST starts a
// fresh cycle". It also clears any squatter rows that accumulated under the
// same id.
// in: ctx, device id. out: rows removed, error.
func (s *EnrollmentService) Reset(ctx context.Context, deviceID string) (int64, error) {
	var removed int64
	err := db.WithAdminAudit(ctx, s.pools.Admin, "device enrollment reset", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM device_enrollments WHERE device_id = $1`, deviceID)
		if err != nil {
			return err
		}
		removed = tag.RowsAffected()
		return nil
	})
	return removed, err
}

// Prune deletes stale unclaimed rows. Anyone on the internet can create rows
// here, so they must age out without an operator noticing.
// in: ctx. out: rows deleted, error.
func (s *EnrollmentService) Prune(ctx context.Context) (int64, error) {
	var n int64
	err := db.WithAdminAudit(ctx, s.pools.Admin, "device enrollment prune", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`DELETE FROM device_enrollments
			  WHERE claimed_at IS NULL AND last_seen_at < $1`,
			time.Now().Add(-EnrollmentTTL))
		if err != nil {
			return err
		}
		n = tag.RowsAffected()
		return nil
	})
	return n, err
}

// StartPruner launches the background sweep: one pass immediately, then one
// per interval until ctx is cancelled. Same shape as the alert redispatcher.
//
// Without a caller Prune is decoration. The announce endpoint is
// unauthenticated, so an unclaimed row is something any caller on the internet
// can create; nothing else in the schema has that property, and nothing else
// removes these rows.
// in: ctx (cancel stops the loop), tick interval (<= 0 falls back to an hour).
// out: done channel, closed on exit (test coordination).
func (s *EnrollmentService) StartPruner(ctx context.Context, interval time.Duration) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		if interval <= 0 {
			interval = time.Hour
		}
		sweep := func() {
			n, err := s.Prune(ctx)
			if err != nil {
				slog.Error("device.enroll.prune_failed", "err", err)
				return
			}
			if n > 0 {
				slog.Info("device.enroll.pruned", "rows_deleted", n)
			}
		}
		sweep()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sweep()
			}
		}
	}()
	return done
}
