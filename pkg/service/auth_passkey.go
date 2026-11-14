package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/bcrypt"

	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/db"
)

const passkeyCeremonyLifetime = 5 * time.Minute

// maxPasskeysPerUser bounds the list a login offers and the settings page shows.
const maxPasskeysPerUser = 10

// maxPasskeyNameLen keeps a key label to one table row.
const maxPasskeyNameLen = 64

// ErrPasskeysOff means the server has no usable WebAuthn relying party config.
var ErrPasskeysOff = errors.New("passkeys are not configured")

// ErrPasskeyLimit means the account already holds maxPasskeysPerUser keys.
var ErrPasskeyLimit = errors.New("passkey limit reached")

// Passkey is one registered key as the settings page lists it.
type Passkey struct {
	ID         int64
	Name       string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// passkeyUser adapts a user and its stored keys to the webauthn.User interface.
type passkeyUser struct {
	id          uuid.UUID
	email       string
	displayName string
	creds       []webauthn.Credential
}

func (u *passkeyUser) WebAuthnID() []byte                         { return u.id[:] }
func (u *passkeyUser) WebAuthnName() string                       { return u.email }
func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }
func (u *passkeyUser) WebAuthnDisplayName() string {
	if u.displayName != "" {
		return u.displayName
	}
	return u.email
}

// newRelyingParty builds the WebAuthn relying party from config, or nil when
// the config cannot back one, so passkeys stay off instead of failing boot.
// in: config. out: relying party or nil.
func newRelyingParty(cfg *config.Config) *webauthn.WebAuthn {
	if cfg == nil || cfg.WebAuthnRPID == "" || len(cfg.WebAuthnOrigins) == 0 {
		return nil
	}
	rp, err := webauthn.New(&webauthn.Config{
		RPID:          cfg.WebAuthnRPID,
		RPDisplayName: "thesada",
		RPOrigins:     cfg.WebAuthnOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementDiscouraged,
			UserVerification: protocol.VerificationPreferred,
		},
		AttestationPreference: protocol.PreferNoAttestation,
	})
	if err != nil {
		slog.Warn("auth.passkey.config_invalid", "rp_id", cfg.WebAuthnRPID, "err", err)
		return nil
	}
	return rp
}

// PasskeysEnabled reports whether this server can run passkey ceremonies.
// in: none. out: bool.
func (s *AuthService) PasskeysEnabled() bool { return s.rp != nil }

// ListPasskeys returns the user's keys, newest first.
// in: tenant id, user id. out: keys, error.
func (s *AuthService) ListPasskeys(tenantID string, userID uuid.UUID) ([]Passkey, error) {
	ctx := context.Background()
	var out []Passkey
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, name, created_at, last_used_at FROM user_passkeys
			 WHERE user_id = $1 ORDER BY created_at DESC, id DESC`, userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p Passkey
			if err := rows.Scan(&p.ID, &p.Name, &p.CreatedAt, &p.LastUsedAt); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("auth: list passkeys: %w", err)
	}
	return out, nil
}

// HasPasskeys reports whether the user has at least one key. A lookup error is not "none".
// in: tenant id, user id. out: has keys, error.
func (s *AuthService) HasPasskeys(tenantID string, userID uuid.UUID) (bool, error) {
	ctx := context.Background()
	var has bool
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM user_passkeys WHERE user_id = $1)`, userID).Scan(&has)
	})
	if err != nil {
		return false, fmt.Errorf("auth: has passkeys: %w", err)
	}
	return has, nil
}

// SecondFactors reports which second factors a login must offer.
// in: tenant id, user id. out: TOTP secret ("" when off), passkeys on, error.
func (s *AuthService) SecondFactors(tenantID string, userID uuid.UUID) (string, bool, error) {
	secret, totpOn, err := s.EnrolledTOTP(tenantID, userID)
	if err != nil {
		return "", false, err
	}
	keys, err := s.HasPasskeys(tenantID, userID)
	if err != nil {
		return "", false, err
	}
	if !totpOn {
		secret = ""
	}
	return secret, keys, nil
}

// BeginPasskeyRegistration starts enrolling a key for a signed-in user.
// in: tenant id, user. out: creation options JSON, ceremony token, expiry, error.
func (s *AuthService) BeginPasskeyRegistration(tenantID string, u *User) ([]byte, string, time.Time, error) {
	if s.rp == nil {
		return nil, "", time.Time{}, ErrPasskeysOff
	}
	ctx := context.Background()
	var pu *passkeyUser
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		var err error
		pu, err = loadPasskeyUser(ctx, tx, u)
		return err
	})
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("auth: begin passkey registration: %w", err)
	}
	if len(pu.creds) >= maxPasskeysPerUser {
		return nil, "", time.Time{}, ErrPasskeyLimit
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(pu.creds))
	for _, c := range pu.creds {
		exclude = append(exclude, c.Descriptor())
	}
	creation, session, err := s.rp.BeginRegistration(pu, webauthn.WithExclusions(exclude))
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("auth: begin passkey registration: %w", err)
	}
	token, expires, err := s.storeCeremony(ctx, tenantID, u.ID, "register", session)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	opts, err := json.Marshal(creation)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("auth: passkey options: %w", err)
	}
	return opts, token, expires, nil
}

// FinishPasskeyRegistration verifies the authenticator's answer and stores the key.
// in: tenant id, user, ceremony token, key name, response body. out: error.
func (s *AuthService) FinishPasskeyRegistration(tenantID string, u *User, token, name string, body []byte) error {
	if s.rp == nil {
		return ErrPasskeysOff
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Security key"
	}
	if len([]rune(name)) > maxPasskeyNameLen {
		name = string([]rune(name)[:maxPasskeyNameLen])
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		return ErrBadCredentials
	}
	hash := sha256.Sum256([]byte(token))
	ctx := context.Background()
	err = db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		session, err := takeCeremony(ctx, tx, hash[:], u.ID, "register")
		if err != nil {
			return err
		}
		pu, err := loadPasskeyUser(ctx, tx, u)
		if err != nil {
			return err
		}
		if len(pu.creds) >= maxPasskeysPerUser {
			return ErrPasskeyLimit
		}
		cred, err := s.rp.CreateCredential(pu, *session, parsed)
		if err != nil {
			slog.Info("auth.passkey.register_rejected", "user_id", u.ID, "err", err)
			return ErrBadCredentials
		}
		transports := make([]string, 0, len(cred.Transport))
		for _, t := range cred.Transport {
			transports = append(transports, string(t))
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO user_passkeys (user_id, credential_id, public_key, attestation_type,
			       aaguid, sign_count, transports, backup_eligible, backup_state, name)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			u.ID, cred.ID, cred.PublicKey, cred.AttestationType, cred.Authenticator.AAGUID,
			int64(cred.Authenticator.SignCount), transports,
			cred.Flags.BackupEligible, cred.Flags.BackupState, name)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrBadCredentials // this credential is already registered
		}
		return err
	})
	if errors.Is(err, ErrBadCredentials) || errors.Is(err, ErrExpired) || errors.Is(err, ErrPasskeyLimit) {
		return err
	}
	if err != nil {
		return fmt.Errorf("auth: finish passkey registration: %w", err)
	}
	return nil
}

// DeletePasskey removes one of the user's keys.
// in: tenant id, user id, key id. out: error (ErrNotFound when it is not theirs).
func (s *AuthService) DeletePasskey(tenantID string, userID uuid.UUID, id int64) error {
	ctx := context.Background()
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM user_passkeys WHERE id = $1 AND user_id = $2`, id, userID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
	if errors.Is(err, ErrNotFound) {
		return err
	}
	if err != nil {
		return fmt.Errorf("auth: delete passkey: %w", err)
	}
	return nil
}

// BeginPasskeyLoginAny starts the assertion for a pending second-factor challenge.
// The challenge row is the only tenant pointer, so the read is cross-tenant.
// in: raw challenge token. out: request options JSON, error.
func (s *AuthService) BeginPasskeyLoginAny(challengeToken string) ([]byte, error) {
	if s.rp == nil {
		return nil, ErrPasskeysOff
	}
	hash := sha256.Sum256([]byte(challengeToken))
	ctx := context.Background()
	var opts []byte
	err := db.WithAdminAudit(ctx, s.pools.Admin, "auth.begin_passkey_login", func(tx pgx.Tx) error {
		u, _, err := pendingChallengeUser(ctx, tx, hash[:])
		if err != nil {
			return err
		}
		pu, err := loadPasskeyUser(ctx, tx, u)
		if err != nil {
			return err
		}
		if len(pu.creds) == 0 {
			return ErrBadCredentials
		}
		assertion, session, err := s.rp.BeginLogin(pu)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(session)
		if err != nil {
			return err
		}
		// One live login ceremony per challenge: a second begin replaces the first.
		if _, err := tx.Exec(ctx, `
			INSERT INTO passkey_ceremonies (token_hash, user_id, kind, session, expires_at)
			VALUES ($1, $2, 'login', $3, $4)
			ON CONFLICT (token_hash) DO UPDATE SET session = EXCLUDED.session, expires_at = EXCLUDED.expires_at
			 WHERE passkey_ceremonies.user_id = EXCLUDED.user_id AND passkey_ceremonies.kind = 'login'`,
			hash[:], u.ID, raw, time.Now().Add(passkeyCeremonyLifetime)); err != nil {
			return err
		}
		opts, err = json.Marshal(assertion)
		return err
	})
	if errors.Is(err, ErrExpired) || errors.Is(err, ErrBadCredentials) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("auth: begin passkey login: %w", err)
	}
	return opts, nil
}

// FinishPasskeyLoginAny checks the assertion and consumes the challenge on success.
// A sign count that did not grow is refused as a possible cloned key.
// in: raw challenge token, response body. out: user, session method, error.
func (s *AuthService) FinishPasskeyLoginAny(challengeToken string, body []byte) (*User, string, error) {
	if s.rp == nil {
		return nil, "", ErrPasskeysOff
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return nil, "", ErrBadCredentials
	}
	hash := sha256.Sum256([]byte(challengeToken))
	ctx := context.Background()
	var u *User
	var method string
	var rejected bool
	err = db.WithAdminAudit(ctx, s.pools.Admin, "auth.finish_passkey_login", func(tx pgx.Tx) error {
		var err error
		u, method, err = pendingChallengeUser(ctx, tx, hash[:])
		if err != nil {
			return err
		}
		session, err := takeCeremony(ctx, tx, hash[:], u.ID, "login")
		if err != nil {
			return err
		}
		pu, err := loadPasskeyUser(ctx, tx, u)
		if err != nil {
			return err
		}
		cred, err := s.rp.ValidateLogin(pu, *session, parsed)
		if err != nil {
			slog.Info("auth.passkey.login_rejected", "user_id", u.ID, "err", err)
			rejected = true
			return noteWrongTOTP(ctx, tx, hash[:])
		}
		if cred.Authenticator.CloneWarning {
			slog.Warn("auth.passkey.counter_replayed", "user_id", u.ID, "sign_count", cred.Authenticator.SignCount)
			rejected = true
			return noteWrongTOTP(ctx, tx, hash[:])
		}
		// Guarded so two parallel assertions with one counter cannot both pass.
		tag, err := tx.Exec(ctx, `
			UPDATE user_passkeys SET sign_count = $3, last_used_at = now(), backup_state = $4
			 WHERE user_id = $1 AND credential_id = $2
			   AND (sign_count < $3 OR (sign_count = 0 AND $3 = 0))`,
			u.ID, cred.ID, int64(cred.Authenticator.SignCount), cred.Flags.BackupState)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			rejected = true
			return noteWrongTOTP(ctx, tx, hash[:])
		}
		tag, err = tx.Exec(ctx, `DELETE FROM totp_challenges WHERE token_hash = $1`, hash[:])
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrExpired
		}
		return nil
	})
	if rejected && err == nil {
		return nil, "", ErrBadCredentials
	}
	if errors.Is(err, ErrExpired) || errors.Is(err, ErrBadCredentials) {
		return nil, "", err
	}
	if err != nil {
		return nil, "", fmt.Errorf("auth: finish passkey login: %w", err)
	}
	return u, method, nil
}

// storeCeremony saves the server half of a ceremony under a fresh token.
// in: ctx, tenant id, user id, kind, session. out: raw token, expiry, error.
func (s *AuthService) storeCeremony(ctx context.Context, tenantID string, userID uuid.UUID, kind string, session *webauthn.SessionData) (string, time.Time, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: passkey token: %w", err)
	}
	raw, err := json.Marshal(session)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: passkey session: %w", err)
	}
	hash := sha256.Sum256([]byte(token))
	expires := time.Now().Add(passkeyCeremonyLifetime)
	err = db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx,
			`INSERT INTO passkey_ceremonies (token_hash, user_id, kind, session, expires_at) VALUES ($1, $2, $3, $4, $5)`,
			hash[:], userID, kind, raw, expires)
		return execErr
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: store passkey ceremony: %w", err)
	}
	return token, expires, nil
}

// takeCeremony deletes and returns a live ceremony, so each one is used once.
// in: ctx, tx, token hash, user id, kind. out: session, error (ErrExpired when gone).
func takeCeremony(ctx context.Context, tx pgx.Tx, hash []byte, userID uuid.UUID, kind string) (*webauthn.SessionData, error) {
	var raw []byte
	var live bool
	err := tx.QueryRow(ctx, `
		DELETE FROM passkey_ceremonies
		 WHERE token_hash = $1 AND user_id = $2 AND kind = $3
		RETURNING session, expires_at > now()`, hash, userID, kind).Scan(&raw, &live)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !live) {
		return nil, ErrExpired
	}
	if err != nil {
		return nil, err
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(raw, &session); err != nil {
		return nil, err
	}
	if !bytes.Equal(session.UserID, userID[:]) {
		return nil, ErrExpired
	}
	return &session, nil
}

// pendingChallengeUser loads the user behind a live second-factor challenge.
// in: ctx, tx, token hash. out: user, session method, error (ErrExpired when gone).
func pendingChallengeUser(ctx context.Context, tx pgx.Tx, hash []byte) (*User, string, error) {
	var u User
	var method string
	err := tx.QueryRow(ctx, `
		SELECT u.id, u.tenant_id, u.email, u.display_name, u.telegram_chat_id,
		       u.is_admin, u.is_super_admin, u.created_at, u.last_login_at, c.method
		  FROM totp_challenges c
		  JOIN users u ON u.id = c.user_id
		 WHERE c.token_hash = $1 AND c.expires_at > now()`, hash).Scan(
		&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.TelegramChatID,
		&u.IsAdmin, &u.IsSuperAdmin, &u.CreatedAt, &u.LastLoginAt, &method)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", ErrExpired
	}
	if err != nil {
		return nil, "", err
	}
	return &u, method, nil
}

// loadPasskeyUser reads the user's keys into the shape the library checks.
// in: ctx, tx, user. out: adapter, error.
func loadPasskeyUser(ctx context.Context, tx pgx.Tx, u *User) (*passkeyUser, error) {
	rows, err := tx.Query(ctx, `
		SELECT credential_id, public_key, attestation_type, aaguid, sign_count,
		       transports, backup_eligible, backup_state
		  FROM user_passkeys WHERE user_id = $1 ORDER BY id`, u.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	pu := &passkeyUser{id: u.ID, email: u.Email}
	if u.DisplayName != nil {
		pu.displayName = *u.DisplayName
	}
	for rows.Next() {
		var c webauthn.Credential
		var count int64
		var transports []string
		if err := rows.Scan(&c.ID, &c.PublicKey, &c.AttestationType, &c.Authenticator.AAGUID,
			&count, &transports, &c.Flags.BackupEligible, &c.Flags.BackupState); err != nil {
			return nil, err
		}
		c.Authenticator.SignCount = signCount32(count)
		for _, t := range transports {
			c.Transport = append(c.Transport, protocol.AuthenticatorTransport(t))
		}
		pu.creds = append(pu.creds, c)
	}
	return pu, rows.Err()
}

// signCount32 maps a stored counter back to the authenticator's uint32.
// in: stored count. out: count, clamped to the uint32 range.
func signCount32(n int64) uint32 {
	switch {
	case n < 0:
		return 0
	case n > math.MaxUint32:
		return math.MaxUint32
	}
	return uint32(n)
}

// ConfirmPassword re-checks the signed-in user's password before a key change.
// Rate-limited per user, and unlike a login it does not touch last_login_at.
// in: tenant id, user id, password. out: ok, error (ErrLoginRateLimited at the cap).
func (s *AuthService) ConfirmPassword(tenantID string, userID uuid.UUID, password string) (bool, error) {
	if !s.loginEmailLimits.Allow("reauth:" + userID.String()) {
		return false, ErrLoginRateLimited
	}
	ctx := context.Background()
	var hash *string
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT password_hash FROM users WHERE id = $1`, userID).Scan(&hash)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, fmt.Errorf("auth: confirm password: %w", err)
	}
	if hash == nil || *hash == "" {
		equaliseLoginTiming(password)
		return false, nil
	}
	return bcrypt.CompareHashAndPassword([]byte(*hash), []byte(password)) == nil, nil
}

// PendingFactorsAny reports which second factors a pending challenge may use.
// in: raw challenge token. out: TOTP on, passkeys on, error (ErrExpired when gone).
func (s *AuthService) PendingFactorsAny(challengeToken string) (bool, bool, error) {
	hash := sha256.Sum256([]byte(challengeToken))
	ctx := context.Background()
	var totpOn, keys bool
	err := db.WithAdminAudit(ctx, s.pools.Admin, "auth.pending_factors", func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			SELECT COALESCE(u.totp_secret, '') <> '',
			       EXISTS (SELECT 1 FROM user_passkeys p WHERE p.user_id = u.id)
			  FROM totp_challenges c
			  JOIN users u ON u.id = c.user_id
			 WHERE c.token_hash = $1 AND c.expires_at > now()`, hash[:]).Scan(&totpOn, &keys)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrExpired
		}
		return err
	})
	if errors.Is(err, ErrExpired) {
		return false, false, err
	}
	if err != nil {
		return false, false, fmt.Errorf("auth: pending factors: %w", err)
	}
	return totpOn, keys, nil
}
