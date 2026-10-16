package service

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/db"
	"thesada.app/app/pkg/totp"
)

const totpChallengeLifetime = 5 * time.Minute

// totpMaxWrongCodes deletes the challenge. A new IP must not reset the count.
const totpMaxWrongCodes = 5

// TOTPRequired reports whether this lookup must challenge before a session.
// A lookup error is not "off".
// in: secret, enrolled flag, lookup error. out: challenge required, error.
func TOTPRequired(secret string, on bool, err error) (bool, error) {
	if err != nil {
		return false, err
	}
	return on && secret != "", nil
}

// EnrolledTOTP loads the secret and whether this login must challenge.
// A lookup error is not "off".
// in: tenant id, user id. out: secret, challenge required, error.
func (s *AuthService) EnrolledTOTP(tenantID string, userID uuid.UUID) (string, bool, error) {
	secret, on, err := s.TOTPSecret(tenantID, userID)
	required, err := TOTPRequired(secret, on, err)
	return secret, required, err
}

// TOTPSecret returns the base32 secret when this password account has TOTP on.
// in: tenant id, user id. out: secret, enrolled, error.
func (s *AuthService) TOTPSecret(tenantID string, userID uuid.UUID) (string, bool, error) {
	ctx := context.Background()
	var secret *string
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT totp_secret FROM users WHERE id = $1`, userID).Scan(&secret)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, ErrNotFound
	}
	if err != nil {
		return "", false, fmt.Errorf("auth: totp secret: %w", err)
	}
	if secret == nil || *secret == "" {
		return "", false, nil
	}
	return *secret, true, nil
}

// SetTOTPSecret stores a confirmed base32 secret. An empty secret turns TOTP off.
// in: tenant id, user id, base32 secret. out: error.
func (s *AuthService) SetTOTPSecret(tenantID string, userID uuid.UUID, secret string) error {
	ctx := context.Background()
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		var value any
		if secret != "" {
			value = secret
		}
		tag, err := tx.Exec(ctx, `UPDATE users SET totp_secret = $2 WHERE id = $1`, userID, value)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("auth: set totp secret: %w", err)
	}
	return nil
}

// BeginTOTPLogin records a short-lived challenge after a correct local login.
// in: tenant id, user id, session method to resume. out: raw token, expiry, error.
func (s *AuthService) BeginTOTPLogin(tenantID string, userID uuid.UUID, method string) (string, time.Time, error) {
	if method == "" {
		return "", time.Time{}, fmt.Errorf("auth: totp challenge method required")
	}
	token, err := randomToken(32)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: totp token: %w", err)
	}
	hash := sha256.Sum256([]byte(token))
	expires := time.Now().Add(totpChallengeLifetime)
	ctx := context.Background()
	err = db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx,
			`INSERT INTO totp_challenges (token_hash, user_id, expires_at, method) VALUES ($1, $2, $3, $4)`,
			hash[:], userID, expires, method)
		return execErr
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: begin totp: %w", err)
	}
	return token, expires, nil
}

// FinishTOTPLoginAny checks the code and deletes the challenge on success.
// The challenge row is the only tenant pointer, so the read is cross-tenant.
// in: raw challenge token, 6-digit code. out: user, session method, error.
func (s *AuthService) FinishTOTPLoginAny(token, code string) (*User, string, error) {
	hash := sha256.Sum256([]byte(token))
	const q = `
		SELECT u.id, u.tenant_id, u.email, u.display_name, u.telegram_chat_id,
		       u.is_admin, u.is_super_admin, u.created_at, u.last_login_at, u.totp_secret,
		       c.method
		  FROM totp_challenges c
		  JOIN users u ON u.id = c.user_id
		 WHERE c.token_hash = $1 AND c.expires_at > now()`
	ctx := context.Background()
	var u User
	var secret *string
	var method string
	var rejected bool
	err := db.WithAdminAudit(ctx, s.pools.Admin, "auth.finish_totp_login", func(tx pgx.Tx) error {
		scanErr := tx.QueryRow(ctx, q, hash[:]).Scan(
			&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.TelegramChatID,
			&u.IsAdmin, &u.IsSuperAdmin, &u.CreatedAt, &u.LastLoginAt, &secret, &method)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return ErrExpired
		}
		if scanErr != nil {
			return scanErr
		}
		if secret == nil || *secret == "" {
			rejected = true
			_, execErr := tx.Exec(ctx, `DELETE FROM totp_challenges WHERE token_hash = $1`, hash[:])
			return execErr
		}
		ok, checkErr := MatchTOTP(*secret, code)
		if checkErr != nil {
			return checkErr
		}
		if !ok {
			rejected = true
			return noteWrongTOTP(ctx, tx, hash[:])
		}
		_, execErr := tx.Exec(ctx, `DELETE FROM totp_challenges WHERE token_hash = $1`, hash[:])
		return execErr
	})
	if rejected && err == nil {
		return nil, "", ErrBadCredentials
	}
	if errors.Is(err, ErrExpired) || errors.Is(err, ErrBadCredentials) {
		return nil, "", err
	}
	if err != nil {
		return nil, "", fmt.Errorf("auth: finish totp: %w", err)
	}
	return &u, method, nil
}

// noteWrongTOTP counts a rejected code and deletes the challenge at the cap.
// in: ctx, tx, token hash. out: error. The count must commit, so this returns nil on a wrong code.
func noteWrongTOTP(ctx context.Context, tx pgx.Tx, hash []byte) error {
	var n int
	err := tx.QueryRow(ctx, `
		UPDATE totp_challenges
		   SET attempts = attempts + 1
		 WHERE token_hash = $1
		RETURNING attempts`, hash).Scan(&n)
	if err != nil {
		return err
	}
	if n < totpMaxWrongCodes {
		return nil
	}
	_, err = tx.Exec(ctx, `DELETE FROM totp_challenges WHERE token_hash = $1`, hash)
	return err
}

// MatchTOTP reports whether code matches an enrolled base32 secret.
// A decode failure is an error, not a rejected code.
// in: base32 secret, code. out: accepted, error.
func MatchTOTP(secret, code string) (bool, error) {
	return totp.Check(secret, code, time.Now())
}

// AllowTOTPAttempt spends an IP token so a pending cookie cannot be guessed freely.
// An empty IP skips the cap so missing addresses do not share one bucket.
// in: client ip. out: true when another attempt is allowed.
func (s *AuthService) AllowTOTPAttempt(ip string) bool {
	return ip == "" || s.loginIPLimits.Allow("totp-ip:"+ip)
}
