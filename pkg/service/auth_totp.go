package service

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/db"
	"thesada.app/app/pkg/totp"
)

const totpChallengeLifetime = 5 * time.Minute

// TOTPSecret returns the base32 secret when this password account has TOTP on.
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
		return "", false, err
	}
	if secret == nil || *secret == "" {
		return "", false, nil
	}
	return *secret, true, nil
}

// SetTOTPSecret stores a confirmed base32 secret. An empty secret turns TOTP off.
func (s *AuthService) SetTOTPSecret(tenantID string, userID uuid.UUID, secret string) error {
	ctx := context.Background()
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
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
}

// BeginTOTPLogin records a short-lived challenge after a correct password.
func (s *AuthService) BeginTOTPLogin(tenantID string, userID uuid.UUID) (string, time.Time, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", time.Time{}, err
	}
	hash := sha256.Sum256([]byte(token))
	expires := time.Now().Add(totpChallengeLifetime)
	ctx := context.Background()
	err = db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx,
			`INSERT INTO totp_challenges (token_hash, user_id, expires_at) VALUES ($1, $2, $3)`,
			hash[:], userID, expires)
		return execErr
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

// FinishTOTPLogin checks the code and deletes the challenge on success.
func (s *AuthService) FinishTOTPLogin(token, code string) (*User, error) {
	hash := sha256.Sum256([]byte(token))
	const q = `
		SELECT u.id, u.tenant_id, u.email, u.display_name, u.telegram_chat_id,
		       u.is_admin, u.is_super_admin, u.created_at, u.last_login_at, u.totp_secret
		  FROM totp_challenges c
		  JOIN users u ON u.id = c.user_id
		 WHERE c.token_hash = $1 AND c.expires_at > now()`
	ctx := context.Background()
	var u User
	var secret *string
	err := db.WithAdminAudit(ctx, s.pools.Admin, "auth.finish_totp_login", func(tx pgx.Tx) error {
		scanErr := tx.QueryRow(ctx, q, hash[:]).Scan(
			&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.TelegramChatID,
			&u.IsAdmin, &u.IsSuperAdmin, &u.CreatedAt, &u.LastLoginAt, &secret)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return ErrExpired
		}
		if scanErr != nil {
			return scanErr
		}
		if secret == nil || *secret == "" {
			return ErrBadCredentials
		}
		raw, decErr := totp.DecodeKey(*secret)
		if decErr != nil || !totp.Verify(raw, code, time.Now()) {
			return ErrBadCredentials
		}
		_, execErr := tx.Exec(ctx, `DELETE FROM totp_challenges WHERE token_hash = $1`, hash[:])
		return execErr
	})
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// AllowTOTPAttempt spends an IP token so a pending cookie cannot be guessed freely.
func (s *AuthService) AllowTOTPAttempt(ip string) bool {
	return ip == "" || s.loginIPLimits.Allow("totp-ip:"+ip)
}
