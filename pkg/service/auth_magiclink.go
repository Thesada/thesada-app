// AuthService - magic_link_tokens: login + reset link issue/consume.
// See auth.go for the service struct and shared types.
//
// RLS: the magic-link lifecycle is auth infrastructure - tokens are
// issued and consumed before any tenant context exists, and consumption is
// keyed purely on a token hash. The whole file therefore runs under
// db.WithAdminAudit on the BYPASSRLS pool, like the session path.
//
// NOTE: 0016_rls_policies.sql ships a magic_link_tokens policy that
// references a non-existent tenant_id column - the table only has user_id.
// That policy is fixed (rewritten transitive via user_id) in the
// 0016 addendum. These methods run on the BYPASSRLS pool either
// way, so they are unaffected by which form the policy takes.
package service

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"

	"thesada.app/app/pkg/db"
)

// magicLinkLifetime is how long a magic link token is valid before it expires.
const magicLinkLifetime = 15 * time.Minute

// resetLinkLifetime is how long a password-reset link stays valid.
const resetLinkLifetime = 30 * time.Minute

// PurposeLogin is the magic_link_tokens.purpose value for login links.
const PurposeLogin = "login"

// PurposeReset is the magic_link_tokens.purpose value for password reset links.
const PurposeReset = "reset"

// CreateMagicLink generates a one-time login token, stores its sha256 hash,
// and returns the raw token the caller embeds into the login URL emailed out.
// in: user_id. out: raw token (url-safe), expiry time, error.
func (s *AuthService) CreateMagicLink(userID uuid.UUID) (string, time.Time, error) {
	return s.CreateMagicLinkCtx(context.Background(), userID)
}

// CreateMagicLinkCtx is CreateMagicLink bounded by ctx, pool acquire included.
// in: ctx, user_id. out: raw token, expiry, error.
func (s *AuthService) CreateMagicLinkCtx(ctx context.Context, userID uuid.UUID) (string, time.Time, error) {
	return s.createLinkToken(ctx, userID, PurposeLogin, magicLinkLifetime)
}

// CreateResetLink generates a password-reset token with a longer lifetime.
// Separate purpose prevents a leaked login link from reaching the /reset flow
// and vice versa.
// in: user_id. out: raw token, expiry time, error.
func (s *AuthService) CreateResetLink(userID uuid.UUID) (string, time.Time, error) {
	return s.CreateResetLinkCtx(context.Background(), userID)
}

// CreateResetLinkCtx is CreateResetLink bounded by ctx.
// in: ctx, user_id. out: raw token, expiry, error.
func (s *AuthService) CreateResetLinkCtx(ctx context.Context, userID uuid.UUID) (string, time.Time, error) {
	return s.createLinkToken(ctx, userID, PurposeReset, resetLinkLifetime)
}

// createLinkToken is the shared INSERT path for both login and reset tokens.
// in: ctx, user_id, purpose tag, lifetime duration. out: raw token, expiry, error.
func (s *AuthService) createLinkToken(ctx context.Context, userID uuid.UUID, purpose string, lifetime time.Duration) (string, time.Time, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", time.Time{}, err
	}
	hash := sha256.Sum256([]byte(token))
	expires := time.Now().Add(lifetime)
	err = db.WithAdminAudit(ctx, s.pools.Admin, "auth.create_link_token", func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx,
			`INSERT INTO magic_link_tokens (user_id, token_hash, expires_at, purpose) VALUES ($1, $2, $3, $4)`,
			userID, hash[:], expires, purpose)
		return execErr
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

// ConsumeMagicLink validates a raw login token and, if it is unconsumed and
// unexpired, marks it consumed and returns the associated user.
// in: raw token string. out: *User on success, ErrNotFound or ErrExpired on failure.
func (s *AuthService) ConsumeMagicLink(token string) (*User, error) {
	return s.consumeLinkToken(token, PurposeLogin, true)
}

// ConsumeResetLink validates a raw password-reset token without consuming it,
// so the reset form can render. ResetPassword is the consuming step.
// in: raw token string. out: *User, token id, error.
func (s *AuthService) ConsumeResetLink(token string) (*User, uuid.UUID, error) {
	hash := sha256.Sum256([]byte(token))
	const query = `
		SELECT t.id, t.user_id, t.expires_at, t.consumed_at, t.purpose,
		       u.tenant_id, u.email, u.display_name, u.telegram_chat_id, u.is_admin, u.is_super_admin, u.created_at, u.last_login_at
		FROM magic_link_tokens t
		JOIN users u ON u.id = t.user_id
		WHERE t.token_hash = $1`
	ctx := context.Background()
	var (
		tokenID    uuid.UUID
		consumedAt *time.Time
		expiresAt  time.Time
		purpose    string
		u          User
	)
	err := db.WithAdminAudit(ctx, s.pools.Admin, "auth.consume_reset_link", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, hash[:]).Scan(
			&tokenID, &u.ID, &expiresAt, &consumedAt, &purpose,
			&u.TenantID, &u.Email, &u.DisplayName, &u.TelegramChatID, &u.IsAdmin, &u.IsSuperAdmin, &u.CreatedAt, &u.LastLoginAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, uuid.Nil, ErrNotFound
	}
	if err != nil {
		return nil, uuid.Nil, err
	}
	if purpose != PurposeReset || consumedAt != nil {
		return nil, uuid.Nil, ErrNotFound
	}
	if time.Now().After(expiresAt) {
		return nil, uuid.Nil, ErrExpired
	}
	return &u, tokenID, nil
}

// ResetPassword consumes a reset token and stores the new password in one
// transaction, so of two POSTs with one token exactly one sets a password.
// in: raw token, new password. out: owning *User, or ErrNotFound / ErrExpired / ErrPasswordTooShort.
func (s *AuthService) ResetPassword(token, password string) (*User, error) {
	if len(password) < MinPasswordLen {
		return nil, ErrPasswordTooShort
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	return s.consumeLinkTokenThen(token, PurposeReset, false, func(tx pgx.Tx, u *User) error {
		tag, err := tx.Exec(ctx, `UPDATE users SET password_hash = $1 WHERE id = $2`, string(hash), u.ID)
		if err != nil {
			return fmt.Errorf("auth: reset password for user %s: %w", u.ID, err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// consumeLinkToken is the shared validation+consume path for login-purpose tokens.
//
// Atomic UPDATE...RETURNING so concurrent consumptions of the same token can
// have at most one winner. Previously this was SELECT-then-UPDATE: two
// concurrent requests with the same token both passed the consumed_at check
// and both created sessions for the user. Forwarding-link harvesting was
// the real concern - intercept the link in transit, race the legitimate
// user, both succeed. Single statement closes the window.
// in: raw token, expected purpose, whether to touch last_login_at. out: *User or error.
func (s *AuthService) consumeLinkToken(token, expectedPurpose string, touchLogin bool) (*User, error) {
	return s.consumeLinkTokenThen(token, expectedPurpose, touchLogin, nil)
}

// consumeLinkTokenThen is consumeLinkToken with then run in the consuming tx; a then error rolls the consume back.
// in: raw token, purpose, touchLogin, optional then. out: *User or error.
func (s *AuthService) consumeLinkTokenThen(token, expectedPurpose string, touchLogin bool, then func(pgx.Tx, *User) error) (*User, error) {
	hash := sha256.Sum256([]byte(token))
	const consumeQuery = `
		UPDATE magic_link_tokens t
		   SET consumed_at = now()
		  FROM users u
		 WHERE u.id = t.user_id
		   AND t.token_hash = $1
		   AND t.consumed_at IS NULL
		   AND t.expires_at > now()
		   AND t.purpose = $2
		RETURNING t.user_id,
		          u.tenant_id, u.email, u.display_name, u.telegram_chat_id,
		          u.is_admin, u.is_super_admin, u.created_at, u.last_login_at`
	ctx := context.Background()
	var u User
	var notConsumed bool // true once the atomic UPDATE matched a row
	var resultErr error  // terminal classification when the UPDATE matched nothing
	err := db.WithAdminAudit(ctx, s.pools.Admin, "auth.consume_link_token", func(tx pgx.Tx) error {
		scanErr := tx.QueryRow(ctx, consumeQuery, hash[:], expectedPurpose).Scan(
			&u.ID,
			&u.TenantID, &u.Email, &u.DisplayName, &u.TelegramChatID,
			&u.IsAdmin, &u.IsSuperAdmin, &u.CreatedAt, &u.LastLoginAt)
		if scanErr == nil {
			notConsumed = true
			if then != nil {
				return then(tx, &u)
			}
			return nil
		}
		if !errors.Is(scanErr, pgx.ErrNoRows) {
			return scanErr
		}
		// The UPDATE matched nothing. Distinguish expired from
		// never-existed-or-already-consumed for UX - caller renders "this
		// link expired" vs "this link is invalid". Look up the row state by
		// hash without changing it.
		var expiresAt time.Time
		var consumedAt *time.Time
		var foundPurpose string
		serr := tx.QueryRow(ctx,
			`SELECT expires_at, consumed_at, purpose
			   FROM magic_link_tokens WHERE token_hash = $1`, hash[:]).Scan(
			&expiresAt, &consumedAt, &foundPurpose)
		if errors.Is(serr, pgx.ErrNoRows) || foundPurpose != expectedPurpose {
			resultErr = ErrNotFound
			return nil
		}
		if serr != nil {
			return serr
		}
		if consumedAt != nil {
			resultErr = ErrNotFound
			return nil
		}
		if time.Now().After(expiresAt) {
			resultErr = ErrExpired
			return nil
		}
		resultErr = ErrNotFound
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !notConsumed {
		return nil, resultErr
	}
	if touchLogin {
		s.touchLastLogin(u.TenantID, u.ID)
	}
	return &u, nil
}
