// AuthService - user_sessions: create, validate, rotate, impersonate.
// See auth.go for the service struct and shared types.
//
// validate/rotate/revoke paths run under WithAdminAudit (BYPASSRLS pool):
// the token IS what resolves the user, so no tenant context exists yet.
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
)

// sessionCookieLifetimePassword is how long a password-authed session lives.
const sessionCookieLifetimePassword = 30 * 24 * time.Hour

// sessionCookieLifetimeMagicLink is how long a magic-link-authed session lives (shorter).
const sessionCookieLifetimeMagicLink = 24 * time.Hour

// sessionRotationInterval is the stolen-cookie bound: a thief has at most
// this long before the next legitimate validation invalidates the old token.
const sessionRotationInterval = 4 * time.Hour

// sessionRotationGrace keeps the previous token hash valid after rotation
// so concurrent in-flight requests (parallel XHRs) don't 401.
const sessionRotationGrace = 60 * time.Second

// CreateSession stores a session token's sha256 hash and returns the raw token for the cookie.
// Uses WithTenant: RLS policy is transitive (user_id -> users.tenant_id), so GUC must hold the tenant.
// in: tenant_id, user_id, auth method, user agent, ip. out: raw token, cookie expiry, error.
func (s *AuthService) CreateSession(tenantID string, userID uuid.UUID, authMethod, userAgent, ip string) (string, time.Time, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", time.Time{}, err
	}
	hash := sha256.Sum256([]byte(token))
	lifetime := sessionCookieLifetimePassword
	if authMethod == "magic_link" {
		lifetime = sessionCookieLifetimeMagicLink
	}
	expires := time.Now().Add(lifetime)
	var ipArg interface{}
	if ip != "" {
		ipArg = ip
	}
	ctx := context.Background()
	err = db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx,
			`INSERT INTO user_sessions (user_id, token_hash, auth_method, expires_at, user_agent, ip)
			 VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6)`,
			userID, hash[:], authMethod, expires, userAgent, ipArg)
		return execErr
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

// Session is the resolved shape of a user_sessions row used by the auth middleware.
// NewToken + NewExpires are populated on rotation; zero values mean no rotation this request.
type Session struct {
	ID                   uuid.UUID
	User                 *User
	ImpersonatedTenantID *string

	NewToken   string
	NewExpires time.Time
}

// ValidateSession resolves a raw token to a Session, updating last_seen_at, rotating when due.
// Runs under WithAdminAudit (BYPASSRLS): the token resolves user+tenant, no prior tenant context exists.
// Rotation is CAS (WHERE token_hash = current): only one concurrent winner; the loser skips rotation.
// in: raw session token. out: *Session, ErrNotFound, or ErrExpired.
func (s *AuthService) ValidateSession(token string) (*Session, error) {
	hash := sha256.Sum256([]byte(token))
	const query = `
		SELECT s.id, s.expires_at, s.impersonated_tenant_id,
		       s.rotated_at, (s.token_hash = $1) AS is_current,
		       u.id, u.tenant_id, u.email, u.display_name, u.telegram_chat_id, u.is_admin, u.is_super_admin, u.created_at, u.last_login_at
		FROM user_sessions s
		JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1
		   OR (s.previous_token_hash = $1 AND s.previous_token_hash_expires_at > now())`
	ctx := context.Background()
	var sess *Session
	err := db.WithAdminAudit(ctx, s.pools.Admin, "auth.validate_session", func(tx pgx.Tx) error {
		var (
			sessionID   uuid.UUID
			expiresAt   time.Time
			impersonate *string
			rotatedAt   time.Time
			isCurrent   bool
			u           User
		)
		serr := tx.QueryRow(ctx, query, hash[:]).Scan(
			&sessionID, &expiresAt, &impersonate, &rotatedAt, &isCurrent,
			&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.TelegramChatID, &u.IsAdmin, &u.IsSuperAdmin, &u.CreatedAt, &u.LastLoginAt)
		if serr != nil {
			return serr
		}
		if time.Now().After(expiresAt) {
			return ErrExpired
		}

		sess = &Session{
			ID:                   sessionID,
			User:                 &u,
			ImpersonatedTenantID: impersonate,
		}

		if isCurrent && time.Since(rotatedAt) >= sessionRotationInterval {
			newToken, ok, rerr := s.rotateSession(ctx, tx, sessionID, hash[:])
			if rerr != nil {
				return rerr
			}
			if ok {
				sess.NewToken = newToken
				sess.NewExpires = expiresAt
				return nil
			}
		}

		_, _ = tx.Exec(ctx, `UPDATE user_sessions SET last_seen_at = now() WHERE id = $1`, sessionID)
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return sess, nil
}

// rotateSession atomically swaps token_hash; the old hash moves to previous_token_hash for grace-window
// coverage of in-flight requests. WHERE token_hash = current is the single-winner gate (ok=false if lost).
// in: ctx, tx, session id, current hash. out: new raw token, landed bool, error.
func (s *AuthService) rotateSession(ctx context.Context, tx pgx.Tx, sessionID uuid.UUID, currentHash []byte) (string, bool, error) {
	newToken, err := randomToken(32)
	if err != nil {
		return "", false, err
	}
	newHash := sha256.Sum256([]byte(newToken))
	tag, err := tx.Exec(ctx,
		`UPDATE user_sessions
		    SET token_hash = $1,
		        previous_token_hash = $2,
		        previous_token_hash_expires_at = now() + $3::interval,
		        rotated_at = now(),
		        last_seen_at = now()
		  WHERE id = $4 AND token_hash = $2`,
		newHash[:], currentHash, sessionRotationGrace.String(), sessionID)
	if err != nil {
		return "", false, err
	}
	if tag.RowsAffected() == 0 {
		return "", false, nil
	}
	return newToken, true, nil
}

// SetImpersonation points a session at another tenant for viewing. Crosses
// tenant boundaries, so super-admin is enforced here, not just in the handler:
// a single guarded UPDATE gates the write on is_super_admin so the check cannot
// race a demote. Zero rows affected means either no such session (ErrNotFound)
// or a non-super one (ErrNotSuperAdmin), disambiguated by an existence probe.
// in: session id, target tenant slug. out: ErrNotSuperAdmin / ErrNotFound / nil.
func (s *AuthService) SetImpersonation(sessionID uuid.UUID, tenantID string) error {
	ctx := context.Background()
	return db.WithAdminAudit(ctx, s.pools.Admin, "auth.set_impersonation", func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE user_sessions s SET impersonated_tenant_id = $1
			   FROM users u
			  WHERE s.id = $2 AND u.id = s.user_id AND u.is_super_admin = true`,
			tenantID, sessionID)
		if err != nil {
			return fmt.Errorf("auth: set impersonation for session %s: %w", sessionID, err)
		}
		if tag.RowsAffected() == 1 {
			return nil
		}
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM user_sessions WHERE id = $1)`, sessionID).Scan(&exists); err != nil {
			return fmt.Errorf("auth: probe session %s: %w", sessionID, err)
		}
		if !exists {
			return ErrNotFound
		}
		return ErrNotSuperAdmin
	})
}

// ClearImpersonation drops any impersonated tenant on the given session,
// returning the super-admin's view to their own tenant.
// in: session id. out: error.
func (s *AuthService) ClearImpersonation(sessionID uuid.UUID) error {
	ctx := context.Background()
	return db.WithAdminAudit(ctx, s.pools.Admin, "auth.clear_impersonation", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE user_sessions SET impersonated_tenant_id = NULL WHERE id = $1`,
			sessionID)
		return err
	})
}

// RevokeSession deletes a session row by raw token. Runs under WithAdminAudit:
// logout presents only the token, with no tenant context.
// in: raw session token. out: error.
func (s *AuthService) RevokeSession(token string) error {
	hash := sha256.Sum256([]byte(token))
	ctx := context.Background()
	return db.WithAdminAudit(ctx, s.pools.Admin, "auth.revoke_session", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM user_sessions WHERE token_hash = $1`, hash[:])
		return err
	})
}
