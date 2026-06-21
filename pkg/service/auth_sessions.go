// AuthService - user_sessions: create, validate, rotate, impersonate.
// See auth.go for the service struct and shared types.
//
// RLS: user_sessions has a transitive policy via user_id ->
// users.tenant_id. CreateSession runs at login time with the user's tenant
// in hand, so it uses db.WithTenant. The validate/rotate/revoke/impersonate
// paths resolve a session by token or session-id BEFORE any tenant context
// exists - they are auth infrastructure, not tenant-scoped data access - so
// they run under db.WithAdminAudit on the BYPASSRLS pool. Each leaves an
// audit-log line; on the ValidateSession path that is one line per
// authenticated request, by design.
package service

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/db"
)

// sessionCookieLifetimePassword is how long a password-authed session lives.
const sessionCookieLifetimePassword = 30 * 24 * time.Hour

// sessionCookieLifetimeMagicLink is how long a magic-link-authed session lives (shorter).
const sessionCookieLifetimeMagicLink = 24 * time.Hour

// sessionRotationInterval bounds how long any single session token value
// stays valid before ValidateSession rotates it. A stolen cookie therefore
// has at most this much grace plus sessionRotationGrace before the next
// real validation by the legitimate browser invalidates it. Picked at 4h
// so password-life sessions (30d) rotate ~180 times and magic-link sessions
// (24h) still rotate several times across normal use.
const sessionRotationInterval = 4 * time.Hour

// sessionRotationGrace is how long the previous token hash continues to
// validate after a rotation. Wide enough for concurrent in-flight requests
// (page load with parallel XHRs) to not 401 when one of them is the one
// that triggered the rotation. 60s is comfortable for HTML + asset fetches
// + XHR fan-out; long enough that a clock-skewed mobile client won't lose
// its session mid-page-load.
const sessionRotationGrace = 60 * time.Second

// CreateSession generates a session token, stores its sha256 hash, and returns
// the raw token the caller must set as a cookie value. Tenant-scoped through
// WithTenant: the user_sessions INSERT is validated by the transitive RLS
// policy (user_id -> users.tenant_id), so the GUC must hold the user's tenant.
// in: tenant_id, user_id, auth method ("password" or "magic_link"), user agent, ip.
// out: raw session token, cookie expiry, error.
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

// Session is the resolved shape of a user_sessions row used by the auth
// middleware. It carries the owning user plus the optional impersonated
// tenant id that a super-admin may have set via /admin/impersonate.
//
// When ValidateSession rotates the underlying token, NewToken + NewExpires
// are populated and the middleware writes a fresh cookie on the response.
// Both are zero values when no rotation happened on this request.
type Session struct {
	ID                   uuid.UUID
	User                 *User
	ImpersonatedTenantID *string

	NewToken   string
	NewExpires time.Time
}

// ValidateSession resolves a raw session token to a Session, refreshing
// last_seen_at as a side effect, and rotates the underlying token if it
// has been in use longer than sessionRotationInterval. Callers use
// session.User + optional session.ImpersonatedTenantID via
// authmw.EffectiveTenantID to scope queries.
//
// Runs under WithAdminAudit on the BYPASSRLS pool: a session token is
// presented before any tenant context exists, so RLS scoping cannot apply
// yet - the token IS what resolves the user and tenant. The whole body
// (lookup + optional rotation + last_seen_at touch) runs in one tx so the
// path emits exactly one audit-log line per request.
//
// Rotation: when the validated token matches the row's current token_hash
// AND rotated_at is older than the interval, a fresh 32-byte token is
// minted and atomically swapped in. The previous hash stays valid for
// sessionRotationGrace so concurrent in-flight requests on the old cookie
// do not 401. The CAS-style WHERE on the rotation UPDATE means only one
// concurrent rotation wins; the loser silently falls back to the old
// token and continues without setting a new cookie.
//
// in: raw session token string. out: *Session on success, ErrNotFound or ErrExpired.
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

// rotateSession swaps token_hash to a freshly minted value, parking the
// previous hash in previous_token_hash for sessionRotationGrace. The WHERE
// on token_hash is the single-winner gate: if a concurrent request already
// rotated, this UPDATE matches zero rows and ok=false comes back, letting
// the caller fall through to the no-rotation path. Runs inside the caller's
// ValidateSession transaction.
// in: ctx, tx, session id, the current token hash just validated.
// out: new raw token (32 bytes hex), true if the rotation landed, error from db.
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

// SetImpersonation marks the given session as viewing a different tenant.
// The caller layer (handler) is responsible for verifying that the session's
// user is a super-admin before invoking this; the service layer only enforces
// that the target tenant exists (via FK constraint). Runs under
// WithAdminAudit: keyed on a session id, and the target tenant is by
// definition not the session owner's own tenant.
// in: session id, target tenant slug. out: error.
func (s *AuthService) SetImpersonation(sessionID uuid.UUID, tenantID string) error {
	ctx := context.Background()
	return db.WithAdminAudit(ctx, s.pools.Admin, "auth.set_impersonation", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE user_sessions SET impersonated_tenant_id = $1 WHERE id = $2`,
			tenantID, sessionID)
		return err
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
