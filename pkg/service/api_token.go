// AuthService companion: api_tokens - issue, validate, revoke, and list the
// bearer tokens that authenticate the JSON /api/v1 surface (the Flutter app).
// Mirrors auth_sessions.go: the raw token is returned once at issue time and
// only its sha256 hash is stored.
//
// RLS: api_tokens is user-bound with a transitive policy (user_id ->
// users.tenant_id). IssueToken + ListTokens have the tenant in hand, so they
// run under db.WithTenant on the App pool. ValidateToken + RevokeToken resolve
// a token BEFORE any tenant context exists - they are auth infrastructure, not
// tenant-scoped data access - so they run under db.WithAdminAudit on the
// BYPASSRLS pool, exactly like ValidateSession / RevokeSession.
package service

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/db"
)

// apiTokenLifetime is how long a freshly issued API token stays valid before
// ValidateToken rejects it with ErrExpired. Long-lived relative to a web
// session because a mobile client cannot silently rotate a cookie; the client
// re-logs-in to mint a fresh one.
const apiTokenLifetime = 90 * 24 * time.Hour

// ApiTokenService issues and validates bearer tokens for /api/v1.
type ApiTokenService struct {
	cfg   *config.Config
	pools db.Pools
}

// ApiToken is the redacted shape of an api_tokens row for the List view -
// never carries the hash or the raw token.
type ApiToken struct {
	ID         uuid.UUID
	Name       string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// IssueToken mints a bearer token for the user, stores its sha256 hash, and
// returns the raw token (shown exactly once). Tenant-scoped through WithTenant
// so the INSERT is validated by the transitive RLS policy (user_id ->
// users.tenant_id), so the GUC must hold the user's tenant.
// in: tenant_id, user_id, human-readable label. out: raw token, expiry, error.
func (s *ApiTokenService) IssueToken(tenantID string, userID uuid.UUID, name string) (string, time.Time, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", time.Time{}, err
	}
	hash := sha256.Sum256([]byte(token))
	expires := time.Now().Add(apiTokenLifetime)
	ctx := context.Background()
	err = db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx,
			`INSERT INTO api_tokens (user_id, token_hash, name, expires_at)
			 VALUES ($1, $2, $3, $4)`,
			userID, hash[:], name, expires)
		return execErr
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

// ValidateToken resolves a raw bearer token to its owning user, refreshing
// last_used_at as a side effect. Runs under WithAdminAudit on the BYPASSRLS
// pool: the token is presented before any tenant context exists, so RLS
// scoping cannot apply yet - the token IS what resolves the user and tenant.
// A revoked token is treated as not found; an expired one returns ErrExpired.
// in: raw bearer token. out: *User on success, ErrNotFound or ErrExpired.
func (s *ApiTokenService) ValidateToken(token string) (*User, error) {
	hash := sha256.Sum256([]byte(token))
	const query = `
		SELECT t.id, t.expires_at, t.revoked_at,
		       u.id, u.tenant_id, u.email, u.display_name, u.telegram_chat_id, u.is_admin, u.is_super_admin, u.created_at, u.last_login_at
		FROM api_tokens t
		JOIN users u ON u.id = t.user_id
		WHERE t.token_hash = $1`
	ctx := context.Background()
	var user *User
	err := db.WithAdminAudit(ctx, s.pools.Admin, "auth.validate_api_token", func(tx pgx.Tx) error {
		var (
			tokenID   uuid.UUID
			expiresAt *time.Time
			revokedAt *time.Time
			u         User
		)
		serr := tx.QueryRow(ctx, query, hash[:]).Scan(
			&tokenID, &expiresAt, &revokedAt,
			&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.TelegramChatID, &u.IsAdmin, &u.IsSuperAdmin, &u.CreatedAt, &u.LastLoginAt)
		if serr != nil {
			return serr
		}
		if revokedAt != nil {
			return ErrNotFound
		}
		if expiresAt != nil && time.Now().After(*expiresAt) {
			return ErrExpired
		}
		_, _ = tx.Exec(ctx, `UPDATE api_tokens SET last_used_at = now() WHERE id = $1`, tokenID)
		user = &u
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

// RevokeToken marks a token revoked by its raw value (logout). Idempotent -
// an already-revoked or unknown token is a no-op. Runs under WithAdminAudit:
// logout presents only the token, with no tenant context.
// in: raw bearer token. out: error.
func (s *ApiTokenService) RevokeToken(token string) error {
	hash := sha256.Sum256([]byte(token))
	ctx := context.Background()
	return db.WithAdminAudit(ctx, s.pools.Admin, "auth.revoke_api_token", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE api_tokens SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL`,
			hash[:])
		return err
	})
}

// ListTokens returns the caller's own tokens (redacted), newest first.
// Tenant-scoped through WithTenant so the SELECT is gated by the RLS policy.
// in: tenant_id, user_id. out: redacted token rows, error.
func (s *ApiTokenService) ListTokens(tenantID string, userID uuid.UUID) ([]ApiToken, error) {
	ctx := context.Background()
	var out []ApiToken
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		rows, qerr := tx.Query(ctx,
			`SELECT id, name, created_at, expires_at, last_used_at, revoked_at
			   FROM api_tokens WHERE user_id = $1 ORDER BY created_at DESC`, userID)
		if qerr != nil {
			return qerr
		}
		defer rows.Close()
		for rows.Next() {
			var t ApiToken
			if serr := rows.Scan(&t.ID, &t.Name, &t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt); serr != nil {
				return serr
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
