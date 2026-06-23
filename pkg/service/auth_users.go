// AuthService - users table: lookup, create, update, password.
// See auth.go for the service struct and shared types.
//
// RLS: tenant-scoped methods run under db.WithTenant; cross-tenant paths
// (login lookup, boot promotion) run under db.WithAdminAudit on BYPASSRLS.
// user_id-keyed methods take an explicit tenantID so cross-tenant PKs match zero rows.
package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"

	"thesada.app/app/pkg/db"
)

// dummyPasswordHash equalises timing for no-user logins so email enumeration is not possible.
// DefaultCost keeps it aligned with real hashes.
var dummyPasswordHash = mustDummyHash()

func mustDummyHash() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("decoy-for-timing-equalisation"), bcrypt.DefaultCost)
	if err != nil {
		panic("service: dummy bcrypt hash generation failed: " + err.Error())
	}
	return h
}

// equaliseLoginTiming spends one decoy bcrypt compare; result discarded.
func equaliseLoginTiming(password string) {
	_ = bcrypt.CompareHashAndPassword(dummyPasswordHash, []byte(password))
}

// GetUserByEmail finds a user by tenant + email (case-insensitive via citext).
// in: tenant_id, email. out: *User or ErrNotFound.
func (s *AuthService) GetUserByEmail(tenantID, email string) (*User, error) {
	const query = `
		SELECT id, tenant_id, email, display_name, telegram_chat_id, is_admin, is_super_admin, created_at, last_login_at
		FROM users WHERE tenant_id = $1 AND email = $2`
	ctx := context.Background()
	var u User
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, tenantID, email).Scan(
			&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.TelegramChatID, &u.IsAdmin, &u.IsSuperAdmin, &u.CreatedAt, &u.LastLoginAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// GetUserByEmailAnyTenant finds a user by email across all tenants (oldest match wins).
// Cross-tenant by design: login has no tenant yet; runs under WithAdminAudit.
// in: email. out: *User or ErrNotFound.
func (s *AuthService) GetUserByEmailAnyTenant(email string) (*User, error) {
	const query = `
		SELECT id, tenant_id, email, display_name, telegram_chat_id, is_admin, is_super_admin, created_at, last_login_at
		FROM users WHERE email = $1 ORDER BY created_at LIMIT 1`
	ctx := context.Background()
	var u User
	err := db.WithAdminAudit(ctx, s.pools.Admin, "auth.get_user_by_email_any_tenant", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, email).Scan(
			&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.TelegramChatID, &u.IsAdmin, &u.IsSuperAdmin, &u.CreatedAt, &u.LastLoginAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// EnsureAdminUser creates an admin user (no password) if one does not exist for the email.
// in: tenant_id, email. out: created or existing *User, error.
func (s *AuthService) EnsureAdminUser(tenantID, email string) (*User, error) {
	u, err := s.GetUserByEmail(tenantID, email)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	// Always super-admin: both single- and multi-tenant deploys need an escape hatch before
	// any tenant-scoped admin exists.
	const insert = `
		INSERT INTO users (tenant_id, email, is_admin, is_super_admin)
		VALUES ($1, $2, true, true)
		RETURNING id, tenant_id, email, display_name, telegram_chat_id, is_admin, is_super_admin, created_at, last_login_at`
	ctx := context.Background()
	var out User
	err = db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, insert, tenantID, email).Scan(
			&out.ID, &out.TenantID, &out.Email, &out.DisplayName, &out.TelegramChatID, &out.IsAdmin, &out.IsSuperAdmin, &out.CreatedAt, &out.LastLoginAt)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// VerifyPassword bcrypt-verifies a password for one tenant+email.
// NOT rate-limited - any attacker-reachable caller must gate attempts itself.
// in: tenant_id, email, plain password. out: *User or ErrBadCredentials.
func (s *AuthService) VerifyPassword(tenantID, email, password string) (*User, error) {
	const query = `
		SELECT id, tenant_id, email, display_name, telegram_chat_id, is_admin, is_super_admin, created_at, last_login_at, password_hash
		FROM users WHERE tenant_id = $1 AND email = $2`
	ctx := context.Background()
	var u User
	var hash *string
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, tenantID, email).Scan(
			&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.TelegramChatID, &u.IsAdmin, &u.IsSuperAdmin, &u.CreatedAt, &u.LastLoginAt, &hash)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		equaliseLoginTiming(password)
		return nil, ErrBadCredentials
	}
	if err != nil {
		return nil, err
	}
	if hash == nil || *hash == "" {
		equaliseLoginTiming(password)
		return nil, ErrBadCredentials
	}
	if bcrypt.CompareHashAndPassword([]byte(*hash), []byte(password)) != nil {
		return nil, ErrBadCredentials
	}
	s.touchLastLogin(u.TenantID, u.ID)
	return &u, nil
}

// VerifyPasswordAnyTenant bcrypt-verifies a password across all tenants (oldest account wins,
// at most maxLoginCandidates). Rate-limited per email+IP; no-candidate result still spends
// one decoy bcrypt so timing cannot enumerate. Cross-tenant by design; runs under WithAdminAudit.
// in: email, plain password, source ip. out: *User, ErrLoginRateLimited, or ErrBadCredentials.
func (s *AuthService) VerifyPasswordAnyTenant(email, password, ip string) (*User, error) {
	if !s.allowLogin(email, ip) {
		return nil, ErrLoginRateLimited
	}
	const query = `
		SELECT id, tenant_id, email, display_name, telegram_chat_id, is_admin, is_super_admin, created_at, last_login_at, password_hash
		FROM users WHERE email = $1 AND password_hash IS NOT NULL
		ORDER BY created_at, tenant_id
		LIMIT $2`
	ctx := context.Background()
	var matched *User
	err := db.WithAdminAudit(ctx, s.pools.Admin, "auth.verify_password_any_tenant", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, email, maxLoginCandidates)
		if err != nil {
			return err
		}
		defer rows.Close()
		compared := 0
		for rows.Next() {
			var u User
			var hash *string
			if err := rows.Scan(&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.TelegramChatID, &u.IsAdmin, &u.IsSuperAdmin, &u.CreatedAt, &u.LastLoginAt, &hash); err != nil {
				return err
			}
			if hash == nil || *hash == "" {
				continue
			}
			compared++
			if bcrypt.CompareHashAndPassword([]byte(*hash), []byte(password)) == nil {
				matched = &u
				return nil
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		// Pad with decoys so a failed login always costs maxLoginCandidates
		// bcrypts - timing then leaks neither existence nor tenant count.
		for i := compared; i < maxLoginCandidates; i++ {
			equaliseLoginTiming(password)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if matched == nil {
		return nil, ErrBadCredentials
	}
	s.touchLastLogin(matched.TenantID, matched.ID)
	return matched, nil
}

// PromoteSuperAdmin marks a user as is_super_admin=true. Idempotent.
// Cross-tenant by design: runs at boot before any tenant context exists; runs under WithAdminAudit.
// in: user_id. out: error.
func (s *AuthService) PromoteSuperAdmin(userID uuid.UUID) error {
	ctx := context.Background()
	return db.WithAdminAudit(ctx, s.pools.Admin, "auth.promote_super_admin", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET is_super_admin = true WHERE id = $1`, userID)
		return err
	})
}

// ListUsersByTenant returns all users in a tenant ordered by email.
// in: tenant_id. out: []User, error.
func (s *AuthService) ListUsersByTenant(tenantID string) ([]User, error) {
	const query = `
		SELECT id, tenant_id, email, display_name, telegram_chat_id, is_admin, is_super_admin, created_at, last_login_at
		FROM users WHERE tenant_id = $1 ORDER BY email`
	ctx := context.Background()
	var out []User
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var u User
			if err := rows.Scan(&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.TelegramChatID, &u.IsAdmin, &u.IsSuperAdmin, &u.CreatedAt, &u.LastLoginAt); err != nil {
				return err
			}
			out = append(out, u)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CreateUser inserts a new user (no password; set via reset-link flow).
// in: tenant_id, email, display_name (may be ""), is_admin. out: *User, error.
func (s *AuthService) CreateUser(tenantID, email, displayName string, isAdmin bool) (*User, error) {
	var dn interface{}
	if displayName != "" {
		dn = displayName
	}
	const query = `
		INSERT INTO users (tenant_id, email, display_name, is_admin)
		VALUES ($1, $2, $3, $4)
		RETURNING id, tenant_id, email, display_name, telegram_chat_id, is_admin, is_super_admin, created_at, last_login_at`
	ctx := context.Background()
	var u User
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, tenantID, email, dn, isAdmin).Scan(
			&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.TelegramChatID, &u.IsAdmin, &u.IsSuperAdmin, &u.CreatedAt, &u.LastLoginAt)
	})
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// GetUserByID returns a user by primary key, tenant-scoped (cross-tenant UUID matches zero rows).
// in: tenant_id, user_id. out: *User, error (ErrNotFound if missing).
func (s *AuthService) GetUserByID(tenantID string, userID uuid.UUID) (*User, error) {
	const query = `
		SELECT id, tenant_id, email, display_name, telegram_chat_id, is_admin, is_super_admin, created_at, last_login_at
		FROM users WHERE id = $1`
	ctx := context.Background()
	var u User
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, userID).Scan(
			&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.TelegramChatID, &u.IsAdmin, &u.IsSuperAdmin, &u.CreatedAt, &u.LastLoginAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// GetUserByIDAny returns a user by primary key with no tenant scoping.
// For callers without a tenant (e.g. OAuth callback resolving LinkingUserID); runs under WithAdminAudit.
// Tenant-scoped callers must use GetUserByID.
// in: user_id. out: *User, error (ErrNotFound if missing).
func (s *AuthService) GetUserByIDAny(userID uuid.UUID) (*User, error) {
	const query = `
		SELECT id, tenant_id, email, display_name, telegram_chat_id, is_admin, is_super_admin, created_at, last_login_at
		FROM users WHERE id = $1`
	ctx := context.Background()
	var u User
	err := db.WithAdminAudit(ctx, s.pools.Admin, "auth.get_user_by_id_any", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, userID).Scan(
			&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.TelegramChatID, &u.IsAdmin, &u.IsSuperAdmin, &u.CreatedAt, &u.LastLoginAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// UpdateDisplayName updates a user's display name (self-service).
// in: tenant_id, user_id, display_name. out: error.
func (s *AuthService) UpdateDisplayName(tenantID string, userID uuid.UUID, displayName string) error {
	var dn interface{}
	if displayName != "" {
		dn = displayName
	}
	ctx := context.Background()
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET display_name = $1 WHERE id = $2`, dn, userID)
		return err
	})
}

// UpdateTelegramChatID updates a user's Telegram chat ID (self-service).
// in: tenant_id, user_id, chat_id (empty string clears). out: error.
func (s *AuthService) UpdateTelegramChatID(tenantID string, userID uuid.UUID, chatID string) error {
	var cid interface{}
	if chatID != "" {
		cid = chatID
	}
	ctx := context.Background()
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users SET telegram_chat_id = $1 WHERE id = $2`, cid, userID)
		return err
	})
}

// UpdateUser updates a user's display name and admin flag.
// in: tenant_id, user_id, display_name, is_admin. out: error.
func (s *AuthService) UpdateUser(tenantID string, userID uuid.UUID, displayName string, isAdmin bool) error {
	var dn interface{}
	if displayName != "" {
		dn = displayName
	}
	ctx := context.Background()
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE users SET display_name = $1, is_admin = $2 WHERE id = $3`,
			dn, isAdmin, userID)
		return err
	})
}

// ToggleAdmin flips is_admin for a tenant-scoped user (super-admin untouched).
// in: tenant_id, user_id. out: new is_admin value, error.
func (s *AuthService) ToggleAdmin(tenantID string, userID uuid.UUID) (bool, error) {
	const query = `
		UPDATE users SET is_admin = NOT is_admin WHERE id = $1
		RETURNING is_admin`
	ctx := context.Background()
	var v bool
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, userID).Scan(&v)
	})
	return v, err
}

// ErrSuperAdminProtected is returned by DeleteUser on a super-admin target.
// Enforced here (not only in the handler) because super rows are platform-critical.
var ErrSuperAdminProtected = errors.New("cannot delete a super-admin")

// DeleteUser removes a user and cascades (sessions, magic links, subscriptions).
// Returns ErrSuperAdminProtected for super-admin targets; read+delete share one tx to prevent
// a concurrent promote from racing the check.
// in: tenant_id, user_id. out: error.
func (s *AuthService) DeleteUser(tenantID string, userID uuid.UUID) error {
	ctx := context.Background()
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		var isSuper bool
		err := tx.QueryRow(ctx, `SELECT is_super_admin FROM users WHERE id = $1`, userID).Scan(&isSuper)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("auth: load user %s for delete: %w", userID, err)
		}
		if isSuper {
			return ErrSuperAdminProtected
		}
		if _, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID); err != nil {
			return fmt.Errorf("auth: delete user %s: %w", userID, err)
		}
		return nil
	})
}

// HasPassword reports whether the given user has a non-null bcrypt hash stored.
// in: tenant_id, user_id. out: true if password set, error on query failure.
func (s *AuthService) HasPassword(tenantID string, userID uuid.UUID) (bool, error) {
	ctx := context.Background()
	var has bool
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT password_hash IS NOT NULL FROM users WHERE id = $1`, userID).Scan(&has)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}
	return has, err
}

// SetPassword bcrypt-hashes the plain password and stores it on the user row.
// Rejects anything under MinPasswordLen with ErrPasswordTooShort so the floor
// holds even for a caller that skips the form-level check.
// in: tenant_id, user_id, plain password. out: error.
func (s *AuthService) SetPassword(tenantID string, userID uuid.UUID, password string) error {
	if len(password) < MinPasswordLen {
		return ErrPasswordTooShort
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	ctx := context.Background()
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE users SET password_hash = $1 WHERE id = $2`, string(hash), userID)
		return err
	})
}

// touchLastLogin updates users.last_login_at. Best-effort; errors are ignored.
// in: tenant_id, user_id. out: none.
func (s *AuthService) touchLastLogin(tenantID string, userID uuid.UUID) {
	ctx := context.Background()
	_ = db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		_, _ = tx.Exec(ctx, `UPDATE users SET last_login_at = now() WHERE id = $1`, userID)
		return nil
	})
}
