// AuthService - waitlist: list, count, convert, add, delete.
// See auth.go for the service struct and shared types.
//
// RLS: waitlist has a direct tenant_id policy. AddToWaitlist runs
// with a tenant in hand (the public signup form posts into a known tenant)
// so it uses db.WithTenant. The list/count/convert/delete paths are
// super-admin cross-tenant operations - they run under db.WithAdminAudit
// on the BYPASSRLS pool.
package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/db"
)

// WaitlistEntry is the view-model for a pending waitlist row.
type WaitlistEntry struct {
	ID        uuid.UUID
	TenantID  string
	Email     string
	Note      *string
	CreatedAt time.Time
}

// ListPendingWaitlist returns every waitlist row that has not yet been
// converted to a user, ordered by tenant then oldest first. Super-admin-only
// callers use this for the /admin/waitlist conversion page. Cross-tenant BY
// DESIGN - runs under WithAdminAudit.
// out: []WaitlistEntry, error.
func (s *AuthService) ListPendingWaitlist() ([]WaitlistEntry, error) {
	const query = `
		SELECT id, tenant_id, email, note, created_at
		FROM waitlist
		WHERE converted_user_id IS NULL
		ORDER BY tenant_id, created_at`
	ctx := context.Background()
	var out []WaitlistEntry
	err := db.WithAdminAudit(ctx, s.pools.Admin, "auth.list_pending_waitlist", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var w WaitlistEntry
			if err := rows.Scan(&w.ID, &w.TenantID, &w.Email, &w.Note, &w.CreatedAt); err != nil {
				return err
			}
			out = append(out, w)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CountPendingWaitlist returns how many waitlist rows have no associated
// user yet. Used by the /admin dashboard tile. Cross-tenant BY DESIGN.
// out: count, error.
func (s *AuthService) CountPendingWaitlist() (int, error) {
	ctx := context.Background()
	var n int
	err := db.WithAdminAudit(ctx, s.pools.Admin, "auth.count_pending_waitlist", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM waitlist WHERE converted_user_id IS NULL`).Scan(&n)
	})
	return n, err
}

// ConvertWaitlistEntry turns a pending waitlist row into a real user in the
// target tenant. Creates the user, marks the waitlist row converted, and
// returns the new user so the caller can fire a reset-link email.
// Target tenant defaults to the waitlist row's own tenant when empty.
//
// Cross-tenant BY DESIGN - a super-admin converts a pending row that may
// belong to any tenant, optionally into a different one. Runs under
// WithAdminAudit; the whole read + insert + mark stays in one tx.
// in: waitlist id, target tenant (may be ""), is_admin flag. out: *User, error.
func (s *AuthService) ConvertWaitlistEntry(waitlistID uuid.UUID, targetTenant string, isAdmin bool) (*User, error) {
	ctx := context.Background()
	var u User
	var notFound bool
	err := db.WithAdminAudit(ctx, s.pools.Admin, "auth.convert_waitlist_entry", func(tx pgx.Tx) error {
		var (
			srcTenant string
			email     string
			note      *string
		)
		qerr := tx.QueryRow(ctx,
			`SELECT tenant_id, email, note FROM waitlist
			 WHERE id = $1 AND converted_user_id IS NULL
			 FOR UPDATE`, waitlistID).Scan(&srcTenant, &email, &note)
		if errors.Is(qerr, pgx.ErrNoRows) {
			notFound = true
			return nil
		}
		if qerr != nil {
			return qerr
		}
		if targetTenant == "" {
			targetTenant = srcTenant
		}
		displayName := ""
		if note != nil {
			displayName = *note
		}
		var dn interface{}
		if displayName != "" {
			dn = displayName
		}
		if qerr := tx.QueryRow(ctx,
			`INSERT INTO users (tenant_id, email, display_name, is_admin)
			 VALUES ($1, $2, $3, $4)
			 RETURNING id, tenant_id, email, display_name, telegram_chat_id, is_admin, is_super_admin, created_at, last_login_at`,
			targetTenant, email, dn, isAdmin).Scan(
			&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.TelegramChatID, &u.IsAdmin, &u.IsSuperAdmin, &u.CreatedAt, &u.LastLoginAt); qerr != nil {
			return qerr
		}
		tag, qerr := tx.Exec(ctx,
			`UPDATE waitlist SET converted_user_id = $1
			 WHERE id = $2 AND converted_user_id IS NULL`, u.ID, waitlistID)
		if qerr != nil {
			return qerr
		}
		if tag.RowsAffected() == 0 {
			notFound = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if notFound {
		return nil, ErrNotFound
	}
	return &u, nil
}

// AddToWaitlist inserts an email into the waitlist (idempotent on tenant+email).
// Tenant-scoped through WithTenant.
// in: tenant_id, email, optional note. out: row id (existing or new), error.
func (s *AuthService) AddToWaitlist(tenantID, email, note string) (uuid.UUID, error) {
	const query = `
		INSERT INTO waitlist (tenant_id, email, note)
		VALUES ($1, $2, NULLIF($3, ''))
		ON CONFLICT (tenant_id, email) DO UPDATE SET email = EXCLUDED.email
		RETURNING id`
	ctx := context.Background()
	var id uuid.UUID
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, tenantID, email, note).Scan(&id)
	})
	return id, err
}

// DeleteWaitlistEntry removes a pending waitlist row by ID. Returns ErrNotFound
// if the row does not exist or was already converted. Cross-tenant BY DESIGN
// (super-admin keyed on a waitlist row id) - runs under WithAdminAudit.
// in: waitlist row id. out: error.
func (s *AuthService) DeleteWaitlistEntry(id uuid.UUID) error {
	ctx := context.Background()
	var affected int64
	err := db.WithAdminAudit(ctx, s.pools.Admin, "auth.delete_waitlist_entry", func(tx pgx.Tx) error {
		tag, execErr := tx.Exec(ctx,
			`DELETE FROM waitlist WHERE id = $1 AND converted_user_id IS NULL`, id)
		if execErr != nil {
			return execErr
		}
		affected = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}
