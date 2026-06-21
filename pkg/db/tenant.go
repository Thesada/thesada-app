// tenant.go - GUC-based per-tx tenant scoping for the RLS rollout. See
// docs/invariants.md "Tenant isolation" for the full design contract.
//
// Phase 0 contract:
//   - WithTenant opens a transaction, sets app.tenant_id via SET LOCAL,
//     hands the tx to the callback, commits or rolls back on return.
//     Phase 1 enables RLS policies that read app.tenant_id; until then this
//     is a no-op gate that callers can adopt incrementally.
//   - WithAdminAudit is the BYPASSRLS path. Every cross-tenant read is
//     expected to flow through this wrapper so admin-side access is logged
//     in one place. Phase 3 makes this mandatory via a static check.
//
// Both helpers take the pool explicitly so the caller picks which DB role
// (app / admin / mqtt) is in play. There is no implicit "current pool".

package db

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNoTenant is returned when WithTenant is called with an empty tenantID.
// Allowing it through would be a silent cross-tenant read once RLS is on -
// the policy uses current_setting('app.tenant_id', true) which evaluates to
// NULL when unset, and "tenant_id = NULL" matches no rows. That's safe for
// SELECT but masks bugs at INSERT time. Reject early instead.
var ErrNoTenant = errors.New("db.WithTenant: tenantID is required")

// WithTenant opens a tx on pool, sets app.tenant_id, runs fn, commits.
// in:  ctx, pool (any of app/admin/mqtt), tenantID (non-empty), fn callback.
// out: error from BEGIN, SET LOCAL, fn, or COMMIT - all bubble up.
//      On any error the tx is rolled back via pgx's deferred Rollback.
func WithTenant(ctx context.Context, pool *pgxpool.Pool, tenantID string, fn func(pgx.Tx) error) error {
	if tenantID == "" {
		return ErrNoTenant
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("WithTenant begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// SET LOCAL cannot take a bound parameter, so set_config(..., is_local=true)
	// does the same job for the transaction while accepting $1 - tenantID is
	// passed as a parameter, never concatenated into SQL. (It is internal, the
	// TEXT primary key on tenants, but parameterizing it is free defence in depth.)
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID); err != nil {
		return fmt.Errorf("WithTenant set_config: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// WithAdminAudit runs fn against the admin (BYPASSRLS) pool with an audit
// log line on entry. The reason string identifies the cross-tenant call site
// for after-the-fact log review.
//
// in:  ctx, admin pool, reason (free-form), fn callback receiving a tx.
// out: error from BEGIN, fn, or COMMIT.
//
// app.tenant_id is intentionally NOT set on this path - the whole point of
// the admin pool is to read across tenants. fn is responsible for any
// per-row tenant filtering it does need.
func WithAdminAudit(ctx context.Context, pool *pgxpool.Pool, reason string, fn func(pgx.Tx) error) error {
	slog.InfoContext(ctx, "rls.admin_audit", "reason", reason)
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("WithAdminAudit begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
