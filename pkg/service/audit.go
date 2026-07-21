// AuditService - durable admin_audit trail for privileged operator
// mutations. The slog lines at the call sites stay (journalctl-grep
// convenience); this table is the queryable record that survives log
// rotation. Operator-only: the table has FORCEd RLS with no policy, so
// every access goes through the BYPASSRLS admin pool.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/db"
)

// AuditService writes and lists admin_audit rows.
type AuditService struct {
	cfg   *config.Config
	pools db.Pools
}

// ErrAuditActionRequired means Record was called without an action slug.
var ErrAuditActionRequired = errors.New("audit: action is required")

// AuditEntry is one privileged mutation to record. Action is a dotted slug
// (the pkg/authz Action vocabulary; this package cannot import authz -
// authz imports service for the User type - so callers pass the string).
// Detail must never carry secret values or payload bodies: field names,
// counts, and target labels only. Empty TargetType/TargetID/TenantID
// store as NULL.
type AuditEntry struct {
	ActorUserID *uuid.UUID
	ActorEmail  string
	Action      string
	TargetType  string
	TargetID    string
	TenantID    string
	Detail      map[string]any
}

// AuditRecord is one stored admin_audit row.
type AuditRecord struct {
	ID          int64
	At          time.Time
	ActorUserID *uuid.UUID
	ActorEmail  string
	Action      string
	TargetType  *string
	TargetID    *string
	TenantID    *string
	Detail      json.RawMessage
}

// AuditFilter narrows List. Zero values mean "no filter"; Limit <= 0
// defaults to 100. ActorEmail is a case-insensitive substring match (the
// table is operator-scale, so a seqscan ILIKE is the cheap option); every
// other field is exact. From is inclusive, To exclusive - a UI passing a
// date range hands the day-after as To. Offset > 0 skips rows for
// pagination.
type AuditFilter struct {
	Action      string
	ActorUserID *uuid.UUID
	ActorEmail  string
	TargetType  string
	TargetID    string
	TenantID    string
	From        time.Time
	To          time.Time
	Limit       int
	Offset      int
}

// auditListMaxLimit caps a single List page so a UI bug cannot pull the
// whole table into memory.
const auditListMaxLimit = 500

// escapeLike neutralizes LIKE metacharacters in user input so a filter of
// "100%" matches the literal text instead of everything.
// in: raw substring. out: pattern-safe substring (caller adds the %...%).
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

// auditListQuery builds the List SQL + bind args from a filter. Pure so
// the clause assembly is unit-testable without a database.
// in: filter. out: full query text, ordered bind args.
func auditListQuery(f AuditFilter) (string, []any) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > auditListMaxLimit {
		limit = auditListMaxLimit
	}
	query := `SELECT id, at, actor_user_id, actor_email, action, target_type, target_id, tenant_id, detail
	            FROM admin_audit`
	var (
		args  []any
		where string
	)
	and := func(clause string, v any) {
		args = append(args, v)
		if where == "" {
			where = " WHERE "
		} else {
			where += " AND "
		}
		// Sprintf builds the bind index only; the value lives in args.
		where += fmt.Sprintf(clause, len(args))
	}
	if f.Action != "" {
		and("action = $%d", f.Action)
	}
	if f.ActorUserID != nil {
		and("actor_user_id = $%d", *f.ActorUserID)
	}
	if f.ActorEmail != "" {
		and("actor_email ILIKE $%d", "%"+escapeLike(f.ActorEmail)+"%")
	}
	if f.TargetType != "" {
		and("target_type = $%d", f.TargetType)
	}
	if f.TargetID != "" {
		and("target_id = $%d", f.TargetID)
	}
	if f.TenantID != "" {
		and("tenant_id = $%d", f.TenantID)
	}
	if !f.From.IsZero() {
		and("at >= $%d", f.From)
	}
	if !f.To.IsZero() {
		and("at < $%d", f.To)
	}
	args = append(args, limit)
	query += where + fmt.Sprintf(" ORDER BY at DESC, id DESC LIMIT $%d", len(args))
	if f.Offset > 0 {
		args = append(args, f.Offset)
		query += fmt.Sprintf(" OFFSET $%d", len(args))
	}
	return query, args
}

// Record inserts one admin_audit row via the admin pool. Callers on
// best-effort paths must not fail the admin action on error - log it loud
// and continue (the mutation already happened).
// in: ctx, entry. out: error from validation or the insert.
func (s *AuditService) Record(ctx context.Context, e AuditEntry) error {
	if e.Action == "" {
		return ErrAuditActionRequired
	}
	return db.WithAdminAudit(ctx, s.pools.Admin, "audit.record", func(tx pgx.Tx) error {
		return auditInsertTx(ctx, tx, e)
	})
}

// auditInsertTx writes one admin_audit row on the given tx, so a caller
// that already holds the mutation's transaction can make the audit write
// atomic with the mutation itself.
// in: ctx, tx (admin pool), entry. out: error from marshal or insert.
func auditInsertTx(ctx context.Context, tx pgx.Tx, e AuditEntry) error {
	detail := e.Detail
	if detail == nil {
		detail = map[string]any{}
	}
	body, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("audit: marshal detail for %s: %w", e.Action, err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO admin_audit (actor_user_id, actor_email, action, target_type, target_id, tenant_id, detail)
		 VALUES ($1, $2, $3, NULLIF($4, ''), NULLIF($5, ''), NULLIF($6, ''), $7)`,
		e.ActorUserID, e.ActorEmail, e.Action, e.TargetType, e.TargetID, e.TenantID, body); err != nil {
		return fmt.Errorf("audit: insert %s: %w", e.Action, err)
	}
	return nil
}

// auditImpersonationTx records an impersonation edge inside the mutation's
// own tx (atomic: a failed audit write rolls the impersonation change
// back). The actor is resolved from the session row - the service only
// sees a session id, and the session's user IS the actor.
// in: ctx, tx, session id, action slug, target tenant slug ("" = none).
// out: error from the insert.
func auditImpersonationTx(ctx context.Context, tx pgx.Tx, sessionID uuid.UUID, action, targetTenant string) error {
	if _, err := tx.Exec(ctx,
		`INSERT INTO admin_audit (actor_user_id, actor_email, action, target_type, target_id, tenant_id, detail)
		 SELECT u.id, u.email, $1, 'tenant', NULLIF($2, ''), NULLIF($2, ''), '{}'::jsonb
		   FROM user_sessions s
		   JOIN users u ON u.id = s.user_id
		  WHERE s.id = $3`,
		action, targetTenant, sessionID); err != nil {
		return fmt.Errorf("audit: insert %s for session %s: %w", action, sessionID, err)
	}
	return nil
}

// List returns admin_audit rows newest-first, optionally filtered by
// action, actor (id or email substring), target, tenant, and time range,
// with limit/offset pagination. Backs the /admin/audit search UI.
// in: ctx, filter. out: rows newest-first, error.
func (s *AuditService) List(ctx context.Context, f AuditFilter) ([]AuditRecord, error) {
	query, args := auditListQuery(f)

	var out []AuditRecord
	err := db.WithAdminAudit(ctx, s.pools.Admin, "audit.list", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rec AuditRecord
			if err := rows.Scan(&rec.ID, &rec.At, &rec.ActorUserID, &rec.ActorEmail,
				&rec.Action, &rec.TargetType, &rec.TargetID, &rec.TenantID, &rec.Detail); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("audit: list: %w", err)
	}
	return out, nil
}
