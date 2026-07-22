// Unit coverage for the audit List query builder: clause assembly, bind
// arg ordering, LIKE escaping, and the limit clamp. Pure function - no DB.
// The end-to-end List semantics live in the integration suite.
package service

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAuditListQuery(t *testing.T) {
	t.Run("no_filter_defaults", func(t *testing.T) {
		q, args := auditListQuery(AuditFilter{})
		if strings.Contains(q, "WHERE") {
			t.Errorf("empty filter built a WHERE clause: %s", q)
		}
		if !strings.Contains(q, "ORDER BY at DESC, id DESC LIMIT $1") {
			t.Errorf("missing order/limit clause: %s", q)
		}
		if len(args) != 1 || args[0] != 100 {
			t.Errorf("args = %v, want [100] (default limit)", args)
		}
		if strings.Contains(q, "OFFSET") {
			t.Errorf("zero offset emitted an OFFSET clause: %s", q)
		}
	})

	t.Run("limit_clamped_to_max", func(t *testing.T) {
		_, args := auditListQuery(AuditFilter{Limit: 10_000})
		if args[len(args)-1] != auditListMaxLimit {
			t.Errorf("limit arg = %v, want clamp to %d", args[len(args)-1], auditListMaxLimit)
		}
	})

	t.Run("all_clauses_in_arg_order", func(t *testing.T) {
		actor := uuid.New()
		from := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
		to := from.AddDate(0, 0, 7)
		q, args := auditListQuery(AuditFilter{
			Action:      "cert.issue",
			ActorUserID: &actor,
			ActorEmail:  "op@example",
			TargetType:  "device",
			TargetID:    "abc",
			TenantID:    "default",
			From:        from,
			To:          to,
			Limit:       50,
			Offset:      50,
		})
		for _, clause := range []string{
			"action = $1", "actor_user_id = $2", "actor_email ILIKE $3",
			"target_type = $4", "target_id = $5", "tenant_id = $6",
			"at >= $7", "at < $8", "LIMIT $9", "OFFSET $10",
		} {
			if !strings.Contains(q, clause) {
				t.Errorf("query missing %q: %s", clause, q)
			}
		}
		want := []any{"cert.issue", actor, "%op@example%", "device", "abc", "default", from, to, 50, 50}
		if len(args) != len(want) {
			t.Fatalf("args len = %d, want %d (%v)", len(args), len(want), args)
		}
		for i := range want {
			if args[i] != want[i] {
				t.Errorf("args[%d] = %v, want %v", i, args[i], want[i])
			}
		}
	})

	t.Run("actor_email_like_metachars_escaped", func(t *testing.T) {
		_, args := auditListQuery(AuditFilter{ActorEmail: `50%_a\b`})
		if got, want := args[0], `%50\%\_a\\b%`; got != want {
			t.Errorf("ILIKE pattern = %q, want %q", got, want)
		}
	})

	t.Run("negative_offset_ignored", func(t *testing.T) {
		q, _ := auditListQuery(AuditFilter{Offset: -5})
		if strings.Contains(q, "OFFSET") {
			t.Errorf("negative offset emitted an OFFSET clause: %s", q)
		}
	})
}
