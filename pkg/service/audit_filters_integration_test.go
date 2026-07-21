//go:build integration

// AuditService.List filter extensions behind the /admin/audit UI: actor
// email substring (case-insensitive, LIKE-metachar safe), target
// type/id exact match, time-range bounds, and offset pagination. The base
// Record/List round-trip lives in audit_integration_test.go.
//
//	go test -tags integration -run TestAuditListFilters ./pkg/service/...
package service_test

import (
	"context"
	"testing"
	"time"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

func TestAuditListFilters(t *testing.T) {
	env := servicetest.Start(t)
	audit := env.Services.Audit
	ctx := context.Background()

	// Distinct action slugs per concern keep the subtests independent of
	// one another and of rows other suites might write.
	record := func(t *testing.T, e service.AuditEntry) {
		t.Helper()
		if err := audit.Record(ctx, e); err != nil {
			t.Fatalf("Record(%s): %v", e.Action, err)
		}
	}

	t.Run("actor_email_substring_case_insensitive", func(t *testing.T) {
		record(t, service.AuditEntry{ActorEmail: "Alpha-Op@x.test", Action: "flt.actor"})
		record(t, service.AuditEntry{ActorEmail: "beta-op@x.test", Action: "flt.actor"})

		got, err := audit.List(ctx, service.AuditFilter{Action: "flt.actor", ActorEmail: "ALPHA"})
		if err != nil || len(got) != 1 || got[0].ActorEmail != "Alpha-Op@x.test" {
			t.Errorf("List(actor~ALPHA) = %d rows err %v, want the Alpha-Op row", len(got), err)
		}
		// Substring, not exact: the common domain matches both.
		if got, _ := audit.List(ctx, service.AuditFilter{Action: "flt.actor", ActorEmail: "op@x.test"}); len(got) != 2 {
			t.Errorf("List(actor~op@x.test) = %d rows, want 2", len(got))
		}
	})

	t.Run("actor_email_like_metachars_are_literal", func(t *testing.T) {
		record(t, service.AuditEntry{ActorEmail: "odd%actor@x.test", Action: "flt.like"})
		record(t, service.AuditEntry{ActorEmail: "plain@x.test", Action: "flt.like"})

		got, err := audit.List(ctx, service.AuditFilter{Action: "flt.like", ActorEmail: "%"})
		if err != nil || len(got) != 1 || got[0].ActorEmail != "odd%actor@x.test" {
			t.Errorf("List(actor~%%) = %d rows err %v, want only the literal-%% row", len(got), err)
		}
	})

	t.Run("target_type_and_id_exact", func(t *testing.T) {
		record(t, service.AuditEntry{ActorEmail: "t@x.test", Action: "flt.target",
			TargetType: "device", TargetID: "dev-1"})
		record(t, service.AuditEntry{ActorEmail: "t@x.test", Action: "flt.target",
			TargetType: "device", TargetID: "dev-2"})
		record(t, service.AuditEntry{ActorEmail: "t@x.test", Action: "flt.target",
			TargetType: "tenant", TargetID: "dev-1"})

		if got, _ := audit.List(ctx, service.AuditFilter{Action: "flt.target", TargetType: "device"}); len(got) != 2 {
			t.Errorf("List(target_type=device) = %d rows, want 2", len(got))
		}
		got, _ := audit.List(ctx, service.AuditFilter{Action: "flt.target", TargetType: "device", TargetID: "dev-1"})
		if len(got) != 1 || got[0].TargetID == nil || *got[0].TargetID != "dev-1" {
			t.Errorf("List(type+id) = %d rows, want exactly the device/dev-1 row", len(got))
		}
	})

	t.Run("time_range_bounds", func(t *testing.T) {
		record(t, service.AuditEntry{ActorEmail: "r@x.test", Action: "flt.range"})
		record(t, service.AuditEntry{ActorEmail: "r@x.test", Action: "flt.range"})
		// Backdate one row two days: admin_audit is append-only for the app
		// roles, so the rewrite goes through the superuser pool.
		if _, err := env.Super.Exec(ctx,
			`UPDATE admin_audit SET at = now() - interval '2 days'
			  WHERE id = (SELECT min(id) FROM admin_audit WHERE action = 'flt.range')`); err != nil {
			t.Fatalf("backdate row: %v", err)
		}

		dayAgo := time.Now().Add(-24 * time.Hour)
		if got, _ := audit.List(ctx, service.AuditFilter{Action: "flt.range", From: dayAgo}); len(got) != 1 {
			t.Errorf("List(From=now-24h) = %d rows, want 1 (backdated row excluded)", len(got))
		}
		if got, _ := audit.List(ctx, service.AuditFilter{Action: "flt.range", To: dayAgo}); len(got) != 1 {
			t.Errorf("List(To=now-24h) = %d rows, want 1 (only the backdated row)", len(got))
		}
		got, _ := audit.List(ctx, service.AuditFilter{Action: "flt.range", From: dayAgo, To: time.Now().Add(time.Hour)})
		if len(got) != 1 {
			t.Errorf("List(From+To window) = %d rows, want 1", len(got))
		}
	})

	t.Run("offset_pages_without_overlap", func(t *testing.T) {
		for range 5 {
			record(t, service.AuditEntry{ActorEmail: "p@x.test", Action: "flt.page"})
		}
		page1, err := audit.List(ctx, service.AuditFilter{Action: "flt.page", Limit: 2})
		if err != nil || len(page1) != 2 {
			t.Fatalf("page1 = %d rows err %v, want 2", len(page1), err)
		}
		page2, err := audit.List(ctx, service.AuditFilter{Action: "flt.page", Limit: 2, Offset: 2})
		if err != nil || len(page2) != 2 {
			t.Fatalf("page2 = %d rows err %v, want 2", len(page2), err)
		}
		page3, err := audit.List(ctx, service.AuditFilter{Action: "flt.page", Limit: 2, Offset: 4})
		if err != nil || len(page3) != 1 {
			t.Fatalf("page3 = %d rows err %v, want 1", len(page3), err)
		}
		seen := map[int64]bool{}
		for _, rec := range append(append(page1, page2...), page3...) {
			if seen[rec.ID] {
				t.Errorf("row id %d appeared on two pages", rec.ID)
			}
			seen[rec.ID] = true
		}
		// Newest-first holds across page boundaries.
		if page1[1].ID < page2[0].ID {
			t.Errorf("page boundary out of order: %d then %d", page1[1].ID, page2[0].ID)
		}
	})
}
