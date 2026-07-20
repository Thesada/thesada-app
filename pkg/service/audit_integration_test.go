//go:build integration

// AuditService integration tests against a real TimescaleDB: the
// Record -> List round-trip, filter + ordering + limit semantics, the
// impersonation edges writing audit rows inside their own tx, and the
// operator-only table contract (the tenant-scoped app role cannot write
// admin_audit even with table grants, because RLS is FORCEd with no policy).
//
//	go test -tags integration -run TestAuditService ./pkg/service/...
package service_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

func TestAuditService(t *testing.T) {
	env := servicetest.Start(t)
	audit := env.Services.Audit
	auth := env.Services.Auth
	ctx := context.Background()

	const tA = "audit-a"
	env.SeedTenant(t, tA)
	actor := mustCreateUser(t, auth, tA, "operator@a.test")

	t.Run("record_then_list_roundtrip", func(t *testing.T) {
		id := actor.ID
		err := audit.Record(ctx, service.AuditEntry{
			ActorUserID: &id,
			ActorEmail:  actor.Email,
			Action:      "cert.issue",
			TargetType:  "device",
			TargetID:    "11111111-1111-1111-1111-111111111111",
			TenantID:    tA,
			Detail:      map[string]any{"device_id": "sht31", "serial": "abc123"},
		})
		if err != nil {
			t.Fatalf("Record: %v", err)
		}

		got, err := audit.List(ctx, service.AuditFilter{Action: "cert.issue"})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("List returned %d rows, want 1", len(got))
		}
		rec := got[0]
		if rec.ActorUserID == nil || *rec.ActorUserID != actor.ID {
			t.Errorf("actor_user_id = %v, want %v", rec.ActorUserID, actor.ID)
		}
		if rec.ActorEmail != actor.Email {
			t.Errorf("actor_email = %q, want %q", rec.ActorEmail, actor.Email)
		}
		if rec.TargetType == nil || *rec.TargetType != "device" {
			t.Errorf("target_type = %v, want device", rec.TargetType)
		}
		if rec.TenantID == nil || *rec.TenantID != tA {
			t.Errorf("tenant_id = %v, want %q", rec.TenantID, tA)
		}
		var detail map[string]any
		if err := json.Unmarshal(rec.Detail, &detail); err != nil {
			t.Fatalf("detail unmarshal: %v", err)
		}
		if detail["device_id"] != "sht31" {
			t.Errorf("detail.device_id = %v, want sht31", detail["device_id"])
		}
		if rec.At.IsZero() {
			t.Error("at is zero, want a server-side timestamp")
		}
	})

	t.Run("record_empty_optionals_store_null", func(t *testing.T) {
		if err := audit.Record(ctx, service.AuditEntry{
			ActorEmail: "operator@a.test",
			Action:     "ota.dispatch",
		}); err != nil {
			t.Fatalf("Record: %v", err)
		}
		got, err := audit.List(ctx, service.AuditFilter{Action: "ota.dispatch"})
		if err != nil || len(got) != 1 {
			t.Fatalf("List: rows %d err %v, want 1 row", len(got), err)
		}
		rec := got[0]
		if rec.TargetType != nil || rec.TargetID != nil || rec.TenantID != nil || rec.ActorUserID != nil {
			t.Errorf("empty optionals stored non-NULL: %+v", rec)
		}
		if string(rec.Detail) != "{}" {
			t.Errorf("nil detail stored as %s, want {}", rec.Detail)
		}
	})

	t.Run("record_requires_action", func(t *testing.T) {
		err := audit.Record(ctx, service.AuditEntry{ActorEmail: "x@a.test"})
		if !errors.Is(err, service.ErrAuditActionRequired) {
			t.Errorf("Record(no action) = %v, want ErrAuditActionRequired", err)
		}
	})

	t.Run("list_filters_and_orders_newest_first", func(t *testing.T) {
		for _, e := range []service.AuditEntry{
			{ActorEmail: "a@a.test", Action: "device.delete", TenantID: tA},
			{ActorEmail: "a@a.test", Action: "device.delete", TenantID: "other"},
			{ActorEmail: "a@a.test", Action: "device.reassign", TenantID: tA},
		} {
			if err := audit.Record(ctx, e); err != nil {
				t.Fatalf("Record(%s): %v", e.Action, err)
			}
		}

		byAction, err := audit.List(ctx, service.AuditFilter{Action: "device.delete"})
		if err != nil {
			t.Fatalf("List(action): %v", err)
		}
		if len(byAction) != 2 {
			t.Errorf("List(action=device.delete) = %d rows, want 2", len(byAction))
		}

		byBoth, err := audit.List(ctx, service.AuditFilter{Action: "device.delete", TenantID: tA})
		if err != nil {
			t.Fatalf("List(action+tenant): %v", err)
		}
		if len(byBoth) != 1 {
			t.Errorf("List(action+tenant) = %d rows, want 1", len(byBoth))
		}

		all, err := audit.List(ctx, service.AuditFilter{})
		if err != nil {
			t.Fatalf("List(all): %v", err)
		}
		for i := 1; i < len(all); i++ {
			if all[i-1].ID < all[i].ID {
				t.Errorf("rows not newest-first at index %d: %d before %d", i, all[i-1].ID, all[i].ID)
			}
		}

		limited, err := audit.List(ctx, service.AuditFilter{Limit: 1})
		if err != nil || len(limited) != 1 {
			t.Errorf("List(limit=1) = %d rows err %v, want exactly 1", len(limited), err)
		}
	})

	t.Run("impersonation_edges_write_audit_rows_in_tx", func(t *testing.T) {
		const tB = "audit-b"
		env.SeedTenant(t, tB)
		super := mustCreateUser(t, auth, tA, "super-audit@a.test")
		if err := auth.PromoteSuperAdmin(super.ID); err != nil {
			t.Fatalf("PromoteSuperAdmin: %v", err)
		}
		token, _, err := auth.CreateSession(tA, super.ID, "password", "", "")
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		sess, err := auth.ValidateSession(token)
		if err != nil {
			t.Fatalf("ValidateSession: %v", err)
		}

		if err := auth.SetImpersonation(sess.ID, tB); err != nil {
			t.Fatalf("SetImpersonation: %v", err)
		}
		if err := auth.ClearImpersonation(sess.ID); err != nil {
			t.Fatalf("ClearImpersonation: %v", err)
		}

		set, err := audit.List(ctx, service.AuditFilter{Action: "impersonation.set"})
		if err != nil || len(set) != 1 {
			t.Fatalf("List(impersonation.set) rows %d err %v, want 1", len(set), err)
		}
		if set[0].ActorEmail != super.Email {
			t.Errorf("set actor = %q, want %q (resolved from the session row)", set[0].ActorEmail, super.Email)
		}
		if set[0].TenantID == nil || *set[0].TenantID != tB {
			t.Errorf("set tenant = %v, want %q", set[0].TenantID, tB)
		}

		cleared, err := audit.List(ctx, service.AuditFilter{Action: "impersonation.clear"})
		if err != nil || len(cleared) != 1 {
			t.Fatalf("List(impersonation.clear) rows %d err %v, want 1", len(cleared), err)
		}
		if cleared[0].TenantID == nil || *cleared[0].TenantID != tB {
			t.Errorf("clear tenant = %v, want %q (the impersonation that ended)", cleared[0].TenantID, tB)
		}

		// A refused set (non-super session) must leave no audit row behind.
		plain := mustCreateUser(t, auth, tA, "plain-audit@a.test")
		ptoken, _, err := auth.CreateSession(tA, plain.ID, "password", "", "")
		if err != nil {
			t.Fatalf("CreateSession(plain): %v", err)
		}
		psess, err := auth.ValidateSession(ptoken)
		if err != nil {
			t.Fatalf("ValidateSession(plain): %v", err)
		}
		if err := auth.SetImpersonation(psess.ID, tB); !errors.Is(err, service.ErrNotSuperAdmin) {
			t.Fatalf("SetImpersonation(plain) = %v, want ErrNotSuperAdmin", err)
		}
		after, err := audit.List(ctx, service.AuditFilter{Action: "impersonation.set"})
		if err != nil || len(after) != 1 {
			t.Errorf("refused impersonation left audit rows: %d err %v, want still 1", len(after), err)
		}
	})

	t.Run("app_role_cannot_write_admin_audit", func(t *testing.T) {
		// servicetest grants thesada_app on ALL TABLES, so this deny is the
		// FORCEd no-policy RLS doing its job, not a missing grant.
		_, err := env.Pools.App.Exec(ctx,
			`INSERT INTO admin_audit (actor_email, action) VALUES ('evil@a.test', 'device.delete')`)
		if err == nil {
			t.Fatal("app-role INSERT into admin_audit succeeded, want RLS deny")
		}
	})

	t.Run("audit_table_is_append_only", func(t *testing.T) {
		// TRUNCATE bypasses RLS entirely - only the 0026 REVOKE ALL stands
		// between an app connection and an erased trail. UPDATE/DELETE on the
		// admin role prove the narrow re-grant (env re-grants broad to
		// thesada_app only, so admin keeps exactly what 0026 left it).
		if _, err := env.Pools.App.Exec(ctx, `TRUNCATE admin_audit`); err == nil {
			t.Fatal("app-role TRUNCATE admin_audit succeeded, want permission denied")
		}
		if _, err := env.Pools.Admin.Exec(ctx, `TRUNCATE admin_audit`); err == nil {
			t.Fatal("admin-role TRUNCATE admin_audit succeeded, want permission denied")
		}
		if _, err := env.Pools.Admin.Exec(ctx,
			`UPDATE admin_audit SET action = 'tampered'`); err == nil {
			t.Fatal("admin-role UPDATE admin_audit succeeded, want permission denied")
		}
		if _, err := env.Pools.Admin.Exec(ctx, `DELETE FROM admin_audit`); err == nil {
			t.Fatal("admin-role DELETE admin_audit succeeded, want permission denied")
		}
	})
}
