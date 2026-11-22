//go:build integration

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"thesada.app/app/pkg/service"
)

// TestAdminRules_TenantSlotNeedsTakeover: the admin editor cannot overwrite a
// slot the tenant editor owns unless the save says takeover. A tenant user,
// the device owner or a user of another tenant, gets nothing from the route.
func TestAdminRules_TenantSlotNeedsTakeover(t *testing.T) {
	f := seedCrossTenant(t)
	ctx := context.Background()
	path := "/admin/devices/" + f.device.String() + "/rules/workspace"
	opID, op := tenantSession(t, f, "op@ct-a.test", false)
	if _, err := f.env.Super.Exec(ctx, `UPDATE users SET is_super_admin = true WHERE id = $1`, opID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.env.Services.RuleWorkspaces.Save(ctx, ctTenantA, f.device, service.DefaultRuleSlot,
		`{"tenant":true}`, "-- tenant rules", "tenant", nil); err != nil {
		t.Fatal(err)
	}
	body := func(source string, takeover bool) []byte {
		b, _ := json.Marshal(map[string]any{"slot": service.DefaultRuleSlot, "workspace_json": `{"op":true}`,
			"lua_content": "-- operator rules", "source": source, "takeover": takeover})
		return b
	}
	tenantKept := func(what string) {
		t.Helper()
		ws, err := f.env.Services.RuleWorkspaces.Latest(ctx, ctTenantA, f.device, service.DefaultRuleSlot)
		if err != nil || ws == nil || ws.Source != "tenant" || ws.LuaContent != "-- tenant rules" {
			t.Fatalf("%s replaced the tenant rules: %+v err = %v", what, ws, err)
		}
	}

	for _, source := range []string{"editor", "push"} {
		if rec := postPasskeyJSON(t, f.srv, path, body(source, false), op); rec.Code != http.StatusConflict {
			t.Errorf("%s save without takeover = %d %s, want 409", source, rec.Code, rec.Body.String())
		}
		tenantKept(source + " save without takeover")
	}
	for name, who := range map[string]*http.Cookie{"device owner": f.owner, "other tenant": f.out} {
		if rec := postPasskeyJSON(t, f.srv, path, body("editor", true), who); rec.Code == http.StatusOK {
			t.Errorf("%s reached the admin save", name)
		}
		tenantKept(name)
	}
	if rec := postPasskeyJSON(t, f.srv, path, body("editor", true), op); rec.Code != http.StatusOK {
		t.Fatalf("takeover = %d %s", rec.Code, rec.Body.String())
	}
	ws, err := f.env.Services.RuleWorkspaces.Latest(ctx, ctTenantA, f.device, service.DefaultRuleSlot)
	if err != nil || ws == nil || ws.Source != "editor" {
		t.Fatalf("takeover did not land: %+v err = %v", ws, err)
	}
	if rec := postPasskeyJSON(t, f.srv, path, body("editor", false), op); rec.Code != http.StatusOK {
		t.Fatalf("save over an operator slot = %d %s, want 200", rec.Code, rec.Body.String())
	}
}

// TestAdminRules_TenantSaveRacingAnAdminSaveWins: a tenant save that lands between the
// admin save's source check and its write keeps the slot. The tenant insert is held open
// until the admin save waits on it, so the race runs the same way every time.
func TestAdminRules_TenantSaveRacingAnAdminSaveWins(t *testing.T) {
	f := seedCrossTenant(t)
	ctx := context.Background()
	path := "/admin/devices/" + f.device.String() + "/rules/workspace"
	opID, op := tenantSession(t, f, "race@ct-a.test", false)
	if _, err := f.env.Super.Exec(ctx, `UPDATE users SET is_super_admin = true WHERE id = $1`, opID); err != nil {
		t.Fatal(err)
	}
	tx, err := f.env.Super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO device_rule_workspaces (device_pk, slot, workspace_json, lua_content, lua_sha256, source)
		VALUES ($1, $2, '{"tenant":true}', '-- tenant rules', 'sha-tenant', 'tenant')`,
		f.device, service.DefaultRuleSlot); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(map[string]any{"slot": service.DefaultRuleSlot, "workspace_json": `{"op":true}`,
		"lua_content": "-- operator rules", "source": "editor"})
	done := make(chan int, 1)
	go func() { done <- postPasskeyJSON(t, f.srv, path, body, op).Code }()

	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		if err := f.env.Super.QueryRow(ctx, `
			SELECT count(*) FROM pg_stat_activity
			 WHERE wait_event_type = 'Lock' AND query LIKE '%device_rule_workspaces%'`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		select {
		case code := <-done:
			t.Fatalf("admin save answered %d before the tenant save committed", code)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the admin save never waited on the tenant insert")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if code := <-done; code != http.StatusConflict {
		t.Errorf("admin save racing a tenant save = %d, want 409", code)
	}
	ws, err := f.env.Services.RuleWorkspaces.Latest(ctx, ctTenantA, f.device, service.DefaultRuleSlot)
	if err != nil || ws == nil || ws.Source != "tenant" || ws.LuaContent != "-- tenant rules" {
		t.Fatalf("the racing admin save replaced the tenant rules: %+v err = %v", ws, err)
	}
	hist, err := f.env.Services.RuleWorkspaces.History(ctx, ctTenantA, f.device, service.DefaultRuleSlot, 10)
	if err != nil || len(hist) != 0 {
		t.Fatalf("history = %d rows err = %v, want none from a refused save", len(hist), err)
	}
}
