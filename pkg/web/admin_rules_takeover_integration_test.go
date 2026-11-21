//go:build integration

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

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
