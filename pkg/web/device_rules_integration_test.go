//go:build integration

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/mqtt/mqtttest"
	"thesada.app/app/pkg/rulesgen"
	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

// testRuleFields is one valid tenant rule block.
func testRuleFields() map[string]any {
	return map[string]any{"METRIC": "temperature", "SENSOR": "Outdoor", "OP": "below", "VALUE": 2,
		"SUSTAIN_N": 5, "SUSTAIN_MIN": 5, "MSG": "Freeze risk", "CODE": "freeze", "COOLDOWN_MIN": 15}
}

// tenantRulesJSON wraps rule fields in a workspace and the request body.
func tenantRulesJSON(t *testing.T, rules ...map[string]any) []byte {
	t.Helper()
	var chain map[string]any
	for i := len(rules) - 1; i >= 0; i-- {
		b := map[string]any{"type": rulesgen.RuleBlock, "fields": rules[i]}
		if chain != nil {
			b["next"] = map[string]any{"block": chain}
		}
		chain = b
	}
	root := map[string]any{"type": rulesgen.RootBlock}
	if chain != nil {
		root["inputs"] = map[string]any{"RULES": map[string]any{"block": chain}}
	}
	ws, _ := json.Marshal(map[string]any{"blocks": map[string]any{"blocks": []any{root}}})
	body, _ := json.Marshal(map[string]string{"workspace_json": string(ws)})
	return body
}

// tenantSession makes a tenant A user and a session for it.
func tenantSession(t *testing.T, f crossTenantFixture, email string, admin bool) (uuid.UUID, *http.Cookie) {
	t.Helper()
	u, err := f.env.Services.Auth.CreateUser(ctTenantA, email, email, admin)
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := f.env.Services.Auth.CreateSession(ctTenantA, u.ID, "magic_link", "go-test", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return u.ID, &http.Cookie{Name: authmw.CookieName, Value: tok}
}

// TestDeviceRules_RolesSaveAndRefusals: a plain tenant user only views, the
// owner and a tenant admin save, a foreign block is refused, and an
// operator-owned slot is neither shown nor overwritten.
func TestDeviceRules_RolesSaveAndRefusals(t *testing.T) {
	f := seedCrossTenant(t)
	dev := "/devices/" + f.device.String()
	_, viewer := tenantSession(t, f, "viewer@ct-a.test", false)
	_, admin := tenantSession(t, f, "admin@ct-a.test", true)
	rows := `SELECT count(*) FROM device_rule_workspace_history WHERE device_pk = $1`
	body := tenantRulesJSON(t, testRuleFields())

	page := getAs(f.srv, dev+"/rules", viewer)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "View only") || strings.Contains(page.Body.String(), `id="btn-save"`) {
		t.Fatalf("viewer page: status %d, want a view-only editor", page.Code)
	}
	if rec := postPasskeyJSON(t, f.srv, dev+"/rules/preview", body, viewer); rec.Code != http.StatusOK {
		t.Fatalf("viewer preview: status %d", rec.Code)
	}
	for _, path := range []string{"/rules/workspace", "/rules/push"} {
		if rec := postPasskeyJSON(t, f.srv, dev+path, body, viewer); rec.Code != http.StatusForbidden {
			t.Errorf("viewer %s: status %d, want 403", path, rec.Code)
		}
	}
	if f.count(t, rows, f.device) != 0 {
		t.Fatal("viewer stored rules")
	}

	if rec := postPasskeyJSON(t, f.srv, dev+"/rules/workspace", body, admin); rec.Code != http.StatusOK {
		t.Fatalf("tenant admin save: status %d %s", rec.Code, rec.Body.String())
	}
	if rec := postPasskeyJSON(t, f.srv, dev+"/rules/workspace", body, f.owner); rec.Code != http.StatusOK {
		t.Fatalf("owner save: status %d %s", rec.Code, rec.Body.String())
	}
	ws, err := f.env.Services.RuleWorkspaces.Latest(context.Background(), ctTenantA, f.device, service.DefaultRuleSlot)
	if err != nil || ws == nil || ws.Source != "tenant" || !strings.Contains(ws.LuaContent, `"freeze:1"`) {
		t.Fatalf("saved workspace = %+v err = %v, want tenant source and generated Lua", ws, err)
	}
	if n := f.count(t, `SELECT count(*) FROM admin_audit WHERE action = 'rules.tenant_save'`); n != 2 {
		t.Fatalf("audit rows = %d, want 2", n)
	}

	foreign := []byte(`{"workspace_json":"{\"blocks\":{\"blocks\":[{\"type\":\"lua_raw\"}]}}"}`)
	before := f.count(t, rows, f.device)
	if rec := postPasskeyJSON(t, f.srv, dev+"/rules/workspace", foreign, f.owner); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "unsupported block") {
		t.Fatalf("foreign block: status %d body %q, want 400", rec.Code, rec.Body.String())
	}
	if f.count(t, rows, f.device) != before {
		t.Fatal("a refused workspace was stored")
	}

	const opCanary = "operator-only-canary"
	if _, err := f.env.Services.RuleWorkspaces.Save(context.Background(), ctTenantA, f.device, service.DefaultRuleSlot,
		`{"canary":"`+opCanary+`"}`, "-- "+opCanary, "editor", nil); err != nil {
		t.Fatal(err)
	}
	got := getAs(f.srv, dev+"/rules/workspace", f.owner)
	if !strings.Contains(got.Body.String(), `"managed":true`) || strings.Contains(got.Body.String(), opCanary) {
		t.Fatalf("managed workspace leaked or not flagged: %s", got.Body.String())
	}
	for _, path := range []string{"/rules/workspace", "/rules/push"} {
		if rec := postPasskeyJSON(t, f.srv, dev+path, body, f.owner); rec.Code != http.StatusConflict {
			t.Errorf("owner %s on an operator slot: status %d, want 409", path, rec.Code)
		}
	}
}

// TestDeviceRules_PushWritesServerLuaAndReloads drives the push body over a
// real broker: the device gets the Lua the server generated, then lua.reload.
func TestDeviceRules_PushWritesServerLuaAndReloads(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)
	s.rulePushes = newRequestStore[*rulePushResult](time.Minute, t.Context().Done())

	const tenant = "rulespush"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/dev1"
	ctx := context.Background()
	pk, err := env.Services.Devices.Upsert(tenant, "dev1", "", "", "", prefix)
	if err != nil {
		t.Fatal(err)
	}
	device, err := env.Services.Devices.GetByIDAny(ctx, pk)
	if err != nil || device == nil {
		t.Fatalf("device: %v", err)
	}
	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	dfs := serveDeviceFS(fd, map[string]string{})
	fd.Handle("lua.reload", func(string, []byte) []mqtttest.Response {
		return []mqtttest.Response{{OK: true, Output: []string{"Lua reloaded"}}}
	})

	var body struct {
		WorkspaceJSON string `json:"workspace_json"`
	}
	_ = json.Unmarshal(tenantRulesJSON(t, testRuleFields()), &body)
	rules, err := rulesgen.Parse(body.WorkspaceJSON)
	if err != nil {
		t.Fatal(err)
	}
	lua := rulesgen.Generate(rules)

	id := s.rulePushes.enqueue()
	claim, ok := s.claimDeviceWrite(device.ID, time.Minute)
	if !ok {
		t.Fatal("claim")
	}
	s.runRulePush(ctx, id, claim, device, prefix, lua, "sha", uuid.New())

	e := s.rulePushes.get(id)
	if e == nil || e.Status != reqStatusDone || e.Response == nil || !e.Response.Written || !e.Response.Reloaded {
		t.Fatalf("push entry = %+v, want written and reloaded", e)
	}
	if got, _ := dfs.file("/scripts/rules.lua"); got != lua {
		t.Fatalf("device rules.lua holds %d bytes, want the %d generated", len(got), len(lua))
	}
	if n := fd.Calls("lua.reload"); n != 1 {
		t.Fatalf("lua.reload calls = %d, want 1", n)
	}

	fd.Handle("lua.reload", func(string, []byte) []mqtttest.Response {
		return []mqtttest.Response{{OK: false, Output: []string{"rules.lua:3: syntax error"}}}
	})
	id = s.rulePushes.enqueue()
	claim, _ = s.claimDeviceWrite(device.ID, time.Minute)
	s.runRulePush(ctx, id, claim, device, prefix, lua, "sha", uuid.New())
	if e := s.rulePushes.get(id); e == nil || e.Status != reqStatusError || !strings.Contains(e.ErrorMsg, "syntax error") {
		t.Fatalf("failed reload entry = %+v, want the device error", e)
	}
}
