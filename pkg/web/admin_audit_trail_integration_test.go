//go:build integration

// Every admin mutation and device command lands one admin_audit row with the
// actor, target and a detail that never carries payload content. Driven
// through the session middleware and RequireSuperAdmin against a real DB and
// broker.
//
//	go test -tags integration -run TestAdminAuditTrail ./pkg/web/...
package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/mqtt/mqtttest"
	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

// trailRow is the newest admin_audit row for one action.
type trailRow struct {
	actor, target, tenant string
	detail                map[string]any
}

// lastAudit reads the newest row for action, failing when there is none.
// in: t, env, action. out: row.
func lastAudit(t *testing.T, env *servicetest.Env, action string) trailRow {
	t.Helper()
	var r trailRow
	var raw []byte
	err := env.Super.QueryRow(context.Background(),
		`SELECT coalesce(actor_email, ''), coalesce(target_id, ''), coalesce(tenant_id, ''), coalesce(detail, '{}'::jsonb)
		   FROM admin_audit WHERE action = $1 ORDER BY id DESC LIMIT 1`, action).
		Scan(&r.actor, &r.target, &r.tenant, &raw)
	if err != nil {
		t.Fatalf("no admin_audit row for %s: %v", action, err)
	}
	if err := json.Unmarshal(raw, &r.detail); err != nil {
		t.Fatalf("detail: %v", err)
	}
	return r
}

func TestAdminAuditTrail(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)
	ctx := context.Background()

	const home, tenant, devID = "aud-home", "aud-t", "aud-dev"
	env.SeedTenant(t, home)
	env.SeedTenant(t, tenant)
	admin, err := env.Services.Auth.CreateUser(home, "root@aud.test", "Root", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.Super.Exec(ctx, `UPDATE users SET is_super_admin = true WHERE id = $1`, admin.ID); err != nil {
		t.Fatal(err)
	}
	tok, _, err := env.Services.Auth.CreateSession(home, admin.ID, "magic_link", "go-test", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	prefix := "thesada/" + tenant + "/" + devID
	pk, err := env.Services.Devices.Upsert(tenant, devID, "", "", "", prefix)
	if err != nil {
		t.Fatal(err)
	}
	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	fd.Handle("version", func(string, []byte) []mqtttest.Response { return mqtttest.OK("1.0") })
	fd.Handle("fs.write", func(string, []byte) []mqtttest.Response { return mqtttest.OK("ok") })

	// call runs one admin handler as the super-admin through the real gates.
	call := func(method, path string, h http.HandlerFunc, body string, form bool, vals map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if form {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range vals {
			req.SetPathValue(k, v)
		}
		req.AddCookie(&http.Cookie{Name: authmw.CookieName, Value: tok})
		rec := httptest.NewRecorder()
		authmw.Middleware(env.Services.Auth, nil)(authmw.RequireSuperAdmin(h)).ServeHTTP(rec, req)
		return rec
	}
	want := func(t *testing.T, action, target string) trailRow {
		t.Helper()
		r := lastAudit(t, env, action)
		if r.actor != "root@aud.test" || r.target != target {
			t.Fatalf("%s row = %+v, want actor root@aud.test target %s", action, r, target)
		}
		return r
	}
	dev := map[string]string{"id": pk.String()}

	t.Run("tenant and user lifecycle", func(t *testing.T) {
		const slug = "aud-new"
		call("POST", "/admin/tenants", s.handleAdminTenantCreate,
			url.Values{"slug": {slug}, "display_name": {"Aud New"}}.Encode(), true, nil)
		want(t, "tenant.create", slug)

		call("POST", "/admin/tenants/"+slug+"/users", s.handleAdminTenantUserCreate,
			url.Values{"email": {"u@aud.test"}}.Encode(), true, map[string]string{"slug": slug})
		u, err := env.Services.Auth.GetUserByEmail(slug, "u@aud.test")
		if err != nil || u == nil {
			t.Fatalf("created user: %v", err)
		}
		uid := map[string]string{"slug": slug, "user_id": u.ID.String()}
		want(t, "user.create", u.ID.String())

		call("POST", "/", s.handleAdminTenantUserToggle, "", true, uid)
		if r := want(t, "user.toggle_admin", u.ID.String()); r.detail["is_admin"] != true {
			t.Fatalf("toggle detail = %v, want is_admin true", r.detail)
		}
		call("POST", "/", s.handleAdminTenantUserUpdate,
			url.Values{"display_name": {"Renamed"}}.Encode(), true, uid)
		want(t, "user.update", u.ID.String())
		call("POST", "/", s.handleAdminTenantUserDelete, "", true, uid)
		want(t, "user.delete", u.ID.String())

		call("POST", "/", s.handleAdminTenantDelete, "", true, map[string]string{"slug": slug})
		want(t, "tenant.delete", slug)
	})

	t.Run("device command records the command, not the payload", func(t *testing.T) {
		rec := call("POST", "/", s.handleAdminDeviceConfigCmd,
			`{"command":"version","payload":"secret-ish-payload"}`, false, dev)
		if rec.Code != http.StatusOK {
			t.Fatalf("cmd = %d %s", rec.Code, rec.Body.String())
		}
		r := want(t, "device.command", pk.String())
		if r.detail["command"] != "version" || r.detail["payload_bytes"] != float64(len("secret-ish-payload")) {
			t.Fatalf("detail = %v", r.detail)
		}
		if b, _ := json.Marshal(r.detail); strings.Contains(string(b), "secret-ish-payload") {
			t.Fatal("audit detail carries the payload")
		}
	})

	t.Run("config write records path and hash, not content", func(t *testing.T) {
		const content = `{"wifi":{"password":"hunter2"}}`
		rec := call("POST", "/", s.handleAdminDeviceConfigWrite,
			`{"path":"/config.json","content":`+string(mustJSON(t, content))+`}`, false, dev)
		if rec.Code != http.StatusOK {
			t.Fatalf("write = %d %s", rec.Code, rec.Body.String())
		}
		r := want(t, "device.config_write", pk.String())
		sum := sha256.Sum256([]byte(content))
		if r.detail["path"] != "/config.json" || r.detail["sha256"] != hex.EncodeToString(sum[:]) {
			t.Fatalf("detail = %v", r.detail)
		}
		if b, _ := json.Marshal(r.detail); strings.Contains(string(b), "hunter2") {
			t.Fatal("audit detail carries the file content")
		}
	})

	t.Run("rule workspace and templates", func(t *testing.T) {
		body := `{"slot":"` + service.DefaultRuleSlot + `","workspace_json":"{}","lua_content":"-- x"}`
		if rec := call("POST", "/", s.handleAdminDeviceRulesWorkspacePOST, body, false, dev); rec.Code != http.StatusOK {
			t.Fatalf("workspace = %d %s", rec.Code, rec.Body.String())
		}
		want(t, "rules.workspace_save", pk.String())

		body = `{"name":"aud tpl","workspace_json":"{}","lua_content":"-- y"}`
		if rec := call("POST", "/", s.handleAdminRuleTemplatesPOST, body, false, dev); rec.Code != http.StatusOK {
			t.Fatalf("template save = %d %s", rec.Code, rec.Body.String())
		}
		want(t, "rule_template.save", "aud tpl")
		if rec := call("DELETE", "/?name="+url.QueryEscape("aud tpl"), s.handleAdminRuleTemplatesDELETE, "", false, dev); rec.Code != http.StatusOK {
			t.Fatalf("template delete = %d %s", rec.Code, rec.Body.String())
		}
		want(t, "rule_template.delete", "aud tpl")
	})
}

// mustJSON encodes v. in: t, value. out: JSON bytes.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
