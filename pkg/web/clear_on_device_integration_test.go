//go:build integration

// Clear on device for a WiFi password: one store row, dropped in one tx after a verified clear,
// an honest flash and audit when that drop fails, a password saved during the clear kept, and a refusal over a tenant default (Q5).
//
//	go test -tags integration -run TestClearOnDevice ./pkg/web/...
package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/mqtt/mqtttest"
	"thesada.app/app/pkg/service/servicetest"
)

func TestClearOnDevice(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)
	ctx := context.Background()

	const tenant = "clear-q5"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/dev1"
	device := seedDevice(t, env, tenant, "dev1", prefix)
	admin, err := env.Services.Auth.CreateUser(tenant, "root@q5.test", "Root", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.Super.Exec(ctx, `UPDATE users SET is_super_admin = true WHERE id = $1`, admin.ID); err != nil {
		t.Fatal(err)
	}
	tok, _, err := env.Services.Auth.CreateSession(tenant, admin.ID, "magic_link", "go-test", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	fd.Handle("secret.clear", func(string, []byte) []mqtttest.Response {
		return mqtttest.OK("secret cleared (falls back to config.json/empty)")
	})
	post := func(field string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(url.Values{"field": {field}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetPathValue("id", device.ID.String())
		req.AddCookie(&http.Cookie{Name: authmw.CookieName, Value: tok})
		rec := httptest.NewRecorder()
		authmw.Middleware(env.Services.Auth, nil)(authmw.RequireSuperAdmin(s.handleAdminDeviceSecretsClearDevice)).ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", rec.Code)
		}
		return rec.Header().Get("Location")
	}
	rows := func(field string) int {
		t.Helper()
		var n int
		if err := env.Super.QueryRow(ctx,
			`SELECT count(*) FROM device_config_secrets WHERE device_pk = $1 AND field = $2`, device.ID, field).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	t.Run("a_tenant_default_password_is_refused", func(t *testing.T) {
		if err := env.Services.Secrets.SetTenantSecret(ctx, tenant, "wifi.password:office", "site"); err != nil {
			t.Fatal(err)
		}
		before := fd.Calls("secret.clear")
		if loc := post("wifi.password:office"); !strings.HasSuffix(loc, "?"+flashSecretClearNVSTenantDefault.query()) {
			t.Errorf("Location = %q, want the tenant default refusal", loc)
		}
		if fd.Calls("secret.clear") != before {
			t.Error("a refused clear reached the device")
		}
	})

	t.Run("an_override_over_a_tenant_default_is_cleared_and_dropped", func(t *testing.T) {
		if err := env.Services.Secrets.SetSecret(ctx, tenant, device.ID, "wifi.password:office", "own"); err != nil {
			t.Fatal(err)
		}
		if loc := post("wifi.password:office"); !strings.HasSuffix(loc, "?"+flashSecretClearedNVS.query()) {
			t.Errorf("Location = %q, want cleared", loc)
		}
		if rows("wifi.password:office") != 0 {
			t.Error("the verified clear kept the override row")
		}
	})

	t.Run("a_password_saved_during_the_clear_survives", func(t *testing.T) {
		const field = "wifi.password:garage"
		if err := env.Services.Secrets.SetSecret(ctx, tenant, device.ID, field, "old"); err != nil {
			t.Fatal(err)
		}
		fd.Handle("secret.clear", func(string, []byte) []mqtttest.Response {
			if err := env.Services.Secrets.SetSecret(ctx, tenant, device.ID, field, "new"); err != nil {
				t.Errorf("save during the clear: %v", err)
			}
			return mqtttest.OK("secret cleared (falls back to config.json/empty)")
		})
		defer fd.Handle("secret.clear", func(string, []byte) []mqtttest.Response {
			return mqtttest.OK("secret cleared (falls back to config.json/empty)")
		})
		if loc := post(field); !strings.HasSuffix(loc, "?"+flashSecretClearedNVSReplaced.query()) {
			t.Errorf("Location = %q, want the saved-meanwhile notice", loc)
		}
		if row := lastAudit(t, env, "device_secret.clear_nvs"); row.detail["store_dropped"] != false || row.detail["store_replaced"] != true {
			t.Errorf("audit detail = %v, want store_dropped false, store_replaced true", row.detail)
		}
		if v, found, err := env.Services.Secrets.Reveal(ctx, tenant, device.ID, field); err != nil || !found || v != "new" {
			t.Errorf("stored %s = %q found=%v err=%v, want the password saved during the clear kept", field, v, found, err)
		}
	})

	t.Run("a_failed_row_drop_is_reported", func(t *testing.T) {
		if err := env.Services.Secrets.SetSecret(ctx, tenant, device.ID, "wifi.password:home", "pw"); err != nil {
			t.Fatal(err)
		}
		if _, err := env.Super.Exec(ctx, `
			CREATE FUNCTION q5_refuse_delete() RETURNS trigger LANGUAGE plpgsql AS
			$$ BEGIN RAISE EXCEPTION 'test refuses the delete'; END $$;
			CREATE TRIGGER q5_refuse BEFORE DELETE ON device_config_secrets
			  FOR EACH ROW WHEN (OLD.field = 'wifi.password:home') EXECUTE FUNCTION q5_refuse_delete();`); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_, _ = env.Super.Exec(ctx, `DROP TRIGGER q5_refuse ON device_config_secrets; DROP FUNCTION q5_refuse_delete();`)
		}()
		if loc := post("wifi.password:home"); !strings.HasSuffix(loc, "?"+flashSecretClearedNVSStoreKept.query()) {
			t.Errorf("Location = %q, want the cleared-but-kept error", loc)
		}
		if rows("wifi.password:home") != 1 {
			t.Error("precondition: the trigger did not keep the row")
		}
		if row := lastAudit(t, env, "device_secret.clear_nvs"); row.detail["store_dropped"] != false {
			t.Errorf("audit detail = %v, want store_dropped false", row.detail)
		}
	})
}
