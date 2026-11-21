//go:build integration

// Device replies that feed a stored fact or a write decision must echo the request's
// req_id (Q4). The fake device answers without one, the way pre-1.4.5 firmware does.
//
//	go test -tags integration -run TestUncorrelated ./pkg/web/...
package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/mqtt/mqtttest"
	"thesada.app/app/pkg/service/servicetest"
)

func TestUncorrelatedReplies(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)
	ctx := context.Background()

	const tenant = "web-corr"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/dev1"
	device := seedDevice(t, env, tenant, "dev1", prefix)
	fd := mqtttest.NewFakeDevice(t, broker, prefix)

	admin, err := env.Services.Auth.CreateUser(tenant, "root@corr.test", "Root", false)
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
	clearDevice := func(field string) string {
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

	t.Run("cli_box_config_dump_shows_output_but_stores_no_snapshot", func(t *testing.T) {
		fd.Handle("config.dump", func(string, []byte) []mqtttest.Response { return mqtttest.OK(`{"device":{"name":"x"}}`) })
		fd.OmitReqID(true, "config.dump")
		defer fd.OmitReqID(false, "config.dump")
		reqID := s.cliRequests.enqueue()
		s.runCLICmd(ctx, reqID, uuid.Nil, device, prefix, "config.dump", "", nil)
		entry := s.cliRequests.get(reqID)
		if entry == nil || entry.Status != reqStatusDone || entry.Response == nil || len(entry.Response.Output) != 1 {
			t.Fatalf("store entry = %+v, want done with the output", entry)
		}
		if snap, err := env.Services.DeviceFiles.Latest(ctx, tenant, device.ID, "config.json"); err != nil || snap != nil {
			t.Fatalf("Latest(config.json) = %+v, %v, want no snapshot", snap, err)
		}
	})

	t.Run("uncorrelated_secret_info_verifies_nothing", func(t *testing.T) {
		fd.Handle("secret.info", func(string, []byte) []mqtttest.Response { return mqtttest.OK("mqtt.password      nvs") })
		fd.OmitReqID(true, "secret.info")
		defer fd.OmitReqID(false, "secret.info")
		if missing, ok := s.verifyInNVS(ctx, device, []string{"mqtt.password"}); ok {
			t.Errorf("verifyInNVS = %v, %v, want unverified", missing, ok)
		}
	})

	t.Run("uncorrelated_secret_clear_keeps_the_store_row", func(t *testing.T) {
		if err := env.Services.Secrets.SetSecret(ctx, tenant, device.ID, "wifi.password:home", "pw"); err != nil {
			t.Fatal(err)
		}
		fd.Handle("secret.clear", func(string, []byte) []mqtttest.Response {
			return mqtttest.OK("secret cleared (falls back to config.json/empty)")
		})
		fd.OmitReqID(true, "secret.clear")
		defer fd.OmitReqID(false, "secret.clear")
		if loc := clearDevice("wifi.password:home"); !strings.HasSuffix(loc, "?"+flashSecretClearNVSUncorrelated.query()) {
			t.Errorf("Location = %q, want %s", loc, flashSecretClearNVSUncorrelated.query())
		}
		if rows("wifi.password:home") != 1 {
			t.Error("an uncorrelated secret.clear dropped the store row")
		}
	})

	t.Run("uncorrelated_secret_info_after_a_blank_ssid_clear_keeps_the_row", func(t *testing.T) {
		if err := env.Services.Secrets.SetSecret(ctx, tenant, device.ID, "wifi.password:two words", "tw"); err != nil {
			t.Fatal(err)
		}
		fd.Handle("secret.set", func(string, []byte) []mqtttest.Response { return mqtttest.OK("secret stored in NVS") })
		fd.Handle("secret.info", func(string, []byte) []mqtttest.Response {
			return mqtttest.OK("wifi.password:two words config/none")
		})
		fd.OmitReqID(true, "secret.info")
		defer fd.OmitReqID(false, "secret.info")
		if loc := clearDevice("wifi.password:two words"); strings.HasSuffix(loc, "?"+flashSecretClearedNVS.query()) {
			t.Errorf("Location = %q, an uncorrelated secret.info must not verify the clear", loc)
		}
		if rows("wifi.password:two words") != 1 {
			t.Error("an unverified clear dropped the store row")
		}
	})

	t.Run("uncorrelated_size_check_fails_the_write", func(t *testing.T) {
		dfs := serveDeviceFS(fd, map[string]string{"/scripts/a.lua": "old"})
		fd.OmitReqID(true, "fs.cat")
		defer fd.OmitReqID(false, "fs.cat")
		claim, ok := s.claimDeviceWrite(device.ID, time.Minute)
		if !ok {
			t.Fatal("claim refused")
		}
		reqID := s.cliRequests.enqueue()
		s.runCLIWrite(ctx, reqID, claim, device, prefix, "/scripts/a.lua", "-- new", nil)
		if entry := s.cliRequests.get(reqID); entry == nil || entry.Status != reqStatusError {
			t.Fatalf("store entry = %+v, want the write failed", entry)
		}
		if body, _ := dfs.file("/scripts/a.lua"); body != "old" {
			t.Errorf("live file = %q, want it untouched", body)
		}
		if n := fd.Calls("fs.mv"); n != 0 {
			t.Errorf("fs.mv calls = %d, an unconfirmed size check must not rename", n)
		}
	})
}
