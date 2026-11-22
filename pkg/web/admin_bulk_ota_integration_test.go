//go:build integration

package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/mqtt/mqtttest"
	"thesada.app/app/pkg/service/servicetest"
)

// TestAdminBulkOTA_CountsAsAConfigChange: an OTA from the devices page stamps
// config_changed_at past the dispatch, and a device with a write running is
// not sent the command.
func TestAdminBulkOTA_CountsAsAConfigChange(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)

	const tenant = "bulk-ota"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/ota1"
	device := seedDevice(t, env, tenant, "ota1", prefix)
	user, err := env.Services.Auth.CreateUser(tenant, "ota@example.com", "Op", false)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := env.Services.Auth.CreateSession(tenant, user.ID, "magic_link", "go-test", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	fd := mqtttest.NewFakeDevice(t, broker, prefix)

	chain := authmw.Middleware(env.Services.Auth, nil)(http.HandlerFunc(s.handleAdminDevicesBulk))
	post := func() string {
		form := url.Values{"action": {"ota"}, "device_ids": {device.ID.String()}}
		req := httptest.NewRequest(http.MethodPost, "/admin/devices/bulk", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: authmw.CookieName, Value: token})
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("bulk ota = %d %s", rec.Code, rec.Body.String())
		}
		return rec.Header().Get("Location")
	}

	claim, ok := s.claimDeviceWrite(device.ID, time.Minute)
	if !ok {
		t.Fatal("claim refused")
	}
	if loc := post(); !strings.Contains(loc, "ota_dispatched_partial") {
		t.Fatalf("ota while a write runs redirected to %q, want the partial flash", loc)
	}
	time.Sleep(500 * time.Millisecond)
	if n := fd.Calls("ota.check"); n != 0 || configChangedAt(t, env, device) != nil {
		t.Fatalf("ota while a write runs: device saw %d ota.check, config_changed_at %v", n, configChangedAt(t, env, device))
	}
	s.releaseDeviceWrite(device.ID, claim)

	before := time.Now()
	if loc := post(); !strings.Contains(loc, "ota_dispatched") || strings.Contains(loc, "partial") {
		t.Fatalf("ota redirected to %q", loc)
	}
	at := configChangedAt(t, env, device)
	if at == nil || !at.After(before.Add(time.Minute)) {
		t.Fatalf("config_changed_at = %v, want a window past the dispatch at %v", at, before)
	}
	if _, ok := s.claimDeviceWrite(device.ID, time.Minute); !ok {
		t.Fatal("the ota kept the device write claim")
	}
	deadline := time.Now().Add(10 * time.Second)
	for fd.Calls("ota.check") == 0 {
		if time.Now().After(deadline) {
			t.Fatal("device never saw ota.check")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestAdminBulkOTA_LaterConfigChangeKeepsTheWindow: a config write or config-changing
// command after a bulk OTA ends its own window, never the OTA's 15 minutes.
func TestAdminBulkOTA_LaterConfigChangeKeepsTheWindow(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)

	const tenant = "bulk-ota-hold"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/ota2"
	ctx := context.Background()
	device := seedDevice(t, env, tenant, "ota2", prefix)
	user, err := env.Services.Auth.CreateUser(tenant, "hold@example.com", "Op", false)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := env.Services.Auth.CreateSession(tenant, user.ID, "magic_link", "go-test", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	serveDeviceFS(fd, map[string]string{"/config.json": `{}`, "/config.json.bak": `{"a":1}`})
	serveNothingInNVS(fd)

	chain := authmw.Middleware(env.Services.Auth, nil)(http.HandlerFunc(s.handleAdminDevicesBulk))
	form := url.Values{"action": {"ota"}, "device_ids": {device.ID.String()}}
	req := httptest.NewRequest(http.MethodPost, "/admin/devices/bulk", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: authmw.CookieName, Value: token})
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)
	if loc := rec.Header().Get("Location"); rec.Code != http.StatusFound || strings.Contains(loc, "partial") {
		t.Fatalf("bulk ota = %d %q", rec.Code, loc)
	}
	hold := configChangedAt(t, env, device)
	if hold == nil || !hold.After(time.Now().Add(10*time.Minute)) {
		t.Fatalf("config_changed_at = %v, want the 15 minute OTA window", hold)
	}
	kept := func(what string) {
		t.Helper()
		if at := configChangedAt(t, env, device); at == nil || at.Before(*hold) {
			t.Fatalf("%s moved config_changed_at from %v to %v", what, hold, at)
		}
	}

	claim, ok := s.claimDeviceWrite(device.ID, time.Minute)
	if !ok {
		t.Fatal("claim refused")
	}
	reqID := s.cliRequests.enqueue()
	s.runCLIWrite(ctx, reqID, claim, device, prefix, "/config.json", `{"b":2}`, nil)
	if entry := s.cliRequests.get(reqID); entry == nil || entry.Status != reqStatusDone {
		t.Fatalf("write entry = %+v, want done", entry)
	}
	kept("a config.json write")
	if snap, err := env.Services.DeviceFiles.Latest(ctx, tenant, device.ID, "/config.json"); err != nil || (snap != nil && snap.Content == `{"b":2}`) {
		t.Fatalf("a write inside the OTA window was stored as a read: %+v err = %v", snap, err)
	}

	claim, ok = s.claimDeviceWrite(device.ID, time.Minute)
	if !ok {
		t.Fatal("claim refused")
	}
	reqID = s.cliRequests.enqueue()
	s.runCLICmd(ctx, reqID, claim, device, prefix, "fs.mv", "/config.json.bak /config.json", nil)
	if entry := s.cliRequests.get(reqID); entry == nil || entry.Status != reqStatusDone {
		t.Fatalf("command entry = %+v, want done", entry)
	}
	kept("a config-changing command")
}
