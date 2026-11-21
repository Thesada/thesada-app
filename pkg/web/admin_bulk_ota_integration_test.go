//go:build integration

package web

import (
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
