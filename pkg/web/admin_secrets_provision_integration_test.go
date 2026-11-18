//go:build integration

// Broker-path integration for the already-paired provision action:
// handleAdminDeviceSecretsProvision pushes every stored secret to the device
// over MQTT and checks it with secret.info, and the clear action sends
// secret.clear. All run against a real mosquitto broker with a FakeDevice.
//
//	go test -tags integration -run TestAdminDeviceSecrets ./pkg/web/...
package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/mqtt/mqtttest"
	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

func TestAdminDeviceSecretsProvision_Integration(t *testing.T) {
	env := servicetest.Start(t) // KEK on
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)
	ctx := context.Background()

	const tenant = "prov-ui"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/dev1"
	pk, err := env.Services.Devices.Upsert(tenant, "dev1", "", "", "", prefix)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}

	// Store two secrets in the app; the rest stay unset.
	for f, v := range map[string]string{"mqtt.password": "mp", "web.password": "wp"} {
		if err := env.Services.Secrets.SetSecret(ctx, tenant, pk, f, v); err != nil {
			t.Fatalf("SetSecret %s: %v", f, err)
		}
	}

	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	var mu sync.Mutex
	got := map[string]string{}
	var unwrapped, empty int
	fd.Handle("secret.set", func(args string, raw []byte) []mqtttest.Response {
		mu.Lock()
		defer mu.Unlock()
		// Enveloped with a req_id, so the reply correlates. args is "" on the raw path.
		if args != "" {
			unwrapped++
		}
		// Payload is "<fwField>\n<value>" - split on the first newline only.
		field, value, _ := strings.Cut(string(raw), "\n")
		if value == "" {
			empty++
		}
		got[field] = value
		return mqtttest.OK("secret stored in NVS")
	})
	info := func(lines ...string) {
		fd.Handle("secret.info", func(string, []byte) []mqtttest.Response { return mqtttest.OK(lines...) })
	}
	provision := func(t *testing.T) string {
		t.Helper()
		rec := httptest.NewRecorder()
		s.handleAdminDeviceSecretsProvision(rec, postFormPath(http.MethodPost, "id", pk.String(), ""))
		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", rec.Code)
		}
		return rec.Header().Get("Location")
	}

	t.Run("provision pushes every stored field and verifies it", func(t *testing.T) {
		info("mqtt.password      nvs", "web.password       nvs", "telegram.bot_token config/none")
		// Only two fields are set; the unset ones count as skipped.
		if loc := provision(t); !strings.HasSuffix(loc, "?"+flashSecretProvisionedMix.query()) {
			t.Errorf("Location = %q, want %s", loc, flashSecretProvisionedMix.query())
		}
		mu.Lock()
		defer mu.Unlock()
		if fd.Calls("secret.set") != 2 || unwrapped != 2 {
			t.Errorf("secret.set calls = %d, enveloped %d, want 2 and 2", fd.Calls("secret.set"), unwrapped)
		}
		if got["mqtt.password"] != "mp" || got["web.password"] != "wp" {
			t.Errorf("pushed = %v, want mqtt.password=mp web.password=wp", got)
		}
	})

	t.Run("a pushed field the device does not hold in NVS is reported", func(t *testing.T) {
		info("mqtt.password      nvs", "web.password       config/none")
		if loc := provision(t); !strings.Contains(loc, flashSecretNotInNVS.query()) {
			t.Errorf("Location = %q, want %s", loc, flashSecretNotInNVS.query())
		}
	})

	t.Run("an empty value never reaches the device", func(t *testing.T) {
		before := fd.Calls("secret.set")
		device, err := env.Services.Devices.GetByIDAny(ctx, pk)
		if err != nil || device == nil {
			t.Fatalf("fetch device: %v", err)
		}
		if _, ok := s.pushSecret(ctx, prefix, "web.password", ""); ok {
			t.Error("pushSecret with an empty value reported success")
		}
		out := provisionDeviceSecrets([]string{"web.password"}, "",
			func(string) (string, bool, error) { return "", true, nil },
			func(fw, v string) (string, bool) { return s.pushSecret(ctx, prefix, fw, v) })
		if out.AbortMsg != "" || len(out.SkippedUnset) != 1 {
			t.Errorf("outcome = %+v, want web.password skipped", out)
		}
		mu.Lock()
		defer mu.Unlock()
		if fd.Calls("secret.set") != before || empty != 0 {
			t.Errorf("secret.set calls %d -> %d, empty values %d, want none sent", before, fd.Calls("secret.set"), empty)
		}
	})

	t.Run("deviceSecretState reads live NVS presence", func(t *testing.T) {
		info("mqtt.password      nvs", "web.password       config/none")
		device, err := env.Services.Devices.GetByIDAny(ctx, pk)
		if err != nil || device == nil {
			t.Fatalf("fetch device: %v", err)
		}
		state, reachable := s.deviceSecretState(ctx, device, service.ScalarSecretFields)
		if !reachable {
			t.Fatal("reachable = false, want true")
		}
		if state["mqtt.password"] != "nvs" || state["web.password"] != "config" || state["telegram.bot_token"] != "none" {
			t.Errorf("state = %v, want mqtt nvs, web config, telegram none", state)
		}
	})

	// The firmware pads to 22 columns, so an SSID's trailing blank reads like padding.
	t.Run("deviceSecretState finds an SSID with a trailing blank", func(t *testing.T) {
		info(fmt.Sprintf("%-22s %s", "wifi.password:Cafe ", "nvs"))
		device, err := env.Services.Devices.GetByIDAny(ctx, pk)
		if err != nil || device == nil {
			t.Fatalf("fetch device: %v", err)
		}
		state, reachable := s.deviceSecretState(ctx, device, []string{"wifi.password:Cafe "})
		if !reachable || state["wifi.password:Cafe "] != "nvs" {
			t.Errorf("state = %v (reachable %v), want wifi.password:Cafe  in nvs", state, reachable)
		}
	})

	// One report line cannot tell Cafe from "Cafe ", so neither field is verified.
	t.Run("deviceSecretState leaves SSIDs that differ by trailing blanks unknown", func(t *testing.T) {
		info(fmt.Sprintf("%-22s %s", "wifi.password:Cafe", "nvs"))
		device, err := env.Services.Devices.GetByIDAny(ctx, pk)
		if err != nil || device == nil {
			t.Fatalf("fetch device: %v", err)
		}
		fields := []string{"wifi.password:Cafe", "wifi.password:Cafe "}
		state, reachable := s.deviceSecretState(ctx, device, fields)
		if !reachable || state[fields[0]] != "" || state[fields[1]] != "" {
			t.Errorf("state = %v (reachable %v), want both unknown", state, reachable)
		}
		if missing, ok := s.verifyInNVS(ctx, device, fields); !ok || len(missing) != 2 {
			t.Errorf("verifyInNVS = %v, %v, want both fields not verified", missing, ok)
		}
	})
}

// TestAdminDeviceSecretsClearDevice: the clear action sends secret.clear for one field,
// leaves the app store alone and records an audit row with the field, never a value.
func TestAdminDeviceSecretsClearDevice(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)
	ctx := context.Background()

	const tenant = "clear-nvs"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/dev1"
	device := seedDevice(t, env, tenant, "dev1", prefix)
	if err := env.Services.Secrets.SetSecret(ctx, tenant, device.ID, "mqtt.password", "mp"); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}
	admin, err := env.Services.Auth.CreateUser(tenant, "root@clear.test", "Root", false)
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
	var cleared []string
	var mu sync.Mutex
	fd.Handle("secret.clear", func(args string, _ []byte) []mqtttest.Response {
		mu.Lock()
		defer mu.Unlock()
		cleared = append(cleared, args)
		return mqtttest.OK("secret cleared (falls back to config.json/empty)")
	})
	post := func(field string) string {
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

	if loc := post("mqtt.password"); !strings.HasSuffix(loc, "?"+flashSecretClearedNVS.query()) {
		t.Errorf("Location = %q, want %s", loc, flashSecretClearedNVS.query())
	}
	mu.Lock()
	if len(cleared) != 1 || cleared[0] != "mqtt.password" {
		t.Errorf("secret.clear args = %v, want [mqtt.password]", cleared)
	}
	mu.Unlock()
	if fd.Calls("secret.set") != 0 {
		t.Error("the clear action sent secret.set")
	}
	if v, _, _ := env.Services.Secrets.Reveal(ctx, tenant, device.ID, "mqtt.password"); v != "mp" {
		t.Errorf("store after a device clear = %q, want mp kept", v)
	}
	row := lastAudit(t, env, "device_secret.clear_nvs")
	if row.actor != "root@clear.test" || row.target != device.ID.String() || row.detail["field"] != "mqtt.password" {
		t.Errorf("audit row = %+v, want actor, device and field", row)
	}

	// An SSID with a blank goes as binary secret.set with an empty value, then secret.info.
	var setPayloads []string
	fd.Handle("secret.set", func(_ string, raw []byte) []mqtttest.Response {
		mu.Lock()
		defer mu.Unlock()
		setPayloads = append(setPayloads, string(raw))
		return mqtttest.OK("secret stored in NVS")
	})
	nvsState := "config/none"
	fd.Handle("secret.info", func(string, []byte) []mqtttest.Response {
		mu.Lock()
		defer mu.Unlock()
		return mqtttest.OK("wifi.password:two words " + nvsState)
	})
	if loc := post("wifi.password:two words"); !strings.HasSuffix(loc, "?"+flashSecretClearedNVS.query()) {
		t.Errorf("blank SSID: Location = %q, want %s", loc, flashSecretClearedNVS.query())
	}
	mu.Lock()
	if len(setPayloads) != 1 || setPayloads[0] != "wifi.password:two words\n" {
		t.Errorf("secret.set payloads = %q, want one clear of the whole field", setPayloads)
	}
	nvsState = "nvs"
	mu.Unlock()
	if loc := post("wifi.password:two words"); !strings.Contains(loc, flashSecretClearNVSFailed.query()) {
		t.Errorf("still in NVS: Location = %q, want %s", loc, flashSecretClearNVSFailed.query())
	}
	// "two words" and "two words " report under one key, so the clear is not verified.
	fd.Handle("secret.info", func(string, []byte) []mqtttest.Response {
		return mqtttest.OK(fmt.Sprintf("%-22s config/none", "wifi.password:two words"),
			fmt.Sprintf("%-22s nvs", "wifi.password:two words "))
	})
	if loc := post("wifi.password:two words"); !strings.HasSuffix(loc, "?"+flashSecretClearedNVSUnverified.query()) {
		t.Errorf("ambiguous report: Location = %q, want %s", loc, flashSecretClearedNVSUnverified.query())
	}

	before := fd.Calls("secret.clear") + fd.Calls("secret.set")
	if loc := post("not.a.field"); !strings.Contains(loc, flashSecretField.query()) {
		t.Errorf("Location = %q, want %s", loc, flashSecretField.query())
	}
	// No stored config, so the legacy bare key has no SSID to name.
	if loc := post("wifi.password"); !strings.Contains(loc, flashSecretClearNVSNoSSID.query()) {
		t.Errorf("legacy: Location = %q, want %s", loc, flashSecretClearNVSNoSSID.query())
	}
	if fd.Calls("secret.clear")+fd.Calls("secret.set") != before {
		t.Error("a refused field reached the device")
	}

	// Store off: the action is refused before anything is sent.
	offCfg := *env.Cfg
	offCfg.DeviceConfigKEK = ""
	off, err := service.New(&offCfg, env.Pools)
	if err != nil {
		t.Fatalf("service.New without KEK: %v", err)
	}
	keep := s.services
	s.services = off
	loc := post("mqtt.password")
	s.services = keep
	if !strings.Contains(loc, flashSecretDisabled.query()) {
		t.Errorf("store off: Location = %q, want %s", loc, flashSecretDisabled.query())
	}
	if fd.Calls("secret.clear")+fd.Calls("secret.set") != before {
		t.Error("the store-off clear reached the device")
	}
}
