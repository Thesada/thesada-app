//go:build integration

// Broker-path integration for the already-paired provision action:
// handleAdminDeviceSecretsProvision pushes every stored secret to the device
// over MQTT, and deviceSecretState reads live NVS state back via secret.info.
// Both run against a real mosquitto broker with a FakeDevice.
//
//	go test -tags integration -run TestAdminDeviceSecretsProvision ./pkg/web/...
package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
	got := map[string]string{}
	fd.Handle("secret.set", func(_ string, raw []byte) []mqtttest.Response {
		// Payload is "<fwField>\n<value>" - split on the first newline only.
		if i := strings.IndexByte(string(raw), '\n'); i >= 0 {
			got[string(raw[:i])] = string(raw[i+1:])
		}
		return mqtttest.OK("secret stored in NVS")
	})

	t.Run("provision pushes every stored field", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := postFormPath(http.MethodPost, "id", pk.String(), "")
		s.handleAdminDeviceSecretsProvision(rec, req)

		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", rec.Code)
		}
		if loc := rec.Header().Get("Location"); !strings.Contains(loc, "ok=provisioned+2") {
			t.Errorf("Location = %q, want ok=provisioned+2", loc)
		}
		if fd.Calls("secret.set") != 2 {
			t.Errorf("secret.set calls = %d, want 2", fd.Calls("secret.set"))
		}
		if got["mqtt.password"] != "mp" || got["web.password"] != "wp" {
			t.Errorf("pushed = %v, want mqtt.password=mp web.password=wp", got)
		}
	})

	t.Run("deviceSecretState reads live NVS presence", func(t *testing.T) {
		fd.Handle("secret.info", func(string, []byte) []mqtttest.Response {
			return mqtttest.OK(
				"mqtt.password      nvs",
				"web.password       config/none",
			)
		})
		device, err := env.Services.Devices.GetByIDAny(ctx, pk)
		if err != nil || device == nil {
			t.Fatalf("fetch device: %v", err)
		}
		state, reachable := s.deviceSecretState(ctx, device, service.ScalarSecretFields)
		if !reachable {
			t.Fatal("reachable = false, want true")
		}
		if state["mqtt.password"] != "nvs" {
			t.Errorf("mqtt.password state = %q, want nvs", state["mqtt.password"])
		}
		if state["web.password"] != "config" {
			t.Errorf("web.password state = %q, want config", state["web.password"])
		}
		if state["telegram.bot_token"] != "none" {
			t.Errorf("telegram.bot_token state = %q, want none", state["telegram.bot_token"])
		}
	})
}
