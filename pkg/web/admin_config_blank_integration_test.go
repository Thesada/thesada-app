//go:build integration

// The write guard on blank secret fields: a scalar passes when the device holds it in NVS,
// and open WiFi networks pass with the store off (KEK unset).
//
//	go test -tags integration -run TestBlankSecretGuard ./pkg/web/...
package web

import (
	"context"
	"strings"
	"testing"

	"thesada.app/app/pkg/mqtt/mqtttest"
	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

const blankMQTTConfig = `{"mqtt":{"host":"b","password":""},"device":{"name":"renamed"}}`

// serveSecretInfo answers secret.info with the given report lines.
func serveSecretInfo(fd *mqtttest.FakeDevice, lines ...string) {
	fd.Handle("secret.info", func(string, []byte) []mqtttest.Response {
		return mqtttest.OK(lines...)
	})
}

func TestBlankSecretGuard_Scalars(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)
	const tenant = "webcfg-blank"
	env.SeedTenant(t, tenant)
	ctx := context.Background()

	dev := func(id string) (*service.Device, *mqtttest.FakeDevice) {
		prefix := "thesada/" + tenant + "/" + id
		return seedDevice(t, env, tenant, id, prefix), mqtttest.NewFakeDevice(t, broker, prefix)
	}

	t.Run("held_in_nvs_saves", func(t *testing.T) {
		device, fd := dev("blank1")
		serveSecretInfo(fd, "mqtt.password          nvs", "web.password           config/none")
		if msg := configWriteRefusal("/config.json", blankMQTTConfig, s.blankSecretLookup(ctx, device, blankMQTTConfig)); msg != "" {
			t.Errorf("a blank mqtt.password the device holds in NVS was refused: %q", msg)
		}
	})

	t.Run("not_in_nvs_is_refused_naming_the_field", func(t *testing.T) {
		device, fd := dev("blank2")
		serveSecretInfo(fd, "mqtt.password          config/none")
		msg := configWriteRefusal("/config.json", blankMQTTConfig, s.blankSecretLookup(ctx, device, blankMQTTConfig))
		if !strings.Contains(msg, "mqtt.password") {
			t.Errorf("refusal = %q, want one naming mqtt.password", msg)
		}
	})

	t.Run("uncorrelated_reply_is_refused", func(t *testing.T) {
		device, fd := dev("blank3")
		serveSecretInfo(fd, "mqtt.password          nvs")
		fd.OmitReqID(true, "secret.info")
		if msg := configWriteRefusal("/config.json", blankMQTTConfig, s.blankSecretLookup(ctx, device, blankMQTTConfig)); msg == "" {
			t.Error("a reply without the request id passed the guard")
		}
	})

	t.Run("one_field_not_in_nvs_refuses_the_write", func(t *testing.T) {
		device, fd := dev("blank4")
		serveSecretInfo(fd, "mqtt.password          nvs", "web.password           config/none")
		content := `{"mqtt":{"password":""},"web":{"password":""}}`
		msg := configWriteRefusal("/config.json", content, s.blankSecretLookup(ctx, device, content))
		if !strings.Contains(msg, "web.password") {
			t.Errorf("refusal = %q, want one naming web.password", msg)
		}
		if n := fd.Calls("secret.info"); n != 1 {
			t.Errorf("secret.info calls = %d, want one per write", n)
		}
	})

	t.Run("an_unknown_empty_leaf_is_refused_naming_it", func(t *testing.T) {
		device, fd := dev("blank5")
		serveSecretInfo(fd, "mqtt.password          nvs")
		content := `{"cellular":{"sim_pin":""}}`
		msg := configWriteRefusal("/config.json", content, s.blankSecretLookup(ctx, device, content))
		if !strings.Contains(msg, "cellular.sim_pin") {
			t.Errorf("refusal = %q, want one naming cellular.sim_pin", msg)
		}
	})

	t.Run("a_set_value_passes_without_asking", func(t *testing.T) {
		device, fd := dev("blank6")
		content := `{"mqtt":{"password":"set"}}`
		if msg := configWriteRefusal("/config.json", content, s.blankSecretLookup(ctx, device, content)); msg != "" {
			t.Errorf("a set mqtt.password was refused: %q", msg)
		}
		if n := fd.Calls("secret.info"); n != 0 {
			t.Errorf("secret.info calls = %d, want none", n)
		}
	})
}

// With the KEK unset an open network has nothing to store, so it passes. A network the device
// holds a password for in NVS is still refused.
func TestBlankSecretGuard_StoreOff(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)
	offCfg := *env.Cfg
	offCfg.DeviceConfigKEK = ""
	off, err := service.New(&offCfg, env.Pools)
	if err != nil {
		t.Fatalf("service.New without KEK: %v", err)
	}
	s.services = off
	offEnv := *env
	offEnv.Services = off
	const tenant = "webcfg-kekoff"
	env.SeedTenant(t, tenant)
	ctx := context.Background()

	dev := func(id string) (*service.Device, *mqtttest.FakeDevice) {
		prefix := "thesada/" + tenant + "/" + id
		device := seedDevice(t, &offEnv, tenant, id, prefix)
		deviceRead(t, &offEnv, device, openCafeConfig)
		return device, mqtttest.NewFakeDevice(t, broker, prefix)
	}

	t.Run("open_network_passes", func(t *testing.T) {
		device, fd := dev("off1")
		serveNothingInNVS(fd)
		if msg := configWriteRefusal("/config.json", openCafeConfig, s.blankSecretLookup(ctx, device, openCafeConfig)); msg != "" {
			t.Errorf("an open cafe with the store off was refused: %q", msg)
		}
	})

	t.Run("password_in_nvs_is_refused", func(t *testing.T) {
		device, fd := dev("off2")
		serveSecretInfo(fd, "wifi.password:cafe     nvs")
		if msg := configWriteRefusal("/config.json", openCafeConfig, s.blankSecretLookup(ctx, device, openCafeConfig)); msg == "" {
			t.Error("a blank cafe the device holds a password for passed with the store off")
		}
	})

	t.Run("a_set_password_passes_as_before", func(t *testing.T) {
		device, _ := dev("off3")
		content := `{"wifi":{"networks":[{"ssid":"cafe","password":"pw"}]}}`
		if msg := configWriteRefusal("/config.json", content, s.blankSecretLookup(ctx, device, content)); msg != "" {
			t.Errorf("a set cafe password was refused: %q", msg)
		}
	})
}
