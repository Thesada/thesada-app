//go:build integration

// Drift pulls skip firmware below the req_id floor with one log line, and a stale read logs no save.
//
//	go test -tags integration -run 'TestBrokerDrift(FirmwareFloor|StaleRead)' ./pkg/mqtt/...
package mqtt

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"thesada.app/app/pkg/mqtt/mqtttest"
	"thesada.app/app/pkg/safego/safegotest"
	"thesada.app/app/pkg/service/servicetest"
)

func TestBrokerDriftFirmwareFloor(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	c := startBrokerClient(t, env, broker)
	logs := safegotest.Capture(t)

	const tenant = "brk-floor"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/dev1"
	ctx := context.Background()
	devicePk, err := env.Services.Devices.Upsert(tenant, "dev1", "", "", "", prefix)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if _, err := env.Super.Exec(ctx, `UPDATE devices SET paired_at = now() WHERE id = $1`, devicePk); err != nil {
		t.Fatalf("mark paired: %v", err)
	}
	configJSON := `{"a":1}`
	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	fd.Handle("config.dump", func(string, []byte) []mqtttest.Response { return mqtttest.OK(configJSON) })
	fd.Handle("fs.ls", func(string, []byte) []mqtttest.Response { return mqtttest.OK() })
	info := func(fw string) []byte {
		b, _ := json.Marshal(map[string]any{"firmware_version": fw, "config_hash": sha256Hex(configJSON)})
		return b
	}
	const skipped = "drift pull skipped, firmware below the supported floor"

	for _, fw := range []string{"", "1.4.4"} {
		c.handleInfo(tenant, "dev1", prefix, info(fw), false)
	}
	if n := logs.Count(skipped); n != 2 {
		t.Fatalf("skip lines = %d, want one per info below the floor or unknown", n)
	}

	c.handleInfo(tenant, "dev1", prefix, info("1.4.5"), false)
	waitFor(t, 15*time.Second, "config.json snapshot at the floor", func() bool {
		snap, err := env.Services.DeviceFiles.Latest(ctx, tenant, devicePk, "config.json")
		return err == nil && snap != nil
	})
	if n := logs.Count(skipped); n != 2 {
		t.Errorf("skip lines = %d after a supported info, want still 2", n)
	}
	if n := logs.Count("drift pull failed"); n != 0 {
		t.Errorf("drift pull failed lines = %d, want 0", n)
	}
}

func TestBrokerDriftStaleReadLogsNoSave(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	c := startBrokerClient(t, env, broker)
	logs := safegotest.Capture(t)

	const tenant = "brk-stale"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/dev1"
	ctx := context.Background()
	devicePk, err := env.Services.Devices.Upsert(tenant, "dev1", "", "26.11.1", "", prefix)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	configJSON := `{"a":1}`
	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	fd.Handle("config.dump", func(string, []byte) []mqtttest.Response { return mqtttest.OK(configJSON) })

	// A config change that may land for an hour makes every read started now stale.
	if err := env.Services.DeviceFiles.MarkConfigChanging(ctx, tenant, devicePk, time.Hour); err != nil {
		t.Fatal(err)
	}
	c.pullAndSnapshot(tenant, devicePk, prefix, "config.json", "drift", sha256Hex(configJSON))
	if fd.Calls("config.dump") != 1 {
		t.Fatalf("config.dump calls = %d, want the pull to reach the device", fd.Calls("config.dump"))
	}
	if snap, err := env.Services.DeviceFiles.Latest(ctx, tenant, devicePk, "config.json"); err != nil || snap != nil {
		t.Fatalf("Latest = %+v, %v, want the stale read dropped", snap, err)
	}
	if n := logs.Count("device_file saved"); n != 0 {
		t.Errorf("device_file saved lines = %d for a dropped read, want 0", n)
	}
	if n := logs.Count("device.read.stale_dropped"); n != 1 {
		t.Errorf("stale_dropped lines = %d, want 1", n)
	}
}
