//go:build integration

// Broker-path integration tests: a real mosquitto container between the app
// client and a FakeDevice answering the firmware CLI protocol, on top of the
// usual migrated-Postgres harness. Covers the three mqtt-side DeviceFiles
// callers (#458): handleInfo's drift chain, pullAndSnapshot, and
// discoverAndSnapshotScripts.
//
//	go test -tags integration -run TestBroker ./pkg/mqtt/...
package mqtt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/alerts"
	"thesada.app/app/pkg/mqtt/mqtttest"
	"thesada.app/app/pkg/service/servicetest"
	"thesada.app/app/pkg/ws"
)

// startBrokerClient connects the app's mqtt client to the test broker and
// blocks until its subscription tree is provably live (probe round-trip
// through a tap - IsConnected alone races the SUBACK).
// in: t, env, broker URL. out: running *Client, stopped via t.Cleanup.
func startBrokerClient(t *testing.T, env *servicetest.Env, brokerURL string) *Client {
	t.Helper()

	cfg := env.Cfg
	cfg.MQTTBrokerURL = brokerURL
	cfg.MQTTClientID = "app-integration-test"
	cfg.MQTTTopicRoot = "thesada"

	c, err := Start(context.Background(), cfg, env.Pools.MQTT,
		alerts.New(cfg, env.Pools.App, nil), ws.New(cfg), env.Services)
	if err != nil {
		t.Fatalf("mqtt start: %v", err)
	}
	t.Cleanup(c.Stop)

	mqtttest.WaitForLive(t, "thesada/__probe__/status",
		func(p string, sink func(string, []byte, bool, byte)) (func(), error) {
			return c.RegisterTap(p, sink)
		}, c.PublishRaw)
	return c
}

// waitFor polls fn until it returns true or the deadline passes. The drift
// chain runs in a goroutine off handleInfo, so effects land asynchronously.
func waitFor(t *testing.T, d time.Duration, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// TestBrokerHandleInfo_DriftPullChain drives the full ingest chain end to
// end: retainedless info publish -> device upsert -> drift detection against
// the device-reported config hash -> CLI pull through the real broker ->
// snapshot row, plus script discovery of an untracked .lua.
func TestBrokerHandleInfo_DriftPullChain(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	c := startBrokerClient(t, env, broker)

	const tenant = "brk1"
	env.SeedTenant(t, tenant)
	// SeedTenant writes SQL directly; onMessage's ExistsBySlug gate reads the
	// TenantService in-memory slug cache, so it must be refreshed or the
	// publish is silently dropped as an unknown tenant.
	if err := env.Services.Tenants.Refresh(); err != nil {
		t.Fatalf("refresh tenant slugs: %v", err)
	}
	prefix := "thesada/" + tenant + "/dev1"
	ctx := context.Background()

	configJSON := `{"device":{"name":"dev1"},"mqtt":{"broker":"x"}}`
	luaContent := "-- custom script\nprint('hello from custom')\n"

	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	fd.Handle("config.dump", func(string, []byte) []mqtttest.Response {
		return mqtttest.OK(configJSON)
	})
	fd.Handle("fs.ls", func(string, []byte) []mqtttest.Response {
		return mqtttest.OK("  120  /scripts/custom.lua")
	})
	// Small chunks force the multi-chunk fs.cat loop, not the happy single read.
	fd.ServeChunkedFile("/scripts/custom.lua", luaContent, 16)

	info := map[string]any{
		"firmware_version": "26.06.1",
		"hardware_type":    "esp32-s3",
		"config_hash":      sha256Hex(configJSON),
	}
	payload, _ := json.Marshal(info)
	if err := c.PublishRaw(prefix+"/info", payload, 0, false); err != nil {
		t.Fatalf("publish info: %v", err)
	}

	// Device row appears with the reported firmware metadata.
	var devicePk uuid.UUID
	waitFor(t, 15*time.Second, "device row", func() bool {
		row := env.Super.QueryRow(ctx,
			`SELECT id FROM devices WHERE tenant_id = $1 AND device_id = 'dev1' AND firmware_version = '26.06.1'`, tenant)
		return row.Scan(&devicePk) == nil
	})

	// Drift pull stored the config snapshot with the device-verified sha.
	waitFor(t, 15*time.Second, "config.json snapshot", func() bool {
		snap, err := env.Services.DeviceFiles.Latest(ctx, tenant, devicePk, "config.json")
		return err == nil && snap != nil && snap.Content == configJSON && snap.Source == "drift"
	})

	// Script discovery pulled the untracked .lua over chunked fs.cat.
	waitFor(t, 15*time.Second, "custom.lua snapshot", func() bool {
		snap, err := env.Services.DeviceFiles.Latest(ctx, tenant, devicePk, "/scripts/custom.lua")
		return err == nil && snap != nil && snap.Content == luaContent
	})
	if got := fd.Calls("fs.cat"); got < 2 {
		t.Errorf("fs.cat calls = %d, want >= 2 (chunked loop)", got)
	}
}

// TestBrokerPullAndSnapshot exercises the pull paths synchronously: the
// config.dump route, the chunked script route, and the two guards
// (sha mismatch, invalid config shape) that must refuse to persist.
func TestBrokerPullAndSnapshot(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	c := startBrokerClient(t, env, broker)

	const tenant = "brk2"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/dev2"
	ctx := context.Background()

	devicePk, err := env.Services.Devices.Upsert(tenant, "dev2", "", "", "", prefix)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}

	fd := mqtttest.NewFakeDevice(t, broker, prefix)

	t.Run("config.dump path stores snapshot", func(t *testing.T) {
		configJSON := `{"a":1}`
		fd.Handle("config.dump", func(string, []byte) []mqtttest.Response {
			return mqtttest.OK(configJSON)
		})
		c.pullAndSnapshot(tenant, devicePk, prefix, "config.json", "drift", sha256Hex(configJSON))
		snap, err := env.Services.DeviceFiles.Latest(ctx, tenant, devicePk, "config.json")
		if err != nil || snap == nil || snap.Content != configJSON {
			t.Fatalf("Latest(config.json) = %+v, %v; want stored content", snap, err)
		}
	})

	t.Run("chunked script path stores snapshot", func(t *testing.T) {
		content := strings.Repeat("x", 50) // 4 chunks at size 16
		fd.ServeChunkedFile("/scripts/big.lua", content, 16)
		c.pullAndSnapshot(tenant, devicePk, prefix, "/scripts/big.lua", "drift", "")
		snap, err := env.Services.DeviceFiles.Latest(ctx, tenant, devicePk, "/scripts/big.lua")
		if err != nil || snap == nil || snap.Content != content {
			t.Fatalf("Latest(big.lua) content mismatch: %+v, %v", snap, err)
		}
	})

	t.Run("sha mismatch is not stored", func(t *testing.T) {
		fd.Handle("config.dump", func(string, []byte) []mqtttest.Response {
			return mqtttest.OK(`{"changed":"after-hash"}`)
		})
		before, err := env.Services.DeviceFiles.Latest(ctx, tenant, devicePk, "config.json")
		if err != nil || before == nil {
			t.Fatalf("latest before mismatch case: %+v err=%v", before, err)
		}
		c.pullAndSnapshot(tenant, devicePk, prefix, "config.json", "drift", sha256Hex("something else"))
		after, err := env.Services.DeviceFiles.Latest(ctx, tenant, devicePk, "config.json")
		if err != nil || after == nil || after.SHA256 != before.SHA256 {
			t.Fatalf("snapshot changed on sha mismatch: before=%s after=%+v err=%v", before.SHA256, after, err)
		}
	})

	t.Run("non-object config content is not stored", func(t *testing.T) {
		fd.Handle("config.dump", func(string, []byte) []mqtttest.Response {
			return mqtttest.OK("ERROR: not json at all")
		})
		before, err := env.Services.DeviceFiles.Latest(ctx, tenant, devicePk, "config.json")
		if err != nil || before == nil {
			t.Fatalf("latest before invalid-content case: %+v err=%v", before, err)
		}
		c.pullAndSnapshot(tenant, devicePk, prefix, "config.json", "drift", "")
		after, err := env.Services.DeviceFiles.Latest(ctx, tenant, devicePk, "config.json")
		if err != nil || after == nil || after.SHA256 != before.SHA256 {
			t.Fatalf("snapshot changed on invalid content: %+v err=%v", after, err)
		}
	})
}

// TestBrokerDiscoverScripts covers the discovery listing: legacy basename
// lines resolve under /scripts/, non-lua entries are skipped, and files with
// an existing snapshot are not re-pulled.
func TestBrokerDiscoverScripts(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	c := startBrokerClient(t, env, broker)

	const tenant = "brk3"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/dev3"
	ctx := context.Background()

	devicePk, err := env.Services.Devices.Upsert(tenant, "dev3", "", "", "", prefix)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}

	// /scripts/known.lua already has a snapshot - discovery must skip it.
	known := "-- already tracked\n"
	if err := env.Services.DeviceFiles.Upsert(ctx, tenant, devicePk, "/scripts/known.lua",
		known, sha256Hex(known), "drift", nil); err != nil {
		t.Fatalf("seed known.lua: %v", err)
	}

	fresh := "-- discovered\n"
	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	fd.Handle("fs.ls", func(string, []byte) []mqtttest.Response {
		// Legacy basename format (pre-v1.3.9 firmware), one tracked file,
		// one noise entry.
		return mqtttest.OK(
			"  14  fresh.lua",
			"  20  known.lua",
			"  99  notes.txt",
		)
	})
	fd.ServeChunkedFile("/scripts/fresh.lua", fresh, 2048)

	c.discoverAndSnapshotScripts(tenant, devicePk, prefix)

	snap, err := env.Services.DeviceFiles.Latest(ctx, tenant, devicePk, "/scripts/fresh.lua")
	if err != nil || snap == nil || snap.Content != fresh {
		t.Fatalf("fresh.lua not discovered: %+v err=%v", snap, err)
	}
	if got := fd.Calls("fs.cat"); got != 1 {
		t.Errorf("fs.cat calls = %d, want exactly 1 (known.lua skipped, notes.txt ignored)", got)
	}
}
