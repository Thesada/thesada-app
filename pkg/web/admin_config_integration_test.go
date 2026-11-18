//go:build integration

// Broker-path integration tests for the admin_config DeviceFiles callers:
// runCLICmd -> snapshotFromCmdResponse ("read"), runCLIWrite's
// chunked push ("write"), and Load from device - each through a
// real mosquitto broker with a FakeDevice answering the CLI protocol.
//
//	go test -tags integration -run TestAdminConfig ./pkg/web/...
package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/alerts"
	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/mqtt"
	"thesada.app/app/pkg/mqtt/mqtttest"
	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
	"thesada.app/app/pkg/ws"
)

// startWebBrokerServer wires a Server exactly like buildHTTPServer does, but
// against the test broker and DB. Blocks until the mqtt subscription tree is
// provably live (probe round-trip - IsConnected alone races the SUBACK).
// in: t, env, broker URL. out: ready *Server with live mqtt client.
func startWebBrokerServer(t *testing.T, env *servicetest.Env, brokerURL string) *Server {
	t.Helper()

	cfg := env.Cfg
	cfg.MQTTBrokerURL = brokerURL
	cfg.MQTTClientID = "web-integration-test"
	cfg.MQTTTopicRoot = "thesada"
	cfg.CLIRequestTimeout = 15 * time.Second

	client, err := mqtt.Start(context.Background(), cfg, env.Pools.App,
		alerts.New(cfg, env.Pools, nil), ws.New(cfg), env.Services)
	if err != nil {
		t.Fatalf("mqtt start: %v", err)
	}
	t.Cleanup(client.Stop)

	mqtttest.WaitForLive(t, "thesada/__probe__/status",
		func(p string, sink func(string, []byte, bool, byte)) (func(), error) {
			return client.RegisterTap(p, sink)
		}, client.PublishRaw)

	return &Server{
		cfg:         cfg,
		services:    env.Services,
		mqtt:        client,
		cliRequests: newCLIRequestStore(time.Minute, t.Context().Done()),
		jobs:        newRequestStore[jobResult](time.Minute, t.Context().Done()),
	}
}

// TestAdminConfigCmd_SnapshotsRead drives runCLICmd end to end: config.dump
// over the broker, response marked done in the store, and the output stored
// as a "read" snapshot by snapshotFromCmdResponse.
func TestAdminConfigCmd_SnapshotsRead(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)

	const tenant = "webcfg1"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/dev1"
	ctx := context.Background()

	pk, err := env.Services.Devices.Upsert(tenant, "dev1", "", "", "", prefix)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	device, err := env.Services.Devices.GetByIDAny(ctx, pk)
	if err != nil || device == nil {
		t.Fatalf("fetch device: %v", err)
	}

	configJSON := `{"device":{"name":"dev1"}}`
	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	fd.Handle("config.dump", func(string, []byte) []mqtttest.Response {
		return mqtttest.OK(configJSON)
	})

	reqID := s.cliRequests.enqueue()
	s.runCLICmd(ctx, reqID, uuid.Nil, device, prefix, "config.dump", "", nil)

	entry := s.cliRequests.get(reqID)
	if entry == nil || entry.Status != reqStatusDone {
		t.Fatalf("store entry = %+v, want done", entry)
	}
	snap, err := env.Services.DeviceFiles.Latest(ctx, tenant, pk, "config.json")
	if err != nil || snap == nil || snap.Content != configJSON || snap.Source != "read" {
		t.Fatalf("Latest(config.json) = %+v err=%v, want read snapshot", snap, err)
	}
}

// deviceFS serves fs.write, fs.append, fs.mv and fs.rm on fd from an in-memory
// file map with the firmware's reply texts. failAppend makes fs.append refuse.
type deviceFS struct {
	mu         sync.Mutex
	files      map[string]string
	failAppend bool
}

func serveDeviceFS(fd *mqtttest.FakeDevice, files map[string]string) *deviceFS {
	d := &deviceFS{files: files}
	write := func(appendMode bool) mqtttest.Handler {
		return func(_ string, raw []byte) []mqtttest.Response {
			d.mu.Lock()
			defer d.mu.Unlock()
			path, content, ok := strings.Cut(string(raw), "\n")
			if !ok {
				return []mqtttest.Response{{OK: false, Output: []string{"Usage: payload = <path>\\n<content>"}}}
			}
			if appendMode && d.failAppend {
				return []mqtttest.Response{{OK: false, Output: []string{"Failed to open file"}}}
			}
			if appendMode {
				d.files[path] += content
				return mqtttest.OK(fmt.Sprintf("Appended %d bytes to %s", len(content), path))
			}
			d.files[path] = content
			return mqtttest.OK(fmt.Sprintf("Wrote %d bytes to %s", len(content), path))
		}
	}
	fd.Handle("fs.write", write(false))
	fd.Handle("fs.append", write(true))
	fd.Handle("fs.mv", func(args string, _ []byte) []mqtttest.Response {
		d.mu.Lock()
		defer d.mu.Unlock()
		src, dst, _ := strings.Cut(args, " ")
		body, ok := d.files[src]
		if !ok {
			return mqtttest.OK("Failed to rename")
		}
		d.files[dst] = body
		delete(d.files, src)
		return mqtttest.OK("Renamed " + src + " -> " + dst)
	})
	fd.Handle("fs.cat", func(args string, _ []byte) []mqtttest.Response {
		d.mu.Lock()
		defer d.mu.Unlock()
		path, _, _ := strings.Cut(args, " ")
		body, ok := d.files[path]
		if !ok {
			return []mqtttest.Response{{OK: false, Output: []string{"File not found"}}}
		}
		total := len(body)
		return []mqtttest.Response{{OK: true, Total: &total}}
	})
	fd.Handle("fs.rm", func(args string, _ []byte) []mqtttest.Response {
		d.mu.Lock()
		defer d.mu.Unlock()
		if _, ok := d.files[args]; !ok {
			return mqtttest.OK("Failed to remove (file not found or directory)")
		}
		delete(d.files, args)
		return mqtttest.OK("Removed " + args)
	})
	return d
}

func (d *deviceFS) file(path string) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	body, ok := d.files[path]
	return body, ok
}

// TestAdminConfigWrite_ChunksAndSnapshots drives runCLIWrite over the broker:
// content over one chunk boundary is staged in <path>.new and renamed into
// place, then stored as a "write" snapshot. A device error on a later chunk
// leaves the live file as it was, removes the staging file and stores nothing.
func TestAdminConfigWrite_ChunksAndSnapshots(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)

	const tenant = "webcfg2"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/dev2"
	ctx := context.Background()

	pk, err := env.Services.Devices.Upsert(tenant, "dev2", "", "", "", prefix)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	device, err := env.Services.Devices.GetByIDAny(ctx, pk)
	if err != nil || device == nil {
		t.Fatalf("fetch device: %v", err)
	}

	const oldConfig = `{"wifi":{"ssid":"old"}}`
	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	dfs := serveDeviceFS(fd, map[string]string{"/config.json": oldConfig})
	calls := func() [5]int {
		return [5]int{fd.Calls("fs.write"), fd.Calls("fs.append"), fd.Calls("fs.cat"), fd.Calls("fs.mv"), fd.Calls("fs.rm")}
	}
	delta := func(a, b [5]int) [5]int {
		var d [5]int
		for i := range d {
			d[i] = b[i] - a[i]
		}
		return d
	}

	t.Run("two-chunk write renamed into place and stored", func(t *testing.T) {
		// > 3900 bytes forces fs.write then fs.append.
		content := strings.Repeat("A", 3900) + strings.Repeat("B", 100)
		before := calls()

		reqID := s.cliRequests.enqueue()
		claim, _ := s.claimDeviceWrite(device.ID, time.Minute)
		s.runCLIWrite(ctx, reqID, claim, device, prefix, "/scripts/pushed.lua", content, nil)

		entry := s.cliRequests.get(reqID)
		if entry == nil || entry.Status != reqStatusDone {
			t.Fatalf("store entry = %+v, want done", entry)
		}
		if d := delta(before, calls()); d != [5]int{1, 1, 1, 1, 0} {
			t.Errorf("write/append/cat/mv/rm calls = %v, want [1 1 1 1 0]", d)
		}
		if got, _ := dfs.file("/scripts/pushed.lua"); got != content {
			t.Errorf("device file holds %d bytes, want %d", len(got), len(content))
		}
		if _, left := dfs.file("/scripts/pushed.lua.new"); left {
			t.Error("staging file left on the device")
		}
		snap, err := env.Services.DeviceFiles.Latest(ctx, tenant, pk, "/scripts/pushed.lua")
		if err != nil || snap == nil || snap.Content != content || snap.Source != "write" {
			t.Fatalf("Latest(pushed.lua) = %+v err=%v, want write snapshot", snap, err)
		}
	})

	t.Run("device error mid-write keeps the live config", func(t *testing.T) {
		content := `{"pad":"` + strings.Repeat("C", 4000) + `"}` // two chunks, passes the guard
		dfs.mu.Lock()
		dfs.failAppend = true
		dfs.mu.Unlock()
		before := calls()

		reqID := s.cliRequests.enqueue()
		claim, _ := s.claimDeviceWrite(device.ID, time.Minute)
		s.runCLIWrite(ctx, reqID, claim, device, prefix, "/config.json", content, nil)

		entry := s.cliRequests.get(reqID)
		if entry == nil || entry.Status != reqStatusError || !strings.Contains(entry.ErrorMsg, "chunk 2/2 device error") {
			t.Fatalf("store entry = %+v, want chunk 2/2 error", entry)
		}
		if d := delta(before, calls()); d != [5]int{1, 1, 0, 0, 1} {
			t.Errorf("write/append/cat/mv/rm calls = %v, want [1 1 0 0 1]", d)
		}
		if got, _ := dfs.file("/config.json"); got != oldConfig {
			t.Errorf("/config.json holds %d bytes, want the old %d untouched", len(got), len(oldConfig))
		}
		if _, left := dfs.file("/config.json.new"); left {
			t.Error("staging file left on the device")
		}
		snap, err := env.Services.DeviceFiles.Latest(ctx, tenant, pk, "/config.json")
		if err != nil || snap != nil {
			t.Fatalf("Latest(config.json) = %+v err=%v, want no snapshot after failed push", snap, err)
		}
	})
}

// seedDevice upserts one device on prefix and returns it with its pk.
func seedDevice(t *testing.T, env *servicetest.Env, tenant, devID, prefix string) *service.Device {
	t.Helper()
	pk, err := env.Services.Devices.Upsert(tenant, devID, "", "", "", prefix)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	device, err := env.Services.Devices.GetByIDAny(context.Background(), pk)
	if err != nil || device == nil {
		t.Fatalf("fetch device: %v", err)
	}
	return device
}

// deviceRead stores content as a current device read of config.json.
func deviceRead(t *testing.T, env *servicetest.Env, device *service.Device, content string) {
	t.Helper()
	ctx := context.Background()
	start, err := env.Services.DeviceFiles.ReadStart(ctx, device.TenantID)
	if err != nil {
		t.Fatalf("ReadStart: %v", err)
	}
	if err := env.Services.DeviceFiles.UpsertFromDevice(ctx, device.TenantID, device.ID, "config.json", content, "sha-seed", "drift", nil, start); err != nil {
		t.Fatalf("seed device read: %v", err)
	}
}

// configChangedAt reads devices.config_changed_at, nil when never set.
func configChangedAt(t *testing.T, env *servicetest.Env, device *service.Device) *time.Time {
	t.Helper()
	var at *time.Time
	if err := env.Super.QueryRow(context.Background(),
		`SELECT config_changed_at FROM devices WHERE id = $1`, device.ID).Scan(&at); err != nil {
		t.Fatalf("read config_changed_at: %v", err)
	}
	return at
}

// openCafeConfig is a device config with cafe open, and a blank write of it.
const openCafeConfig = `{"wifi":{"networks":[{"ssid":"cafe","password":""}]}}`

// serveNothingInNVS answers secret.info with cafe not in NVS, which the open WiFi guard asks.
func serveNothingInNVS(fd *mqtttest.FakeDevice) {
	fd.Handle("secret.info", func(string, []byte) []mqtttest.Response {
		return mqtttest.OK("wifi.password:cafe     config/none")
	})
}

// TestAdminConfigWrite_RefreshesTheSecretStore: a device reported "cafe" open, then an
// operator writes a password for it. The marker goes, so a blank cafe is refused after.
func TestAdminConfigWrite_RefreshesTheSecretStore(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)

	const tenant = "webcfg-open"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/dev3"
	ctx := context.Background()
	device := seedDevice(t, env, tenant, "dev3", prefix)
	deviceRead(t, env, device, openCafeConfig)
	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	serveDeviceFS(fd, map[string]string{"/config.json": `{}`})

	written := `{"wifi":{"networks":[{"ssid":"cafe","password":"now-locked"}]}}`
	reqID := s.cliRequests.enqueue()
	claim, _ := s.claimDeviceWrite(device.ID, time.Minute)
	s.runCLIWrite(ctx, reqID, claim, device, prefix, "/config.json", written, nil)
	if entry := s.cliRequests.get(reqID); entry == nil || entry.Status != reqStatusDone {
		t.Fatalf("store entry = %+v, want done", entry)
	}

	got, found, err := env.Services.Secrets.Reveal(ctx, tenant, device.ID, "wifi.password:cafe")
	if err != nil || !found || got != "now-locked" {
		t.Fatalf("store after write = %q found=%v err=%v, want now-locked", got, found, err)
	}
	if msg := configWriteRefusal("/config.json", openCafeConfig, s.openWifiLookup(ctx, device, openCafeConfig)); msg == "" {
		t.Error("an empty cafe password after the write must be refused")
	}
}

// TestAdminConfigCmd_ConfigRenameMakesMarkersStale: an fs.mv over config.json changes
// the config past the app, so the guard refuses an empty password it passed before.
func TestAdminConfigCmd_ConfigRenameMakesMarkersStale(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)

	const tenant = "webcfg-mv"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/dev5"
	ctx := context.Background()
	device := seedDevice(t, env, tenant, "dev5", prefix)
	deviceRead(t, env, device, openCafeConfig)
	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	serveNothingInNVS(fd)
	if msg := configWriteRefusal("/config.json", openCafeConfig, s.openWifiLookup(ctx, device, openCafeConfig)); msg != "" {
		t.Fatalf("precondition: an open cafe must pass the guard, got %q", msg)
	}
	serveDeviceFS(fd, map[string]string{
		"/config.json":     `{}`,
		"/config.json.bak": `{"wifi":{"networks":[{"ssid":"cafe","password":"locked"}]}}`,
	})
	claim, ok := s.claimDeviceWrite(device.ID, time.Minute)
	if !ok {
		t.Fatal("claim refused")
	}
	reqID := s.cliRequests.enqueue()
	s.runCLICmd(ctx, reqID, claim, device, prefix, "fs.mv", "/config.json.bak /config.json", nil)
	if entry := s.cliRequests.get(reqID); entry == nil || entry.Status != reqStatusDone {
		t.Fatalf("store entry = %+v, want done", entry)
	}
	if configChangedAt(t, env, device) == nil {
		t.Error("the rename left config_changed_at unset")
	}
	if msg := configWriteRefusal("/config.json", openCafeConfig, s.openWifiLookup(ctx, device, openCafeConfig)); msg == "" {
		t.Error("an empty cafe password after the rename must be refused")
	}
	if _, held := s.deviceWrites.Load(device.ID); held {
		t.Error("the command left the device write claim held")
	}
}

// TestAdminConfigWrite_StaleMarkerRefusedAfterRestart: the order lives in the DB, so a
// new service bundle and server on the same DB still refuse a marker older than a change.
func TestAdminConfigWrite_StaleMarkerRefusedAfterRestart(t *testing.T) {
	env := servicetest.Start(t)
	ctx := context.Background()

	const tenant = "webcfg-restart"
	env.SeedTenant(t, tenant)
	device := seedDevice(t, env, tenant, "dev6", "thesada/"+tenant+"/dev6")
	deviceRead(t, env, device, openCafeConfig)
	if err := env.Services.DeviceFiles.MarkConfigChanged(ctx, tenant, device.ID); err != nil {
		t.Fatalf("MarkConfigChanged: %v", err)
	}

	fresh, err := service.New(env.Cfg, env.Pools)
	if err != nil {
		t.Fatalf("service.New: %v", err)
	}
	restarted := &Server{cfg: env.Cfg, services: fresh}
	if msg := configWriteRefusal("/config.json", openCafeConfig, restarted.openWifiLookup(ctx, device, openCafeConfig)); msg == "" {
		t.Error("a restarted server let a stale open marker through")
	}
}

// TestAdminConfigWrite_GuardRunsAgainAtWriteTime: a config change between the enqueue
// check and the worker makes the marker stale, so the worker refuses and sends nothing (M6).
func TestAdminConfigWrite_GuardRunsAgainAtWriteTime(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)

	const tenant = "webcfg-guard"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/dev7"
	ctx := context.Background()
	device := seedDevice(t, env, tenant, "dev7", prefix)
	deviceRead(t, env, device, openCafeConfig)
	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	serveDeviceFS(fd, map[string]string{"/config.json": `{}`})
	serveNothingInNVS(fd)

	claim, _ := s.claimDeviceWrite(device.ID, time.Minute)
	if msg := configWriteRefusal("/config.json", openCafeConfig, s.openWifiLookup(ctx, device, openCafeConfig)); msg != "" {
		t.Fatalf("precondition: the enqueue check passes, got %q", msg)
	}
	if err := env.Services.DeviceFiles.MarkConfigChanged(ctx, tenant, device.ID); err != nil {
		t.Fatalf("MarkConfigChanged: %v", err)
	}
	reqID := s.cliRequests.enqueue()
	s.runCLIWrite(ctx, reqID, claim, device, prefix, "/config.json", openCafeConfig, nil)
	entry := s.cliRequests.get(reqID)
	if entry == nil || entry.Status != reqStatusError || !strings.Contains(entry.ErrorMsg, "empty secret fields") {
		t.Fatalf("store entry = %+v, want the guard refusal", entry)
	}
	if n := fd.Calls("fs.write"); n != 0 {
		t.Errorf("device saw %d fs.write, a refused write sends nothing", n)
	}
}

// TestAdminConfigCmd_ConfigChangeIs409WhileAWriteRuns: a config-changing command takes the
// device write claim, so it is refused while a write holds it and runs once it is free.
func TestAdminConfigCmd_ConfigChangeIs409WhileAWriteRuns(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)

	const tenant = "webcfg-claim"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/dev8"
	device := seedDevice(t, env, tenant, "dev8", prefix)
	user, err := env.Services.Auth.CreateUser(tenant, "op8@example.com", "Op", false)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	token, _, err := env.Services.Auth.CreateSession(tenant, user.ID, "magic_link", "go-test", "127.0.0.1")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	fd.Handle("config.set", func(string, []byte) []mqtttest.Response { return mqtttest.OK("ok") })

	chain := authmw.Middleware(env.Services.Auth, nil)(http.HandlerFunc(s.handleAdminDeviceConfigCmd))
	post := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"command":"config.set","payload":"device.name x"}`))
		req.SetPathValue("id", device.ID.String())
		req.AddCookie(&http.Cookie{Name: authmw.CookieName, Value: token})
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		return rec
	}

	claim, ok := s.claimDeviceWrite(device.ID, time.Minute)
	if !ok {
		t.Fatal("claim refused")
	}
	if rec := post(); rec.Code != http.StatusConflict {
		t.Fatalf("config.set while a write runs = %d, want 409", rec.Code)
	}
	if n := fd.Calls("config.set"); n != 0 {
		t.Fatalf("device saw %d config.set, a refused command sends nothing", n)
	}
	s.releaseDeviceWrite(device.ID, claim)

	rec := post()
	if rec.Code != http.StatusOK {
		t.Fatalf("config.set after the write = %d %s", rec.Code, rec.Body.String())
	}
	var enq cliEnqueueResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &enq); err != nil {
		t.Fatalf("enqueue body: %v", err)
	}
	id, _ := uuid.Parse(enq.RequestID)
	deadline := time.Now().Add(30 * time.Second)
	for {
		if e := s.cliRequests.get(id); e != nil && e.Status != reqStatusPending {
			if e.Status != reqStatusDone {
				t.Fatalf("config.set ended %s: %s", e.Status, e.ErrorMsg)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("config.set never finished")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if configChangedAt(t, env, device) == nil {
		t.Error("config.set left config_changed_at unset")
	}
}

// TestAdminConfigWrite_UnknownRenameMarksConfigChanged: an fs.mv that times out and
// cannot be read back may have landed, so the config counts as changed.
func TestAdminConfigWrite_UnknownRenameMarksConfigChanged(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)
	s.cfg.CLIRequestTimeout = 2 * time.Second

	const tenant = "webcfg-unknown"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/dev9"
	ctx := context.Background()
	device := seedDevice(t, env, tenant, "dev9", prefix)
	deviceRead(t, env, device, openCafeConfig)

	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	dfs := serveDeviceFS(fd, map[string]string{"/config.json": `{}`})
	// The rename lands but its reply never comes, and the readback carries no bytes.
	fd.Handle("fs.mv", func(args string, _ []byte) []mqtttest.Response {
		dfs.mu.Lock()
		defer dfs.mu.Unlock()
		src, dst, _ := strings.Cut(args, " ")
		dfs.files[dst] = dfs.files[src]
		delete(dfs.files, src)
		return nil
	})

	claim, _ := s.claimDeviceWrite(device.ID, time.Minute)
	reqID := s.cliRequests.enqueue()
	s.runCLIWrite(ctx, reqID, claim, device, prefix, "/config.json", `{"a":1}`, nil)
	entry := s.cliRequests.get(reqID)
	if entry == nil || entry.Status != reqStatusTimeout || !strings.Contains(entry.ErrorMsg, "outcome is unknown") {
		t.Fatalf("store entry = %+v, want an unknown rename", entry)
	}
	if configChangedAt(t, env, device) == nil {
		t.Fatal("an unknown rename left config_changed_at unset")
	}
	if msg := configWriteRefusal("/config.json", openCafeConfig, s.openWifiLookup(ctx, device, openCafeConfig)); msg == "" {
		t.Error("the marker from before the unknown rename still passes the guard")
	}
}

// TestAdminConfigWrite_MarksChangeBeforeSending: by the first chunk the config already
// counts as changed, so a marker from before the write no longer passes the guard.
func TestAdminConfigWrite_MarksChangeBeforeSending(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)

	const tenant = "webcfg-premark"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/dev11"
	ctx := context.Background()
	device := seedDevice(t, env, tenant, "dev11", prefix)
	deviceRead(t, env, device, openCafeConfig)

	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	dfs := serveDeviceFS(fd, map[string]string{"/config.json": `{}`})
	var openAtFirstChunk, checked bool
	fd.Handle("fs.write", func(_ string, raw []byte) []mqtttest.Response {
		open, err := env.Services.DeviceFiles.OpenNetworkCurrent(ctx, tenant, device.ID, "cafe")
		if err != nil {
			t.Errorf("OpenNetworkCurrent: %v", err)
		}
		openAtFirstChunk, checked = open, true
		p, body, _ := strings.Cut(string(raw), "\n")
		dfs.mu.Lock()
		dfs.files[p] = body
		dfs.mu.Unlock()
		return mqtttest.OK(fmt.Sprintf("Wrote %d bytes to %s", len(body), p))
	})

	claim, _ := s.claimDeviceWrite(device.ID, time.Minute)
	reqID := s.cliRequests.enqueue()
	s.runCLIWrite(ctx, reqID, claim, device, prefix, "/config.json", `{"a":1}`, nil)
	if entry := s.cliRequests.get(reqID); entry == nil || entry.Status != reqStatusDone {
		t.Fatalf("store entry = %+v, want done", entry)
	}
	if !checked || openAtFirstChunk {
		t.Errorf("checked=%v open at the first chunk=%v, want the change marked before sending", checked, openAtFirstChunk)
	}
}

// TestAdminConfigWrite_FailedMarkAfterRenameKeepsMarkersStale: a drift read of the old file
// while the write runs, then a rename whose change mark fails. Its marker must not pass.
func TestAdminConfigWrite_FailedMarkAfterRenameKeepsMarkersStale(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)

	const tenant = "webcfg-postmark"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/dev14"
	ctx := context.Background()
	device := seedDevice(t, env, tenant, "dev14", prefix)

	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	dfs := serveDeviceFS(fd, map[string]string{"/config.json": openCafeConfig})
	refuse := fmt.Sprintf(`
		CREATE FUNCTION refuse_mark_%[1]s() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'mark refused by the test'; END $$;
		CREATE TRIGGER refuse_mark_%[1]s BEFORE UPDATE OF config_changed_at ON devices
		FOR EACH ROW WHEN (NEW.id = '%[2]s') EXECUTE FUNCTION refuse_mark_%[1]s();`,
		strings.ReplaceAll(device.ID.String(), "-", ""), device.ID)
	fd.Handle("fs.mv", func(args string, _ []byte) []mqtttest.Response {
		dfs.mu.Lock()
		defer dfs.mu.Unlock()
		// The old file, read after the pre-send mark and before the rename.
		start, err := env.Services.DeviceFiles.ReadStart(ctx, tenant)
		if err == nil {
			err = env.Services.DeviceFiles.UpsertFromDevice(ctx, tenant, device.ID, "config.json",
				dfs.files["/config.json"], "sha-old", "drift", nil, start)
		}
		if err != nil {
			t.Errorf("drift read during the write: %v", err)
		}
		if _, err := env.Super.Exec(ctx, refuse); err != nil {
			t.Errorf("install the mark refusal: %v", err)
		}
		src, dst, _ := strings.Cut(args, " ")
		dfs.files[dst] = dfs.files[src]
		delete(dfs.files, src)
		return mqtttest.OK("Renamed " + src + " -> " + dst)
	})

	written := `{"wifi":{"networks":[{"ssid":"cafe","password":"now-locked"}]}}`
	claim, _ := s.claimDeviceWrite(device.ID, time.Minute)
	reqID := s.cliRequests.enqueue()
	s.runCLIWrite(ctx, reqID, claim, device, prefix, "/config.json", written, nil)
	if entry := s.cliRequests.get(reqID); entry == nil || entry.Status != reqStatusError {
		t.Fatalf("store entry = %+v, want the recording error", entry)
	}
	if body, _ := dfs.file("/config.json"); body != written {
		t.Fatalf("/config.json = %q, want the rename landed", body)
	}
	if msg := configWriteRefusal("/config.json", openCafeConfig, s.openWifiLookup(ctx, device, openCafeConfig)); msg == "" {
		t.Error("a marker of the file the rename replaced passes the guard")
	}
}

// TestAdminConfigWrite_SnapshotFailureKeepsOtherWrites: only config.json feeds the guard, so a
// failed snapshot row of another file leaves the write done (the rules push then reloads).
func TestAdminConfigWrite_SnapshotFailureKeepsOtherWrites(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)

	const tenant = "webcfg-snapfail"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/dev12"
	ctx := context.Background()
	device := seedDevice(t, env, tenant, "dev12", prefix)
	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	serveDeviceFS(fd, map[string]string{})
	// No such user: the device_files row fails its updated_by foreign key.
	ghost := uuid.New()

	for path, want := range map[string]requestStatus{"/scripts/x.lua": reqStatusDone, "/config.json": reqStatusError} {
		claim, _ := s.claimDeviceWrite(device.ID, time.Minute)
		reqID := s.cliRequests.enqueue()
		s.runCLIWrite(ctx, reqID, claim, device, prefix, path, `{"a":1}`, &ghost)
		if entry := s.cliRequests.get(reqID); entry == nil || entry.Status != want {
			t.Errorf("%s: entry = %+v, want %s", path, entry, want)
		}
	}
}

// TestAdminConfigLoad_RefreshesMarkers: Load from device reads config.json server side
// through the device read path, so it stores the snapshot and a fresh marker (M4).
func TestAdminConfigLoad_RefreshesMarkers(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)

	const tenant = "webcfg-load"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/dev10"
	ctx := context.Background()
	device := seedDevice(t, env, tenant, "dev10", prefix)
	deviceRead(t, env, device, openCafeConfig)
	if err := env.Services.DeviceFiles.MarkConfigChanged(ctx, tenant, device.ID); err != nil {
		t.Fatalf("MarkConfigChanged: %v", err)
	}

	live := `{"mqtt":{"password":"mq"},"wifi":{"networks":[{"ssid":"cafe","password":""}]},"pad":"` +
		strings.Repeat("x", 300) + `"}`
	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	fd.ServeChunkedFile("/config.json", live, 100)
	serveNothingInNVS(fd)

	reqID := s.cliRequests.enqueue()
	s.runConfigLoad(ctx, reqID, device, nil)
	entry := s.cliRequests.get(reqID)
	if entry == nil || entry.Status != reqStatusDone || entry.Response == nil || entry.Response.Data == nil || *entry.Response.Data != live {
		t.Fatalf("store entry = %+v, want done with the file", entry)
	}
	if n := fd.Calls("fs.cat"); n < 4 {
		t.Errorf("fs.cat calls = %d, want the file read in chunks", n)
	}
	if msg := configWriteRefusal("/config.json", openCafeConfig, s.openWifiLookup(ctx, device, openCafeConfig)); msg != "" {
		t.Errorf("after a load cafe must pass the guard again, got %q", msg)
	}
	snap, err := env.Services.DeviceFiles.Latest(ctx, tenant, device.ID, "config.json")
	if err != nil || snap == nil || snap.Source != "read" || strings.Contains(snap.Content, `"mq"`) {
		t.Fatalf("snapshot = %+v err=%v, want a blanked read", snap, err)
	}
	if v, _, _ := env.Services.Secrets.Reveal(ctx, tenant, device.ID, "mqtt.password"); v != "mq" {
		t.Errorf("mqtt.password = %q, want the gap filled", v)
	}
}

// TestAdminConfigWrite_SecondWriteToTheDeviceIs409 posts a second write while
// the first is still on the device: it is refused before anything is sent,
// and the device takes writes again once the first one finished.
func TestAdminConfigWrite_SecondWriteToTheDeviceIs409(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)

	const tenant = "webcfg4"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/dev4"
	pk, err := env.Services.Devices.Upsert(tenant, "dev4", "", "", "", prefix)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	user, err := env.Services.Auth.CreateUser(tenant, "op4@example.com", "Op", false)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	token, _, err := env.Services.Auth.CreateSession(tenant, user.ID, "magic_link", "go-test", "127.0.0.1")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	dfs := serveDeviceFS(fd, map[string]string{})
	// Hold the first fs.write on the device until the test lets it go.
	gate := make(chan struct{})
	var held, released sync.Once
	release := func() { released.Do(func() { close(gate) }) }
	t.Cleanup(release)
	write := func(_ string, raw []byte) []mqtttest.Response {
		held.Do(func() { <-gate })
		path, content, _ := strings.Cut(string(raw), "\n")
		dfs.mu.Lock()
		dfs.files[path] = content
		dfs.mu.Unlock()
		return mqtttest.OK(fmt.Sprintf("Wrote %d bytes to %s", len(content), path))
	}
	fd.Handle("fs.write", write)

	chain := authmw.Middleware(env.Services.Auth, nil)(http.HandlerFunc(s.handleAdminDeviceConfigWrite))
	post := func(content string) *httptest.ResponseRecorder {
		body, err := json.Marshal(map[string]string{"path": "/config.json", "content": content})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))
		req.SetPathValue("id", pk.String())
		req.AddCookie(&http.Cookie{Name: authmw.CookieName, Value: token})
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)
		return rec
	}
	waitDone := func(rec *httptest.ResponseRecorder) {
		t.Helper()
		var enq cliEnqueueResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &enq); err != nil {
			t.Fatalf("enqueue body %q: %v", rec.Body.String(), err)
		}
		id, err := uuid.Parse(enq.RequestID)
		if err != nil {
			t.Fatalf("request id: %v", err)
		}
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			if e := s.cliRequests.get(id); e != nil && e.Status != reqStatusPending {
				if e.Status != reqStatusDone {
					t.Fatalf("write ended %s: %s", e.Status, e.ErrorMsg)
				}
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("write never finished")
	}

	first := post(`{"a":1}`)
	if first.Code != http.StatusOK {
		t.Fatalf("first write = %d %s", first.Code, first.Body.String())
	}
	for i := 0; fd.Calls("fs.write") == 0; i++ {
		if i > 200 {
			t.Fatal("first write never reached the device")
		}
		time.Sleep(25 * time.Millisecond)
	}
	second := post(`{"b":2}`)
	if second.Code != http.StatusConflict {
		t.Fatalf("second write while the first runs = %d, want 409", second.Code)
	}
	release()
	waitDone(first)
	if fd.Calls("fs.write") != 1 {
		t.Fatalf("device saw %d fs.write, the refused write must send nothing", fd.Calls("fs.write"))
	}

	third := post(`{"c":3}`)
	if third.Code != http.StatusOK {
		t.Fatalf("write after the first finished = %d %s", third.Code, third.Body.String())
	}
	waitDone(third)
	if got, _ := dfs.file("/config.json"); got != `{"c":3}` {
		t.Fatalf("/config.json = %q, want the third write", got)
	}
}
