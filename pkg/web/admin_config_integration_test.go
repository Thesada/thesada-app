//go:build integration

// Broker-path integration tests for the admin_config DeviceFiles callers:
// runCLICmd -> snapshotFromCmdResponse ("read"), runCLIWrite's
// chunked push ("write"), and the /config/snapshot endpoint - each through a
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
	"thesada.app/app/pkg/csrf"
	"thesada.app/app/pkg/mqtt"
	"thesada.app/app/pkg/mqtt/mqtttest"
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
	s.runCLICmd(ctx, reqID, device, prefix, "config.dump", "", nil)

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
		content := strings.Repeat("C", 4000) // two chunks
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

// TestAdminConfigWrite_RefreshesTheSecretStore: a device reported "cafe" open, then an
// operator writes a password for it. The write updates the store at once, so a later
// write with an empty "cafe" password is refused instead of erasing the new one.
func TestAdminConfigWrite_RefreshesTheSecretStore(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)

	const tenant = "webcfg-open"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/dev3"
	ctx := context.Background()
	pk, err := env.Services.Devices.Upsert(tenant, "dev3", "", "", "", prefix)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	device, err := env.Services.Devices.GetByIDAny(ctx, pk)
	if err != nil || device == nil {
		t.Fatalf("fetch device: %v", err)
	}
	if err := env.Services.Secrets.SetSecret(ctx, tenant, pk, "wifi.password:cafe", ""); err != nil {
		t.Fatalf("seed open marker: %v", err)
	}
	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	serveDeviceFS(fd, map[string]string{"/config.json": `{}`})

	written := `{"wifi":{"networks":[{"ssid":"cafe","password":"now-locked"}]}}`
	reqID := s.cliRequests.enqueue()
	claim, _ := s.claimDeviceWrite(device.ID, time.Minute)
	s.runCLIWrite(ctx, reqID, claim, device, prefix, "/config.json", written, nil)
	if entry := s.cliRequests.get(reqID); entry == nil || entry.Status != reqStatusDone {
		t.Fatalf("store entry = %+v, want done", entry)
	}

	got, found, err := env.Services.Secrets.Reveal(ctx, tenant, pk, "wifi.password:cafe")
	if err != nil || !found || got != "now-locked" {
		t.Fatalf("store after write = %q found=%v err=%v, want now-locked", got, found, err)
	}
	blank := `{"wifi":{"networks":[{"ssid":"cafe","password":""}]}}`
	if msg := configWriteRefusal("/config.json", blank, s.openWifiLookup(ctx, device)); msg == "" {
		t.Error("an empty cafe password after the write must be refused")
	}
}

// TestAdminConfigCmd_ConfigRenameDropsOpenMarkers: an fs.mv over config.json changes the
// config past the store, so the open markers go and the guard refuses an empty password.
func TestAdminConfigCmd_ConfigRenameDropsOpenMarkers(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)

	const tenant = "webcfg-mv"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/dev5"
	ctx := context.Background()
	pk, err := env.Services.Devices.Upsert(tenant, "dev5", "", "", "", prefix)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	device, err := env.Services.Devices.GetByIDAny(ctx, pk)
	if err != nil || device == nil {
		t.Fatalf("fetch device: %v", err)
	}
	if err := env.Services.Secrets.SetSecret(ctx, tenant, pk, "wifi.password:cafe", ""); err != nil {
		t.Fatalf("seed open marker: %v", err)
	}
	blank := `{"wifi":{"networks":[{"ssid":"cafe","password":""}]}}`
	if msg := configWriteRefusal("/config.json", blank, s.openWifiLookup(ctx, device)); msg != "" {
		t.Fatalf("precondition: an open cafe must pass the guard, got %q", msg)
	}

	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	serveDeviceFS(fd, map[string]string{
		"/config.json":     `{}`,
		"/config.json.bak": `{"wifi":{"networks":[{"ssid":"cafe","password":"locked"}]}}`,
	})
	reqID := s.cliRequests.enqueue()
	s.runCLICmd(ctx, reqID, device, prefix, "fs.mv", "/config.json.bak /config.json", nil)
	if entry := s.cliRequests.get(reqID); entry == nil || entry.Status != reqStatusDone {
		t.Fatalf("store entry = %+v, want done", entry)
	}

	if _, found, _ := env.Services.Secrets.Reveal(ctx, tenant, pk, "wifi.password:cafe"); found {
		t.Error("the cafe open marker survived the rename")
	}
	if msg := configWriteRefusal("/config.json", blank, s.openWifiLookup(ctx, device)); msg == "" {
		t.Error("an empty cafe password after the rename must be refused")
	}
}

// TestAdminConfigWrite_DistrustedMarkersRefuseEmpty: after a config change the store could
// not follow, a marker still in the store no longer lets an empty password through.
func TestAdminConfigWrite_DistrustedMarkersRefuseEmpty(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)

	const tenant = "webcfg-dist"
	env.SeedTenant(t, tenant)
	ctx := context.Background()
	pk, err := env.Services.Devices.Upsert(tenant, "dev6", "", "", "", "thesada/"+tenant+"/dev6")
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	device, err := env.Services.Devices.GetByIDAny(ctx, pk)
	if err != nil || device == nil {
		t.Fatalf("fetch device: %v", err)
	}
	if err := env.Services.Secrets.SetSecret(ctx, tenant, pk, "wifi.password:cafe", ""); err != nil {
		t.Fatalf("seed open marker: %v", err)
	}
	env.Services.DeviceFiles.DistrustOpenNetworks(pk)
	blank := `{"wifi":{"networks":[{"ssid":"cafe","password":""}]}}`
	if msg := configWriteRefusal("/config.json", blank, s.openWifiLookup(ctx, device)); msg == "" {
		t.Error("a distrusted open marker let an empty password through")
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

// TestAdminConfigSnapshotEndpoint drives the HTTP handler through the session
// middleware: a logged-in user posts assembled content and it lands as a
// snapshot attributed to that user.
func TestAdminConfigSnapshotEndpoint(t *testing.T) {
	env := servicetest.Start(t)

	const tenant = "webcfg3"
	env.SeedTenant(t, tenant)
	ctx := context.Background()

	s := &Server{cfg: env.Cfg, services: env.Services}

	pk, err := env.Services.Devices.Upsert(tenant, "dev3", "", "", "", "")
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	user, err := env.Services.Auth.CreateUser(tenant, "op@example.com", "Op", false)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	token, _, err := env.Services.Auth.CreateSession(tenant, user.ID, "magic_link", "go-test", "127.0.0.1")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	content := "-- assembled by frontend\nreturn 1\n"
	body, err := json.Marshal(map[string]string{
		"path": "/scripts/assembled.lua", "content": content, "source": "read",
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	// The production chain from web.go: csrf outside, session auth inside.
	// Going through it (not the bare handler) is what catches a dropped or
	// misordered middleware.
	secret := []byte(env.Cfg.CookieSecret)
	chain := csrf.Middleware(secret, nil)(authmw.Middleware(env.Services.Auth, nil)(
		http.HandlerFunc(s.handleAdminDeviceConfigSnapshot)))

	// Mint a signed CSRF cookie the way a browser gets one: a safe request.
	mintRec := httptest.NewRecorder()
	csrf.Middleware(secret, nil)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
		ServeHTTP(mintRec, httptest.NewRequest(http.MethodGet, "/", nil))
	var csrfCookie *http.Cookie
	for _, c := range mintRec.Result().Cookies() {
		if c.Name == csrf.CookieName {
			csrfCookie = c
		}
	}
	if csrfCookie == nil {
		t.Fatal("csrf middleware minted no cookie on GET")
	}

	newSnapshotReq := func(withCSRF bool) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))
		req.SetPathValue("id", pk.String())
		req.AddCookie(&http.Cookie{Name: authmw.CookieName, Value: token})
		if withCSRF {
			req.AddCookie(csrfCookie)
			req.Header.Set(csrf.HeaderName, csrfCookie.Value)
		}
		return req
	}

	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, newSnapshotReq(false))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status without csrf token = %d, want 403", rec.Code)
	}

	rec = httptest.NewRecorder()
	chain.ServeHTTP(rec, newSnapshotReq(true))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s, want 200", rec.Code, rec.Body.String())
	}
	snap, err := env.Services.DeviceFiles.Latest(ctx, tenant, pk, "/scripts/assembled.lua")
	if err != nil || snap == nil || snap.Content != content || snap.Source != "read" {
		t.Fatalf("Latest(assembled.lua) = %+v err=%v, want stored snapshot", snap, err)
	}
	if snap.UpdatedBy == nil || *snap.UpdatedBy != user.ID {
		t.Errorf("UpdatedBy = %v, want %s", snap.UpdatedBy, user.ID)
	}
}
