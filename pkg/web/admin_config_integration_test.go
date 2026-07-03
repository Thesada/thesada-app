//go:build integration

// Broker-path integration tests for the admin_config DeviceFiles callers
// (#458): runCLICmd -> snapshotFromCmdResponse ("read"), runCLIWrite's
// chunked push ("write"), and the /config/snapshot endpoint - each through a
// real mosquitto broker with a FakeDevice answering the CLI protocol.
//
//	go test -tags integration -run TestAdminConfig ./pkg/web/...
package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

	client, err := mqtt.Start(context.Background(), cfg, env.Pools.MQTT,
		alerts.New(cfg, env.Pools.App, nil), ws.New(cfg), env.Services)
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
		cliRequests: newCLIRequestStore(time.Minute),
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
	if entry == nil || entry.Status != cliStatusDone {
		t.Fatalf("store entry = %+v, want done", entry)
	}
	snap, err := env.Services.DeviceFiles.Latest(ctx, tenant, pk, "config.json")
	if err != nil || snap == nil || snap.Content != configJSON || snap.Source != "read" {
		t.Fatalf("Latest(config.json) = %+v err=%v, want read snapshot", snap, err)
	}
}

// TestAdminConfigWrite_ChunksAndSnapshots drives runCLIWrite: content over
// one chunk boundary goes out as fs.write + fs.append, lands as a "write"
// snapshot; a device error on a later chunk marks the entry failed and must
// NOT store a snapshot.
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

	fd := mqtttest.NewFakeDevice(t, broker, prefix)

	t.Run("two-chunk write stored with source write", func(t *testing.T) {
		// > 3900 bytes forces fs.write then fs.append.
		content := strings.Repeat("A", 3900) + strings.Repeat("B", 100)
		var got strings.Builder
		writeHandler := func(_ string, raw []byte) []mqtttest.Response {
			// raw = "path\nchunk"
			parts := strings.SplitN(string(raw), "\n", 2)
			if len(parts) != 2 || parts[0] != "/scripts/pushed.lua" {
				return []mqtttest.Response{{OK: false, Output: []string{"bad payload"}}}
			}
			got.WriteString(parts[1])
			return mqtttest.OK("written")
		}
		fd.Handle("fs.write", writeHandler)
		fd.Handle("fs.append", writeHandler)

		reqID := s.cliRequests.enqueue()
		s.runCLIWrite(ctx, reqID, device, prefix, "/scripts/pushed.lua", content, nil)

		entry := s.cliRequests.get(reqID)
		if entry == nil || entry.Status != cliStatusDone {
			t.Fatalf("store entry = %+v, want done", entry)
		}
		if fd.Calls("fs.write") != 1 || fd.Calls("fs.append") != 1 {
			t.Errorf("chunk calls write=%d append=%d, want 1/1",
				fd.Calls("fs.write"), fd.Calls("fs.append"))
		}
		if got.String() != content {
			t.Errorf("device received %d bytes, want %d (content mismatch)", got.Len(), len(content))
		}
		snap, err := env.Services.DeviceFiles.Latest(ctx, tenant, pk, "/scripts/pushed.lua")
		if err != nil || snap == nil || snap.Content != content || snap.Source != "write" {
			t.Fatalf("Latest(pushed.lua) = %+v err=%v, want write snapshot", snap, err)
		}
	})

	t.Run("device error mid-write stores nothing", func(t *testing.T) {
		content := strings.Repeat("C", 4000) // two chunks
		fd.Handle("fs.write", func(string, []byte) []mqtttest.Response {
			return mqtttest.OK("written")
		})
		fd.Handle("fs.append", func(string, []byte) []mqtttest.Response {
			return []mqtttest.Response{{OK: false, Output: []string{"disk full"}}}
		})

		reqID := s.cliRequests.enqueue()
		s.runCLIWrite(ctx, reqID, device, prefix, "/scripts/fail.lua", content, nil)

		entry := s.cliRequests.get(reqID)
		if entry == nil || entry.Status != cliStatusError {
			t.Fatalf("store entry = %+v, want error", entry)
		}
		snap, err := env.Services.DeviceFiles.Latest(ctx, tenant, pk, "/scripts/fail.lua")
		if err != nil || snap != nil {
			t.Fatalf("Latest(fail.lua) = %+v err=%v, want no snapshot after failed push", snap, err)
		}
	})
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
	chain := csrf.Middleware(secret)(authmw.Middleware(env.Services.Auth)(
		http.HandlerFunc(s.handleAdminDeviceConfigSnapshot)))

	// Mint a signed CSRF cookie the way a browser gets one: a safe request.
	mintRec := httptest.NewRecorder()
	csrf.Middleware(secret)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
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
