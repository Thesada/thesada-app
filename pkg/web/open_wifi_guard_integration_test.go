//go:build integration

// The config.json write guard passes an empty WiFi password only when a current read shows the
// file holds "" for that SSID and a correlated secret.info shows nothing in NVS for it (Q1).
//
//	go test -tags integration -run TestOpenWifiGuard ./pkg/web/...
package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/mqtt"
	"thesada.app/app/pkg/mqtt/mqtttest"
	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

func TestOpenWifiGuard(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)
	ctx := context.Background()

	const tenant = "webcfg-q1"
	env.SeedTenant(t, tenant)
	admin, err := env.Services.Auth.CreateUser(tenant, "root@q1.test", "Root", false)
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

	n := 0
	// setup seeds a device whose last read shows cafe open, served by a fake device whose
	// secret.info reports cafe as info says.
	setup := func(t *testing.T, info string) (*service.Device, *mqtttest.FakeDevice, *sync.Mutex, *string) {
		t.Helper()
		n++
		id := "q1dev" + string(rune('a'+n))
		prefix := "thesada/" + tenant + "/" + id
		device := seedDevice(t, env, tenant, id, prefix)
		deviceRead(t, env, device, openCafeConfig)
		fd := mqtttest.NewFakeDevice(t, broker, prefix)
		serveDeviceFS(fd, map[string]string{"/config.json": `{}`})
		var mu sync.Mutex
		state := info
		fd.Handle("secret.info", func(string, []byte) []mqtttest.Response {
			mu.Lock()
			defer mu.Unlock()
			return mqtttest.OK("mqtt.password          nvs", "wifi.password:cafe     "+state)
		})
		return device, fd, &mu, &state
	}
	work := func(t *testing.T, device *service.Device) *requestEntry[*mqtt.CLIResponse] {
		t.Helper()
		claim, ok := s.claimDeviceWrite(device.ID, time.Minute)
		if !ok {
			t.Fatal("claim refused")
		}
		reqID := s.cliRequests.enqueue()
		s.runCLIWrite(ctx, reqID, claim, device, s.deviceTopicPrefix(device), "/config.json", openCafeConfig, nil)
		return s.cliRequests.get(reqID)
	}
	enqueue := func(t *testing.T, device *service.Device) (int, string) {
		t.Helper()
		body, _ := json.Marshal(cliWriteRequest{Path: "/config.json", Content: openCafeConfig})
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
		req.SetPathValue("id", device.ID.String())
		req.AddCookie(&http.Cookie{Name: authmw.CookieName, Value: tok})
		rec := httptest.NewRecorder()
		authmw.Middleware(env.Services.Auth, nil)(authmw.RequireSuperAdmin(s.handleAdminDeviceConfigWrite)).ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	t.Run("guard_passes_when_secret_info_reports_nothing_in_nvs", func(t *testing.T) {
		device, fd, _, _ := setup(t, "config/none")
		if entry := work(t, device); entry == nil || entry.Status != reqStatusDone {
			t.Fatalf("store entry = %+v, want done", entry)
		}
		if fd.Calls("secret.info") != 1 {
			t.Errorf("secret.info calls = %d, want one round trip", fd.Calls("secret.info"))
		}
	})

	t.Run("guard_refuses_when_nvs_holds_a_password", func(t *testing.T) {
		device, fd, _, _ := setup(t, "nvs")
		entry := work(t, device)
		if entry == nil || entry.Status != reqStatusError || !strings.Contains(entry.ErrorMsg, "NVS") {
			t.Fatalf("store entry = %+v, want a refusal naming NVS", entry)
		}
		if code, body := enqueue(t, device); code != http.StatusUnprocessableEntity || !strings.Contains(body, "NVS") {
			t.Errorf("enqueue = %d %q, want 422 naming NVS", code, body)
		}
		if fd.Calls("fs.write") != 0 {
			t.Error("a refused write reached the device")
		}
	})

	t.Run("guard_refuses_when_secret_info_is_uncorrelated", func(t *testing.T) {
		device, fd, _, _ := setup(t, "config/none")
		fd.OmitReqID(true, "secret.info")
		entry := work(t, device)
		if entry == nil || entry.Status != reqStatusError || !strings.Contains(entry.ErrorMsg, "secret.info") {
			t.Fatalf("store entry = %+v, want a refusal naming secret.info", entry)
		}
		if fd.Calls("fs.write") != 0 {
			t.Error("a refused write reached the device")
		}
	})

	t.Run("guard_refuses_when_secret_info_fails", func(t *testing.T) {
		device, fd, _, _ := setup(t, "config/none")
		fd.Handle("secret.info", func(string, []byte) []mqtttest.Response {
			return []mqtttest.Response{{OK: false, Output: []string{"error"}}}
		})
		if code, body := enqueue(t, device); code != http.StatusUnprocessableEntity || !strings.Contains(body, "secret.info") {
			t.Errorf("enqueue = %d %q, want 422 naming secret.info", code, body)
		}
		if fd.Calls("fs.write") != 0 {
			t.Error("a refused write reached the device")
		}
	})

	// A password stored after the open read reaches NVS by a provision, which secret.info sees.
	t.Run("a_password_provisioned_after_the_open_read_is_refused_at_write_time", func(t *testing.T) {
		device, fd, mu, state := setup(t, "config/none")
		if code, body := enqueue(t, device); code != http.StatusOK {
			t.Fatalf("enqueue = %d %q, want 200", code, body)
		}
		waitDone(t, s, device)
		mu.Lock()
		*state = "nvs"
		mu.Unlock()
		before := fd.Calls("fs.write")
		if entry := work(t, device); entry == nil || entry.Status != reqStatusError {
			t.Fatalf("store entry = %+v, want the worker refusal", entry)
		}
		if fd.Calls("fs.write") != before {
			t.Error("the worker sent a write the NVS check refused")
		}
	})
}

// waitDone waits until no write holds the device.
func waitDone(t *testing.T, s *Server, device *service.Device) {
	t.Helper()
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if _, held := s.deviceWrites.Load(device.ID); !held {
			return
		}
	}
	t.Fatal("the write never released the device")
}
