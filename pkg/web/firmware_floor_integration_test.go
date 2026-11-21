//go:build integration

// A staged write or a tenant rule push to firmware below 1.4.5, or of unknown version, is refused
// before anything reaches the device. 1.4.5 passes.
//
//	go test -tags integration -run TestFirmwareFloor ./pkg/web/...
package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/mqtt/mqtttest"
	"thesada.app/app/pkg/rulesgen"
	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

func TestFirmwareFloor(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)
	s.rulePushes = newRequestStore[*rulePushResult](time.Minute, t.Context().Done())
	ctx := context.Background()

	const tenant = "fw-floor"
	env.SeedTenant(t, tenant)
	admin, err := env.Services.Auth.CreateUser(tenant, "root@fwfloor.test", "Root", true)
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

	var ws struct {
		WorkspaceJSON string `json:"workspace_json"`
	}
	_ = json.Unmarshal(tenantRulesJSON(t, testRuleFields()), &ws)
	rules, err := rulesgen.Parse(ws.WorkspaceJSON)
	if err != nil {
		t.Fatal(err)
	}
	lua := rulesgen.Generate(rules)

	device := func(t *testing.T, id, fw string) (*service.Device, *mqtttest.FakeDevice) {
		t.Helper()
		prefix := "thesada/" + tenant + "/" + id
		pk, err := env.Services.Devices.Upsert(tenant, id, "", fw, "", prefix)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := env.Services.RuleWorkspaces.Save(ctx, tenant, pk, service.DefaultRuleSlot,
			ws.WorkspaceJSON, lua, tenantRuleSource, &admin.ID); err != nil {
			t.Fatal(err)
		}
		d, err := env.Services.Devices.GetByIDAny(ctx, pk)
		if err != nil || d == nil {
			t.Fatalf("device: %v", err)
		}
		fd := mqtttest.NewFakeDevice(t, broker, prefix)
		serveDeviceFS(fd, map[string]string{})
		fd.Handle("lua.reload", func(string, []byte) []mqtttest.Response { return mqtttest.OK("Lua reloaded") })
		return d, fd
	}
	serve := func(d *service.Device, h http.HandlerFunc, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
		req.SetPathValue("id", d.ID.String())
		req.AddCookie(&http.Cookie{Name: authmw.CookieName, Value: tok})
		rec := httptest.NewRecorder()
		authmw.Middleware(env.Services.Auth, nil)(h).ServeHTTP(rec, req)
		return rec
	}
	write := func(d *service.Device) *httptest.ResponseRecorder {
		body, _ := json.Marshal(cliWriteRequest{Path: "/scripts/x.lua", Content: "-- x"})
		return serve(d, authmw.RequireSuperAdmin(s.handleAdminDeviceConfigWrite), body)
	}
	push := func(d *service.Device) *httptest.ResponseRecorder {
		return serve(d, s.handleDeviceRulesPush, []byte("{}"))
	}
	sent := func(fd *mqtttest.FakeDevice) int {
		n := 0
		for _, c := range []string{"fs.write", "fs.append", "fs.cat", "fs.mv", "fs.rm", "lua.reload"} {
			n += fd.Calls(c)
		}
		return n
	}

	for _, fw := range []string{"1.4.4", ""} {
		t.Run("refused_before_dispatch_on_"+map[string]string{"1.4.4": "1.4.4", "": "unknown"}[fw], func(t *testing.T) {
			d, fd := device(t, "old"+strings.ReplaceAll(fw, ".", ""), fw)
			// Push first: its claim would refuse the write anyway, the write's gate runs before the claim.
			for _, c := range []struct {
				name string
				send func(*service.Device) *httptest.ResponseRecorder
			}{{"push", push}, {"write", write}} {
				if rec := c.send(d); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), service.MinFirmwareVersion) {
					t.Errorf("%s = %d %q, want 409 naming firmware %s", c.name, rec.Code, rec.Body.String(), service.MinFirmwareVersion)
				}
			}
			time.Sleep(500 * time.Millisecond)
			if n := sent(fd); n != 0 {
				t.Errorf("%d commands reached a device below the floor", n)
			}
		})
	}

	t.Run("the_floor_passes", func(t *testing.T) {
		d, fd := device(t, "floor", service.MinFirmwareVersion)
		rec := write(d)
		var enq cliEnqueueResponse
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &enq) != nil {
			t.Fatalf("write = %d %q, want 200", rec.Code, rec.Body.String())
		}
		id, err := uuid.Parse(enq.RequestID)
		if err != nil {
			t.Fatal(err)
		}
		waitUntil(t, "the write", func() bool {
			e := s.cliRequests.get(id)
			return e != nil && e.Status != reqStatusPending
		})
		if e := s.cliRequests.get(id); e.Status != reqStatusDone || fd.Calls("fs.mv") == 0 {
			t.Fatalf("write ended %s %q, want done with a rename", e.Status, e.ErrorMsg)
		}
		if rec := push(d); rec.Code != http.StatusOK {
			t.Fatalf("push = %d %q, want 200", rec.Code, rec.Body.String())
		}
		waitUntil(t, "the push's lua.reload", func() bool { return fd.Calls("lua.reload") > 0 })
	})
}

// waitUntil polls fn for up to 30 s.
func waitUntil(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
