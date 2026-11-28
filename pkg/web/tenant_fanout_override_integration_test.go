//go:build integration

// A tenant default fan-out re-checks each device's override before the push, so a device overridden
// after the target list was read is skipped. No row lock is held across the push, and a value written
// during it is sent after it. Each device has its own budget, so one stuck on its row lock is skipped alone.
//
//	go test -tags integration -run 'TestTenantFanOut' ./pkg/web/...
package web

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/mqtt/mqtttest"
	"thesada.app/app/pkg/service/servicetest"
)

// syncBuffer is a log sink the MQTT goroutines can write while the test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestTenantFanOutDeviceBudget(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)
	ctx := context.Background()

	prevBudget := fanOutPerDeviceBudget
	fanOutPerDeviceBudget = 2 * time.Second
	t.Cleanup(func() { fanOutPerDeviceBudget = prevBudget })
	var logs syncBuffer
	prevLog := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prevLog) })

	const tenant = "fanout-budget"
	const field = "wifi.password:site"
	env.SeedTenant(t, tenant)
	if err := env.Services.Secrets.SetTenantSecret(ctx, tenant, field, "default"); err != nil {
		t.Fatal(err)
	}
	ids := []string{"stuck", "b", "c"}
	fds := make([]*mqtttest.FakeDevice, 0, len(ids))
	pks := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		prefix := "thesada/" + tenant + "/" + id
		d := seedDevice(t, env, tenant, id, prefix)
		if _, err := env.Super.Exec(ctx, `UPDATE devices SET paired_at = now() WHERE id = $1`, d.ID); err != nil {
			t.Fatal(err)
		}
		fd := mqtttest.NewFakeDevice(t, broker, prefix)
		fd.Handle("secret.set", func(string, []byte) []mqtttest.Response { return mqtttest.OK("stored") })
		fds, pks = append(fds, fd), append(pks, d.ID)
	}
	// The stuck device is first in the target order, the other two after it.
	if _, err := env.Super.Exec(ctx, `UPDATE devices SET last_seen_at = now() WHERE id = $1`, pks[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := env.Super.Exec(ctx, `UPDATE devices SET last_seen_at = NULL WHERE id = ANY($1)`, pks[1:]); err != nil {
		t.Fatal(err)
	}
	if got, err := env.Services.Secrets.ProvisionTargets(ctx, tenant, field); err != nil || len(got) != 3 || got[0] != pks[0] {
		t.Fatalf("ProvisionTargets = %v, %v, want 3 targets with the stuck device first", got, err)
	}
	holder, err := env.Super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = holder.Rollback(context.Background()) })
	if _, err := holder.Exec(ctx, `SELECT 1 FROM devices WHERE id = $1 FOR UPDATE`, pks[0]); err != nil {
		t.Fatal(err)
	}

	admin, err := env.Services.Auth.CreateUser(tenant, "root@budget.test", "Root", false)
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
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(url.Values{"field": {field}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("slug", tenant)
	req.AddCookie(&http.Cookie{Name: authmw.CookieName, Value: tok})
	rec := httptest.NewRecorder()
	authmw.Middleware(env.Services.Auth, nil)(authmw.RequireSuperAdmin(s.handleAdminTenantSecretsProvision)).ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}

	if n := fds[0].Calls("secret.set"); n != 0 {
		t.Errorf("stuck device secret.set calls = %d, want 0", n)
	}
	for i, fd := range fds[1:] {
		if n := fd.Calls("secret.set"); n != 1 {
			t.Errorf("device %d secret.set calls = %d, want 1 after the stuck one timed out", i+1, n)
		}
	}
	row := lastAudit(t, env, "tenant_secret.provision")
	if row.detail["pushed"] != float64(2) || row.detail["skipped"] != float64(1) {
		t.Errorf("audit detail = %v, want pushed 2, skipped 1", row.detail)
	}
	out := logs.String()
	if !strings.Contains(out, "tenant_secret.fanout_lookup_failed") || !strings.Contains(out, pks[0].String()) {
		t.Errorf("log lacks the skip of the stuck device:\n%s", out)
	}
	if strings.Contains(out, "tenant_secret.fanout_truncated") {
		t.Errorf("one stuck device truncated the sweep:\n%s", out)
	}
}

func TestTenantFanOutOverride(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)
	ctx := context.Background()

	const tenant = "fanout-ovr"
	const field = "wifi.password:site"
	env.SeedTenant(t, tenant)
	if err := env.Services.Secrets.SetTenantSecret(ctx, tenant, field, "default"); err != nil {
		t.Fatal(err)
	}
	device := func(id string) (uuid.UUID, *mqtttest.FakeDevice) {
		t.Helper()
		prefix := "thesada/" + tenant + "/" + id
		d := seedDevice(t, env, tenant, id, prefix)
		if _, err := env.Super.Exec(ctx, `UPDATE devices SET paired_at = now() WHERE id = $1`, d.ID); err != nil {
			t.Fatal(err)
		}
		return d.ID, mqtttest.NewFakeDevice(t, broker, prefix)
	}
	targets := func(want uuid.UUID) []uuid.UUID {
		t.Helper()
		got, err := env.Services.Secrets.ProvisionTargets(ctx, tenant, field)
		if err != nil {
			t.Fatal(err)
		}
		for _, pk := range got {
			if pk == want {
				return []uuid.UUID{pk}
			}
		}
		t.Fatalf("ProvisionTargets = %v, want %s listed", got, want)
		return nil
	}

	t.Run("an_override_after_the_target_list_is_skipped", func(t *testing.T) {
		pk, fd := device("ovr1")
		fd.Handle("secret.set", func(string, []byte) []mqtttest.Response { return mqtttest.OK("stored") })
		list := targets(pk)
		if err := env.Services.Secrets.SetSecret(ctx, tenant, pk, field, "own"); err != nil {
			t.Fatal(err)
		}
		out := s.fanOutTenantSecret(ctx, tenant, field, "default", list)
		if out.Pushed != 0 || out.Unreachable != 0 || out.Rejected != 0 || out.Skipped != 0 {
			t.Errorf("fan-out = %+v, want the overridden device in no push bucket", out)
		}
		if n := fd.Calls("secret.set"); n != 0 {
			t.Errorf("secret.set calls = %d, want the default kept off an overridden device", n)
		}
	})

	// blockedPush records each secret.set value. The first call runs write while the push is blocked.
	blockedPush := func(t *testing.T, fd *mqtttest.FakeDevice, write func() error) (func() []string, *atomic.Bool) {
		var mu sync.Mutex
		var sent []string
		var during atomic.Bool
		fd.Handle("secret.set", func(_ string, raw []byte) []mqtttest.Response {
			_, v, _ := strings.Cut(string(raw), "\n")
			mu.Lock()
			sent = append(sent, v)
			first := len(sent) == 1
			mu.Unlock()
			if first {
				done := make(chan error, 1)
				go func() { done <- write() }()
				select {
				case err := <-done:
					if err != nil {
						t.Errorf("write during the push: %v", err)
					}
					during.Store(true)
				case <-time.After(5 * time.Second):
				}
			}
			return mqtttest.OK("stored")
		})
		return func() []string {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), sent...)
		}, &during
	}

	t.Run("an_override_write_completes_during_a_running_push", func(t *testing.T) {
		pk, fd := device("ovr2")
		list := targets(pk)
		sent, during := blockedPush(t, fd, func() error {
			return env.Services.Secrets.SetSecret(ctx, tenant, pk, field, "own")
		})
		out := s.fanOutTenantSecret(ctx, tenant, field, "default", list)
		if !during.Load() {
			t.Fatal("the override write waited for the push: the device row stayed locked across it")
		}
		if got := sent(); len(got) != 2 || got[0] != "default" || got[1] != "own" {
			t.Errorf("secret.set values = %q, want default, then the override sent after it", got)
		}
		if out.Overridden != 1 || out.Pushed != 0 || out.Unreachable != 0 || out.Rejected != 0 || out.Skipped != 0 {
			t.Errorf("fan-out = %+v, want the device counted overridden", out)
		}
		if v, _, err := env.Services.Secrets.Reveal(ctx, tenant, pk, field); err != nil || v != "own" {
			t.Errorf("override = %q, %v, want own kept after the push", v, err)
		}
	})

	t.Run("a_newer_default_during_a_running_push_is_sent_after_it", func(t *testing.T) {
		pk, fd := device("ovr3")
		list := targets(pk)
		t.Cleanup(func() { _ = env.Services.Secrets.SetTenantSecret(ctx, tenant, field, "default") })
		sent, during := blockedPush(t, fd, func() error {
			return env.Services.Secrets.SetTenantSecret(ctx, tenant, field, "newer")
		})
		out := s.fanOutTenantSecret(ctx, tenant, field, "default", list)
		if !during.Load() {
			t.Fatal("the default write waited for the push")
		}
		if got := sent(); len(got) != 2 || got[0] != "default" || got[1] != "newer" {
			t.Errorf("secret.set values = %q, want default, then the newer default sent after it", got)
		}
		if out.Pushed != 1 || out.Overridden != 0 {
			t.Errorf("fan-out = %+v, want the device pushed", out)
		}
	})
}
