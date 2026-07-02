//go:build integration

// Write-only secrets UI POST path against a real DB: the handler encrypts and
// stores the submitted value (round-trips through the encrypted store) and
// rejects empty / unknown fields. The GET render is chrome and stays covered
// by template-parse; this is the security-relevant write path.
//
//	go test -tags integration -run TestAdminDeviceSecretsSet ./pkg/web/...
package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"thesada.app/app/pkg/service/servicetest"
)

func TestAdminDeviceSecretsSet_Integration(t *testing.T) {
	env := servicetest.Start(t) // harness runs feature-ON (DeviceConfigKEK set)
	s := &Server{services: env.Services, cfg: env.Cfg}
	ctx := context.Background()

	const tenant = "sec-ui"
	env.SeedTenant(t, tenant)
	pk, err := env.Services.Devices.Upsert(tenant, "sec-ui-dev", "", "", "", "")
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}

	t.Run("stores the secret and redirects ok", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := postFormPath(http.MethodPost, "id", pk.String(), "field=mqtt.password&value=hunter2")
		s.handleAdminDeviceSecretsSet(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", rec.Code)
		}
		if loc := rec.Header().Get("Location"); !strings.Contains(loc, "ok=set") {
			t.Errorf("Location = %q, want ok=set", loc)
		}
		// Persisted and decrypts back to exactly what was submitted.
		got, found, err := env.Services.Secrets.Reveal(ctx, tenant, pk, "mqtt.password")
		if err != nil || !found || got != "hunter2" {
			t.Errorf("Reveal = %q found=%v err=%v, want hunter2", got, found, err)
		}
		if st, _ := env.Services.Secrets.Status(ctx, tenant, pk); !st["mqtt.password"] {
			t.Error("Status should show mqtt.password set")
		}
	})

	t.Run("overwrite replaces the stored value", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := postFormPath(http.MethodPost, "id", pk.String(), "field=mqtt.password&value=second")
		s.handleAdminDeviceSecretsSet(rec, req)
		if got, _, _ := env.Services.Secrets.Reveal(ctx, tenant, pk, "mqtt.password"); got != "second" {
			t.Errorf("Reveal after overwrite = %q, want second", got)
		}
	})

	t.Run("empty value is rejected, nothing stored", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := postFormPath(http.MethodPost, "id", pk.String(), "field=web.password&value=")
		s.handleAdminDeviceSecretsSet(rec, req)
		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", rec.Code)
		}
		if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=") {
			t.Errorf("Location = %q, want error=", loc)
		}
		if _, found, _ := env.Services.Secrets.Reveal(ctx, tenant, pk, "web.password"); found {
			t.Error("web.password must not be stored after an empty submit")
		}
	})

	t.Run("unknown field is rejected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := postFormPath(http.MethodPost, "id", pk.String(), "field=not.a.field&value=x")
		s.handleAdminDeviceSecretsSet(rec, req)
		if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=") {
			t.Errorf("unknown-field Location = %q, want error=", loc)
		}
	})
}
