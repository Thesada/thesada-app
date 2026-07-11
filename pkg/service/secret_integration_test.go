//go:build integration

// SecretService integration tests. Envelope round-trip
// through the real DB: per-tenant DEK create + wrap, secret encrypt + upsert,
// server-side decrypt, write-only Status, and RLS tenant isolation. Also the
// feature-off gate and the malformed-KEK boot failure.
//
//	go test -tags integration -run TestSecretService ./pkg/service/...
package service_test

import (
	"context"
	"errors"
	"testing"

	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

// testKEK is a deterministic, valid base64 32-byte root KEK for the enabled
// service. Test-only material, never a real deployment key.
const testKEK = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

func TestSecretService(t *testing.T) {
	env := servicetest.Start(t)
	dev := env.Services.Devices
	ctx := context.Background()

	// The bundle's SecretService is feature-off (env cfg has no KEK); build an
	// enabled one on the same pools for the crypto paths.
	sec, err := service.NewSecretService(&config.Config{DeviceConfigKEK: testKEK}, env.Pools)
	if err != nil {
		t.Fatalf("NewSecretService: %v", err)
	}
	if !sec.Enabled() {
		t.Fatal("service with a valid KEK should be Enabled")
	}

	const tA, tB = "sec-a", "sec-b"
	env.SeedTenant(t, tA)
	env.SeedTenant(t, tB)

	t.Run("Set_Reveal_roundtrip", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "sec-dev-1", "", "", "", "")
		if err := sec.SetSecret(ctx, tA, pk, "wifi.password", "hunter2"); err != nil {
			t.Fatalf("SetSecret: %v", err)
		}
		got, found, err := sec.Reveal(ctx, tA, pk, "wifi.password")
		if err != nil || !found {
			t.Fatalf("Reveal = %q found=%v err=%v, want value", got, found, err)
		}
		if got != "hunter2" {
			t.Errorf("Reveal = %q, want hunter2", got)
		}
	})

	t.Run("Set_overwrites", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "sec-dev-ovw", "", "", "", "")
		if err := sec.SetSecret(ctx, tA, pk, "mqtt.password", "first"); err != nil {
			t.Fatalf("SetSecret 1: %v", err)
		}
		if err := sec.SetSecret(ctx, tA, pk, "mqtt.password", "second"); err != nil {
			t.Fatalf("SetSecret 2: %v", err)
		}
		got, _, err := sec.Reveal(ctx, tA, pk, "mqtt.password")
		if err != nil {
			t.Fatalf("Reveal: %v", err)
		}
		if got != "second" {
			t.Errorf("Reveal after overwrite = %q, want second", got)
		}
	})

	t.Run("Status_is_write_only", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "sec-dev-st", "", "", "", "")
		if err := sec.SetSecret(ctx, tA, pk, "telegram.bot_token", "tok"); err != nil {
			t.Fatalf("SetSecret: %v", err)
		}
		st, err := sec.Status(ctx, tA, pk)
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		// Only a scalar is set, so Status is exactly the scalar set (no wifi rows).
		if len(st) != len(service.ScalarSecretFields) {
			t.Fatalf("Status has %d fields, want %d", len(st), len(service.ScalarSecretFields))
		}
		if !st["telegram.bot_token"] {
			t.Error("telegram.bot_token should be set")
		}
		if st["wifi.ap_password"] || st["web.password"] {
			t.Error("unset fields should be false")
		}
	})

	t.Run("PerSSID_wifi_passwords_coexist", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "sec-dev-multi", "", "", "", "")
		// Two networks stored under distinct per-SSID keys (migration 0024
		// relaxed the field CHECK to accept wifi.password:<ssid>).
		if err := sec.SetSecret(ctx, tA, pk, "wifi.password:HomeNet", "home-pw"); err != nil {
			t.Fatalf("SetSecret HomeNet: %v", err)
		}
		if err := sec.SetSecret(ctx, tA, pk, "wifi.password:Barn", "barn-pw"); err != nil {
			t.Fatalf("SetSecret Barn: %v", err)
		}
		for field, want := range map[string]string{
			"wifi.password:HomeNet": "home-pw",
			"wifi.password:Barn":    "barn-pw",
		} {
			got, found, err := sec.Reveal(ctx, tA, pk, field)
			if err != nil || !found || got != want {
				t.Errorf("Reveal(%q) = %q found=%v err=%v, want %q", field, got, found, err, want)
			}
		}
		// Both show as set in Status, alongside the 4 scalars.
		st, err := sec.Status(ctx, tA, pk)
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		if !st["wifi.password:HomeNet"] || !st["wifi.password:Barn"] {
			t.Errorf("Status missing a per-SSID wifi row: %v", st)
		}
		if len(st) != len(service.ScalarSecretFields)+2 {
			t.Errorf("Status has %d fields, want %d (scalars + 2 wifi)", len(st), len(service.ScalarSecretFields)+2)
		}
	})

	t.Run("Reveal_unset_field", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "sec-dev-unset", "", "", "", "")
		got, found, err := sec.Reveal(ctx, tA, pk, "wifi.ap_password")
		if err != nil {
			t.Fatalf("Reveal: %v", err)
		}
		if found || got != "" {
			t.Errorf("Reveal unset = %q found=%v, want \"\" false", got, found)
		}
	})

	t.Run("unknown_field_rejected", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "sec-dev-bad", "", "", "", "")
		if err := sec.SetSecret(ctx, tA, pk, "not.a.field", "x"); err == nil {
			t.Error("SetSecret with unknown field should error")
		}
	})

	t.Run("RLS_tenant_isolation", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "sec-iso", "", "", "", "")
		if err := sec.SetSecret(ctx, tA, pk, "web.password", "a-secret"); err != nil {
			t.Fatalf("SetSecret: %v", err)
		}
		// Tenant B cannot see or decrypt tenant A's secret by the same pk.
		st, err := sec.Status(ctx, tB, pk)
		if err != nil {
			t.Fatalf("cross-tenant Status: %v", err)
		}
		if st["web.password"] {
			t.Error("tenant B sees tenant A's web.password status")
		}
		if got, found, err := sec.Reveal(ctx, tB, pk, "web.password"); err != nil || found || got != "" {
			t.Errorf("cross-tenant Reveal = %q found=%v err=%v, want \"\" false", got, found, err)
		}
	})

	t.Run("EnsureTenantDEK_idempotent", func(t *testing.T) {
		const tE = "sec-dek"
		env.SeedTenant(t, tE)
		if err := sec.EnsureTenantDEK(ctx, tE); err != nil {
			t.Fatalf("EnsureTenantDEK 1: %v", err)
		}
		if err := sec.EnsureTenantDEK(ctx, tE); err != nil {
			t.Fatalf("EnsureTenantDEK 2: %v", err)
		}
		var n int
		if err := env.Super.QueryRow(ctx,
			`SELECT count(*) FROM tenant_dek WHERE tenant_id = $1`, tE).Scan(&n); err != nil {
			t.Fatalf("count DEK rows: %v", err)
		}
		if n != 1 {
			t.Errorf("tenant_dek rows = %d, want exactly 1", n)
		}
	})

	t.Run("feature_off_gate", func(t *testing.T) {
		off, err := service.NewSecretService(&config.Config{DeviceConfigKEK: ""}, env.Pools)
		if err != nil {
			t.Fatalf("NewSecretService empty KEK: %v", err)
		}
		if off.Enabled() {
			t.Error("empty KEK should leave the feature off")
		}
		pk := mustUpsert(t, dev, tA, "sec-off", "", "", "", "")
		if err := off.SetSecret(ctx, tA, pk, "wifi.password", "x"); !errors.Is(err, service.ErrSecretsDisabled) {
			t.Errorf("SetSecret off = %v, want ErrSecretsDisabled", err)
		}
		if _, _, err := off.Reveal(ctx, tA, pk, "wifi.password"); !errors.Is(err, service.ErrSecretsDisabled) {
			t.Errorf("Reveal off = %v, want ErrSecretsDisabled", err)
		}
		// Status still works with the feature off (pure existence read).
		if _, err := off.Status(ctx, tA, pk); err != nil {
			t.Errorf("Status off = %v, want nil", err)
		}
	})

	t.Run("malformed_KEK_fails_construction", func(t *testing.T) {
		if _, err := service.NewSecretService(&config.Config{DeviceConfigKEK: "not-base64!!"}, env.Pools); err == nil {
			t.Error("malformed KEK should fail NewSecretService")
		}
		if _, err := service.NewSecretService(&config.Config{DeviceConfigKEK: "c2hvcnQ="}, env.Pools); err == nil {
			t.Error("wrong-length KEK should fail NewSecretService")
		}
	})
}
