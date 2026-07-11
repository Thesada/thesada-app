//go:build integration

// Phase 7 integration tests: root-KEK rotation (RotateRootKEK) and the
// existing-device backfill (BackfillDeviceSecrets).
//
//	go test -tags integration -run 'TestSecretRotation|TestSecretBackfill' ./pkg/service/...
package service_test

import (
	"context"
	"strings"
	"testing"

	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/secrets"
	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

// testKEKNew is a second, distinct valid base64 32-byte KEK for rotation.
const testKEKNew = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="

func TestSecretRotation(t *testing.T) {
	env := servicetest.Start(t)
	ctx := context.Background()

	oldSvc, err := service.NewSecretService(&config.Config{DeviceConfigKEK: testKEK}, env.Pools)
	if err != nil {
		t.Fatalf("old service: %v", err)
	}

	const tenant = "rot-a"
	env.SeedTenant(t, tenant)
	pk := mustUpsert(t, env.Services.Devices, tenant, "rot-dev", "", "", "", "")
	if err := oldSvc.SetSecret(ctx, tenant, pk, "wifi.password", "rotate-me"); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}

	// Rotate the root KEK: DEK re-wrapped under the new key, ciphertext untouched.
	newKeyring, err := secrets.NewKeyring(testKEKNew)
	if err != nil {
		t.Fatalf("new keyring: %v", err)
	}
	res, err := oldSvc.RotateRootKEK(ctx, newKeyring)
	if err != nil {
		t.Fatalf("RotateRootKEK: %v", err)
	}
	if res.Rotated < 1 {
		t.Fatalf("rotated %d tenant DEKs, want >= 1", res.Rotated)
	}

	// Idempotent + tolerant: a second sweep with the old key still live
	// re-wraps nothing (every row is already under the new key) instead of
	// double-wrapping or erroring - this is what makes re-running safe and
	// closes the swap-window orphan race.
	res2, err := oldSvc.RotateRootKEK(ctx, newKeyring)
	if err != nil {
		t.Fatalf("second RotateRootKEK: %v", err)
	}
	if res2.Rotated != 0 || res2.AlreadyNew < 1 {
		t.Errorf("re-run = %+v, want Rotated=0 AlreadyNew>=1 (idempotent)", res2)
	}

	// kek_version bumped on the rotated row.
	var ver int
	if err := env.Super.QueryRow(ctx,
		`SELECT kek_version FROM tenant_dek WHERE tenant_id = $1`, tenant).Scan(&ver); err != nil {
		t.Fatalf("read kek_version: %v", err)
	}
	if ver != 2 {
		t.Errorf("kek_version = %d, want 2 after one rotation", ver)
	}

	// The NEW key decrypts the same plaintext (DEK unchanged, only re-wrapped).
	newSvc, err := service.NewSecretService(&config.Config{DeviceConfigKEK: testKEKNew}, env.Pools)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	got, found, err := newSvc.Reveal(ctx, tenant, pk, "wifi.password")
	if err != nil || !found || got != "rotate-me" {
		t.Errorf("Reveal under new KEK = %q found=%v err=%v, want rotate-me", got, found, err)
	}

	// The OLD key can no longer unwrap the re-wrapped DEK.
	if _, _, err := oldSvc.Reveal(ctx, tenant, pk, "wifi.password"); err == nil {
		t.Error("Reveal under old KEK should fail after rotation")
	}
}

func TestSecretBackfill(t *testing.T) {
	env := servicetest.Start(t)
	ctx := context.Background()

	const tenant = "bf-a"
	env.SeedTenant(t, tenant)
	pk := mustUpsert(t, env.Services.Devices, tenant, "bf-dev", "", "", "", "")

	// Seed a PLAINTEXT config.json straight into device_files via the superuser
	// pool, bypassing the Upsert blanking chokepoint - this is the pre-feature
	// state backfill exists to migrate.
	const plaintext = `{"wifi":{"ap_password":"app","networks":[` +
		`{"ssid":"home","password":"wp"},{"ssid":"barn","password":"bp"}]},` +
		`"mqtt":{"password":"mp"},"telegram":{"bot_token":"tt"},"web":{"password":"webp"}}`
	if _, err := env.Super.Exec(ctx,
		`INSERT INTO device_files (device_pk, path, content, sha256, source, updated_at)
		 VALUES ($1, 'config.json', $2, 'seed-sha', 'seed', now())`, pk, plaintext); err != nil {
		t.Fatalf("seed plaintext config: %v", err)
	}

	res, err := service.BackfillDeviceSecrets(ctx, env.Services.Secrets, env.Services.Devices, env.Services.DeviceFiles)
	if err != nil {
		t.Fatalf("BackfillDeviceSecrets: %v", err)
	}
	// 4 scalars (ap/mqtt/telegram/web) + one per wifi network (home, barn).
	if res.Secrets != 6 {
		t.Errorf("migrated %d secrets, want 6 (4 scalar + 2 per-SSID wifi)", res.Secrets)
	}
	if res.DevicesMigrated != 1 {
		t.Errorf("devices migrated = %d, want 1", res.DevicesMigrated)
	}

	// The secrets are now in the encrypted store and decrypt to the seeded values.
	for field, want := range map[string]string{
		"wifi.password:home": "wp",
		"wifi.password:barn": "bp",
		"wifi.ap_password":   "app",
		"mqtt.password":      "mp",
		"telegram.bot_token": "tt",
		"web.password":       "webp",
	} {
		got, found, err := env.Services.Secrets.Reveal(ctx, tenant, pk, field)
		if err != nil || !found || got != want {
			t.Errorf("Reveal(%q) = %q found=%v err=%v, want %q", field, got, found, err, want)
		}
	}

	// The stored config is now blanked - no plaintext left in device_files.
	snap, err := env.Services.DeviceFiles.Latest(ctx, tenant, pk, "config.json")
	if err != nil || snap == nil {
		t.Fatalf("Latest config = %v err %v", snap, err)
	}
	for _, leak := range []string{`"wp"`, `"bp"`, `"app"`, `"mp"`, `"tt"`, `"webp"`} {
		if strings.Contains(snap.Content, leak) {
			t.Errorf("blanked config still contains secret %s:\n%s", leak, snap.Content)
		}
	}
	for _, ssid := range []string{"home", "barn"} {
		if !strings.Contains(snap.Content, ssid) {
			t.Errorf("blanked config dropped the non-secret ssid %q:\n%s", ssid, snap.Content)
		}
	}

	// Idempotent: a second run finds nothing to migrate (config now blank).
	res2, err := service.BackfillDeviceSecrets(ctx, env.Services.Secrets, env.Services.Devices, env.Services.DeviceFiles)
	if err != nil {
		t.Fatalf("second backfill: %v", err)
	}
	if res2.Secrets != 0 || res2.DevicesMigrated != 0 {
		t.Errorf("second backfill migrated %d secrets / %d devices, want 0/0 (already blank)", res2.Secrets, res2.DevicesMigrated)
	}
}

// TestSecretBackfillBackstopReblank covers the finding that a config whose
// only sensitive field is caught by the backstop regex (not one of the
// allowlist ScalarSecretFields) must still be re-blanked - migrating zero secrets
// must not mean leaving plaintext behind.
func TestSecretBackfillBackstopReblank(t *testing.T) {
	env := servicetest.Start(t)
	ctx := context.Background()

	const tenant = "bf-bs"
	env.SeedTenant(t, tenant)
	pk := mustUpsert(t, env.Services.Devices, tenant, "bf-bs-dev", "", "", "", "")

	// No allowlist secret; only a backstop-caught "api_key".
	const plaintext = `{"cloud":{"api_key":"leak-me","region":"us"},"device":{"name":"x"}}`
	if _, err := env.Super.Exec(ctx,
		`INSERT INTO device_files (device_pk, path, content, sha256, source, updated_at)
		 VALUES ($1, 'config.json', $2, 'seed-sha', 'seed', now())`, pk, plaintext); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	res, err := service.BackfillDeviceSecrets(ctx, env.Services.Secrets, env.Services.Devices, env.Services.DeviceFiles)
	if err != nil {
		t.Fatalf("BackfillDeviceSecrets: %v", err)
	}
	// Nothing to migrate to the encrypted store (no allowlist field)...
	if res.Secrets != 0 {
		t.Errorf("migrated %d secrets, want 0 (backstop-only field is not in the store)", res.Secrets)
	}
	// ...but the backstop plaintext must be blanked in the stored config.
	snap, err := env.Services.DeviceFiles.Latest(ctx, tenant, pk, "config.json")
	if err != nil || snap == nil {
		t.Fatalf("Latest = %v err %v", snap, err)
	}
	if strings.Contains(snap.Content, "leak-me") {
		t.Errorf("backstop plaintext not blanked by backfill:\n%s", snap.Content)
	}
	if !strings.Contains(snap.Content, "us") {
		t.Errorf("non-secret field dropped:\n%s", snap.Content)
	}
}
