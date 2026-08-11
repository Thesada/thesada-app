//go:build integration

// Tenant-default secret integration tests: the precedence contract (#450).
// A device resolves to its own override if it has one, otherwise to the tenant
// default, otherwise to nothing - and rotating a default must not disturb a
// device the operator has pinned.
//
//	go test -tags integration -run TestTenantSecretDefaults ./pkg/service/...
package service_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

func TestTenantSecretDefaults(t *testing.T) {
	env := servicetest.Start(t)
	dev := env.Services.Devices
	ctx := context.Background()

	sec, err := service.NewSecretService(&config.Config{DeviceConfigKEK: testKEK}, env.Pools)
	if err != nil {
		t.Fatalf("NewSecretService: %v", err)
	}

	const tA, tB = "tsec-a", "tsec-b"
	env.SeedTenant(t, tA)
	env.SeedTenant(t, tB)

	t.Run("device_with_no_override_inherits_the_default", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "tsec-inherit", "", "", "", "")
		if err := sec.SetTenantSecret(ctx, tA, "mqtt.password", "site-wide"); err != nil {
			t.Fatalf("SetTenantSecret: %v", err)
		}
		got, origin, err := sec.Resolve(ctx, tA, pk, "mqtt.password")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got != "site-wide" || origin != service.OriginTenant {
			t.Errorf("Resolve = %q/%s, want site-wide/%s", got, origin, service.OriginTenant)
		}
	})

	t.Run("override_wins_over_the_default", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "tsec-override", "", "", "", "")
		if err := sec.SetTenantSecret(ctx, tA, "telegram.bot_token", "tenant-token"); err != nil {
			t.Fatalf("SetTenantSecret: %v", err)
		}
		if err := sec.SetSecret(ctx, tA, pk, "telegram.bot_token", "device-token"); err != nil {
			t.Fatalf("SetSecret: %v", err)
		}
		got, origin, err := sec.Resolve(ctx, tA, pk, "telegram.bot_token")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got != "device-token" || origin != service.OriginOverride {
			t.Errorf("Resolve = %q/%s, want device-token/%s", got, origin, service.OriginOverride)
		}
	})

	// The acceptance criterion that matters most: rotating a tenant default is
	// how an operator changes a site password, and it must not silently
	// re-point a device that was deliberately pinned to its own value.
	t.Run("override_survives_a_default_rotation", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "tsec-survives", "", "", "", "")
		if err := sec.SetTenantSecret(ctx, tA, "web.password", "old-default"); err != nil {
			t.Fatalf("SetTenantSecret 1: %v", err)
		}
		if err := sec.SetSecret(ctx, tA, pk, "web.password", "pinned"); err != nil {
			t.Fatalf("SetSecret: %v", err)
		}
		if err := sec.SetTenantSecret(ctx, tA, "web.password", "new-default"); err != nil {
			t.Fatalf("SetTenantSecret 2: %v", err)
		}
		got, origin, err := sec.Resolve(ctx, tA, pk, "web.password")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got != "pinned" || origin != service.OriginOverride {
			t.Errorf("Resolve = %q/%s, want pinned/%s", got, origin, service.OriginOverride)
		}
	})

	t.Run("clearing_an_override_falls_back_to_the_default", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "tsec-clear", "", "", "", "")
		if err := sec.SetTenantSecret(ctx, tA, "wifi.ap_password", "default-ap"); err != nil {
			t.Fatalf("SetTenantSecret: %v", err)
		}
		if err := sec.SetSecret(ctx, tA, pk, "wifi.ap_password", "device-ap"); err != nil {
			t.Fatalf("SetSecret: %v", err)
		}
		deleted, err := sec.ClearDeviceSecret(ctx, tA, pk, "wifi.ap_password")
		if err != nil || !deleted {
			t.Fatalf("ClearDeviceSecret = %v, %v; want true, nil", deleted, err)
		}
		got, origin, err := sec.Resolve(ctx, tA, pk, "wifi.ap_password")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got != "default-ap" || origin != service.OriginTenant {
			t.Errorf("Resolve = %q/%s, want default-ap/%s", got, origin, service.OriginTenant)
		}
		// Clearing again is a no-op, not an error: the operator's intent is
		// "no override here" either way.
		deleted, err = sec.ClearDeviceSecret(ctx, tA, pk, "wifi.ap_password")
		if err != nil {
			t.Fatalf("ClearDeviceSecret twice: %v", err)
		}
		if deleted {
			t.Error("second ClearDeviceSecret reported a delete, want false")
		}
	})

	t.Run("no_default_and_no_override_resolves_to_unset", func(t *testing.T) {
		pk := mustUpsert(t, dev, tB, "tsec-none", "", "", "", "")
		got, origin, err := sec.Resolve(ctx, tB, pk, "mqtt.password")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got != "" || origin != service.OriginUnset {
			t.Errorf("Resolve = %q/%s, want \"\"/%s", got, origin, service.OriginUnset)
		}
	})

	// RLS plus the AAD both bind a default to its tenant; neither may leak.
	t.Run("a_default_does_not_cross_tenants", func(t *testing.T) {
		pk := mustUpsert(t, dev, tB, "tsec-isolation", "", "", "", "")
		if err := sec.SetTenantSecret(ctx, tA, "telegram.bot_token", "tenant-a-only"); err != nil {
			t.Fatalf("SetTenantSecret: %v", err)
		}
		got, origin, err := sec.Resolve(ctx, tB, pk, "telegram.bot_token")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got != "" || origin != service.OriginUnset {
			t.Errorf("tenant B resolved %q/%s from tenant A's default", got, origin)
		}
	})

	t.Run("clearing_a_default_leaves_overrides_alone", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "tsec-clear-default", "", "", "", "")
		if err := sec.SetTenantSecret(ctx, tA, "mqtt.password", "doomed"); err != nil {
			t.Fatalf("SetTenantSecret: %v", err)
		}
		if err := sec.SetSecret(ctx, tA, pk, "mqtt.password", "kept"); err != nil {
			t.Fatalf("SetSecret: %v", err)
		}
		deleted, err := sec.ClearTenantSecret(ctx, tA, "mqtt.password")
		if err != nil || !deleted {
			t.Fatalf("ClearTenantSecret = %v, %v; want true, nil", deleted, err)
		}
		got, origin, err := sec.Resolve(ctx, tA, pk, "mqtt.password")
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got != "kept" || origin != service.OriginOverride {
			t.Errorf("Resolve = %q/%s, want kept/%s", got, origin, service.OriginOverride)
		}
	})

	// Own tenant: the three origins have to be observed against a known-empty
	// starting state, and tA has accumulated defaults from the subtests above.
	t.Run("OriginStatus_reports_override_inherited_and_unset", func(t *testing.T) {
		const tO = "tsec-origins-tenant"
		env.SeedTenant(t, tO)
		pk := mustUpsert(t, dev, tO, "tsec-origins", "", "", "", "")
		if err := sec.SetTenantSecret(ctx, tO, "web.password", "inherited-value"); err != nil {
			t.Fatalf("SetTenantSecret web: %v", err)
		}
		if err := sec.SetTenantSecret(ctx, tO, "wifi.ap_password", "inherited-ap"); err != nil {
			t.Fatalf("SetTenantSecret ap: %v", err)
		}
		if err := sec.SetSecret(ctx, tO, pk, "wifi.ap_password", "own-ap"); err != nil {
			t.Fatalf("SetSecret: %v", err)
		}
		origins, err := sec.OriginStatus(ctx, tO, pk)
		if err != nil {
			t.Fatalf("OriginStatus: %v", err)
		}
		if got := origins["wifi.ap_password"]; got != service.OriginOverride {
			t.Errorf("wifi.ap_password origin = %s, want %s", got, service.OriginOverride)
		}
		if got := origins["web.password"]; got != service.OriginTenant {
			t.Errorf("web.password origin = %s, want %s", got, service.OriginTenant)
		}
		if got := origins["telegram.bot_token"]; got != service.OriginUnset {
			t.Errorf("telegram.bot_token origin = %s, want %s", got, service.OriginUnset)
		}
	})

	// A default's ciphertext is bound to (tenant, "tenant-default", field). A
	// device row's is bound to (tenant, device_pk, field). Neither AAD may open
	// the other's blob, so a DB-write attacker cannot promote a device secret
	// to a tenant default or vice versa.
	t.Run("tenant_and_device_ciphertexts_are_not_interchangeable", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "tsec-aad", "", "", "", "")
		if err := sec.SetTenantSecret(ctx, tA, "web.password", "the-default"); err != nil {
			t.Fatalf("SetTenantSecret: %v", err)
		}
		// Relocate the default's ciphertext onto the device row.
		var blob []byte
		if err := env.Super.QueryRow(ctx,
			`SELECT ciphertext FROM device_config_secrets
			  WHERE tenant_id = $1 AND device_pk IS NULL AND field = 'web.password'`,
			tA).Scan(&blob); err != nil {
			t.Fatalf("read default ciphertext: %v", err)
		}
		if _, err := env.Super.Exec(ctx,
			`INSERT INTO device_config_secrets (tenant_id, device_pk, field, ciphertext)
			 VALUES ($1, $2, 'web.password', $3)`, tA, pk, blob); err != nil {
			t.Fatalf("plant relocated ciphertext: %v", err)
		}
		if _, _, err := sec.Resolve(ctx, tA, pk, "web.password"); err == nil {
			t.Error("Resolve accepted a tenant-default ciphertext on a device row, want decrypt failure")
		}
	})

	t.Run("ProvisionTargets_lists_paired_non_overridden_devices_only", func(t *testing.T) {
		const tP = "tsec-targets"
		env.SeedTenant(t, tP)
		inherits := mustUpsert(t, dev, tP, "tsec-t-inherits", "", "", "", "")
		overrides := mustUpsert(t, dev, tP, "tsec-t-overrides", "", "", "", "")
		unpaired := mustUpsert(t, dev, tP, "tsec-t-unpaired", "", "", "", "")

		if err := sec.SetTenantSecret(ctx, tP, "mqtt.password", "fan-out-me"); err != nil {
			t.Fatalf("SetTenantSecret: %v", err)
		}
		if err := sec.SetSecret(ctx, tP, overrides, "mqtt.password", "pinned"); err != nil {
			t.Fatalf("SetSecret: %v", err)
		}
		// Only the first two are paired; the third has no NVS to write.
		if _, err := env.Super.Exec(ctx,
			`UPDATE devices SET paired_at = now() WHERE id = ANY($1)`,
			[]uuid.UUID{inherits, overrides}); err != nil {
			t.Fatalf("mark paired: %v", err)
		}

		targets, err := sec.ProvisionTargets(ctx, tP, "mqtt.password")
		if err != nil {
			t.Fatalf("ProvisionTargets: %v", err)
		}
		if len(targets) != 1 || targets[0] != inherits {
			t.Fatalf("ProvisionTargets = %v, want exactly [%v]", targets, inherits)
		}
		for _, id := range targets {
			if id == overrides {
				t.Error("an overridden device must not be a fan-out target")
			}
			if id == unpaired {
				t.Error("an unpaired device must not be a fan-out target")
			}
		}
	})

	t.Run("feature_off_rejects_tenant_writes_but_allows_status", func(t *testing.T) {
		off, err := service.NewSecretService(&config.Config{}, env.Pools)
		if err != nil {
			t.Fatalf("NewSecretService(off): %v", err)
		}
		if err := off.SetTenantSecret(ctx, tA, "mqtt.password", "nope"); err == nil {
			t.Error("SetTenantSecret with the feature off should fail")
		}
		if _, err := off.TenantStatus(ctx, tA); err != nil {
			t.Errorf("TenantStatus with the feature off: %v", err)
		}
		// Deletes stay available with the feature off, deliberately: a
		// deployment that has lost its KEK can still drop rows it can no longer
		// decrypt. The UI hides the buttons; the service does not block them.
		const tOff = "tsec-feature-off"
		env.SeedTenant(t, tOff)
		if err := sec.SetTenantSecret(ctx, tOff, "web.password", "doomed"); err != nil {
			t.Fatalf("SetTenantSecret: %v", err)
		}
		deleted, err := off.ClearTenantSecret(ctx, tOff, "web.password")
		if err != nil || !deleted {
			t.Errorf("ClearTenantSecret with the feature off = %v, %v; want true, nil", deleted, err)
		}
	})

	// The legacy bare key has no SSID, so provisioning would append the
	// DEVICE's primary SSID and land on wifi.password:<ssid> - the same NVS key
	// a per-SSID override writes. A tenant default must never be able to
	// collide with an override that way.
	t.Run("tenant_default_rejects_the_legacy_bare_wifi_key", func(t *testing.T) {
		err := sec.SetTenantSecret(ctx, tA, service.LegacyWifiPassword, "site-wifi")
		if err == nil {
			t.Fatal("SetTenantSecret accepted the bare wifi.password, want rejection")
		}
		// The per-SSID form is the supported way to set a tenant WiFi default.
		if err := sec.SetTenantSecret(ctx, tA, service.WifiSecretField("SiteNet"), "site-wifi"); err != nil {
			t.Errorf("SetTenantSecret(wifi.password:SiteNet): %v", err)
		}
	})

	// A pre-per-SSID device row provisions onto wifi.password:<primary SSID>,
	// so a per-SSID tenant default aimed at the same NVS key must treat that
	// device as already pinned. Otherwise the fan-out drops the device off its
	// network, which is the loudest possible failure for a vacuum.
	t.Run("legacy_device_row_counts_as_an_override_for_a_per_SSID_default", func(t *testing.T) {
		const tL = "tsec-legacy"
		env.SeedTenant(t, tL)
		legacy := mustUpsert(t, dev, tL, "tsec-l-legacy", "", "", "", "")
		plain := mustUpsert(t, dev, tL, "tsec-l-plain", "", "", "", "")
		if err := sec.SetSecret(ctx, tL, legacy, service.LegacyWifiPassword, "pinned-wifi"); err != nil {
			t.Fatalf("SetSecret legacy: %v", err)
		}
		if err := sec.SetTenantSecret(ctx, tL, service.WifiSecretField("SiteNet"), "site-wifi"); err != nil {
			t.Fatalf("SetTenantSecret: %v", err)
		}
		if _, err := env.Super.Exec(ctx,
			`UPDATE devices SET paired_at = now() WHERE id = ANY($1)`,
			[]uuid.UUID{legacy, plain}); err != nil {
			t.Fatalf("mark paired: %v", err)
		}
		targets, err := sec.ProvisionTargets(ctx, tL, service.WifiSecretField("SiteNet"))
		if err != nil {
			t.Fatalf("ProvisionTargets: %v", err)
		}
		for _, id := range targets {
			if id == legacy {
				t.Error("a device pinned via the legacy bare wifi.password must not be a per-SSID fan-out target")
			}
		}
		if len(targets) != 1 || targets[0] != plain {
			t.Errorf("targets = %v, want exactly [%v]", targets, plain)
		}
		counts, err := sec.ProvisionTargetCounts(ctx, tL)
		if err != nil {
			t.Fatalf("ProvisionTargetCounts: %v", err)
		}
		if got := counts[service.WifiSecretField("SiteNet")]; got != len(targets) {
			t.Errorf("count = %d, ProvisionTargets = %d; the page must not under-report the blast radius",
				got, len(targets))
		}
	})

	// A bare tenant-default row cannot be created any more, but one may exist
	// from an older build or direct SQL. It must stay inert rather than being
	// remapped onto a device's primary SSID at provision time.
	t.Run("a_planted_bare_tenant_default_is_never_inherited", func(t *testing.T) {
		const tP2 = "tsec-planted"
		env.SeedTenant(t, tP2)
		pk := mustUpsert(t, dev, tP2, "tsec-p-dev", "", "", "", "")
		// Plant it the only way it can now exist: raw SQL past the service.
		if err := sec.SetTenantSecret(ctx, tP2, "web.password", "seed-the-dek"); err != nil {
			t.Fatalf("SetTenantSecret: %v", err)
		}
		var blob []byte
		if err := env.Super.QueryRow(ctx,
			`SELECT ciphertext FROM device_config_secrets
			  WHERE tenant_id = $1 AND device_pk IS NULL AND field = 'web.password'`,
			tP2).Scan(&blob); err != nil {
			t.Fatalf("read ciphertext: %v", err)
		}
		if _, err := env.Super.Exec(ctx,
			`INSERT INTO device_config_secrets (tenant_id, device_pk, field, ciphertext)
			 VALUES ($1, NULL, $2, $3)`, tP2, service.LegacyWifiPassword, blob); err != nil {
			t.Fatalf("plant bare tenant default: %v", err)
		}
		got, origin, err := sec.Resolve(ctx, tP2, pk, service.LegacyWifiPassword)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if origin != service.OriginUnset {
			t.Errorf("Resolve = %q/%s, want unset - a bare tenant default must not be inherited", got, origin)
		}
	})

	t.Run("ProvisionTargetCounts_matches_ProvisionTargets", func(t *testing.T) {
		const tC = "tsec-counts"
		env.SeedTenant(t, tC)
		a := mustUpsert(t, dev, tC, "tsec-c-a", "", "", "", "")
		b := mustUpsert(t, dev, tC, "tsec-c-b", "", "", "", "")
		if err := sec.SetTenantSecret(ctx, tC, "mqtt.password", "shared"); err != nil {
			t.Fatalf("SetTenantSecret: %v", err)
		}
		if err := sec.SetSecret(ctx, tC, b, "mqtt.password", "pinned"); err != nil {
			t.Fatalf("SetSecret: %v", err)
		}
		if _, err := env.Super.Exec(ctx,
			`UPDATE devices SET paired_at = now() WHERE id = ANY($1)`,
			[]uuid.UUID{a, b}); err != nil {
			t.Fatalf("mark paired: %v", err)
		}
		targets, err := sec.ProvisionTargets(ctx, tC, "mqtt.password")
		if err != nil {
			t.Fatalf("ProvisionTargets: %v", err)
		}
		counts, err := sec.ProvisionTargetCounts(ctx, tC)
		if err != nil {
			t.Fatalf("ProvisionTargetCounts: %v", err)
		}
		if counts["mqtt.password"] != len(targets) {
			t.Errorf("count = %d, ProvisionTargets = %d; the page and the sweep must agree",
				counts["mqtt.password"], len(targets))
		}
		if counts["mqtt.password"] != 1 {
			t.Errorf("count = %d, want 1 (only the non-overridden paired device)", counts["mqtt.password"])
		}
	})
}
