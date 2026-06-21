//go:build integration

// SettingsService integration tests. Read-through bool
// cache: SetBool write+cache, GetBool fallback, Refresh from DB, and per-tenant
// cache-key isolation.
//
//	go test -tags integration -run TestSettingsService ./pkg/service/...
package service_test

import (
	"context"
	"testing"

	"thesada.app/app/pkg/service/servicetest"
)

func TestSettingsService(t *testing.T) {
	env := servicetest.Start(t)
	set := env.Services.Settings
	ctx := context.Background()

	const tA, tB = "set-a", "set-b"
	env.SeedTenant(t, tA)
	env.SeedTenant(t, tB)

	t.Run("SetBool_then_GetBool_and_fallback", func(t *testing.T) {
		// Unset key returns the fallback.
		if v := set.GetBool(tA, "feature_x", true); v != true {
			t.Errorf("unset key = %v, want fallback true", v)
		}
		if err := set.SetBool(tA, "feature_x", false); err != nil {
			t.Fatalf("SetBool: %v", err)
		}
		// SetBool primes the cache, so GetBool sees it without a Refresh.
		if v := set.GetBool(tA, "feature_x", true); v != false {
			t.Errorf("after SetBool false, GetBool = %v, want false", v)
		}
	})

	t.Run("GetBool_is_tenant_scoped", func(t *testing.T) {
		if err := set.SetBool(tA, "scoped_flag", true); err != nil {
			t.Fatalf("SetBool: %v", err)
		}
		// Tenant B has no such row -> its own fallback, never tenant A's value.
		if v := set.GetBool(tB, "scoped_flag", false); v != false {
			t.Errorf("tenant B GetBool = %v, want fallback false (no cross-tenant read)", v)
		}
	})

	t.Run("Refresh_loads_from_db", func(t *testing.T) {
		// Write straight to the table (bypassing SetBool's cache update) so the
		// value is only visible after a Refresh.
		if _, err := env.Super.Exec(ctx,
			`INSERT INTO settings (tenant_id, key, value) VALUES ($1, $2, 'true'::jsonb)`,
			tA, "refreshed_flag"); err != nil {
			t.Fatalf("seed setting: %v", err)
		}
		if v := set.GetBool(tA, "refreshed_flag", false); v != false {
			t.Error("GetBool saw the row before Refresh - unexpected cache hit")
		}
		if err := set.Refresh(); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		if v := set.GetBool(tA, "refreshed_flag", false); v != true {
			t.Errorf("after Refresh = %v, want true", v)
		}
	})
}
