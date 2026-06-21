//go:build integration

package servicetest

import (
	"context"
	"testing"
)

// TestStart_Smoke validates the harness end to end: a container comes up, every
// migration applies, all three role pools connect, and a Services bundle is
// wired. If this passes, per-service integration tests can rely on Start.
func TestStart_Smoke(t *testing.T) {
	env := Start(t)
	ctx := context.Background()

	for name, pool := range map[string]interface{ Ping(context.Context) error }{
		"app":   env.Pools.App,
		"admin": env.Pools.Admin,
		"mqtt":  env.Pools.MQTT,
		"super": env.Super,
	} {
		if err := pool.Ping(ctx); err != nil {
			t.Errorf("ping %s pool: %v", name, err)
		}
	}

	if env.Services == nil || env.Services.Devices == nil || env.Services.Auth == nil {
		t.Fatal("Services bundle not wired")
	}

	// Seed + read-back through the superuser pool proves migrations built the
	// schema and the fixture helper works.
	env.SeedTenant(t, "smoke-tenant")
	var n int
	if err := env.Super.QueryRow(ctx,
		`SELECT count(*) FROM tenants WHERE id = $1`, "smoke-tenant").Scan(&n); err != nil {
		t.Fatalf("read back seeded tenant: %v", err)
	}
	if n != 1 {
		t.Errorf("seeded tenant count = %d, want 1", n)
	}
}
