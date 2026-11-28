//go:build integration

package servicetest

import (
	"context"
	"testing"
)

// TestStart_Smoke validates the harness end to end: a container comes up, every
// migration applies, all three role pools connect, and a Services bundle is
// wired. The ingest role is on Env.MQTTRole, not Pools, since nothing routes
// through it. If this passes, per-service integration tests can rely on Start.
func TestStart_Smoke(t *testing.T) {
	env := Start(t)
	ctx := context.Background()

	for name, pool := range map[string]interface{ Ping(context.Context) error }{
		"app":   env.Pools.App,
		"admin": env.Pools.Admin,
		"mqtt":  env.MQTTRole,
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

// TestStart_FreshDatabaseEachCall: Start clones the migrated template, so rows
// from an earlier Start are gone, while the owner and the database ACL
// (migration 0001 grants CONNECT) carry over to the clone.
func TestStart_FreshDatabaseEachCall(t *testing.T) {
	ctx := context.Background()
	Start(t).SeedTenant(t, "first-start")

	env := Start(t)
	var n int
	if err := env.Super.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE id = $1`, "first-start").Scan(&n); err != nil {
		t.Fatalf("count tenants: %v", err)
	}
	if n != 0 {
		t.Errorf("first Start's tenant after a second Start = %d rows, want 0", n)
	}

	var owner string
	if err := env.Super.QueryRow(ctx,
		`SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()`).Scan(&owner); err != nil {
		t.Fatalf("read owner: %v", err)
	}
	if owner != "thesada_app" {
		t.Errorf("database owner = %q, want thesada_app", owner)
	}
	var acl, tmplACL *string
	if err := env.Super.QueryRow(ctx, `
		SELECT (SELECT datacl::text FROM pg_database WHERE datname = current_database()),
		       (SELECT datacl::text FROM pg_database WHERE datname = $1)`, tmplName).Scan(&acl, &tmplACL); err != nil {
		t.Fatalf("read database ACLs: %v", err)
	}
	if tmplACL == nil || acl == nil || *acl != *tmplACL {
		t.Errorf("database ACL = %s, want the template's %s", show(acl), show(tmplACL))
	}
}

// show prints a nullable text column.
func show(s *string) string {
	if s == nil {
		return "NULL"
	}
	return *s
}
