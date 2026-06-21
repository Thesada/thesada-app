//go:build integration

package servicetest

import (
	"context"
	"testing"
	"time"

	"thesada.app/app/migrations"
	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/db"
	"thesada.app/app/pkg/service"
)

// Env is a fully migrated, role-scoped test database plus a Services bundle
// wired to it. Service tests drive Services for the code under test and use
// Super (the RLS-bypassing superuser pool) to seed and assert out-of-band.
type Env struct {
	BaseURL  string   // superuser base connection URL
	Super    *db.Pool // superuser pool - bypasses RLS, used for seeding
	Pools    db.Pools // App / Admin / MQTT role-scoped pools
	Services *service.Services
	Cfg      *config.Config
}

// Start brings up a container, applies every migration, opens the three
// role-scoped pools, and builds a Services bundle against them. This is the
// entry point for DB-backed service tests.
//
// in: testing.T. out: ready *Env. All resources are released via t.Cleanup.
func Start(t *testing.T) *Env {
	t.Helper()
	ctx := context.Background()

	super, baseURL := StartPostgres(t)

	if err := migrations.Apply(ctx, super); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	// 0013 created thesada_app_admin / thesada_app_mqtt as NOLOGIN. Grant LOGIN
	// + password so the test can open pools as them, and give the app role
	// explicit table access (the superuser owns the tables it created, so once
	// RLS is on, thesada_app needs grants for non-owner access).
	if _, err := super.Exec(ctx, `
		ALTER ROLE thesada_app_admin LOGIN PASSWORD '`+rolePassword+`';
		ALTER ROLE thesada_app_mqtt  LOGIN PASSWORD '`+rolePassword+`';
		GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES    IN SCHEMA public TO thesada_app;
		GRANT USAGE,  SELECT, UPDATE         ON ALL SEQUENCES IN SCHEMA public TO thesada_app;`,
	); err != nil {
		t.Fatalf("finalize role logins + app grants: %v", err)
	}

	pools := db.Pools{}
	for _, p := range []struct {
		role string
		dst  **db.Pool
	}{
		{"thesada_app", &pools.App},
		{"thesada_app_admin", &pools.Admin},
		{"thesada_app_mqtt", &pools.MQTT},
	} {
		dsn, err := roleURL(baseURL, p.role)
		if err != nil {
			t.Fatalf("build %s URL: %v", p.role, err)
		}
		pool, err := db.Open(ctx, dsn)
		if err != nil {
			t.Fatalf("open %s pool: %v", p.role, err)
		}
		*p.dst = pool
		t.Cleanup(pool.Close)
	}

	// Minimal config: enough for service.New + the bits service methods read.
	// Extend per-test as specific methods demand more fields.
	cfg := &config.Config{
		CookieSecret:      "servicetest-cookie-secret-32-bytes-min",
		CLIRequestTimeout: 30 * time.Second,
		CADir:             t.TempDir(),
	}

	return &Env{
		BaseURL:  baseURL,
		Super:    super,
		Pools:    pools,
		Services: service.New(cfg, pools),
		Cfg:      cfg,
	}
}

// SeedTenant inserts a tenant row through the superuser pool (bypassing RLS).
// Most service fixtures start from a tenant; this keeps that one-liner.
// in: testing.T, env, tenant slug. out: none; t.Fatal on failure.
func (e *Env) SeedTenant(t *testing.T, tenantID string) {
	t.Helper()
	if _, err := e.Super.Exec(context.Background(),
		`INSERT INTO tenants (id, display_name) VALUES ($1, $2)`,
		tenantID, "servicetest "+tenantID); err != nil {
		t.Fatalf("seed tenant %q: %v", tenantID, err)
	}
}

// Truncate empties the named tables (CASCADE) via the superuser pool, for tests
// that want a clean slate between subtests without a full container restart.
// in: testing.T, env, table names. out: none; t.Fatal on failure.
func (e *Env) Truncate(t *testing.T, tables ...string) {
	t.Helper()
	for _, tbl := range tables {
		// Table names are test-controlled constants, not request input: pgx
		// cannot bind a SQL identifier as a parameter, so concatenation is the
		// only option and is safe here.
		if _, err := e.Super.Exec(context.Background(),
			`TRUNCATE TABLE `+tbl+` CASCADE`); err != nil {
			t.Fatalf("truncate %q: %v", tbl, err)
		}
	}
}
