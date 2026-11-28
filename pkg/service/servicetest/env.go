//go:build integration

package servicetest

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	"thesada.app/app/migrations"
	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/db"
	"thesada.app/app/pkg/service"
)

// Env is a fully migrated, role-scoped test database plus a Services bundle
// wired to it. Service tests drive Services for the code under test and use
// Super (the RLS-bypassing superuser pool) to seed and assert out-of-band.
type Env struct {
	BaseURL string   // superuser base connection URL
	Super   *db.Pool // superuser pool - bypasses RLS, used for seeding
	Pools   db.Pools // App / Admin role-scoped pools
	// MQTTRole is the ingest role's pool. Not part of Pools because ingest is
	// not routed through it; kept so its grants stay covered.
	MQTTRole *db.Pool
	Services *service.Services
	Cfg      *config.Config
}

// tmplName holds the migrated schema each Start clones into dbName.
const tmplName = "thesada_tmpl"

// shared is one migrated container per test binary. Ryuk reaps it on exit.
// Without Ryuk each Start runs its own, which its cleanup terminates.
var shared struct {
	once    sync.Once
	baseURL string
	err     error
}

// migrateTemplate brings up a container with start, migrates dbName as the
// production migrate role, finalizes the role logins and grants, then turns
// dbName into the template. Same steps Start ran per test before.
// in: testing.T (for logs), start. out: base URL, error.
func migrateTemplate(t *testing.T, start func() (string, error)) (string, error) {
	ctx := context.Background()
	baseURL, err := startRetry(t, start)
	if err != nil {
		return "", fmt.Errorf("start timescaledb container: %w", err)
	}
	super, err := db.Open(ctx, baseURL)
	if err != nil {
		return "", fmt.Errorf("open superuser pool: %w", err)
	}
	defer super.Close()
	if err := provision(ctx, super); err != nil {
		return "", err
	}
	if err := bootstrapProdRoles(ctx, super); err != nil {
		return "", err
	}
	migrator, err := openAs(ctx, baseURL, "thesada_app")
	if err != nil {
		return "", err
	}
	err = migrations.Apply(ctx, migrator)
	migrator.Close()
	if err != nil {
		return "", fmt.Errorf("apply migrations as thesada_app: %w", err)
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
		return "", fmt.Errorf("finalize role logins + app grants: %w", err)
	}
	super.Close()

	admin, err := openDB(ctx, baseURL, "postgres")
	if err != nil {
		return "", err
	}
	defer admin.Close()
	if _, err := admin.Exec(ctx, `ALTER DATABASE `+dbName+` RENAME TO `+tmplName); err != nil {
		return "", fmt.Errorf("make template: %w", err)
	}
	return baseURL, nil
}

// cloneTemplate replaces dbName with a fresh copy of the template, with the
// template's owner and database ACL (0001 grants CONNECT on dbName).
// in: context, base URL. out: error.
func cloneTemplate(ctx context.Context, baseURL string) error {
	admin, err := openDB(ctx, baseURL, "postgres")
	if err != nil {
		return err
	}
	defer admin.Close()
	for _, q := range []string{
		`DROP DATABASE IF EXISTS ` + dbName + ` WITH (FORCE)`,
		`CREATE DATABASE ` + dbName + ` TEMPLATE ` + tmplName + ` OWNER thesada_app`,
		`UPDATE pg_database SET datacl = (SELECT datacl FROM pg_database WHERE datname = '` + tmplName + `') WHERE datname = '` + dbName + `'`,
	} {
		if _, err := admin.Exec(ctx, q); err != nil {
			return fmt.Errorf("clone template: %w", err)
		}
	}
	return nil
}

// sharedOrOwn is the binary's shared migrated container, or one for t alone when
// Ryuk is disabled. in: testing.T. out: base URL, error.
func sharedOrOwn(t *testing.T) (string, error) {
	if testcontainers.ReadConfig().Config.RyukDisabled {
		return migrateTemplate(t, func() (string, error) { return startOnce(t, postgres.Run) })
	}
	shared.once.Do(func() {
		shared.baseURL, shared.err = migrateTemplate(t, func() (string, error) { return startOnce(nil, postgres.Run) })
	})
	return shared.baseURL, shared.err
}

// Start gives the test a fully migrated database, opens the three role-scoped
// pools, and builds a Services bundle against them. The container and the
// migrations run once per test binary, once per Start without Ryuk. Each Start
// gets a fresh copy of the migrated database under the same name. Tests using
// Start must not run in parallel with each other.
//
// in: testing.T. out: ready *Env. All resources are released via t.Cleanup.
func Start(t *testing.T) *Env {
	t.Helper()
	ctx := context.Background()

	baseURL, err := sharedOrOwn(t)
	if err != nil {
		t.Fatalf("timescaledb: %v", err)
	}
	if err := cloneTemplate(ctx, baseURL); err != nil {
		t.Fatal(err)
	}
	super, err := db.Open(ctx, baseURL)
	if err != nil {
		t.Fatalf("open superuser pool: %v", err)
	}
	t.Cleanup(super.Close)

	// Opened but not wired into Pools: proves the ingest role exists and can
	// log in with its grants intact, which is what routing will need.
	var mqttPool *db.Pool
	pools := db.Pools{}
	for _, p := range []struct {
		role string
		dst  **db.Pool
	}{
		{"thesada_app", &pools.App},
		{"thesada_app_admin", &pools.Admin},
		{"thesada_app_mqtt", &mqttPool},
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
	//
	// DeviceConfigKEK is set so the harness models the feature-ON steady state
	// (device-config secrets enabled): TenantService.Create then provisions a
	// per-tenant DEK, and SecretService round-trips. It is a deterministic
	// test-only base64 32-byte key, never a real deployment key.
	cfg := &config.Config{
		CookieSecret:      "servicetest-cookie-secret-32-bytes-min",
		CLIRequestTimeout: 30 * time.Second,
		CADir:             t.TempDir(),
		DeviceConfigKEK:   "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		WebAuthnRPID:      PasskeyRPID,
		WebAuthnOrigins:   []string{PasskeyOrigin},
	}

	services, err := service.New(cfg, pools)
	if err != nil {
		t.Fatalf("build services: %v", err)
	}

	return &Env{
		BaseURL:  baseURL,
		Super:    super,
		Pools:    pools,
		MQTTRole: mqttPool,
		Services: services,
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

// The relying party the test config uses, for webauthntest authenticators.
const (
	PasskeyRPID   = "app.thesada.test"
	PasskeyOrigin = "https://app.thesada.test"
)
