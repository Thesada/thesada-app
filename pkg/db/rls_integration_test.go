//go:build integration

// rls_integration_test.go - RLS acceptance test.
//
// Proves the RLS policies in 0016_rls_policies.sql actually isolate
// tenants. This is the first DB-backed test in the repo, so it is fenced
// behind the `integration` build tag: `make test` / the default CI lane
// never compile it. Run it explicitly:
//
//	THESADA_TEST_DATABASE_URL='postgres://postgres:pw@127.0.0.1:5432/thesada_app?sslmode=disable' \
//	    go test -tags integration -run TestRLS ./pkg/db/...
//
// Preconditions on the target database:
//   - It is DISPOSABLE. The test creates roles and seeds rows.
//   - It is named `thesada_app` - migration 0013 does
//     `GRANT CONNECT ON DATABASE thesada_app`, which fails on any other name.
//   - The connecting user is a superuser (CREATE ROLE / CREATE EXTENSION)
//     and is NOT one of the thesada_app* roles (so seeding bypasses RLS).
//   - TimescaleDB is available - migration 0003 builds a hypertable. The
//     test skips cleanly if the extension is absent.
//
// What it checks (the session-doc step-3 acceptance criteria):
//   - tenant-A on the App pool sees only tenant-A rows; tenant-B is 0 rows.
//   - the fixed magic_link_tokens policy (transitive via user_id) isolates.
//   - the new deleted_device_tombstones policy (direct) isolates.
//   - the MQTT pool (NOBYPASSRLS) is gated identically to App.
//   - the Admin pool (BYPASSRLS, via WithAdminAudit) sees every tenant.

package db_test

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"thesada.app/app/migrations"
	"thesada.app/app/pkg/db"
)

// rolePassword is shared by all three thesada_app* roles for the test run.
// The target DB is disposable, so a fixed literal is fine and keeps URL
// rewriting trivial.
const rolePassword = "rlstest"

// tenantA / tenantB are the two isolation subjects. Both satisfy the
// tenants.id slug constraint (^[a-z0-9-]{3,32}$) and avoid the reserved
// list from migration 0004.
const (
	tenantA = "rlstest-a"
	tenantB = "rlstest-b"
)

// rlsPools holds the role-scoped pools the acceptance test drives, plus
// the superuser pool used for setup + seeding (it bypasses RLS).
type rlsPools struct {
	super *pgxpool.Pool
	app   *pgxpool.Pool
	admin *pgxpool.Pool
	mqtt  *pgxpool.Pool
}

// roleURL rewrites a base connection URL to authenticate as the given
// role with rolePassword, leaving host/db/options untouched.
// in:  base URL string, role name. out: rewritten URL string, error.
func roleURL(base, role string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	u.User = url.UserPassword(role, rolePassword)
	return u.String(), nil
}

// setupRLSDatabase brings a disposable database to the state phase 3
// expects: all three roles present + able to log in, every migration
// applied with the RLS gate ON, and the app role granted table access.
// It then opens one pool per role.
//
// in:  testing.T, superuser connection URL.
// out: rlsPools; t.Fatal on any setup failure, t.Skip when a precondition
//      (db name, TimescaleDB) is not met.
func setupRLSDatabase(t *testing.T, baseURL string) *rlsPools {
	t.Helper()
	ctx := context.Background()

	u, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse THESADA_TEST_DATABASE_URL: %v", err)
	}
	if u.Path != "/thesada_app" {
		t.Skipf("test DB must be named thesada_app (0013 grants CONNECT on it); got %q", u.Path)
	}

	super, err := db.Open(ctx, baseURL)
	if err != nil {
		t.Fatalf("open superuser pool: %v", err)
	}

	// Skip rather than fail when TimescaleDB is missing - migration 0003
	// needs create_hypertable and there is nothing the test can do about
	// a cluster without the extension.
	var hasTimescale bool
	if err := super.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'timescaledb')`,
	).Scan(&hasTimescale); err != nil {
		t.Fatalf("probe for timescaledb: %v", err)
	}
	if !hasTimescale {
		super.Close()
		t.Skip("TimescaleDB not available on the test cluster; migration 0003 cannot run")
	}

	// Migration 0003 calls create_hypertable but never CREATE EXTENSION -
	// production deploy automation installs the extension out of band.
	// The test owns its throwaway DB, so it installs it here.
	if _, err := super.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS timescaledb`); err != nil {
		super.Close()
		t.Fatalf("create timescaledb extension: %v", err)
	}

	// thesada_app must exist before migration 0013 (it references the role
	// in ALTER DEFAULT PRIVILEGES). Create it idempotently with LOGIN so
	// the App pool can connect; NOBYPASSRLS so RLS actually applies.
	if _, err := super.Exec(ctx, `
		DO $$
		BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'thesada_app') THEN
				CREATE ROLE thesada_app LOGIN NOBYPASSRLS PASSWORD '`+rolePassword+`';
			ELSE
				ALTER ROLE thesada_app LOGIN NOBYPASSRLS PASSWORD '`+rolePassword+`';
			END IF;
		END $$;`); err != nil {
		t.Fatalf("provision thesada_app role: %v", err)
	}

	// 0016 is ungated - it applies unconditionally.
	if err := migrations.Apply(ctx, super); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}

	// 0013 created thesada_app_admin / thesada_app_mqtt as NOLOGIN. Grant
	// LOGIN + password so the test can open pools as them, and give the
	// app role table access (the superuser owns the tables it created, so
	// thesada_app needs explicit grants once RLS removes owner-implicit
	// access).
	if _, err := super.Exec(ctx, `
		ALTER ROLE thesada_app_admin LOGIN PASSWORD '`+rolePassword+`';
		ALTER ROLE thesada_app_mqtt  LOGIN PASSWORD '`+rolePassword+`';
		GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES    IN SCHEMA public TO thesada_app;
		GRANT USAGE,  SELECT, UPDATE         ON ALL SEQUENCES IN SCHEMA public TO thesada_app;`,
	); err != nil {
		t.Fatalf("finalize role logins + app grants: %v", err)
	}

	pools := &rlsPools{super: super}
	for _, p := range []struct {
		name string
		role string
		dst  **pgxpool.Pool
	}{
		{"app", "thesada_app", &pools.app},
		{"admin", "thesada_app_admin", &pools.admin},
		{"mqtt", "thesada_app_mqtt", &pools.mqtt},
	} {
		dsn, err := roleURL(baseURL, p.role)
		if err != nil {
			t.Fatalf("build %s URL: %v", p.name, err)
		}
		pool, err := db.Open(ctx, dsn)
		if err != nil {
			t.Fatalf("open %s pool: %v", p.name, err)
		}
		*p.dst = pool
	}

	t.Cleanup(func() {
		pools.app.Close()
		pools.admin.Close()
		pools.mqtt.Close()
		pools.super.Close()
	})
	return pools
}

// seedTenants wipes any leftover test rows then inserts one tenant, user,
// device, magic-link token and tombstone for each of tenant A and B.
// All writes go through the superuser pool, which bypasses RLS.
//
// in: testing.T, rlsPools. out: none; t.Fatal on failure.
func seedTenants(t *testing.T, p *rlsPools) {
	t.Helper()
	ctx := context.Background()

	cleanup := func() {
		// tenants cascade to users/devices/magic_link_tokens via FKs;
		// deleted_device_tombstones.tenant_id is a plain column (no FK),
		// so it is cleared explicitly.
		_, _ = p.super.Exec(ctx,
			`DELETE FROM deleted_device_tombstones WHERE tenant_id = ANY($1)`,
			[]string{tenantA, tenantB})
		_, _ = p.super.Exec(ctx,
			`DELETE FROM tenants WHERE id = ANY($1)`, []string{tenantA, tenantB})
	}
	cleanup()
	t.Cleanup(cleanup)

	for i, tid := range []string{tenantA, tenantB} {
		// One INSERT chain per tenant. device_id / token bytes are made
		// unique per tenant so a leaked cross-tenant row is unambiguous.
		batch := &pgx.Batch{}
		batch.Queue(
			`INSERT INTO tenants (id, display_name) VALUES ($1, $2)`,
			tid, "RLS test "+tid)
		batch.Queue(
			`INSERT INTO users (tenant_id, email) VALUES ($1, $2)`,
			tid, "user@"+tid+".test")
		batch.Queue(
			`INSERT INTO devices (tenant_id, device_id) VALUES ($1, $2)`,
			tid, "dev-"+tid)
		batch.Queue(
			`INSERT INTO magic_link_tokens (user_id, token_hash, expires_at)
			 SELECT id, $2, $3 FROM users WHERE tenant_id = $1`,
			tid, []byte{byte(i), 't', 'o', 'k'}, time.Now().Add(time.Hour))
		batch.Queue(
			`INSERT INTO deleted_device_tombstones (tenant_id, device_id, topic_prefix)
			 VALUES ($1, $2, $3)`,
			tid, "gone-"+tid, "thesada/"+tid+"/gone")
		br := p.super.SendBatch(ctx, batch)
		for q := 0; q < batch.Len(); q++ {
			if _, err := br.Exec(); err != nil {
				_ = br.Close()
				t.Fatalf("seed %s (statement %d): %v", tid, q, err)
			}
		}
		if err := br.Close(); err != nil {
			t.Fatalf("seed %s close: %v", tid, err)
		}
	}
}

// countInTenant runs a COUNT(*) for the given table inside a WithTenant
// transaction on the supplied pool, so RLS sees app.tenant_id.
// in: ctx, pool, tenant id, table name. out: row count, error.
func countInTenant(ctx context.Context, pool *pgxpool.Pool, tenant, table string) (int, error) {
	var n int
	err := db.WithTenant(ctx, pool, tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&n)
	})
	return n, err
}

// TestRLSTenantIsolation is the RLS acceptance test. Each subtest
// asserts one isolation property; a failure here means a tenant could read
// another tenant's rows once the gate is flipped in production.
func TestRLSTenantIsolation(t *testing.T) {
	baseURL := os.Getenv("THESADA_TEST_DATABASE_URL")
	if baseURL == "" {
		t.Skip("THESADA_TEST_DATABASE_URL not set; see file header for setup")
	}
	ctx := context.Background()
	p := setupRLSDatabase(t, baseURL)
	seedTenants(t, p)

	// Every tenant-scoped table seeded with exactly one row per tenant.
	// Under RLS the App pool must see its own row and nothing else.
	scoped := []string{"devices", "magic_link_tokens", "deleted_device_tombstones"}

	t.Run("app_pool_sees_only_own_tenant", func(t *testing.T) {
		for _, table := range scoped {
			for _, tid := range []string{tenantA, tenantB} {
				n, err := countInTenant(ctx, p.app, tid, table)
				if err != nil {
					t.Fatalf("count %s as %s: %v", table, tid, err)
				}
				if n != 1 {
					t.Errorf("%s as %s: got %d rows, want 1 (own tenant only)", table, tid, n)
				}
			}
		}
	})

	t.Run("app_pool_cannot_see_other_tenant_device", func(t *testing.T) {
		// Direct cross-tenant probe: ask tenant-A's session for tenant-B's
		// device_id by value. RLS must return zero rows.
		err := db.WithTenant(ctx, p.app, tenantA, func(tx pgx.Tx) error {
			var n int
			if err := tx.QueryRow(ctx,
				`SELECT count(*) FROM devices WHERE device_id = $1`,
				"dev-"+tenantB).Scan(&n); err != nil {
				return err
			}
			if n != 0 {
				t.Errorf("tenant-A saw %d tenant-B devices, want 0", n)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("cross-tenant probe: %v", err)
		}
	})

	t.Run("mqtt_pool_is_rls_gated", func(t *testing.T) {
		// The MQTT ingest role is NOBYPASSRLS, so it must be scoped
		// identically to App. It only has SELECT on devices.
		n, err := countInTenant(ctx, p.mqtt, tenantA, "devices")
		if err != nil {
			t.Fatalf("mqtt count devices as tenant-A: %v", err)
		}
		if n != 1 {
			t.Errorf("mqtt pool tenant-A: got %d devices, want 1", n)
		}
	})

	t.Run("admin_pool_sees_all_tenants", func(t *testing.T) {
		// WithAdminAudit runs on the BYPASSRLS role; it must see both
		// seeded tenants' rows in every scoped table.
		for _, table := range scoped {
			var n int
			err := db.WithAdminAudit(ctx, p.admin, "rls phase3 acceptance", func(tx pgx.Tx) error {
				return tx.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&n)
			})
			if err != nil {
				t.Fatalf("admin count %s: %v", table, err)
			}
			if n < 2 {
				t.Errorf("admin pool %s: got %d rows, want >= 2 (both tenants)", table, n)
			}
		}
	})
}
