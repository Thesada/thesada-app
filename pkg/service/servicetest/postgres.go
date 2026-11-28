//go:build integration

// Package servicetest spins a throwaway TimescaleDB in a container and brings
// it to the state the app expects (extension + roles + migrations), so DB-backed
// service tests run with one helper call and no external setup.
//
// Everything here is fenced behind the `integration` build tag: `make test` and
// the default CI lane never compile it. Run the integration lane explicitly:
//
//	go test -tags integration ./...
//
// Requires a reachable Docker daemon (testcontainers talks to it directly). The
// image matches prod - timescale/timescaledb:2.27.1-pg17 - so SQL-shape and
// extension behaviour line up with what deploys.
package servicetest

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"thesada.app/app/pkg/db"
)

// Image is the TimescaleDB tag the test container runs. Kept in lockstep with
// the production database image so tests exercise the prod engine.
const Image = "timescale/timescaledb:2.27.1-pg17"

// dbName must be `thesada_app`: migration 0013 does `GRANT CONNECT ON DATABASE
// thesada_app`, which fails under any other name.
const dbName = "thesada_app"

// superUser is the bootstrap superuser. It is NOT one of the thesada_app* roles,
// so writes through its pool bypass RLS - exactly what seeding needs.
const superUser = "postgres"

// rolePassword is shared by the superuser and all three thesada_app* roles. The
// container is disposable, so a fixed literal keeps URL rewriting trivial.
const rolePassword = "svctest"

// startupBudget bounds the whole wait: initdb, the entrypoint restart, the port.
const startupBudget = 90 * time.Second

// startAttempts caps the fresh containers one StartPostgres call may try.
const startAttempts = 3

// waitReady waits for the final server's ready line, then for 5432 to be mapped
// and listening. The log match alone also passes a container that already exited.
func waitReady() testcontainers.CustomizeRequestOption {
	return testcontainers.WithWaitStrategyAndDeadline(startupBudget,
		wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(startupBudget),
		wait.ForListeningPort("5432/tcp").WithStartupTimeout(startupBudget),
	)
}

// startRetry calls start up to startAttempts times and logs each failure.
// in: testing.TB, start func. out: the first base URL that came up, or the last error.
func startRetry(t testing.TB, start func() (string, error)) (string, error) {
	t.Helper()
	var err error
	for i := 1; i <= startAttempts; i++ {
		var baseURL string
		if baseURL, err = start(); err == nil {
			return baseURL, nil
		}
		t.Logf("timescaledb start attempt %d/%d: %v", i, startAttempts, err)
	}
	return "", err
}

// runFunc has postgres.Run's shape, so a test can hand startOnce a broken container.
type runFunc func(context.Context, string, ...testcontainers.ContainerCustomizer) (*postgres.PostgresContainer, error)

// startFn is the single start StartPostgres retries. Tests swap it.
var startFn = func(t *testing.T) (string, error) { return startOnce(t, postgres.Run) }

// startOnce runs one container and reads its URL, terminating it on any error.
// in: testing.T or nil, run func. out: base URL, error. With a t it registers
// cleanup on success. Without one the container lives until Ryuk reaps it.
func startOnce(t *testing.T, run runFunc) (string, error) {
	ctx := context.Background()
	ctr, err := run(ctx, Image,
		postgres.WithDatabase(dbName),
		postgres.WithUsername(superUser),
		postgres.WithPassword(rolePassword),
		// Disable TimescaleDB background workers. Their cagg-refresh job
		// scheduler otherwise races migration DDL (0015 alters the oauth
		// caggs) and intermittently deadlocks on a fresh container. Schema +
		// service tests never need background refresh. Prod keeps them on.
		testcontainers.WithCmd("postgres", "-c", "timescaledb.max_background_workers=0",
			"-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off"),
		// Throwaway data, so no durability: the data dir lives in memory.
		testcontainers.WithTmpfs(map[string]string{"/var/lib/postgresql/data": "rw"}),
		waitReady(),
	)
	if err == nil {
		var baseURL string
		if baseURL, err = ctr.ConnectionString(ctx, "sslmode=disable"); err == nil {
			err = holdReaper(ctx, ctr)
		}
		if err == nil {
			// Background ctx: the test's ctx may already be cancelled at cleanup.
			if t != nil {
				t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })
			}
			return baseURL, nil
		}
	}
	_ = testcontainers.TerminateContainer(ctr)
	return "", err
}

// StartPostgres launches a fresh TimescaleDB container and returns a superuser
// pool plus its base connection URL. The container has the timescaledb
// extension installed and the `thesada_app` LOGIN/NOBYPASSRLS role created (both
// preconditions for migrations.Apply: 0003 needs the extension, 0013 references
// the role). It does NOT apply migrations - callers that want the full schema
// use Start; the migration round-trip test applies them itself.
//
// in: testing.T. out: superuser *db.Pool, base URL string. Registers cleanup
// that closes the pool and terminates the container.
func StartPostgres(t *testing.T) (*db.Pool, string) {
	t.Helper()
	ctx := context.Background()

	baseURL, err := startRetry(t, func() (string, error) { return startFn(t) })
	if err != nil {
		t.Fatalf("start timescaledb container: %v", err)
	}

	super, err := db.Open(ctx, baseURL)
	if err != nil {
		t.Fatalf("open superuser pool: %v", err)
	}
	t.Cleanup(super.Close)

	if err := provision(ctx, super); err != nil {
		t.Fatal(err)
	}
	return super, baseURL
}

// provision installs the extension and the thesada_app role on a fresh container.
// in: context, superuser pool. out: error.
func provision(ctx context.Context, super *db.Pool) error {
	// 0003 calls create_hypertable but never CREATE EXTENSION (prod installs it
	// out of band); the throwaway container owns its DB, so install it here.
	if _, err := super.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS timescaledb`); err != nil {
		return fmt.Errorf("create timescaledb extension: %w", err)
	}

	// thesada_app must exist before 0013 (ALTER DEFAULT PRIVILEGES references
	// it). LOGIN so the App pool can connect; NOBYPASSRLS so RLS applies.
	if _, err := super.Exec(ctx,
		`CREATE ROLE thesada_app LOGIN NOBYPASSRLS PASSWORD '`+rolePassword+`'`); err != nil {
		return fmt.Errorf("provision thesada_app role: %w", err)
	}
	return nil
}

// BootstrapProdRoles gives the container the production role shape, mirroring
// infrastructure playbooks/templates/thesada-app-db-bootstrap.sql.j2:
// thesada_app owns the database and schema, is NOSUPERUSER NOBYPASSRLS, and is
// a member of the BYPASSRLS thesada_app_admin. Migrating as thesada_app then
// meets FORCE RLS the way the production migrate run does.
// in: testing.T, superuser pool. out: none.
func BootstrapProdRoles(t *testing.T, super *db.Pool) {
	t.Helper()
	if err := bootstrapProdRoles(context.Background(), super); err != nil {
		t.Fatal(err)
	}
}

// bootstrapProdRoles is BootstrapProdRoles without the testing.T.
// in: context, superuser pool. out: error.
func bootstrapProdRoles(ctx context.Context, super *db.Pool) error {
	if _, err := super.Exec(ctx, `
		CREATE ROLE thesada_app_admin LOGIN NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD '`+rolePassword+`';
		CREATE ROLE thesada_app_mqtt  LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD '`+rolePassword+`';
		ALTER ROLE thesada_app NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
		ALTER DATABASE `+dbName+` OWNER TO thesada_app;
		ALTER SCHEMA public OWNER TO thesada_app;
		GRANT ALL ON SCHEMA public TO thesada_app;
		GRANT thesada_app_admin TO thesada_app;
		GRANT USAGE, CREATE ON SCHEMA public TO thesada_app_admin;
		DO $$ BEGIN
		  IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = '_timescaledb_internal') THEN
		    GRANT USAGE, CREATE ON SCHEMA _timescaledb_internal TO thesada_app_admin;
		  END IF;
		END $$;`); err != nil {
		return fmt.Errorf("bootstrap production roles: %w", err)
	}
	return nil
}

// openAs opens a pool authenticated as role. The caller closes it.
// in: context, base URL, role. out: pool, error.
func openAs(ctx context.Context, baseURL, role string) (*db.Pool, error) {
	dsn, err := roleURL(baseURL, role)
	if err != nil {
		return nil, fmt.Errorf("build %s URL: %w", role, err)
	}
	pool, err := db.Open(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s pool: %w", role, err)
	}
	return pool, nil
}

// openDB opens a superuser pool on another database of the same server.
// in: context, base URL, database name. out: pool, error. The caller closes it.
func openDB(ctx context.Context, baseURL, name string) (*db.Pool, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	u.Path = "/" + name
	pool, err := db.Open(ctx, u.String())
	if err != nil {
		return nil, fmt.Errorf("open %s pool: %w", name, err)
	}
	return pool, nil
}

// OpenAs opens a pool authenticated as role, closed via t.Cleanup.
// in: testing.T, base URL, role. out: pool.
func OpenAs(t *testing.T, baseURL, role string) *db.Pool {
	t.Helper()
	dsn, err := roleURL(baseURL, role)
	if err != nil {
		t.Fatalf("build %s URL: %v", role, err)
	}
	pool, err := db.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open %s pool: %v", role, err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// OpenAsTraced is OpenAs with a pgx query tracer, for tests that count statements.
// in: testing.T, base URL, role, tracer. out: pool, closed on cleanup.
func OpenAsTraced(t *testing.T, baseURL, role string, tracer pgx.QueryTracer) *db.Pool {
	t.Helper()
	dsn, err := roleURL(baseURL, role)
	if err != nil {
		t.Fatalf("build %s URL: %v", role, err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse %s URL: %v", role, err)
	}
	cfg.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open traced %s pool: %v", role, err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// roleURL rewrites a base connection URL to authenticate as the given role with
// rolePassword, leaving host/db/options untouched.
// in: base URL, role name. out: rewritten URL, error.
func roleURL(base, role string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	u.User = url.UserPassword(role, rolePassword)
	return u.String(), nil
}
