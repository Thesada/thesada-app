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
	"net/url"
	"testing"
	"time"

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

	container, err := postgres.Run(ctx, Image,
		postgres.WithDatabase(dbName),
		postgres.WithUsername(superUser),
		postgres.WithPassword(rolePassword),
		// Disable TimescaleDB background workers. Their cagg-refresh job
		// scheduler otherwise races migration DDL (0015 alters the oauth
		// caggs) and intermittently deadlocks on a fresh container. Schema +
		// service tests never need background refresh; prod keeps them on.
		testcontainers.WithCmd("postgres", "-c", "timescaledb.max_background_workers=0"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(90*time.Second)),
	)
	if err != nil {
		t.Fatalf("start timescaledb container: %v", err)
	}
	t.Cleanup(func() {
		// Background ctx: the test's ctx may already be cancelled at cleanup.
		_ = container.Terminate(context.Background())
	})

	baseURL, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("container connection string: %v", err)
	}

	super, err := db.Open(ctx, baseURL)
	if err != nil {
		t.Fatalf("open superuser pool: %v", err)
	}
	t.Cleanup(super.Close)

	// 0003 calls create_hypertable but never CREATE EXTENSION (prod installs it
	// out of band); the throwaway container owns its DB, so install it here.
	if _, err := super.Exec(ctx, `CREATE EXTENSION IF NOT EXISTS timescaledb`); err != nil {
		t.Fatalf("create timescaledb extension: %v", err)
	}

	// thesada_app must exist before 0013 (ALTER DEFAULT PRIVILEGES references
	// it). LOGIN so the App pool can connect; NOBYPASSRLS so RLS applies.
	if _, err := super.Exec(ctx,
		`CREATE ROLE thesada_app LOGIN NOBYPASSRLS PASSWORD '`+rolePassword+`'`); err != nil {
		t.Fatalf("provision thesada_app role: %v", err)
	}

	return super, baseURL
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
