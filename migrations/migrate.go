// Package migrations owns the schema-migration runner for thesada-app.
//
// Migrations live as sibling .sql files embedded into the binary via go:embed
// so the shipped artifact stays self-contained. Each file is run exactly once
// per database, tracked by basename in a schema_migrations table.
//
// The runner is invoked via `thesada-app migrate` from the deploy workflow
// before the new binary's symlink is swapped in, so any failure aborts the
// deploy with the old binary still serving and the schema untouched.
package migrations

import (
	"context"
	"embed"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FS holds every .sql file alongside this package at build time. The runner
// lists, sorts, and diffs it against the schema_migrations table.
//
//go:embed *.sql
var FS embed.FS

// trackingTableDDL creates the schema_migrations table. Run unconditionally
// at the start of every Apply call; safe because of IF NOT EXISTS.
const trackingTableDDL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`

// preRunnerAppliedVersions are the migration basenames that were applied
// manually to the live database before the runner existed.
// When Apply() finds a tracking table with zero rows AND a sentinel
// pre-runner table still present (users), it seeds these versions so the
// subsequent loop skips them instead of re-running DDL that would fail.
//
// This list never grows. Every migration added after the runner landed
// records itself via the normal runOne path.
var preRunnerAppliedVersions = []string{
	"0001_init",
	"0002_magic_link_purpose",
	"0003_timescale_hypertable",
	"0004_multi_tenant_admin",
	"0005_session_impersonation",
}

// gatedMigrations names migrations that require an explicit env-var opt-in
// before they apply. Mapping is version -> env var name; the runner skips
// the migration unless the named env var is exactly "true".
//
// Currently empty. 0016_rls_policies was gated behind
// THESADA_APPLY_RLS_POLICIES - shipped ahead of the
// db.WithTenant consumer code so RLS could not enforce zero-row reads
// before pkg/web and pkg/mqtt were wrapped. Ungated once RLS became the
// steady-state default.
//
// Lifecycle: add an entry when shipping a load-bearing migration ahead of
// the consumer code; remove the entry once the consumer code lands and the
// migration is the steady-state default. The skip is logged at WARN so
// it stays visible in deploy logs.
var gatedMigrations = map[string]string{}

// Apply runs every migration newer than the highest version recorded in
// schema_migrations. Each file runs inside its own transaction so a failure
// in the middle of the batch leaves the db in a consistent state and the
// successfully-applied prefix is still recorded.
//
// File bodies may optionally contain their own BEGIN;/COMMIT; wrappers (kept
// for pre-runner compatibility). The runner strips those so the whole
// execution happens in exactly one caller-controlled transaction.
//
// in: ctx, pgx pool. out: error on any failure.
func Apply(ctx context.Context, pool *pgxpool.Pool) error {
	if _, err := pool.Exec(ctx, trackingTableDDL); err != nil {
		return fmt.Errorf("ensure schema_migrations: %w", err)
	}

	applied, err := loadApplied(ctx, pool)
	if err != nil {
		return fmt.Errorf("load applied versions: %w", err)
	}

	// Bootstrap: an existing database that predates the runner has no rows
	// in schema_migrations but every pre-runner schema object is already
	// there. Detect via the `users` sentinel (shipped in 0001) and seed the
	// tracking table so the loop below skips 0001..0005 instead of trying
	// to re-run DDL that would fail on duplicate objects.
	if len(applied) == 0 {
		seeded, err := bootstrapPreRunnerSchema(ctx, pool)
		if err != nil {
			return fmt.Errorf("bootstrap pre-runner schema: %w", err)
		}
		if seeded {
			applied, err = loadApplied(ctx, pool)
			if err != nil {
				return fmt.Errorf("reload applied versions after bootstrap: %w", err)
			}
		}
	}

	files, err := listMigrationFiles()
	if err != nil {
		return fmt.Errorf("list embedded migrations: %w", err)
	}
	slog.Info("migrations discovered", "count", len(files), "already_applied", len(applied))

	var ran int
	for _, name := range files {
		version := strings.TrimSuffix(name, ".sql")
		if _, ok := applied[version]; ok {
			continue
		}
		if envVar, gated := gatedMigrations[version]; gated && os.Getenv(envVar) != "true" {
			slog.Warn("migration gated, skipping until opt-in env var is set",
				"version", version, "env_var", envVar)
			continue
		}
		start := time.Now()
		body, err := FS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		stripped := stripOuterTx(string(body))
		if err := runOne(ctx, pool, version, stripped); err != nil {
			return fmt.Errorf("apply %s: %w", version, err)
		}
		slog.Info("migration applied", "version", version, "duration_ms", time.Since(start).Milliseconds())
		ran++
	}
	slog.Info("migrations complete", "applied_now", ran, "total_on_disk", len(files))
	return nil
}

// bootstrapPreRunnerSchema seeds schema_migrations with every pre-runner
// version when it detects a live database that predates the runner (i.e.
// has the `users` table from 0001 but no tracking rows). Returns true if
// any seed rows were inserted, false if the database is fresh.
// in: ctx, pool. out: seeded?, error.
func bootstrapPreRunnerSchema(ctx context.Context, pool *pgxpool.Pool) (bool, error) {
	var exists bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables
		                WHERE table_schema='public' AND table_name='users')`).Scan(&exists); err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}
	for _, v := range preRunnerAppliedVersions {
		if _, err := pool.Exec(ctx,
			`INSERT INTO schema_migrations (version) VALUES ($1)
			 ON CONFLICT (version) DO NOTHING`, v); err != nil {
			return false, err
		}
	}
	slog.Info("migrations bootstrap: pre-runner schema detected, seeded tracking", "versions", len(preRunnerAppliedVersions))
	return true, nil
}

// loadApplied reads the schema_migrations table into a set of version strings.
// in: ctx, pool. out: set of versions, error.
func loadApplied(ctx context.Context, pool *pgxpool.Pool) (map[string]struct{}, error) {
	rows, err := pool.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]struct{})
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out[v] = struct{}{}
	}
	return out, rows.Err()
}

// listMigrationFiles returns the sorted list of .sql files embedded in FS.
// out: sorted file basenames, error.
func listMigrationFiles() ([]string, error) {
	entries, err := FS.ReadDir(".")
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		files = append(files, e.Name())
	}
	sort.Strings(files)
	return files, nil
}

// runOne executes a single migration inside its own pgx transaction and
// records the version on success. The caller has already stripped any
// embedded BEGIN/COMMIT from the body so a single tx.Exec runs the whole
// thing atomically.
// in: ctx, pool, version tag, stripped sql body. out: error.
func runOne(ctx context.Context, pool *pgxpool.Pool, version, body string) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, body); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations (version) VALUES ($1)
			 ON CONFLICT (version) DO NOTHING`, version)
		return err
	})
}

// stripOuterTx removes lines that are exactly `BEGIN;` or `COMMIT;` (or their
// whitespace-padded variants) from a migration body. Only the outermost
// wrapper is targeted - inner `BEGIN/END` blocks in plpgsql DO bodies are
// untouched because they don't terminate with a bare semicolon on their own
// line in practice.
// in: raw sql body. out: same body with outer tx wrapper removed.
func stripOuterTx(body string) string {
	lines := strings.Split(body, "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.EqualFold(trimmed, "BEGIN;") || strings.EqualFold(trimmed, "COMMIT;") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}
