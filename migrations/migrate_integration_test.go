//go:build integration

// Migration round-trip acceptance test. Proves Apply on a fresh
// TimescaleDB applies every embedded migration and is idempotent: a second
// Apply is a clean no-op. The runner is forward-only (no down migrations), so
// idempotent re-apply is the reachable correctness property - it catches a
// migration that isn't safely re-runnable (e.g. a CREATE missing IF NOT EXISTS
// that double-applies because tracking failed).
//
//	go test -tags integration ./migrations/...
package migrations_test

import (
	"context"
	"io/fs"
	"testing"

	"thesada.app/app/migrations"
	"thesada.app/app/pkg/db"
	"thesada.app/app/pkg/service/servicetest"
)

func TestMigrations_FreshApplyThenIdempotent(t *testing.T) {
	ctx := context.Background()
	super, _ := servicetest.StartPostgres(t)

	// Expected count = every *.sql on disk (gatedMigrations is empty, so none
	// are skipped on a fresh DB).
	files, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		t.Fatalf("glob embedded migrations: %v", err)
	}
	wantApplied := len(files)
	if wantApplied == 0 {
		t.Fatal("no embedded migrations found - glob pattern wrong?")
	}

	// First apply: every migration runs.
	if err := migrations.Apply(ctx, super); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	got1 := countMigrations(t, super)
	if got1 != wantApplied {
		t.Errorf("after first apply: schema_migrations has %d rows, want %d (all on-disk migrations)", got1, wantApplied)
	}

	// Second apply: must succeed and record nothing new.
	if err := migrations.Apply(ctx, super); err != nil {
		t.Fatalf("second Apply (idempotency): %v", err)
	}
	got2 := countMigrations(t, super)
	if got2 != got1 {
		t.Errorf("second apply changed schema_migrations: %d -> %d, want no-op", got1, got2)
	}
}

// countMigrations returns the number of recorded versions in schema_migrations.
func countMigrations(t *testing.T, super *db.Pool) int {
	t.Helper()
	var n int
	if err := super.QueryRow(context.Background(),
		`SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	return n
}
