//go:build integration

package service_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service/servicetest"
)

// TestAbsenceSweep_OneWarnPerStretchAndClearOnSight checks the cross-tenant sweep
// and that a live sighting clears only that tenant's row.
// in: t. out: none.
func TestAbsenceSweep_OneWarnPerStretchAndClearOnSight(t *testing.T) {
	env := servicetest.Start(t)
	ctx := context.Background()
	env.SeedTenant(t, "abs-a")
	env.SeedTenant(t, "abs-b")
	quietA := seedQuietDevice(t, env, "abs-a", "thesada-abs-a")
	quietB := seedQuietDevice(t, env, "abs-b", "thesada-abs-b")
	fresh := seedQuietDevice(t, env, "abs-a", "thesada-abs-fresh")
	if _, err := env.Super.Exec(ctx, `UPDATE devices SET last_seen_at = now() WHERE id = $1`, fresh); err != nil {
		t.Fatal(err)
	}

	env.Services.Alerts.RaiseAbsencesAny(ctx)
	env.Services.Alerts.RaiseAbsencesAny(ctx)
	if n := absenceCount(t, env, quietA); n != 1 {
		t.Fatalf("quiet A alerts = %d, want 1", n)
	}
	if n := absenceCount(t, env, quietB); n != 1 {
		t.Fatalf("quiet B alerts = %d, want 1", n)
	}
	if n := absenceCount(t, env, fresh); n != 0 {
		t.Fatalf("fresh alerts = %d, want 0", n)
	}

	if _, found, err := env.Services.Devices.BumpSeenIfExists("abs-a", "thesada-abs-a"); err != nil || !found {
		t.Fatalf("bump found=%v err=%v", found, err)
	}
	if cleared := absenceCleared(t, env, quietA); !cleared {
		t.Fatal("sighting did not clear A's absence")
	}
	if cleared := absenceCleared(t, env, quietB); cleared {
		t.Fatal("A's sighting cleared B's absence")
	}
}

// seedQuietDevice inserts a paired device last seen 20 minutes ago.
// in: t, env, tenant, device id. out: device pk.
func seedQuietDevice(t *testing.T, env *servicetest.Env, tenant, deviceID string) uuid.UUID {
	t.Helper()
	pk, err := env.Services.Devices.Upsert(tenant, deviceID, "", "", "", "thesada/"+tenant+"/"+deviceID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = env.Super.Exec(context.Background(),
		`UPDATE devices SET paired_at = now() - interval '1 hour', last_seen_at = now() - interval '20 minutes' WHERE id = $1`, pk)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

// absenceCount is how many absence alerts this device has.
// in: t, env, device pk. out: count.
func absenceCount(t *testing.T, env *servicetest.Env, pk uuid.UUID) int {
	t.Helper()
	var n int
	if err := env.Super.QueryRow(context.Background(),
		`SELECT count(*) FROM device_alerts WHERE device_pk = $1 AND code = 'absence'`, pk).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// absenceCleared reports whether every absence row for the device has cleared_at set.
// in: t, env, device pk. out: true when the open episode is cleared.
func absenceCleared(t *testing.T, env *servicetest.Env, pk uuid.UUID) bool {
	t.Helper()
	var n int
	err := env.Super.QueryRow(context.Background(),
		`SELECT count(*) FROM device_alerts WHERE device_pk = $1 AND code = 'absence' AND cleared_at IS NOT NULL`, pk).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	return n == 1
}
