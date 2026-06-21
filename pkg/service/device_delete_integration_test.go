//go:build integration

// DeviceService.DeleteByID integration tests. The basic
// row-removal is asserted in device_integration_test.go; this covers the edges
// that make the single DELETE safe: FK CASCADE to child rows, RLS tenant
// scoping (a delete under the wrong tenant is a silent no-op, not a leak),
// the empty-tenant guard, and idempotence on an unknown id.
//
//	go test -tags integration -run TestDeviceDelete ./pkg/service/...
package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"thesada.app/app/pkg/db"
	"thesada.app/app/pkg/service/servicetest"
)

// TestDeviceDelete exercises DeleteByID's cascade + tenant-scoping edges.
//
// in:  a migrated testcontainer env, two seeded tenants.
// out: asserts a child device_alerts row cascades away with its device, that a
//
//	wrong-tenant delete leaves the row intact, that an empty tenant returns
//	ErrNoTenant, and that deleting an unknown id is a no-op.
func TestDeviceDelete(t *testing.T) {
	env := servicetest.Start(t)
	dev := env.Services.Devices
	alerts := env.Services.Alerts
	ctx := context.Background()

	const tA, tB = "devdel-a", "devdel-b"
	env.SeedTenant(t, tA)
	env.SeedTenant(t, tB)

	// countAlerts reads device_alerts out-of-band (superuser, RLS-bypassing)
	// so the cascade can be observed independent of the tenant GUC.
	countAlerts := func(t *testing.T, devicePK uuid.UUID) int {
		t.Helper()
		var n int
		if err := env.Super.QueryRow(ctx,
			`SELECT count(*) FROM device_alerts WHERE device_pk = $1`, devicePK).Scan(&n); err != nil {
			t.Fatalf("count alerts: %v", err)
		}
		return n
	}

	t.Run("cascade_removes_children", func(t *testing.T) {
		devPK, err := dev.Upsert(tA, "dev-cascade", "C", "1.0.0", "esp32", "thesada/dev-cascade")
		if err != nil {
			t.Fatalf("seed device: %v", err)
		}
		if _, err := alerts.InsertAlert(ctx, tA, devPK, "crit", "E9", "fire", nil); err != nil {
			t.Fatalf("seed alert: %v", err)
		}
		if n := countAlerts(t, devPK); n != 1 {
			t.Fatalf("pre-delete alert count = %d, want 1", n)
		}

		if err := dev.DeleteByID(ctx, tA, devPK); err != nil {
			t.Fatalf("DeleteByID: %v", err)
		}
		if got, _ := dev.GetByID(devPK, tA); got != nil {
			t.Errorf("device still present after delete")
		}
		if n := countAlerts(t, devPK); n != 0 {
			t.Errorf("post-delete alert count = %d, want 0 (FK cascade)", n)
		}
	})

	t.Run("wrong_tenant_is_noop", func(t *testing.T) {
		devPK, err := dev.Upsert(tA, "dev-scope", "S", "1.0.0", "esp32", "thesada/dev-scope")
		if err != nil {
			t.Fatalf("seed device: %v", err)
		}
		// Delete under tenant B: the RLS policy on devices hides A's row, so
		// the DELETE matches nothing. No error, and the row survives.
		if err := dev.DeleteByID(ctx, tB, devPK); err != nil {
			t.Fatalf("cross-tenant DeleteByID errored: %v", err)
		}
		if got, _ := dev.GetByID(devPK, tA); got == nil {
			t.Errorf("device removed by wrong-tenant delete (RLS leak)")
		}
	})

	t.Run("empty_tenant_errors", func(t *testing.T) {
		if err := dev.DeleteByID(ctx, "", uuid.New()); !errors.Is(err, db.ErrNoTenant) {
			t.Errorf("DeleteByID(empty tenant) = %v, want ErrNoTenant", err)
		}
	})

	t.Run("unknown_id_is_noop", func(t *testing.T) {
		if err := dev.DeleteByID(ctx, tA, uuid.New()); err != nil {
			t.Errorf("DeleteByID(unknown id) = %v, want nil", err)
		}
	})
}
