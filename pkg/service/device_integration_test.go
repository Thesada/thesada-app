//go:build integration

// DeviceService integration tests - exercises all 13 public
// methods against a real TimescaleDB, including the tenant-scoped vs admin
// (BYPASSRLS) split and the tombstone lifecycle. One container per run; each
// subtest uses its own device ids so they don't collide on the
// (tenant_id, device_id) unique key.
//
//	go test -tags integration -run TestDeviceService ./pkg/service/...
package service_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

// strval dereferences a *string for assertions, reporting "<nil>" for nil so a
// failure message is unambiguous.
func strval(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

// mustUpsert seeds a device and fails the test loudly on error. A discarded
// error here would hand back uuid.Nil and corrupt the assertion that follows,
// masking the real (setup) failure as a confusing logic failure.
// in: t, device service, tenant, device id, name, firmware, hardware, topic.
// out: device pk.
func mustUpsert(t *testing.T, dev *service.DeviceService, tenantID, deviceID, name, fw, hw, topic string) uuid.UUID {
	t.Helper()
	id, err := dev.Upsert(tenantID, deviceID, name, fw, hw, topic)
	if err != nil {
		t.Fatalf("seed device %s/%s: %v", tenantID, deviceID, err)
	}
	return id
}

func TestDeviceService(t *testing.T) {
	env := servicetest.Start(t)
	dev := env.Services.Devices
	ctx := context.Background()

	const tA, tB = "dev-test-a", "dev-test-b"
	env.SeedTenant(t, tA)
	env.SeedTenant(t, tB)

	t.Run("Upsert_creates_then_updates_without_clobber", func(t *testing.T) {
		id, err := dev.Upsert(tA, "dev-upsert", "Kitchen", "1.0.0", "cyd", "thesada/a/dev-upsert")
		if err != nil {
			t.Fatalf("Upsert create: %v", err)
		}
		if id == uuid.Nil {
			t.Fatal("Upsert returned nil id")
		}

		got, err := dev.GetByID(id, tA)
		if err != nil || got == nil {
			t.Fatalf("GetByID after create: got %v err %v", got, err)
		}
		if strval(got.DisplayName) != "Kitchen" || strval(got.FirmwareVersion) != "1.0.0" {
			t.Errorf("fields = %q/%q, want Kitchen/1.0.0", strval(got.DisplayName), strval(got.FirmwareVersion))
		}
		if got.LastSeenAt == nil {
			t.Error("Upsert should bump last_seen_at, got nil")
		}

		// Re-upsert: bump firmware only, leave name empty -> name must survive
		// (COALESCE/NULLIF), firmware updates, id is stable.
		id2, err := dev.Upsert(tA, "dev-upsert", "", "1.1.0", "", "")
		if err != nil {
			t.Fatalf("Upsert update: %v", err)
		}
		if id2 != id {
			t.Errorf("Upsert id changed: %v -> %v", id, id2)
		}
		got, _ = dev.GetByID(id, tA)
		if strval(got.DisplayName) != "Kitchen" {
			t.Errorf("display_name clobbered: %q, want Kitchen", strval(got.DisplayName))
		}
		if strval(got.FirmwareVersion) != "1.1.0" {
			t.Errorf("firmware not updated: %q, want 1.1.0", strval(got.FirmwareVersion))
		}
	})

	t.Run("UpsertSeen_does_not_set_last_seen_on_insert", func(t *testing.T) {
		id, err := dev.UpsertSeen(tA, "dev-seen", "Garage", "1.0.0", "eth", "thesada/a/dev-seen")
		if err != nil {
			t.Fatalf("UpsertSeen: %v", err)
		}
		got, err := dev.GetByID(id, tA)
		if err != nil || got == nil {
			t.Fatalf("GetByID: %v %v", got, err)
		}
		if got.LastSeenAt != nil {
			t.Errorf("UpsertSeen set last_seen_at on insert: %v, want nil", got.LastSeenAt)
		}
	})

	t.Run("BumpSeenIfExists_found_and_missing", func(t *testing.T) {
		id, err := dev.Upsert(tA, "dev-bump", "", "", "", "")
		if err != nil {
			t.Fatalf("seed Upsert: %v", err)
		}
		gotID, found, err := dev.BumpSeenIfExists(tA, "dev-bump")
		if err != nil {
			t.Fatalf("BumpSeenIfExists existing: %v", err)
		}
		if !found || gotID != id {
			t.Errorf("existing: found=%v id=%v, want true %v", found, gotID, id)
		}
		gotID, found, err = dev.BumpSeenIfExists(tA, "dev-does-not-exist")
		if err != nil {
			t.Fatalf("BumpSeenIfExists missing: %v", err)
		}
		if found || gotID != uuid.Nil {
			t.Errorf("missing: found=%v id=%v, want false uuid.Nil", found, gotID)
		}
	})

	t.Run("GetByID_GetByDeviceID_miss_returns_nil", func(t *testing.T) {
		if got, err := dev.GetByID(uuid.New(), tA); err != nil || got != nil {
			t.Errorf("GetByID unknown: got %v err %v, want nil nil", got, err)
		}
		if got, err := dev.GetByDeviceID(tA, "nope"); err != nil || got != nil {
			t.Errorf("GetByDeviceID unknown: got %v err %v, want nil nil", got, err)
		}
		id := mustUpsert(t, dev, tA, "dev-bydevid", "", "", "", "")
		got, err := dev.GetByDeviceID(tA, "dev-bydevid")
		if err != nil || got == nil || got.ID != id {
			t.Fatalf("GetByDeviceID hit: got %v err %v, want id %v", got, err, id)
		}
	})

	t.Run("RLS_tenant_isolation", func(t *testing.T) {
		id := mustUpsert(t, dev, tA, "dev-iso", "Secret", "1.0.0", "cyd", "")
		// tenant B must not see tenant A's device by pk or by device_id.
		if got, err := dev.GetByID(id, tB); err != nil || got != nil {
			t.Errorf("cross-tenant GetByID leaked: got %v err %v, want nil", got, err)
		}
		if got, err := dev.GetByDeviceID(tB, "dev-iso"); err != nil || got != nil {
			t.Errorf("cross-tenant GetByDeviceID leaked: got %v err %v, want nil", got, err)
		}
	})

	t.Run("GetByIDAny_crosses_tenant", func(t *testing.T) {
		id := mustUpsert(t, dev, tB, "dev-any", "AdminView", "2.0.0", "s3", "")
		got, err := dev.GetByIDAny(ctx, id)
		if err != nil || got == nil {
			t.Fatalf("GetByIDAny: got %v err %v", got, err)
		}
		if got.TenantID != tB || strval(got.DisplayName) != "AdminView" {
			t.Errorf("GetByIDAny = tenant %q name %q, want %q AdminView", got.TenantID, strval(got.DisplayName), tB)
		}
		if got, err := dev.GetByIDAny(ctx, uuid.New()); err != nil || got != nil {
			t.Errorf("GetByIDAny unknown: got %v err %v, want nil nil", got, err)
		}
	})

	t.Run("ListByTenant_scoped_ListAllForAdmin_global", func(t *testing.T) {
		// Fresh tenants so counts are deterministic regardless of other subtests.
		const tc = "dev-test-c"
		env.SeedTenant(t, tc)
		mustUpsert(t, dev, tc, "c1", "", "", "", "")
		mustUpsert(t, dev, tc, "c2", "", "", "", "")

		list, err := dev.ListByTenant(tc)
		if err != nil {
			t.Fatalf("ListByTenant: %v", err)
		}
		if len(list) != 2 {
			t.Errorf("ListByTenant(%s) = %d devices, want 2", tc, len(list))
		}
		for _, d := range list {
			if d.TenantID != tc {
				t.Errorf("ListByTenant leaked tenant %q", d.TenantID)
			}
		}

		all, err := dev.ListAllForAdmin(ctx)
		if err != nil {
			t.Fatalf("ListAllForAdmin: %v", err)
		}
		// Global view spans tenants - must exceed any single tenant's slice.
		if len(all) <= len(list) {
			t.Errorf("ListAllForAdmin = %d, want > single-tenant %d", len(all), len(list))
		}
	})

	t.Run("Reassign_moves_tenant", func(t *testing.T) {
		id := mustUpsert(t, dev, tA, "dev-move", "Mover", "1.0.0", "cyd", "")
		if err := dev.Reassign(ctx, id, tB); err != nil {
			t.Fatalf("Reassign: %v", err)
		}
		// Old tenant can no longer see it; new tenant can.
		if got, _ := dev.GetByID(id, tA); got != nil {
			t.Errorf("after reassign, source tenant still sees device")
		}
		got, err := dev.GetByID(id, tB)
		if err != nil || got == nil || got.TenantID != tB {
			t.Errorf("after reassign, target GetByID = %v err %v, want tenant %s", got, err, tB)
		}
	})

	t.Run("Tombstone_lifecycle", func(t *testing.T) {
		if got, err := dev.IsTombstoned(ctx, tA, "dev-tomb"); err != nil || got {
			t.Errorf("pre-tombstone IsTombstoned = %v err %v, want false", got, err)
		}
		if err := dev.Tombstone(ctx, tA, "dev-tomb", "thesada/a/dev-tomb"); err != nil {
			t.Fatalf("Tombstone: %v", err)
		}
		if got, err := dev.IsTombstoned(ctx, tA, "dev-tomb"); err != nil || !got {
			t.Errorf("post-tombstone IsTombstoned = %v err %v, want true", got, err)
		}
		// Tenant isolation on tombstones (direct RLS policy in 0016).
		if got, err := dev.IsTombstoned(ctx, tB, "dev-tomb"); err != nil || got {
			t.Errorf("cross-tenant tombstone leaked = %v err %v, want false", got, err)
		}
		if err := dev.RemoveTombstone(ctx, tA, "dev-tomb"); err != nil {
			t.Fatalf("RemoveTombstone: %v", err)
		}
		if got, err := dev.IsTombstoned(ctx, tA, "dev-tomb"); err != nil || got {
			t.Errorf("after RemoveTombstone = %v err %v, want false", got, err)
		}
	})

	t.Run("DeleteByID_removes_row", func(t *testing.T) {
		id := mustUpsert(t, dev, tA, "dev-del", "", "", "", "")
		if err := dev.DeleteByID(ctx, tA, id); err != nil {
			t.Fatalf("DeleteByID: %v", err)
		}
		if got, _ := dev.GetByID(id, tA); got != nil {
			t.Errorf("device still present after DeleteByID")
		}
	})
}
