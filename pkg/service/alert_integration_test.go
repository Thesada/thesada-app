//go:build integration

// AlertService integration tests. Alert ingest +
// per-device / per-tenant queries (with RLS isolation - device_alerts is a
// plain RLS-policed table, unlike telemetry) and subscription CRUD.
//
//	go test -tags integration -run TestAlertService ./pkg/service/...
package service_test

import (
	"context"
	"testing"

	"thesada.app/app/pkg/service/servicetest"
)

func TestAlertService(t *testing.T) {
	env := servicetest.Start(t)
	al := env.Services.Alerts
	dev := env.Services.Devices
	ctx := context.Background()

	const tA, tB = "alert-a", "alert-b"
	env.SeedTenant(t, tA)
	env.SeedTenant(t, tB)

	t.Run("Insert_and_RecentAlerts_filter_limit", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "alert-dev-1", "", "", "", "")
		for _, sev := range []string{"info", "warn", "crit"} {
			if _, err := al.InsertAlert(ctx, tA, pk, sev, sev+"-code", "msg", []byte("{}")); err != nil {
				t.Fatalf("InsertAlert %s: %v", sev, err)
			}
		}
		all, err := al.RecentAlerts(ctx, tA, pk, "", 10)
		if err != nil || len(all) != 3 {
			t.Fatalf("RecentAlerts all = %d (err %v), want 3", len(all), err)
		}
		crit, err := al.RecentAlerts(ctx, tA, pk, "crit", 10)
		if err != nil || len(crit) != 1 || crit[0].Severity != "crit" {
			t.Errorf("RecentAlerts crit = %v err %v, want one crit", crit, err)
		}
		if lim, _ := al.RecentAlerts(ctx, tA, pk, "", 2); len(lim) != 2 {
			t.Errorf("limit = %d, want 2", len(lim))
		}
	})

	t.Run("RecentByTenant_joins_device_id", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "alert-dev-tenant", "", "", "", "")
		if _, err := al.InsertAlert(ctx, tA, pk, "warn", "c", "m", []byte("{}")); err != nil {
			t.Fatalf("InsertAlert: %v", err)
		}
		rows, err := al.RecentByTenant(ctx, tA, 50)
		if err != nil {
			t.Fatalf("RecentByTenant: %v", err)
		}
		found := false
		for _, r := range rows {
			if r.DevicePK == pk && r.DeviceID == "alert-dev-tenant" {
				found = true
			}
		}
		if !found {
			t.Error("RecentByTenant did not return the alert with its device_id")
		}
	})

	t.Run("RLS_tenant_isolation", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "alert-iso", "", "", "", "")
		if _, err := al.InsertAlert(ctx, tA, pk, "crit", "c", "m", []byte("{}")); err != nil {
			t.Fatalf("InsertAlert: %v", err)
		}
		// device_alerts has a transitive RLS policy, so tenant B sees nothing.
		if got, err := al.RecentAlerts(ctx, tB, pk, "", 10); err != nil || len(got) != 0 {
			t.Errorf("cross-tenant RecentAlerts = %v err %v, want empty", got, err)
		}
		if got, err := al.RecentByTenant(ctx, tB, 50); err != nil {
			t.Errorf("RecentByTenant tB err %v", err)
		} else {
			for _, r := range got {
				if r.DevicePK == pk {
					t.Error("tenant B saw tenant A's alert")
				}
			}
		}
	})

	t.Run("Subscriptions_create_list_delete_owner_scoped", func(t *testing.T) {
		u := mustCreateUser(t, env.Services.Auth, tA, "sub@a.test")
		other := mustCreateUser(t, env.Services.Auth, tA, "other-sub@a.test")
		pk := mustUpsert(t, dev, tA, "sub-dev", "", "", "", "")

		// One device-specific + one all-devices (nil device_pk) subscription.
		if err := al.CreateSubscription(ctx, tA, u.ID, &pk, "email", "warn"); err != nil {
			t.Fatalf("CreateSubscription device: %v", err)
		}
		if err := al.CreateSubscription(ctx, tA, u.ID, nil, "telegram", "crit"); err != nil {
			t.Fatalf("CreateSubscription all: %v", err)
		}
		subs, err := al.ListSubscriptions(ctx, tA, u.ID)
		if err != nil || len(subs) != 2 {
			t.Fatalf("ListSubscriptions = %d (err %v), want 2", len(subs), err)
		}
		target := subs[0].ID

		// A different user cannot delete it (owner-scoped WHERE).
		if err := al.DeleteSubscription(ctx, tA, target, other.ID); err != nil {
			t.Fatalf("DeleteSubscription non-owner: %v", err)
		}
		if subs, _ := al.ListSubscriptions(ctx, tA, u.ID); len(subs) != 2 {
			t.Errorf("after non-owner delete = %d subs, want still 2", len(subs))
		}
		// Owner can.
		if err := al.DeleteSubscription(ctx, tA, target, u.ID); err != nil {
			t.Fatalf("DeleteSubscription owner: %v", err)
		}
		if subs, _ := al.ListSubscriptions(ctx, tA, u.ID); len(subs) != 1 {
			t.Errorf("after owner delete = %d subs, want 1", len(subs))
		}
	})
}
