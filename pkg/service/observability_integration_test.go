//go:build integration

// ObservabilityService.Snapshot integration test: every stat block against
// seeded rows - waitlist funnel, alert delivery buckets (including the
// always-present zero 'dead' bucket and the 24h/7d window split), fleet +
// cert lifecycle breakdown, and audit action counts.
//
//	go test -tags integration -run TestObservabilityService ./pkg/service/...
package service_test

import (
	"context"
	"testing"
	"time"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

func TestObservabilityService(t *testing.T) {
	env := servicetest.Start(t)
	svc := env.Services.Observability
	certs := env.Services.Certificates
	dev := env.Services.Devices
	alerts := env.Services.Alerts
	ctx := context.Background()

	const tA = "obs-a"
	env.SeedTenant(t, tA)

	// Waitlist: two pending, one converted.
	converted := mustCreateUser(t, env.Services.Auth, tA, "converted@obs.test")
	for _, row := range []struct {
		email string
		user  any
	}{
		{"pending-1@obs.test", nil},
		{"pending-2@obs.test", nil},
		{"done@obs.test", converted.ID},
	} {
		if _, err := env.Super.Exec(ctx,
			`INSERT INTO waitlist (tenant_id, email, converted_user_id) VALUES ($1, $2, $3)`,
			tA, row.email, row.user); err != nil {
			t.Fatalf("seed waitlist %s: %v", row.email, err)
		}
	}

	// Fleet: four devices - one live-paired, one pending, one failed, one revoked.
	nb, na := time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
	const pem = "-----BEGIN CERTIFICATE-----\nobs\n-----END CERTIFICATE-----"
	dActive := mustUpsert(t, dev, tA, "obs-active", "", "", "", "")
	if err := certs.Issue(ctx, tA, dActive, "obs-serial-1", "cn-1", nb, na, pem); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	dPending := mustUpsert(t, dev, tA, "obs-pending", "", "", "", "")
	if _, err := certs.IssuePending(ctx, tA, dPending, "obs-serial-2", "cn-2", nb, na, pem); err != nil {
		t.Fatalf("IssuePending: %v", err)
	}
	dFailed := mustUpsert(t, dev, tA, "obs-failed", "", "", "", "")
	failedID, err := certs.IssuePending(ctx, tA, dFailed, "obs-serial-3", "cn-3", nb, na, pem)
	if err != nil {
		t.Fatalf("IssuePending: %v", err)
	}
	if err := certs.MarkFailed(ctx, tA, failedID); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}
	dRevoked := mustUpsert(t, dev, tA, "obs-revoked", "", "", "", "")
	if err := certs.Issue(ctx, tA, dRevoked, "obs-serial-4", "cn-4", nb, na, pem); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := certs.Revoke(ctx, tA, dRevoked); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Alerts: one fresh pending, one fresh dead, one delivered 3 days ago
	// (inside 7d, outside 24h).
	mustAlert := func(status string, age time.Duration) {
		t.Helper()
		id, err := alerts.InsertAlert(ctx, tA, dActive, "warn", "obs", "observability seed", nil)
		if err != nil {
			t.Fatalf("InsertAlert: %v", err)
		}
		if _, err := env.Super.Exec(ctx,
			`UPDATE device_alerts SET delivery_status = $1, received_at = now() - make_interval(secs => $2) WHERE id = $3`,
			status, age.Seconds(), id); err != nil {
			t.Fatalf("set alert state: %v", err)
		}
	}
	mustAlert("pending", 0)
	mustAlert("dead", 0)
	mustAlert("delivered", 72*time.Hour)

	// Audit: three fresh rows, plus one backdated out of the 24h window.
	for _, action := range []string{"obs.cert", "obs.cert", "obs.delete", "obs.old"} {
		if err := env.Services.Audit.Record(ctx, service.AuditEntry{
			ActorEmail: "op@obs.test", Action: action}); err != nil {
			t.Fatalf("Record(%s): %v", action, err)
		}
	}
	if _, err := env.Super.Exec(ctx,
		`UPDATE admin_audit SET at = now() - interval '2 days' WHERE action = 'obs.old'`); err != nil {
		t.Fatalf("backdate audit row: %v", err)
	}

	stats, err := svc.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	t.Run("waitlist_funnel", func(t *testing.T) {
		w := stats.Waitlist
		if w.Total != 3 || w.Pending != 2 || w.Converted != 1 {
			t.Errorf("funnel = %+v, want total 3 / pending 2 / converted 1", w)
		}
	})

	t.Run("alert_delivery_buckets", func(t *testing.T) {
		got := map[string]service.AlertDeliveryCount{}
		for _, c := range stats.Alerts {
			got[c.Status] = c
		}
		for status, want := range map[string]service.AlertDeliveryCount{
			"pending":   {Status: "pending", Last24h: 1, Last7d: 1},
			"dead":      {Status: "dead", Last24h: 1, Last7d: 1},
			"delivered": {Status: "delivered", Last24h: 0, Last7d: 1},
			"none":      {Status: "none", Last24h: 0, Last7d: 0},
		} {
			if got[status] != want {
				t.Errorf("bucket %s = %+v, want %+v", status, got[status], want)
			}
		}
		if len(stats.Alerts) != 4 {
			t.Errorf("bucket count = %d, want all 4 lifecycle states (zeros included)", len(stats.Alerts))
		}
	})

	t.Run("fleet_and_cert_breakdown", func(t *testing.T) {
		f := stats.Fleet
		if f.TotalDevices != 4 || f.PairedDevices != 1 {
			t.Errorf("devices = %+v, want total 4 / paired 1", f)
		}
		if f.CertActive != 1 || f.CertPending != 1 || f.CertFailed != 1 || f.CertRevoked != 1 {
			t.Errorf("certs = %+v, want 1 of each lifecycle bucket", f)
		}
	})

	t.Run("audit_last_24h_by_action", func(t *testing.T) {
		got := map[string]int{}
		for _, c := range stats.Audit {
			got[c.Action] = c.Count
		}
		if got["obs.cert"] != 2 || got["obs.delete"] != 1 {
			t.Errorf("audit counts = %v, want obs.cert 2 / obs.delete 1", got)
		}
		if _, ok := got["obs.old"]; ok {
			t.Error("backdated action counted inside the 24h window")
		}
		// Busiest-first ordering.
		if len(stats.Audit) > 1 && stats.Audit[0].Count < stats.Audit[1].Count {
			t.Errorf("audit buckets not busiest-first: %+v", stats.Audit)
		}
	})
}
