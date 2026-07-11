//go:build integration

// Real-Postgres contracts for alert dispatch under RLS. Regression for the
// 2026-07-10 review finding: the Notifier queried the App pool with no
// app.tenant_id GUC, every FORCE RLS policy evaluated false, loadAlert got
// zero rows, and no alert notification was ever delivered. These drive
// Dispatch and the tx-scoped helpers against a testcontainers TimescaleDB
// with RLS enabled, on the same App pool main.go wires in.
//
//	go test -tags integration -run TestDispatch ./pkg/alerts/...
package alerts

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/db"
	"thesada.app/app/pkg/service/servicetest"
)

// seedAlert inserts tenant -> device -> alert via the superuser pool and
// returns the device pk and alert id.
func seedAlert(t *testing.T, env *servicetest.Env, tenant string) (string, int64) {
	t.Helper()
	ctx := context.Background()
	env.SeedTenant(t, tenant)
	var devicePk string
	if err := env.Super.QueryRow(ctx,
		`INSERT INTO devices (tenant_id, device_id, display_name)
		 VALUES ($1, $2, $3) RETURNING id`,
		tenant, "owb-test-1", "Test OWB").Scan(&devicePk); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	var alertID int64
	if err := env.Super.QueryRow(ctx,
		`INSERT INTO device_alerts (device_pk, severity, code, message)
		 VALUES ($1, 'crit', 'TEST', 'boiler over temperature') RETURNING id`,
		devicePk).Scan(&alertID); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	return devicePk, alertID
}

func TestDispatch_TenantScope(t *testing.T) {
	env := servicetest.Start(t)
	ctx := context.Background()
	devicePk, alertID := seedAlert(t, env, "acme")
	n := New(env.Cfg, env.Pools.App, nil)

	// No subscribers: Dispatch must still see the alert row through RLS and
	// return nil. Pre-fix this failed with "alert lookup: no rows in result
	// set" because app.tenant_id was never set on the App pool.
	if err := n.Dispatch(ctx, "acme", alertID); err != nil {
		t.Fatalf("Dispatch with tenant GUC: %v", err)
	}

	// A different tenant must NOT see the row - proves the queries really
	// run under the RLS policy rather than some bypass.
	env.SeedTenant(t, "intruder")
	if err := n.Dispatch(ctx, "intruder", alertID); err == nil {
		t.Fatal("Dispatch under wrong tenant should fail the alert lookup")
	}

	// Empty tenant is rejected outright (db.ErrNoTenant), never a silent
	// zero-row read.
	if err := n.Dispatch(ctx, "", alertID); err == nil {
		t.Fatal("Dispatch with empty tenant should be rejected")
	}

	// Seed a matching email subscription and check the tx-scoped helpers see
	// alert + recipient and can mark delivery, all under the tenant GUC.
	var userID string
	if err := env.Super.QueryRow(ctx,
		`INSERT INTO users (tenant_id, email) VALUES ($1, $2) RETURNING id`,
		"acme", "ops@example.com").Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := env.Super.Exec(ctx,
		`INSERT INTO alert_subscriptions (user_id, device_pk, channel, min_severity)
		 VALUES ($1, $2, 'email', 'warn')`, userID, devicePk); err != nil {
		t.Fatalf("seed subscription: %v", err)
	}

	err := db.WithTenant(ctx, n.db, "acme", func(tx pgx.Tx) error {
		row, err := n.loadAlert(ctx, tx, alertID)
		if err != nil {
			return err
		}
		if row.severity != "crit" || row.message != "boiler over temperature" {
			t.Errorf("loadAlert row mismatch: %+v", row)
		}
		recipients, err := n.loadRecipients(ctx, tx, alertID)
		if err != nil {
			return err
		}
		if len(recipients) != 1 || recipients[0].email != "ops@example.com" {
			t.Errorf("loadRecipients = %+v, want one ops@example.com", recipients)
		}
		return n.markDelivered(ctx, tx, alertID, true, false)
	})
	if err != nil {
		t.Fatalf("tenant-scoped helpers: %v", err)
	}

	var deliveredEmail, deliveredTg bool
	if err := env.Super.QueryRow(ctx,
		`SELECT delivered_email, delivered_telegram FROM device_alerts WHERE id = $1`,
		alertID).Scan(&deliveredEmail, &deliveredTg); err != nil {
		t.Fatalf("read delivery flags: %v", err)
	}
	if !deliveredEmail || deliveredTg {
		t.Fatalf("delivery flags = email:%v tg:%v, want email:true tg:false", deliveredEmail, deliveredTg)
	}
}
