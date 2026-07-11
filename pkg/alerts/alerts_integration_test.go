//go:build integration

// Real-Postgres contracts for alert dispatch under RLS, plus the delivery
// retry / dead-letter / redispatch lifecycle. These drive Dispatch and Sweep
// against a testcontainers TimescaleDB with RLS enabled, on the same App and
// Admin pools main.go wires in; sends are stubbed via the Notifier seams.
//
//	go test -tags integration -run TestDispatch ./pkg/alerts/...
package alerts

import (
	"context"
	"errors"
	"testing"
	"time"

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

// seedEmailSub subscribes a fresh user to the device via the email channel.
func seedEmailSub(t *testing.T, env *servicetest.Env, tenant, devicePk, email string) {
	t.Helper()
	ctx := context.Background()
	var userID string
	if err := env.Super.QueryRow(ctx,
		`INSERT INTO users (tenant_id, email) VALUES ($1, $2) RETURNING id`,
		tenant, email).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := env.Super.Exec(ctx,
		`INSERT INTO alert_subscriptions (user_id, device_pk, channel, min_severity)
		 VALUES ($1, $2, 'email', 'warn')`, userID, devicePk); err != nil {
		t.Fatalf("seed subscription: %v", err)
	}
}

// deliveryRow reads the lifecycle columns out-of-band via the superuser pool.
func deliveryRow(t *testing.T, env *servicetest.Env, alertID int64) (status string, attempts int, email, tg bool, next time.Time) {
	t.Helper()
	if err := env.Super.QueryRow(context.Background(),
		`SELECT delivery_status, delivery_attempts, delivered_email, delivered_telegram, next_attempt_at
		 FROM device_alerts WHERE id = $1`, alertID).Scan(&status, &attempts, &email, &tg, &next); err != nil {
		t.Fatalf("read delivery row: %v", err)
	}
	return status, attempts, email, tg, next
}

// makeDue rewinds next_attempt_at so the sweeper considers the alert due now.
func makeDue(t *testing.T, env *servicetest.Env, alertID int64) {
	t.Helper()
	if _, err := env.Super.Exec(context.Background(),
		`UPDATE device_alerts SET next_attempt_at = now() - interval '1 minute' WHERE id = $1`,
		alertID); err != nil {
		t.Fatalf("rewind next_attempt_at: %v", err)
	}
}

func TestDispatch_TenantScope(t *testing.T) {
	env := servicetest.Start(t)
	ctx := context.Background()
	devicePk, alertID := seedAlert(t, env, "acme")
	n := New(env.Cfg, env.Pools, nil)

	// No subscribers: Dispatch must still see the alert row through RLS,
	// mark it 'none', and return nil. Pre-fix this failed with "alert
	// lookup: no rows in result set" because app.tenant_id was never set
	// on the App pool.
	if err := n.Dispatch(ctx, "acme", alertID); err != nil {
		t.Fatalf("Dispatch with tenant GUC: %v", err)
	}
	if status, _, _, _, _ := deliveryRow(t, env, alertID); status != "none" {
		t.Fatalf("delivery_status = %q, want none (no matching subscription)", status)
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
	// alert + recipient, all under the tenant GUC.
	seedEmailSub(t, env, "acme", devicePk, "ops@example.com")
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
		return nil
	})
	if err != nil {
		t.Fatalf("tenant-scoped helpers: %v", err)
	}

	// recordOutcome ORs the per-channel flags and stamps the lifecycle.
	if err := n.recordOutcome(ctx, "acme", alertID, true, false, "delivered", 1, time.Time{}); err != nil {
		t.Fatalf("recordOutcome: %v", err)
	}
	status, attempts, email, tg, _ := deliveryRow(t, env, alertID)
	if status != "delivered" || attempts != 1 || !email || tg {
		t.Fatalf("delivery row = %s/%d email:%v tg:%v, want delivered/1 email:true tg:false",
			status, attempts, email, tg)
	}
}

func TestDispatch_FailedSendSchedulesRetry_ThenDeadLetters(t *testing.T) {
	env := servicetest.Start(t)
	ctx := context.Background()
	devicePk, alertID := seedAlert(t, env, "acme")
	seedEmailSub(t, env, "acme", devicePk, "ops@example.com")

	env.Cfg.AlertMaxAttempts = 2
	env.Cfg.AlertRetryBase = time.Minute
	n := New(env.Cfg, env.Pools, nil)
	sends := 0
	n.sendEmail = func(_, _, _, _ string) error { sends++; return errors.New("smtp down") }

	// Attempt 1: send fails -> row stays pending with a future next_attempt_at.
	if err := n.Dispatch(ctx, "acme", alertID); err != nil {
		t.Fatalf("Dispatch attempt 1: %v", err)
	}
	status, attempts, email, _, next := deliveryRow(t, env, alertID)
	if status != "pending" || attempts != 1 || email {
		t.Fatalf("after attempt 1: %s/%d email:%v, want pending/1 email:false", status, attempts, email)
	}
	if !next.After(time.Now().Add(30 * time.Second)) {
		t.Fatalf("next_attempt_at = %v, want backed off ~1m into the future", next)
	}

	// Attempt 2 exhausts the budget -> dead, and no further dispatch sends.
	if err := n.Dispatch(ctx, "acme", alertID); err != nil {
		t.Fatalf("Dispatch attempt 2: %v", err)
	}
	if status, attempts, _, _, _ = deliveryRow(t, env, alertID); status != "dead" || attempts != 2 {
		t.Fatalf("after attempt 2: %s/%d, want dead/2", status, attempts)
	}
	if err := n.Dispatch(ctx, "acme", alertID); err != nil {
		t.Fatalf("Dispatch on dead row: %v", err)
	}
	if sends != 2 {
		t.Fatalf("sends = %d, want 2 (dead row must not re-send)", sends)
	}
}

func TestSweep_RedeliversPendingAcrossTenants(t *testing.T) {
	env := servicetest.Start(t)
	ctx := context.Background()
	pkA, alertA := seedAlert(t, env, "acme")
	seedEmailSub(t, env, "acme", pkA, "ops@acme.example")
	pkB, alertB := seedAlert(t, env, "globex")
	seedEmailSub(t, env, "globex", pkB, "ops@globex.example")

	env.Cfg.AlertMaxAttempts = 5
	env.Cfg.AlertRetryBase = time.Minute
	n := New(env.Cfg, env.Pools, nil)
	n.sendEmail = func(_, _, _, _ string) error { return errors.New("smtp down") }

	for _, pair := range []struct {
		tenant string
		id     int64
	}{{"acme", alertA}, {"globex", alertB}} {
		if err := n.Dispatch(ctx, pair.tenant, pair.id); err != nil {
			t.Fatalf("Dispatch %s: %v", pair.tenant, err)
		}
	}

	// Not yet due: a sweep must not touch either row.
	n.sendEmail = func(_, _, _, _ string) error { return nil }
	n.Sweep(ctx)
	if status, attempts, _, _, _ := deliveryRow(t, env, alertA); status != "pending" || attempts != 1 {
		t.Fatalf("sweep before due: %s/%d, want pending/1", status, attempts)
	}

	// Due: one sweep pass redelivers both tenants' alerts through the
	// admin scan + tenant-scoped dispatch path.
	makeDue(t, env, alertA)
	makeDue(t, env, alertB)
	n.Sweep(ctx)
	for _, id := range []int64{alertA, alertB} {
		status, attempts, email, _, _ := deliveryRow(t, env, id)
		if status != "delivered" || attempts != 2 || !email {
			t.Fatalf("after sweep, alert %d: %s/%d email:%v, want delivered/2 email:true", id, status, attempts, email)
		}
	}

	// Startup-shaped case: a row that never got its inline dispatch (process
	// death) is picked up by a sweep with zero prior attempts.
	pkC, alertC := seedAlert(t, env, "initech")
	seedEmailSub(t, env, "initech", pkC, "ops@initech.example")
	makeDue(t, env, alertC)
	n.Sweep(ctx)
	if status, attempts, _, _, _ := deliveryRow(t, env, alertC); status != "delivered" || attempts != 1 {
		t.Fatalf("startup redispatch: %s/%d, want delivered/1", status, attempts)
	}
}

func TestDispatch_PartialChannelFailure_RetriesOnlyFailedChannel(t *testing.T) {
	env := servicetest.Start(t)
	ctx := context.Background()
	devicePk, alertID := seedAlert(t, env, "acme")
	seedEmailSub(t, env, "acme", devicePk, "ops@example.com")
	var userID string
	if err := env.Super.QueryRow(ctx,
		`INSERT INTO users (tenant_id, email, telegram_chat_id) VALUES ($1, $2, $3) RETURNING id`,
		"acme", "tg@example.com", "12345").Scan(&userID); err != nil {
		t.Fatalf("seed tg user: %v", err)
	}
	if _, err := env.Super.Exec(ctx,
		`INSERT INTO alert_subscriptions (user_id, device_pk, channel, min_severity)
		 VALUES ($1, $2, 'telegram', 'warn')`, userID, devicePk); err != nil {
		t.Fatalf("seed tg subscription: %v", err)
	}

	env.Cfg.AlertMaxAttempts = 5
	env.Cfg.AlertRetryBase = time.Minute
	n := New(env.Cfg, env.Pools, nil)
	emailSends, tgSends := 0, 0
	n.sendEmail = func(_, _, _, _ string) error { emailSends++; return nil }
	n.sendTG = func(_ context.Context, _, _ string) error { tgSends++; return errors.New("telegram 502") }

	// Email lands, telegram fails -> pending with delivered_email already set.
	if err := n.Dispatch(ctx, "acme", alertID); err != nil {
		t.Fatalf("Dispatch attempt 1: %v", err)
	}
	status, attempts, email, tg, _ := deliveryRow(t, env, alertID)
	if status != "pending" || attempts != 1 || !email || tg {
		t.Fatalf("after attempt 1: %s/%d email:%v tg:%v, want pending/1 email:true tg:false",
			status, attempts, email, tg)
	}

	// Retry succeeds on telegram and must not re-send the email.
	n.sendTG = func(_ context.Context, _, _ string) error { tgSends++; return nil }
	if err := n.Dispatch(ctx, "acme", alertID); err != nil {
		t.Fatalf("Dispatch attempt 2: %v", err)
	}
	status, attempts, email, tg, _ = deliveryRow(t, env, alertID)
	if status != "delivered" || attempts != 2 || !email || !tg {
		t.Fatalf("after attempt 2: %s/%d email:%v tg:%v, want delivered/2 both true",
			status, attempts, email, tg)
	}
	if emailSends != 1 || tgSends != 2 {
		t.Fatalf("sends email:%d tg:%d, want email:1 tg:2", emailSends, tgSends)
	}
}
