//go:build integration

package alerts

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"thesada.app/app/migrations"
	"thesada.app/app/pkg/service/servicetest"
)

// TestDispatch_MigratedUserGetsEachChannelOnce: a user set up the old way
// (account email, users.telegram_chat_id, a webhook destination) still gets an
// alert on every channel exactly once after 0043 moved them into channel rows.
func TestDispatch_MigratedUserGetsEachChannelOnce(t *testing.T) {
	env := servicetest.Start(t)
	ctx := context.Background()
	devicePk, alertID := seedAlert(t, env, "acme")
	if _, err := env.Super.Exec(ctx, `
		ALTER TABLE alert_subscriptions DROP COLUMN channel_id;
		DROP TABLE notification_channels`); err != nil {
		t.Fatalf("roll back 0043: %v", err)
	}
	var userID string
	if err := env.Super.QueryRow(ctx,
		`INSERT INTO users (tenant_id, email, telegram_chat_id) VALUES ('acme', 'old@acme.test', '5150') RETURNING id`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if _, err := env.Super.Exec(ctx, `
		INSERT INTO alert_subscriptions (user_id, device_pk, channel, min_severity, destination) VALUES
		    ($1, $2,   'email',    'warn', NULL),
		    ($1, NULL, 'email',    'info', NULL),
		    ($1, NULL, 'telegram', 'warn', NULL),
		    ($1, $2,   'webhook',  'warn', 'https://hook.example/old')`, userID, devicePk); err != nil {
		t.Fatalf("seed old subscriptions: %v", err)
	}
	mctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	for _, f := range []string{"0043_notification_channels.sql", "0044_channel_follows_account.sql"} {
		body, err := migrations.FS.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := pgx.BeginFunc(mctx, env.Pools.App, func(tx pgx.Tx) error {
			_, err := tx.Exec(mctx, string(body))
			return err
		}); err != nil {
			t.Fatalf("%s on the production role: %v", f, err)
		}
	}

	n := New(env.Cfg, env.Pools, nil)
	var emails, chats, hooks []string
	n.sendEmail = func(to, _, _, _ string) error { emails = append(emails, to); return nil }
	n.sendTG = func(_ context.Context, chat, _ string) error { chats = append(chats, chat); return nil }
	n.webhookHTTP = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		hooks = append(hooks, r.URL.String())
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	if err := n.Dispatch(ctx, "acme", alertID); err != nil {
		t.Fatal(err)
	}
	if strings.Join(emails, ",") != "old@acme.test" || strings.Join(chats, ",") != "5150" ||
		strings.Join(hooks, ",") != "https://hook.example/old" {
		t.Fatalf("sends email=%v telegram=%v webhook=%v, want one each to the old targets", emails, chats, hooks)
	}
	if status, _, _, _, _ := deliveryRow(t, env, alertID); status != "delivered" {
		t.Fatalf("status = %s, want delivered", status)
	}

	// A switched-off channel is skipped on the next alert.
	if _, err := env.Super.Exec(ctx, `UPDATE notification_channels SET enabled = false WHERE kind = 'telegram' AND user_id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	var alert2 int64
	if err := env.Super.QueryRow(ctx,
		`INSERT INTO device_alerts (device_pk, severity, code, message) VALUES ($1, 'crit', 'TEST2', 'second') RETURNING id`,
		devicePk).Scan(&alert2); err != nil {
		t.Fatal(err)
	}
	chats = nil
	if err := n.Dispatch(ctx, "acme", alert2); err != nil {
		t.Fatal(err)
	}
	if len(chats) != 0 {
		t.Fatalf("disabled telegram channel still sent: %v", chats)
	}

	// The account email channel follows an email change.
	if _, err := env.Super.Exec(ctx, `UPDATE users SET email = 'new@acme.test' WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}
	var alert3 int64
	if err := env.Super.QueryRow(ctx,
		`INSERT INTO device_alerts (device_pk, severity, code, message) VALUES ($1, 'crit', 'TEST3', 'third') RETURNING id`,
		devicePk).Scan(&alert3); err != nil {
		t.Fatal(err)
	}
	emails = nil
	if err := n.Dispatch(ctx, "acme", alert3); err != nil {
		t.Fatal(err)
	}
	if strings.Join(emails, ",") != "new@acme.test" {
		t.Fatalf("after an email change sends went to %v, want new@acme.test once", emails)
	}
}
