//go:build integration

package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"thesada.app/app/migrations"
	"thesada.app/app/pkg/service/servicetest"
)

// TestMigration0043_ChannelsFromOldColumns rolls the schema back to before 0043,
// seeds the old shape, then runs the 0043 body on the production migrate role
// (thesada_app: owner, NOBYPASSRLS, FORCE RLS on), as the runner does.
func TestMigration0043_ChannelsFromOldColumns(t *testing.T) {
	env := servicetest.Start(t)
	ctx := context.Background()
	const tenant = "mig43"
	env.SeedTenant(t, tenant)
	if _, err := env.Super.Exec(ctx, `
		ALTER TABLE alert_subscriptions DROP COLUMN channel_id;
		DROP TABLE notification_channels`); err != nil {
		t.Fatalf("roll back 0043: %v", err)
	}
	var withTG, noTG string
	if err := env.Super.QueryRow(ctx, `INSERT INTO users (tenant_id, email, telegram_chat_id) VALUES ($1, 'tg@mig43.test', ' 4242 ') RETURNING id`, tenant).Scan(&withTG); err != nil {
		t.Fatal(err)
	}
	if err := env.Super.QueryRow(ctx, `INSERT INTO users (tenant_id, email) VALUES ($1, 'plain@mig43.test') RETURNING id`, tenant).Scan(&noTG); err != nil {
		t.Fatal(err)
	}
	if _, err := env.Super.Exec(ctx, `
		INSERT INTO alert_subscriptions (user_id, channel, min_severity, destination) VALUES
		    ($1, 'email', 'warn', NULL),
		    ($1, 'telegram', 'crit', NULL),
		    ($1, 'webhook', 'info', 'https://hooks.example/a'),
		    ($1, 'webhook', 'warn', 'https://hooks.example/a'),
		    ($2, 'email', 'info', NULL),
		    ($2, 'telegram', 'warn', NULL)`, withTG, noTG); err != nil {
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

	type ch struct{ kind, target string }
	want := map[string][]ch{
		withTG: {{"email", "tg@mig43.test"}, {"telegram", "4242"}, {"webhook", "https://hooks.example/a"}},
		noTG:   {{"email", "plain@mig43.test"}},
	}
	for user, chans := range want {
		var n int
		if err := env.Super.QueryRow(ctx, `SELECT count(*) FROM notification_channels WHERE user_id = $1`, user).Scan(&n); err != nil || n != len(chans) {
			t.Fatalf("user %s has %d channels (%v), want %d", user, n, err, len(chans))
		}
		for _, c := range chans {
			if err := env.Super.QueryRow(ctx, `SELECT count(*) FROM notification_channels WHERE user_id = $1 AND kind = $2 AND target = $3 AND enabled`,
				user, c.kind, c.target).Scan(&n); err != nil || n != 1 {
				t.Errorf("user %s missing %s %s", user, c.kind, c.target)
			}
		}
	}
	var linked, unlinked int
	if err := env.Super.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE s.channel_id IS NOT NULL AND c.kind = s.channel),
		       count(*) FILTER (WHERE s.channel_id IS NULL)
		FROM alert_subscriptions s LEFT JOIN notification_channels c ON c.id = s.channel_id`).Scan(&linked, &unlinked); err != nil {
		t.Fatal(err)
	}
	var follows int
	if err := env.Super.QueryRow(ctx, `SELECT count(*) FROM notification_channels WHERE follows_account AND kind = 'email'`).Scan(&follows); err != nil || follows != 2 {
		t.Fatalf("account email channels = %d, %v, want 2 (one per user)", follows, err)
	}
	// The plain user's telegram rule had no chat id and never sent: it stays unlinked.
	if linked != 5 || unlinked != 1 {
		t.Fatalf("linked %d, unlinked %d, want 5 and 1", linked, unlinked)
	}
}
