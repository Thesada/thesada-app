//go:build integration

package service_test

import (
	"context"
	"errors"
	"testing"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

func TestNotificationChannels(t *testing.T) {
	env := servicetest.Start(t)
	al := env.Services.Alerts
	ctx := context.Background()
	const tA, tB = "chan-a", "chan-b"
	env.SeedTenant(t, tA)
	env.SeedTenant(t, tB)
	u := mustCreateUser(t, env.Services.Auth, tA, "chan@a.test")
	out := mustCreateUser(t, env.Services.Auth, tB, "chan@b.test")

	t.Run("targets_are_checked_per_kind", func(t *testing.T) {
		bad := map[string]string{
			"email":    "Name <x@a.test>",
			"telegram": "12ab",
			"webhook":  "ftp://hooks.example/x",
			"sms":      "+15551234",
		}
		for kind, target := range bad {
			if _, err := al.CreateChannel(ctx, tA, u.ID, kind, target, ""); err == nil {
				t.Errorf("%s %q was accepted", kind, target)
			}
		}
		for kind, target := range map[string]string{"email": "two@a.test", "telegram": "-100123", "webhook": "https://hooks.example/a"} {
			if _, err := al.CreateChannel(ctx, tA, u.ID, kind, target, ""); err != nil {
				t.Errorf("%s %q refused: %v", kind, target, err)
			}
		}
	})

	t.Run("same_target_twice_is_one_channel", func(t *testing.T) {
		a, err := al.CreateChannel(ctx, tA, u.ID, "telegram", "777", "first")
		if err != nil {
			t.Fatal(err)
		}
		b, err := al.CreateChannel(ctx, tA, u.ID, "telegram", " 777 ", "second")
		if err != nil || a != b {
			t.Fatalf("second add = %v, %v, want the first id %v", b, err, a)
		}
	})

	t.Run("update_toggle_delete_and_webhook_mirror", func(t *testing.T) {
		id, err := al.CreateChannel(ctx, tA, u.ID, "webhook", "https://hooks.example/old", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := al.CreateChannelSubscription(ctx, tA, u.ID, nil, id, "warn"); err != nil {
			t.Fatal(err)
		}
		if err := al.UpdateChannel(ctx, tA, u.ID, id, "https://hooks.example/new", "ops", true); err != nil {
			t.Fatal(err)
		}
		var dest string
		if err := env.Super.QueryRow(ctx, `SELECT destination FROM alert_subscriptions WHERE channel_id = $1`, id).Scan(&dest); err != nil || dest != "https://hooks.example/new" {
			t.Fatalf("mirror destination = %q, %v", dest, err)
		}
		if err := al.UpdateChannel(ctx, tA, u.ID, id, "not a url", "", true); !errors.Is(err, service.ErrBadWebhook) {
			t.Fatalf("bad update = %v, want ErrBadWebhook", err)
		}
		if err := al.SetChannelEnabled(ctx, tA, u.ID, id, false); err != nil {
			t.Fatal(err)
		}
		subs, _ := al.ListSubscriptions(ctx, tA, u.ID)
		for _, s := range subs {
			if s.ChannelID != nil && *s.ChannelID == id && s.Enabled {
				t.Fatal("subscription still reads its channel as enabled")
			}
		}
		if err := al.DeleteChannel(ctx, tA, u.ID, id); err != nil {
			t.Fatal(err)
		}
		var n int
		if err := env.Super.QueryRow(ctx, `SELECT count(*) FROM alert_subscriptions WHERE channel_id = $1`, id).Scan(&n); err != nil || n != 0 {
			t.Fatalf("subscriptions left on a deleted channel = %d, %v", n, err)
		}
	})

	t.Run("account_email_channel_follows_the_account", func(t *testing.T) {
		v := mustCreateUser(t, env.Services.Auth, tA, "acct@a.test")
		if err := al.CreateSubscription(ctx, tA, v.ID, nil, "email", "warn", ""); err != nil {
			t.Fatal(err)
		}
		chs, err := al.ListChannels(ctx, tA, v.ID)
		if err != nil || len(chs) != 1 || !chs[0].FollowsAccount || chs[0].Target != "acct@a.test" {
			t.Fatalf("channels = %+v, %v, want one account channel", chs, err)
		}
		if err := al.UpdateChannel(ctx, tA, v.ID, chs[0].ID, "other@a.test", "me", false); err != nil {
			t.Fatal(err)
		}
		if _, err := env.Super.Exec(ctx, `UPDATE users SET email = 'moved@a.test' WHERE id = $1`, v.ID); err != nil {
			t.Fatal(err)
		}
		chs, _ = al.ListChannels(ctx, tA, v.ID)
		if chs[0].Target != "moved@a.test" || chs[0].Label != "me" || chs[0].Enabled {
			t.Fatalf("after edit and email change = %+v, want target moved@a.test, label me, off", chs[0])
		}
		// A second email subscription reuses the account channel.
		if err := al.CreateSubscription(ctx, tA, v.ID, nil, "email", "crit", ""); err != nil {
			t.Fatal(err)
		}
		if chs, _ = al.ListChannels(ctx, tA, v.ID); len(chs) != 1 {
			t.Fatalf("second email rule made %d channels, want 1", len(chs))
		}
		// A user-added email channel stays a plain target.
		id, err := al.CreateChannel(ctx, tA, v.ID, "email", "ops@a.test", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := al.UpdateChannel(ctx, tA, v.ID, id, "ops2@a.test", "", true); err != nil {
			t.Fatal(err)
		}
		for _, c := range func() []service.NotificationChannel { c, _ := al.ListChannels(ctx, tA, v.ID); return c }() {
			if c.ID == id && (c.FollowsAccount || c.Target != "ops2@a.test") {
				t.Fatalf("plain email channel = %+v", c)
			}
		}
	})

	t.Run("another_tenant_cannot_touch_a_channel", func(t *testing.T) {
		id, err := al.CreateChannel(ctx, tA, u.ID, "email", "keep@a.test", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := al.SetChannelEnabled(ctx, tB, out.ID, id, false); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("tenant B toggle = %v, want ErrNotFound", err)
		}
		if err := al.UpdateChannel(ctx, tB, out.ID, id, "x@b.test", "", true); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("tenant B update = %v, want ErrNotFound", err)
		}
		if err := al.DeleteChannel(ctx, tB, out.ID, id); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("tenant B delete = %v, want ErrNotFound", err)
		}
		if err := al.CreateChannelSubscription(ctx, tB, out.ID, nil, id, "warn"); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("tenant B subscribe = %v, want ErrNotFound", err)
		}
		if chs, _ := al.ListChannels(ctx, tB, out.ID); len(chs) != 0 {
			t.Errorf("tenant B lists %d channels", len(chs))
		}
		// The owner's own call goes through, so the refusals above are not a broken path.
		if err := al.SetChannelEnabled(ctx, tA, u.ID, id, false); err != nil {
			t.Fatalf("owner toggle: %v", err)
		}
	})
}
