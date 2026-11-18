//go:build integration

package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

func TestChannelConfirm(t *testing.T) {
	env := servicetest.Start(t)
	al := env.Services.Alerts
	ctx := context.Background()
	const tA = "confirm-a"
	env.SeedTenant(t, tA)
	u := mustCreateUser(t, env.Services.Auth, tA, "me@a.test")
	yes := func() bool { return true }

	confirmed := func(t *testing.T, id uuid.UUID) bool {
		t.Helper()
		chs, err := al.ListChannels(ctx, tA, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range chs {
			if c.ID == id {
				return c.Confirmed
			}
		}
		t.Fatalf("channel %s not listed", id)
		return false
	}
	issue := func(t *testing.T, id uuid.UUID, resend bool) string {
		t.Helper()
		_, tok, err := al.IssueChannelConfirm(ctx, tA, u.ID, id, resend, yes)
		if err != nil || tok == "" {
			t.Fatalf("issue = %q, %v", tok, err)
		}
		return tok
	}

	t.Run("other_address_waits_and_token_is_single_use", func(t *testing.T) {
		id, err := al.CreateChannel(ctx, tA, u.ID, "email", "friend@b.test", "")
		if err != nil {
			t.Fatal(err)
		}
		if confirmed(t, id) {
			t.Fatal("a new address to someone else counts as confirmed")
		}
		if err := al.CreateChannelSubscription(ctx, tA, u.ID, nil, id, "warn"); err != nil {
			t.Fatal(err)
		}
		subs, _ := al.ListSubscriptions(ctx, tA, u.ID)
		if len(subs) != 1 || subs[0].Confirmed {
			t.Fatalf("subscription on it reads confirmed: %+v", subs)
		}
		tok := issue(t, id, false)
		if again, _, _ := al.IssueChannelConfirm(ctx, tA, u.ID, id, false, yes); again != "" {
			t.Fatal("a second add replaced a live link")
		}
		if ok, err := al.ChannelConfirmValid(ctx, tok); err != nil || !ok {
			t.Fatalf("valid = %v, %v", ok, err)
		}
		if confirmed(t, id) {
			t.Fatal("checking the link confirmed the channel")
		}
		if err := al.ConfirmChannel(ctx, tok); err != nil {
			t.Fatal(err)
		}
		if !confirmed(t, id) {
			t.Fatal("confirm did not land")
		}
		if err := al.ConfirmChannel(ctx, tok); !errors.Is(err, service.ErrNotFound) {
			t.Fatalf("second use = %v, want ErrNotFound", err)
		}
		if ok, _ := al.ChannelConfirmValid(ctx, tok); ok {
			t.Fatal("a used link still reads valid")
		}
	})

	t.Run("expired_token_fails", func(t *testing.T) {
		id, err := al.CreateChannel(ctx, tA, u.ID, "email", "late@b.test", "")
		if err != nil {
			t.Fatal(err)
		}
		tok := issue(t, id, false)
		if _, err := env.Super.Exec(ctx, `UPDATE notification_channels SET confirm_expires_at = now() - interval '1 second' WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
		if ok, _ := al.ChannelConfirmValid(ctx, tok); ok {
			t.Fatal("an expired link reads valid")
		}
		if err := al.ConfirmChannel(ctx, tok); !errors.Is(err, service.ErrNotFound) {
			t.Fatalf("expired confirm = %v, want ErrNotFound", err)
		}
		if confirmed(t, id) {
			t.Fatal("an expired link confirmed the channel")
		}
	})

	t.Run("label_edit_keeps_confirmation", func(t *testing.T) {
		id, err := al.CreateChannel(ctx, tA, u.ID, "email", "first@b.test", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := al.ConfirmChannel(ctx, issue(t, id, false)); err != nil {
			t.Fatal(err)
		}
		if err := al.UpdateChannel(ctx, tA, u.ID, id, "first@b.test", "same", true); err != nil {
			t.Fatal(err)
		}
		if !confirmed(t, id) {
			t.Fatal("a label edit dropped the confirmation")
		}
		if _, tok, err := al.IssueChannelConfirm(ctx, tA, u.ID, id, true, yes); err != nil || tok != "" {
			t.Fatalf("resend on a confirmed channel = %q, %v, want nothing due", tok, err)
		}
	})

	t.Run("changing_the_address_resets_confirmation", func(t *testing.T) {
		id, err := al.CreateChannel(ctx, tA, u.ID, "email", "one@b.test", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := al.ConfirmChannel(ctx, issue(t, id, false)); err != nil {
			t.Fatal(err)
		}
		if err := al.UpdateChannel(ctx, tA, u.ID, id, "two@b.test", "", true); err != nil {
			t.Fatal(err)
		}
		if confirmed(t, id) {
			t.Fatal("a changed address kept the old confirmation")
		}
		pending := issue(t, id, false)
		if err := al.UpdateChannel(ctx, tA, u.ID, id, "three@b.test", "", true); err != nil {
			t.Fatal(err)
		}
		if err := al.ConfirmChannel(ctx, pending); !errors.Is(err, service.ErrNotFound) {
			t.Fatalf("link for the previous address = %v, want ErrNotFound", err)
		}
		if confirmed(t, id) {
			t.Fatal("the previous address's link confirmed the new one")
		}
	})

	t.Run("own_address_needs_no_mail", func(t *testing.T) {
		id, err := al.CreateChannel(ctx, tA, u.ID, "email", "ME@a.test", "")
		if err != nil {
			t.Fatal(err)
		}
		if !confirmed(t, id) {
			t.Fatal("the account address waits for a link")
		}
		asked := false
		if _, tok, err := al.IssueChannelConfirm(ctx, tA, u.ID, id, true, func() bool { asked = true; return true }); err != nil || tok != "" || asked {
			t.Fatalf("own address issue = %q, %v, asked %v, want nothing due", tok, err, asked)
		}
		moved, err := al.CreateChannel(ctx, tA, u.ID, "email", "elsewhere@b.test", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := al.UpdateChannel(ctx, tA, u.ID, moved, "me@a.test", "", true); err != nil {
			t.Fatal(err)
		}
		if !confirmed(t, moved) {
			t.Fatal("editing a channel to the account address left it waiting")
		}
	})

	t.Run("telegram_and_webhook_are_not_gated", func(t *testing.T) {
		tg, err := al.CreateChannel(ctx, tA, u.ID, "telegram", "4242", "")
		if err != nil {
			t.Fatal(err)
		}
		var hook uuid.UUID
		if err := env.Super.QueryRow(ctx, `
			INSERT INTO notification_channels (user_id, kind, target) VALUES ($1, 'webhook', 'https://hooks.example/c')
			RETURNING id`, u.ID).Scan(&hook); err != nil {
			t.Fatal(err)
		}
		for _, id := range []uuid.UUID{tg, hook} {
			if !confirmed(t, id) {
				t.Fatalf("channel %s waits for a link", id)
			}
			if _, tok, err := al.IssueChannelConfirm(ctx, tA, u.ID, id, true, yes); err != nil || tok != "" {
				t.Fatalf("issue on %s = %q, %v, want nothing due", id, tok, err)
			}
		}
	})

	t.Run("refused_cap_keeps_the_live_link", func(t *testing.T) {
		id, err := al.CreateChannel(ctx, tA, u.ID, "email", "capped@b.test", "")
		if err != nil {
			t.Fatal(err)
		}
		tok := issue(t, id, false)
		if _, _, err := al.IssueChannelConfirm(ctx, tA, u.ID, id, true, func() bool { return false }); !errors.Is(err, service.ErrConfirmLimited) {
			t.Fatalf("refused issue = %v, want ErrConfirmLimited", err)
		}
		if err := al.ConfirmChannel(ctx, tok); err != nil {
			t.Fatalf("the live link died on a refused resend: %v", err)
		}
	})

	t.Run("other_user_cannot_issue", func(t *testing.T) {
		id, err := al.CreateChannel(ctx, tA, u.ID, "email", "mine@b.test", "")
		if err != nil {
			t.Fatal(err)
		}
		other := mustCreateUser(t, env.Services.Auth, tA, "other@a.test")
		if _, _, err := al.IssueChannelConfirm(ctx, tA, other.ID, id, true, yes); !errors.Is(err, service.ErrNotFound) {
			t.Fatalf("other user issue = %v, want ErrNotFound", err)
		}
	})
}

// An edit that read the old target before a concurrent edit committed must not keep
// that edit's confirmation. The test holds the row itself, so the interleaving is forced.
func TestChannelUpdate_ConcurrentEditKeepsNoConfirmation(t *testing.T) {
	env := servicetest.Start(t)
	al := env.Services.Alerts
	ctx := context.Background()
	const tA = "confirm-race"
	env.SeedTenant(t, tA)
	u := mustCreateUser(t, env.Services.Auth, tA, "me@race.test")
	id, err := al.CreateChannel(ctx, tA, u.ID, "email", "friend@b.test", "")
	if err != nil {
		t.Fatal(err)
	}

	lock, err := env.Super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Rollback(ctx) }()
	// Play the other edit: move to the account address, which confirms without a link.
	if _, err := lock.Exec(ctx,
		`UPDATE notification_channels SET target = 'me@race.test', confirmed_at = now() WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- al.UpdateChannel(ctx, tA, u.ID, id, "friend@b.test", "", true) }()
	for i := 0; ; i++ {
		var waiting int
		if err := env.Super.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE NOT granted`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		if i == 100 {
			t.Fatal("the edit never blocked on the channel row")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := lock.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	chs, err := al.ListChannels(ctx, tA, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range chs {
		if c.ID == id && c.Confirmed {
			t.Fatal("friend@b.test kept the account address's confirmation without a link")
		}
	}
}
