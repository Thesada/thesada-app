//go:build integration

package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

// TestNotificationChannelLimits: label and target caps, a duplicate target on
// update, and which telegram channel a kind-only subscription binds.
func TestNotificationChannelLimits(t *testing.T) {
	env := servicetest.Start(t)
	al := env.Services.Alerts
	ctx := context.Background()
	const tenant = "chan-limits"
	env.SeedTenant(t, tenant)
	u := mustCreateUser(t, env.Services.Auth, tenant, "limits@a.test")

	t.Run("label_and_target_are_capped", func(t *testing.T) {
		longLabel := strings.Repeat("l", service.MaxChannelLabelLen+1)
		if _, err := al.CreateChannel(ctx, tenant, u.ID, "telegram", "101", longLabel); !errors.Is(err, service.ErrChannelTooLong) {
			t.Fatalf("long label = %v, want ErrChannelTooLong", err)
		}
		longURL := "https://hooks.example/" + strings.Repeat("p", service.MaxChannelTargetLen)
		if _, err := al.CreateChannel(ctx, tenant, u.ID, "webhook", longURL, ""); !errors.Is(err, service.ErrChannelTooLong) {
			t.Fatalf("long target = %v, want ErrChannelTooLong", err)
		}
		if err := al.CreateSubscription(ctx, tenant, u.ID, nil, "webhook", "warn", longURL); !errors.Is(err, service.ErrChannelTooLong) {
			t.Fatalf("long kind-only webhook = %v, want ErrChannelTooLong", err)
		}
		id, err := al.CreateChannel(ctx, tenant, u.ID, "telegram", "102", strings.Repeat("l", service.MaxChannelLabelLen))
		if err != nil {
			t.Fatalf("label at the cap refused: %v", err)
		}
		if err := al.UpdateChannel(ctx, tenant, u.ID, id, "102", longLabel, true); !errors.Is(err, service.ErrChannelTooLong) {
			t.Fatalf("long label on update = %v, want ErrChannelTooLong", err)
		}
	})

	t.Run("duplicate_target_on_update", func(t *testing.T) {
		if _, err := al.CreateChannel(ctx, tenant, u.ID, "telegram", "201", ""); err != nil {
			t.Fatal(err)
		}
		b, err := al.CreateChannel(ctx, tenant, u.ID, "telegram", "202", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := al.UpdateChannel(ctx, tenant, u.ID, b, "201", "", true); !errors.Is(err, service.ErrChannelExists) {
			t.Fatalf("update onto an existing target = %v, want ErrChannelExists", err)
		}
	})

	t.Run("kind_only_telegram_binds_an_enabled_channel", func(t *testing.T) {
		v := mustCreateUser(t, env.Services.Auth, tenant, "tg@a.test")
		old, err := al.CreateChannel(ctx, tenant, v.ID, "telegram", "301", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := al.SetChannelEnabled(ctx, tenant, v.ID, old, false); err != nil {
			t.Fatal(err)
		}
		if err := al.CreateSubscription(ctx, tenant, v.ID, nil, "telegram", "warn", ""); !errors.Is(err, service.ErrNoChannel) {
			t.Fatalf("only a disabled telegram channel = %v, want ErrNoChannel", err)
		}
		newer, err := al.CreateChannel(ctx, tenant, v.ID, "telegram", "302", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := al.CreateSubscription(ctx, tenant, v.ID, nil, "telegram", "warn", ""); err != nil {
			t.Fatal(err)
		}
		subs, err := al.ListSubscriptions(ctx, tenant, v.ID)
		if err != nil || len(subs) != 1 || subs[0].ChannelID == nil || *subs[0].ChannelID != newer {
			t.Fatalf("subscription bound %+v (err %v), want the enabled channel %v", subs, err, newer)
		}
	})
}
