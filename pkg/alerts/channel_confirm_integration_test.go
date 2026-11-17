//go:build integration

package alerts

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

// TestDispatch_UnconfirmedEmailChannelGetsNoMail: an email channel to another
// address sends nothing until its link is used. The account address and a
// telegram channel send from the start.
func TestDispatch_UnconfirmedEmailChannelGetsNoMail(t *testing.T) {
	env := servicetest.Start(t)
	ctx := context.Background()
	al := env.Services.Alerts
	devicePk, alertID := seedAlert(t, env, "acme")
	u, err := env.Services.Auth.CreateUser("acme", "own@acme.test", "", false)
	if err != nil {
		t.Fatal(err)
	}
	other, err := al.CreateChannel(ctx, "acme", u.ID, "email", "other@elsewhere.test", "")
	if err != nil {
		t.Fatal(err)
	}
	own, err := al.CreateChannel(ctx, "acme", u.ID, "email", "Own@acme.test", "")
	if err != nil {
		t.Fatal(err)
	}
	tg, err := al.CreateChannel(ctx, "acme", u.ID, "telegram", "5150", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, ch := range []uuid.UUID{other, own, tg} {
		if err := al.CreateChannelSubscription(ctx, "acme", u.ID, nil, ch, "info"); err != nil {
			t.Fatal(err)
		}
	}

	n := New(env.Cfg, env.Pools, nil)
	var emails, chats []string
	n.sendEmail = func(to, _, _, _ string) error { emails = append(emails, to); return nil }
	n.sendTG = func(_ context.Context, chat, _ string) error { chats = append(chats, chat); return nil }
	dispatch := func(id int64) {
		t.Helper()
		emails, chats = nil, nil
		if err := n.Dispatch(ctx, "acme", id); err != nil {
			t.Fatal(err)
		}
		sort.Strings(emails)
	}

	dispatch(alertID)
	if strings.Join(emails, ",") != "Own@acme.test" || strings.Join(chats, ",") != "5150" {
		t.Fatalf("before confirm sends email=%v telegram=%v, want only Own@acme.test and 5150", emails, chats)
	}

	_, token, err := al.IssueChannelConfirm(ctx, "acme", u.ID, other, false, func() bool { return true })
	if err != nil || token == "" {
		t.Fatalf("issue = %q, %v", token, err)
	}
	if err := al.ConfirmChannel(ctx, token); err != nil {
		t.Fatal(err)
	}
	var alert2 int64
	if err := env.Super.QueryRow(ctx,
		`INSERT INTO device_alerts (device_pk, severity, code, message) VALUES ($1, 'crit', 'TEST2', 'second') RETURNING id`,
		devicePk).Scan(&alert2); err != nil {
		t.Fatal(err)
	}
	dispatch(alert2)
	if strings.Join(emails, ",") != "Own@acme.test,other@elsewhere.test" {
		t.Fatalf("after confirm sends went to %v, want both addresses", emails)
	}
	if err := al.ConfirmChannel(ctx, token); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("second use = %v, want ErrNotFound", err)
	}
}
