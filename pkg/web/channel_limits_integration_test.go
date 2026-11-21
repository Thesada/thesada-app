//go:build integration

package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service"
)

// TestSettingsChannels_LimitsDuplicatesAndToggle: an over-long label and a
// duplicate target answer 400 with a message, and the toggle reads both
// checkbox spellings.
func TestSettingsChannels_LimitsDuplicatesAndToggle(t *testing.T) {
	c := startConfirmWeb(t)
	uid, session := c.session(t, "chan-web", "owner@chan.test")
	ctx := context.Background()
	add := func(target string) uuid.UUID {
		t.Helper()
		rec := postAuthed(t, c.srv, "/settings/channels/add", url.Values{"kind": {"telegram"}, "target": {target}}, session, "")
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("add %s = %d %s", target, rec.Code, rec.Body.String())
		}
		var id uuid.UUID
		if err := c.env.Super.QueryRow(ctx, `SELECT id FROM notification_channels WHERE user_id = $1 AND target = $2`, uid, target).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	enabled := func(id uuid.UUID) bool {
		t.Helper()
		var on bool
		if err := c.env.Super.QueryRow(ctx, `SELECT enabled FROM notification_channels WHERE id = $1`, id).Scan(&on); err != nil {
			t.Fatal(err)
		}
		return on
	}
	first, second := add("4001"), add("4002")

	long := strings.Repeat("x", service.MaxChannelLabelLen+1)
	rec := postAuthed(t, c.srv, "/settings/channels/add", url.Values{"kind": {"telegram"}, "target": {"4003"}, "label": {long}}, session, "")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "too long") {
		t.Fatalf("long label add = %d %q, want 400 naming the cap", rec.Code, rec.Body.String())
	}

	rec = postAuthed(t, c.srv, "/settings/channels/"+second.String()+"/update", url.Values{"target": {"4001"}, "enabled": {"on"}}, session, "")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "already have a channel") {
		t.Fatalf("duplicate update = %d %q, want 400 naming the duplicate", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "23505") {
		t.Fatal("the database error reached the user")
	}

	for _, tc := range []struct {
		value string
		want  bool
	}{{"false", false}, {"on", true}, {"false", false}, {"true", true}} {
		rec := postAuthed(t, c.srv, "/settings/channels/"+first.String()+"/toggle", url.Values{"enabled": {tc.value}}, session, "")
		if rec.Code != http.StatusSeeOther || enabled(first) != tc.want {
			t.Fatalf("toggle %q = %d, enabled %v, want %v", tc.value, rec.Code, enabled(first), tc.want)
		}
	}
}
