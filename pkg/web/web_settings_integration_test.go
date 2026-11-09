//go:build integration

package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/service/servicetest"
)

// A failed profile save redirects with an error, not "saved". A settings list
// that fails to load shows a warning instead of an empty section.
func TestSettings_FailuresAreShown(t *testing.T) {
	env := servicetest.Start(t)
	srv := New(env.Cfg, env.Services, nil, nil, nil, nil)
	ctx := context.Background()
	const tenant = "settings-fail"
	env.SeedTenant(t, tenant)
	uid := mustWebUser(t, env, tenant, "settings@a.test", "")
	tok, _, err := env.Services.Auth.CreateSession(tenant, uid, "magic_link", "go-test", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	session := &http.Cookie{Name: authmw.CookieName, Value: tok}
	getSettings := func() string {
		req := httptest.NewRequest(http.MethodGet, "/settings", nil)
		req.AddCookie(session)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /settings = %d", rec.Code)
		}
		return rec.Body.String()
	}
	const warning = "Some settings could not be loaded."
	if strings.Contains(getSettings(), warning) {
		t.Fatal("healthy settings page shows the load warning")
	}

	if _, err := env.Super.Exec(ctx, `
		CREATE FUNCTION refuse_profile() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'profile store down'; END $$;
		CREATE TRIGGER refuse_profile BEFORE UPDATE OF display_name ON users
		    FOR EACH ROW EXECUTE FUNCTION refuse_profile();`); err != nil {
		t.Fatal(err)
	}
	rec := postAuthed(t, srv, "/settings/profile", url.Values{"display_name": {"Ada"}}, session, "")
	if loc := rec.Header().Get("Location"); loc != "/settings?err=profile" {
		t.Fatalf("failed profile save redirects to %q, want /settings?err=profile", loc)
	}

	if _, err := env.Super.Exec(ctx, `ALTER TABLE alert_subscriptions RENAME TO alert_subscriptions_gone`); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(getSettings(), warning) {
		t.Fatal("settings page hid a failed subscription list")
	}
}
