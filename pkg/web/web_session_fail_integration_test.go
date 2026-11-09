//go:build integration

package web

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/service/servicetest"
)

// A login whose session row cannot be written answers 500, not a redirect
// into the dashboard without a session.
func TestLogin_SessionCreateFailureIs500(t *testing.T) {
	env := servicetest.Start(t)
	srv := New(env.Cfg, env.Services, nil, nil, nil, nil)
	const tenant = "sess-fail"
	env.SeedTenant(t, tenant)
	mustWebUser(t, env, tenant, "sess-fail@a.test", "correct-horse")
	if _, err := env.Super.Exec(context.Background(), `
		CREATE FUNCTION refuse_session() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'session store down'; END $$;
		CREATE TRIGGER refuse_session BEFORE INSERT ON user_sessions
		    FOR EACH ROW EXECUTE FUNCTION refuse_session();`); err != nil {
		t.Fatal(err)
	}

	rec := postLogin(t, srv, "sess-fail@a.test", "correct-horse")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("login with a failing session store = %d %s, want 500", rec.Code, rec.Header().Get("Location"))
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == authmw.CookieName && c.Value != "" {
			t.Fatal("failed login set a session cookie")
		}
	}
}

// An email-match auto-link that fails says so, instead of the no-account copy.
func TestOIDCCallback_EmailMatchLinkFailureIsReported(t *testing.T) {
	env := servicetest.Start(t)
	srv := New(env.Cfg, env.Services, nil, nil, nil, nil)
	const tenant = "oidc-linkfail"
	const slug = "sso-linkfail"
	env.SeedTenant(t, tenant)
	idp := newFakeIdP(t, "match-sub")
	idp.email = "match@a.test"
	if _, err := env.Super.Exec(context.Background(),
		`INSERT INTO oauth_providers (tenant_id, slug, display_name, kind, issuer_url, client_id, client_secret, enabled)
		 VALUES ($1, $2, 'SSO', 'oidc', $3, 'client-oidc', 'secret', true)`,
		tenant, slug, idp.srv.URL); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	mustWebUser(t, env, tenant, "match@a.test", "")
	if _, err := env.Super.Exec(context.Background(), `
		CREATE FUNCTION refuse_link() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'identity store down'; END $$;
		CREATE TRIGGER refuse_link BEFORE INSERT ON user_oauth_identities
		    FOR EACH ROW EXECUTE FUNCTION refuse_link();`); err != nil {
		t.Fatal(err)
	}

	cb, cookies := idp.start(t, srv, slug)
	rec := callback(srv, cb, cookies)
	if hasSession(rec) {
		t.Fatal("failed link signed in")
	}
	if body := rec.Body.String(); !strings.Contains(body, "Could not link this SSO identity") {
		t.Fatalf("callback = %d, want the link-failure message, got: %s", rec.Code, body)
	}
}
