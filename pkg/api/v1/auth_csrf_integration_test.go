//go:build integration

// A cross-site form can post text/plain or a urlencoded body without a CORS
// preflight. The unauthenticated JSON auth endpoints refuse both, so another
// site cannot sign the victim's browser into the attacker's account.
//
//	go test -tags integration -run TestAuthHandlers_RefuseNonJSONBody ./pkg/api/v1/...
package v1_test

import (
	"net/http"
	"testing"

	apiv1 "thesada.app/app/pkg/api/v1"
	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/service/servicetest"
)

func TestAuthHandlers_RefuseNonJSONBody(t *testing.T) {
	env := servicetest.Start(t)
	srv := apiv1.New(env.Cfg, env.Services, nil, nil)
	const tenant = "apiauth-csrf"
	env.SeedTenant(t, tenant)
	u, err := env.Services.Auth.CreateUser(tenant, "attacker@example.com", "A", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Services.Auth.SetPassword(tenant, u.ID, "attacker password"); err != nil {
		t.Fatal(err)
	}
	creds := `{"email":"attacker@example.com","password":"attacker password"}`

	for _, path := range []string{"/auth/login", "/auth/magic-link", "/auth/magic-link/verify", "/auth/totp", "/auth/signup"} {
		for _, ct := range []string{"text/plain", "application/x-www-form-urlencoded", ""} {
			rec := post(srv, path, creds, map[string]string{"Content-Type": ct})
			if rec.Code != http.StatusUnsupportedMediaType {
				t.Errorf("POST %s as %q = %d, want 415", path, ct, rec.Code)
			}
			for _, c := range rec.Result().Cookies() {
				if c.Name == authmw.CookieName && c.Value != "" {
					t.Errorf("POST %s as %q set a session cookie", path, ct)
				}
			}
		}
	}

	// The same body as JSON still signs in, so the refusal above is the type check.
	if rec := post(srv, "/auth/login", creds, map[string]string{"Content-Type": "application/json; charset=utf-8"}); rec.Code != http.StatusOK {
		t.Fatalf("JSON login = %d (%s), want 200", rec.Code, rec.Body.String())
	}
}
