//go:build integration

// The emailed sign-in link: a GET (what a mail scanner does) shows a button
// and consumes nothing; the POST signs in once.
//
//	go test -tags integration -run TestMagicLinkWeb ./pkg/web/...
package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/csrf"
	"thesada.app/app/pkg/service/servicetest"
)

func TestMagicLinkWeb_GetConsumesNothingPostSignsInOnce(t *testing.T) {
	env := servicetest.Start(t)
	srv := New(env.Cfg, env.Services, nil, nil, nil, nil)
	const tenant = "ml-web"
	env.SeedTenant(t, tenant)
	uid := mustWebUser(t, env, tenant, "ml@a.test", "")
	token, _, err := env.Services.Auth.CreateMagicLink(uid)
	if err != nil {
		t.Fatal(err)
	}

	// A scanner, or the user's first click: a page with a button, no session.
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login/verify?token="+url.QueryEscape(token), nil))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `action="/login/verify"`) {
			t.Fatalf("GET = %d, want the confirm form", rec.Code)
		}
		for _, c := range rec.Result().Cookies() {
			if c.Name == authmw.CookieName && c.Value != "" {
				t.Fatal("GET set a session cookie")
			}
		}
	}

	post := func() *httptest.ResponseRecorder {
		tok := csrfCookie(t, srv)
		form := url.Values{"token": {token}, csrf.FormField: {tok.Value}}
		return submitForm(srv, "/login/verify", form, []*http.Cookie{tok}, "")
	}
	first := post()
	if first.Code != http.StatusFound || first.Header().Get("Location") != "/devices" {
		t.Fatalf("POST = %d %s, want 302 /devices", first.Code, first.Header().Get("Location"))
	}
	if c := cookieNamed(t, first, authmw.CookieName); c == nil {
		t.Fatal("POST set no session")
	}
	if again := post(); !strings.Contains(again.Body.String(), "invalid or already used") {
		t.Fatalf("second POST = %d, want the already-used page", again.Code)
	}
}
