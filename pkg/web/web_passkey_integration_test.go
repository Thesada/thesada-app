//go:build integration

package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/csrf"
	"thesada.app/app/pkg/service/servicetest"
	"thesada.app/app/pkg/webauthntest"
)

// postPasskeyJSON sends a JSON ceremony POST with the CSRF header and cookies.
// in: t, handler, path, body, cookies. out: recorder.
func postPasskeyJSON(t *testing.T, srv http.Handler, path string, body []byte, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	tok := csrfCookie(t, srv)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(csrf.HeaderName, tok.Value)
	req.AddCookie(tok)
	for _, c := range cookies {
		if c != nil {
			req.AddCookie(c)
		}
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// TestPasskeyWeb_EnrollFromSettingsThenSignIn checks the browser contract end to end.
// in: t. out: none.
func TestPasskeyWeb_EnrollFromSettingsThenSignIn(t *testing.T) {
	env := servicetest.Start(t)
	srv := New(env.Cfg, env.Services, nil, nil, nil, nil)
	const tenant = "pk-web"
	env.SeedTenant(t, tenant)
	auth := env.Services.Auth

	uid := mustWebUser(t, env, tenant, "pk-web@a.test", "correct-horse")
	tok, _, err := auth.CreateSession(tenant, uid, "password", "go-test", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	session := &http.Cookie{Name: authmw.CookieName, Value: tok}

	wrong := postPasskeyJSON(t, srv, "/settings/passkeys/begin", []byte(`{"password":"nope"}`), session)
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password = %d %s, want 401", wrong.Code, wrong.Body.String())
	}
	noCSRF := httptest.NewRequest(http.MethodPost, "/settings/passkeys/begin", strings.NewReader(`{"password":"correct-horse"}`))
	noCSRF.Header.Set("Content-Type", "application/json")
	noCSRF.AddCookie(session)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, noCSRF)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("begin without CSRF = %d, want 403", rec.Code)
	}

	begin := postPasskeyJSON(t, srv, "/settings/passkeys/begin", []byte(`{"password":"correct-horse"}`), session)
	if begin.Code != http.StatusOK {
		t.Fatalf("begin = %d %s", begin.Code, begin.Body.String())
	}
	reg := cookieNamed(t, begin, passkeyRegCookie)
	key, err := webauthntest.New(servicetest.PasskeyRPID, servicetest.PasskeyOrigin)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := key.Register(begin.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"name": "YubiKey", "credential": json.RawMessage(cred)})
	finish := postPasskeyJSON(t, srv, "/settings/passkeys/finish", body, session, reg)
	if finish.Code != http.StatusOK || !strings.Contains(finish.Body.String(), "saved=passkey") {
		t.Fatalf("finish = %d %s", finish.Code, finish.Body.String())
	}
	page := getAs(srv, "/settings", session)
	if !strings.Contains(page.Body.String(), "YubiKey") {
		t.Fatal("settings does not list the new key")
	}

	login := postLogin(t, srv, "pk-web@a.test", "correct-horse")
	if login.Code != http.StatusFound || login.Header().Get("Location") != "/login/totp" {
		t.Fatalf("login = %d %s, want the second-factor page", login.Code, login.Header().Get("Location"))
	}
	pending := cookieNamed(t, login, totpPendingCookie)
	form := httptest.NewRequest(http.MethodGet, "/login/totp", nil)
	form.AddCookie(pending)
	frec := httptest.NewRecorder()
	srv.ServeHTTP(frec, form)
	if !strings.Contains(frec.Body.String(), "Use passkey") || strings.Contains(frec.Body.String(), `name="code"`) {
		t.Fatalf("passkey-only page should offer the key and no code form: %s", frec.Body.String())
	}

	lbegin := postPasskeyJSON(t, srv, "/login/passkey/begin", nil, pending)
	if lbegin.Code != http.StatusOK {
		t.Fatalf("login begin = %d %s", lbegin.Code, lbegin.Body.String())
	}
	assertion, err := key.Login(lbegin.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	lfinish := postPasskeyJSON(t, srv, "/login/passkey/finish", assertion, pending)
	if lfinish.Code != http.StatusOK || !strings.Contains(lfinish.Body.String(), `"/devices"`) {
		t.Fatalf("login finish = %d %s", lfinish.Code, lfinish.Body.String())
	}
	cookieNamed(t, lfinish, authmw.CookieName)

	again := postPasskeyJSON(t, srv, "/login/passkey/begin", nil, pending)
	if again.Code != http.StatusUnauthorized || !strings.Contains(again.Body.String(), `"/login"`) {
		t.Fatalf("reused challenge = %d %s, want 401 to /login", again.Code, again.Body.String())
	}
}
