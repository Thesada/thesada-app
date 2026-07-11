package csrf

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

var testSecret = []byte("test-secret-at-least-32-bytes-long!!")

// okHandler is the protected next-handler; reaching it means CSRF passed.
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// TestSign_Deterministic_And_KeyBound proves the signature depends on the key,
// which is what makes a planted cookie forgeable only by the secret holder.
func TestSign_Deterministic_And_KeyBound(t *testing.T) {
	a := sign(testSecret, "body")
	if a != sign(testSecret, "body") {
		t.Error("sign not deterministic for same key+body")
	}
	if a == sign([]byte("a-different-secret-value-32-bytes!!"), "body") {
		t.Error("signature did not change with the key")
	}
}

// TestValidToken_AcceptsMintedRejectsForged is the core signed-double-submit
// property: only a value carrying a signature under the secret validates.
func TestValidToken_AcceptsMintedRejectsForged(t *testing.T) {
	good, err := mint(testSecret)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if !validToken(testSecret, good) {
		t.Error("minted token rejected")
	}
	forged := []string{
		"attacker-chosen-body.attacker-chosen-sig", // attacker has no secret
		"no-dot-no-signature",
		"body.",
		".sig",
		"",
		good + "x", // tampered tail
	}
	for _, v := range forged {
		if validToken(testSecret, v) {
			t.Errorf("validToken accepted forged value %q", v)
		}
	}
	// A valid body re-signed under the wrong key must fail under the real one.
	body := strings.SplitN(good, ".", 2)[0]
	if validToken(testSecret, body+"."+sign([]byte("wrong-key-also-32-bytes-long-xxxx!!"), body)) {
		t.Error("validToken accepted a wrong-key signature")
	}
}

// run drives the middleware once and returns the recorder.
func run(t *testing.T, method string, cookie *http.Cookie, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	var body string
	if form != nil {
		body = form.Encode()
	}
	r := httptest.NewRequest(method, "/", strings.NewReader(body))
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	Middleware(testSecret, nil)(okHandler()).ServeHTTP(rec, r)
	return rec
}

// TestMiddleware_SafeMethodMintsSignedCookie checks a GET seeds a validly
// signed cookie that the handler can echo into forms.
func TestMiddleware_SafeMethodMintsSignedCookie(t *testing.T) {
	rec := run(t, http.MethodGet, nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", rec.Code)
	}
	c := findCookie(rec.Result().Cookies())
	if c == nil {
		t.Fatal("no csrf cookie set on GET")
	}
	if !validToken(testSecret, c.Value) {
		t.Errorf("minted cookie %q fails its own signature check", c.Value)
	}
	if !c.HttpOnly {
		t.Error("csrf cookie must be HttpOnly: the token reaches JS via the template var, nothing reads the cookie")
	}
}

// TestMiddleware_RejectsPostWithoutToken is the baseline CSRF guard.
func TestMiddleware_RejectsPostWithoutToken(t *testing.T) {
	if rec := run(t, http.MethodPost, nil, url.Values{}); rec.Code != http.StatusForbidden {
		t.Errorf("POST without token = %d, want 403", rec.Code)
	}
}

// TestMiddleware_AcceptsMatchingSignedToken is the happy path: cookie value and
// form field agree and the cookie is validly signed.
func TestMiddleware_AcceptsMatchingSignedToken(t *testing.T) {
	tok, err := mint(testSecret)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	cookie := &http.Cookie{Name: CookieName, Value: tok}
	rec := run(t, http.MethodPost, cookie, url.Values{FormField: {tok}})
	if rec.Code != http.StatusOK {
		t.Errorf("POST with matching signed token = %d, want 200", rec.Code)
	}
}

// TestMiddleware_RejectsPlantedCookie is the attack this upgrade defends: a
// sibling-subdomain attacker plants a cookie value they also submit. Because it
// is not signed under the secret, the middleware replaces the cookie and the
// submitted value no longer matches, so the request is refused.
func TestMiddleware_RejectsPlantedCookie(t *testing.T) {
	planted := "attacker-known-value.attacker-known-sig"
	cookie := &http.Cookie{Name: CookieName, Value: planted}
	rec := run(t, http.MethodPost, cookie, url.Values{FormField: {planted}})
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST with planted unsigned cookie = %d, want 403", rec.Code)
	}
	// The planted cookie must be discarded and replaced with a real signed one.
	c := findCookie(rec.Result().Cookies())
	if c == nil || c.Value == planted || !validToken(testSecret, c.Value) {
		t.Errorf("rejection did not mint a fresh signed cookie; got %v", c)
	}
}

// TestMiddleware_RejectsMismatchedToken guards the equality check itself.
func TestMiddleware_RejectsMismatchedToken(t *testing.T) {
	a, _ := mint(testSecret)
	b, _ := mint(testSecret)
	cookie := &http.Cookie{Name: CookieName, Value: a}
	rec := run(t, http.MethodPost, cookie, url.Values{FormField: {b}})
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST with mismatched token = %d, want 403", rec.Code)
	}
}

// TestHasValidToken covers the /api/v1 escape hatch: a header-echoed, validly
// signed, matching token passes; a missing header, absent cookie, planted
// (unsigned) cookie, or mismatched header all fail.
func TestHasValidToken(t *testing.T) {
	tok, err := mint(testSecret)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	other, err := mint(testSecret)
	if err != nil {
		t.Fatalf("mint other: %v", err)
	}

	newReq := func(cookieVal, header string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/x", nil)
		if cookieVal != "" {
			r.AddCookie(&http.Cookie{Name: CookieName, Value: cookieVal})
		}
		if header != "" {
			r.Header.Set(HeaderName, header)
		}
		return r
	}

	cases := []struct {
		name   string
		cookie string
		header string
		want   bool
	}{
		{"matching signed token", tok, tok, true},
		{"no header", tok, "", false},
		{"no cookie", "", tok, false},
		{"planted unsigned cookie", "a.b", "a.b", false},
		{"header mismatches cookie", tok, other, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := HasValidToken(newReq(c.cookie, c.header), testSecret); got != c.want {
				t.Errorf("HasValidToken = %v, want %v", got, c.want)
			}
		})
	}
}

// findCookie returns the csrf cookie from a response, or nil.
func findCookie(cs []*http.Cookie) *http.Cookie {
	for _, c := range cs {
		if c.Name == CookieName {
			return c
		}
	}
	return nil
}
