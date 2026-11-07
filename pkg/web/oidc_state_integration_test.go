//go:build integration

// An OIDC callback finishes only in the browser that started the flow. An
// attacker who signs in at the IdP and hands the callback URL to a victim
// does not get the victim's browser signed into the attacker's account.
//
//	go test -tags integration -run TestOIDCCallback ./pkg/web/...
package web

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/service/servicetest"
)

// fakeIdP is a minimal OIDC provider that signs an id_token for one subject
// with the nonce of the last authorize request it was shown.
type fakeIdP struct {
	srv     *httptest.Server
	key     *rsa.PrivateKey
	subject string
	mu      sync.Mutex
	nonce   string
	tokens  int
}

// newFakeIdP serves discovery, JWKS and a token endpoint.
// in: t, subject the IdP signs in. out: idp.
func newFakeIdP(t *testing.T, subject string) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key, subject: subject}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.srv.URL,
			"authorization_endpoint":                f.srv.URL + "/authorize",
			"token_endpoint":                        f.srv.URL + "/token",
			"jwks_uri":                              f.srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		nonce := f.nonce
		f.tokens++
		f.mu.Unlock()
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
			(&jose.SignerOptions{}).WithHeader("kid", "k1"))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		now := time.Now()
		idTok, err := jwt.Signed(signer).Claims(map[string]any{
			"iss": f.srv.URL, "aud": "client-oidc", "sub": f.subject, "nonce": nonce,
			"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		}).Serialize()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": idTok})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// start runs GET /auth/oidc/{slug}/start and plays the IdP's login: it
// returns the callback URL the IdP would redirect to, and the cookies the
// starting browser holds.
// in: t, app, slug. out: callback path with query, browser cookies.
func (f *fakeIdP) start(t *testing.T, srv http.Handler, slug string) (string, []*http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/oidc/"+slug+"/start", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("start = %d (%s), want 302", rec.Code, rec.Body.String())
	}
	authz, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := authz.Query()
	f.mu.Lock()
	f.nonce = q.Get("nonce")
	f.mu.Unlock()
	cb := "/auth/oidc/" + slug + "/callback?" + url.Values{"code": {"c1"}, "state": {q.Get("state")}}.Encode()
	return cb, rec.Result().Cookies()
}

// callback runs the callback URL in a browser holding cookies.
// in: app, callback path, cookies. out: recorder.
func callback(srv http.Handler, cb string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, cb, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// hasSession reports whether rec set a non-empty session cookie.
// in: recorder. out: bool.
func hasSession(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == authmw.CookieName && c.Value != "" {
			return true
		}
	}
	return false
}

func TestOIDCCallback_OnlyTheStartingBrowserSignsIn(t *testing.T) {
	env := servicetest.Start(t)
	srv := New(env.Cfg, env.Services, nil, nil, nil, nil)
	const tenant = "oidc-csrf"
	const slug = "sso-csrf"
	env.SeedTenant(t, tenant)
	idp := newFakeIdP(t, "attacker-sub")
	var pid uuid.UUID
	if err := env.Super.QueryRow(context.Background(),
		`INSERT INTO oauth_providers (tenant_id, slug, display_name, kind, issuer_url, client_id, client_secret, enabled)
		 VALUES ($1, $2, 'SSO', 'oidc', $3, 'client-oidc', 'secret', true) RETURNING id`,
		tenant, slug, idp.srv.URL).Scan(&pid); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	attacker := mustWebUser(t, env, tenant, "attacker@a.test", "")
	if err := env.Services.OAuth.LinkIdentity(context.Background(), attacker, pid, "attacker-sub", "attacker@a.test"); err != nil {
		t.Fatalf("link identity: %v", err)
	}

	// The attacker starts a flow, signs in at the IdP and hands the callback
	// URL to the victim, whose browser never saw /start.
	cb, _ := idp.start(t, srv, slug)
	if rec := callback(srv, cb, nil); hasSession(rec) {
		t.Fatalf("victim browser signed into the attacker's account (%d %s)", rec.Code, rec.Header().Get("Location"))
	}
	idp.mu.Lock()
	exchanged := idp.tokens
	idp.mu.Unlock()
	if exchanged != 0 {
		t.Fatalf("callback without the start cookie reached the code exchange %d times", exchanged)
	}

	// The browser that started the flow signs in, so the refusal above is the binding.
	cb, cookies := idp.start(t, srv, slug)
	rec := callback(srv, cb, cookies)
	if !hasSession(rec) || rec.Code != http.StatusFound {
		t.Fatalf("starting browser = %d %q, want a session and a redirect", rec.Code, rec.Header().Get("Location"))
	}
	// The state cookie is single-use: replaying the callback in that browser fails.
	if again := callback(srv, cb, cookies); hasSession(again) {
		t.Fatal("callback replay signed in again")
	}
}
