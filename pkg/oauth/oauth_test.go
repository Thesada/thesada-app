package oauth

// Contract tests for the OIDC client. Two harnesses keep this in the
// default (Docker-free) test lane:
//
//	fakeIDP     - an httptest OIDC provider (discovery + token + JWKS +
//	              userinfo) that mints RS256 id_tokens, exercising
//	              LoadProvider discovery and every Exchange branch.
//	fakeQuerier - a two-method stand-in for *pgxpool.Pool, exercising
//	              Start (state/nonce/PKCE generation) and LookupState
//	              (single-use + expiry) with no database.
//
// What must stay true is asserted directly; the inputs that must fail
// (bad nonce, wrong aud/iss/key, expired/unknown state, open-redirect
// return_to) each get their own case.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const testClientID = "test-client"

// ── fakeIDP ────────────────────────────────────────────────────────────

type fakeIDP struct {
	srv  *httptest.Server
	priv *rsa.PrivateKey
	kid  string

	// Per-test knobs.
	tokenStatus    int            // token endpoint HTTP status (0 => 200)
	includeIDToken bool           // include id_token in the token response
	idToken        string         // the id_token string to return
	userinfoBody   map[string]any // userinfo JSON (nil => 404)
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	idp := &fakeIDP{priv: priv, kid: "test-key"}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                idp.srv.URL,
			"authorization_endpoint":                idp.srv.URL + "/authorize",
			"token_endpoint":                        idp.srv.URL + "/token",
			"jwks_uri":                              idp.srv.URL + "/jwks",
			"userinfo_endpoint":                     idp.srv.URL + "/userinfo",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       &idp.priv.PublicKey,
			KeyID:     idp.kid,
			Algorithm: "RS256",
			Use:       "sig",
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		if idp.tokenStatus != 0 && idp.tokenStatus != http.StatusOK {
			http.Error(w, `{"error":"invalid_grant"}`, idp.tokenStatus)
			return
		}
		resp := map[string]any{
			"access_token": "fake-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		if idp.includeIDToken {
			resp["id_token"] = idp.idToken
		}
		writeJSON(w, resp)
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		if idp.userinfoBody == nil {
			http.Error(w, "no userinfo", http.StatusNotFound)
			return
		}
		writeJSON(w, idp.userinfoBody)
	})

	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// baseClaims returns a fresh, valid claim set. Tests mutate the map to
// build the must-fail variants.
func (idp *fakeIDP) baseClaims(nonce string) map[string]any {
	return map[string]any{
		"iss":                idp.srv.URL,
		"aud":                testClientID,
		"exp":                time.Now().Add(time.Hour).Unix(),
		"iat":                time.Now().Unix(),
		"sub":                "user-sub-123",
		"email":              "  User@Example.COM  ",
		"email_verified":     true,
		"name":               "Test User",
		"preferred_username": "tuser",
		"groups":             []string{"admins"},
		"nonce":              nonce,
	}
}

// mint signs claims as a compact JWS. signWith/kid default to the IdP's own
// key so the JWKS matches; pass an alternate key to forge a bad signature.
func (idp *fakeIDP) mint(t *testing.T, claims map[string]any, signWith *rsa.PrivateKey, kid string) string {
	t.Helper()
	if signWith == nil {
		signWith = idp.priv
	}
	if kid == "" {
		kid = idp.kid
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: signWith, KeyID: kid}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	s, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return s
}

// loadTestProvider runs discovery against the fake IdP and returns a ready
// Provider. redirectBase is fixed so redirect_uri derivation is assertable.
func loadTestProvider(t *testing.T, idp *fakeIDP) *Provider {
	t.Helper()
	p, err := LoadProvider(context.Background(), ProviderRow{
		ID:        uuid.New(),
		Slug:      "kanidm",
		Kind:      "oidc",
		IssuerURL: idp.srv.URL,
		ClientID:  testClientID,
		Scopes:    []string{"openid", "email", "profile"},
	}, "https://app.example.test/")
	if err != nil {
		t.Fatalf("LoadProvider: %v", err)
	}
	return p
}

// ── fakeQuerier ────────────────────────────────────────────────────────

type execCall struct {
	sql  string
	args []any
}

type fakeQuerier struct {
	execErr   error
	execCalls []execCall
	rowFn     func(dest ...any) error
	querySQL  []string
}

func (f *fakeQuerier) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.execCalls = append(f.execCalls, execCall{sql: sql, args: args})
	return pgconn.CommandTag{}, f.execErr
}

func (f *fakeQuerier) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	f.querySQL = append(f.querySQL, sql)
	return fakeRow{fn: f.rowFn}
}

// insertArgs returns the args of the oauth_auth_requests INSERT (skipping
// the best-effort sweep DELETE).
func (f *fakeQuerier) insertArgs(t *testing.T) []any {
	t.Helper()
	for _, c := range f.execCalls {
		if strings.Contains(c.sql, "INSERT INTO oauth_auth_requests") {
			return c.args
		}
	}
	t.Fatalf("no INSERT captured; calls=%d", len(f.execCalls))
	return nil
}

type fakeRow struct{ fn func(dest ...any) error }

func (r fakeRow) Scan(dest ...any) error { return r.fn(dest...) }

// ── LoadProvider ───────────────────────────────────────────────────────

func TestLoadProvider_RejectsNonOIDCKind(t *testing.T) {
	_, err := LoadProvider(context.Background(), ProviderRow{Kind: "saml"}, "https://app.example.test")
	if err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("kind=saml err = %v, want 'not implemented'", err)
	}
}

func TestLoadProvider_Discovers(t *testing.T) {
	idp := newFakeIDP(t)
	if p := loadTestProvider(t, idp); p == nil {
		t.Fatal("nil provider")
	}
}

// ── Start: PKCE + state + open-redirect ────────────────────────────────

func TestStart_PinsPKCEAndStateToPersistedRow(t *testing.T) {
	idp := newFakeIDP(t)
	p := loadTestProvider(t, idp)
	q := &fakeQuerier{}

	raw, err := p.Start(context.Background(), q, StartOpts{ReturnTo: "/dashboard"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse authorize URL: %v", err)
	}
	qp := u.Query()

	if got := qp.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", got)
	}
	if qp.Get("code_challenge") == "" {
		t.Error("code_challenge missing")
	}
	if qp.Get("state") == "" || qp.Get("nonce") == "" {
		t.Error("state or nonce missing from authorize URL")
	}
	if got := qp.Get("redirect_uri"); got != "https://app.example.test/auth/oidc/kanidm/callback" {
		t.Errorf("redirect_uri = %q, want derived callback", got)
	}

	// The persisted row must correspond to what the URL advertises.
	args := q.insertArgs(t)
	storedState, storedNonce, storedVerifier, storedReturn := args[0].(string), args[2].(string), args[3].(string), args[4].(string)
	if storedState != qp.Get("state") {
		t.Errorf("persisted state %q != URL state %q", storedState, qp.Get("state"))
	}
	if storedNonce != qp.Get("nonce") {
		t.Errorf("persisted nonce %q != URL nonce %q", storedNonce, qp.Get("nonce"))
	}
	if pkceChallenge(storedVerifier) != qp.Get("code_challenge") {
		t.Error("persisted pkce_verifier does not derive the URL code_challenge")
	}
	if storedReturn != "/dashboard" {
		t.Errorf("persisted return_to = %q, want /dashboard", storedReturn)
	}
}

func TestStart_UnsafeReturnToFallsBackToRoot(t *testing.T) {
	idp := newFakeIDP(t)
	p := loadTestProvider(t, idp)
	for _, bad := range []string{"//evil.example.com", "https://evil.example.com", "", `/\evil`} {
		q := &fakeQuerier{}
		if _, err := p.Start(context.Background(), q, StartOpts{ReturnTo: bad}); err != nil {
			t.Fatalf("Start(%q): %v", bad, err)
		}
		if got := q.insertArgs(t)[4].(string); got != "/" {
			t.Errorf("return_to for %q = %q, want / (open-redirect guard)", bad, got)
		}
	}
}

func TestStart_PropagatesPersistError(t *testing.T) {
	idp := newFakeIDP(t)
	p := loadTestProvider(t, idp)
	q := &fakeQuerier{execErr: errors.New("boom")}
	if _, err := p.Start(context.Background(), q, StartOpts{}); err == nil || !strings.Contains(err.Error(), "persist state") {
		t.Fatalf("err = %v, want 'persist state'", err)
	}
}

// ── LookupState: single-use + expiry ───────────────────────────────────

func TestLookupState_HitConsumesRow(t *testing.T) {
	pid := uuid.New()
	q := &fakeQuerier{rowFn: func(dest ...any) error {
		*(dest[0].(*uuid.UUID)) = pid
		*(dest[1].(*string)) = "the-nonce"
		*(dest[2].(*string)) = "the-verifier"
		*(dest[3].(*string)) = "/back"
		*(dest[4].(**uuid.UUID)) = nil
		*(dest[5].(*time.Time)) = time.Now().Add(time.Minute)
		return nil
	}}
	pr, err := LookupState(context.Background(), q, "some-state")
	if err != nil {
		t.Fatalf("LookupState: %v", err)
	}
	if pr.ProviderID != pid || pr.Nonce != "the-nonce" || pr.PKCEVerifier != "the-verifier" || pr.ReturnTo != "/back" {
		t.Errorf("resolved row = %+v", pr)
	}
	// Single-use: the read must be a deleting read.
	if len(q.querySQL) != 1 || !strings.Contains(q.querySQL[0], "DELETE FROM oauth_auth_requests") {
		t.Errorf("lookup query = %v, want a DELETE...RETURNING", q.querySQL)
	}
}

func TestLookupState_UnknownReturnsSentinel(t *testing.T) {
	q := &fakeQuerier{rowFn: func(_ ...any) error { return pgx.ErrNoRows }}
	if _, err := LookupState(context.Background(), q, "nope"); !errors.Is(err, ErrUnknownState) {
		t.Fatalf("err = %v, want ErrUnknownState", err)
	}
}

func TestLookupState_ExpiredReturnsSentinel(t *testing.T) {
	q := &fakeQuerier{rowFn: func(dest ...any) error {
		*(dest[0].(*uuid.UUID)) = uuid.New()
		*(dest[1].(*string)) = "n"
		*(dest[2].(*string)) = "v"
		*(dest[3].(*string)) = "/"
		*(dest[4].(**uuid.UUID)) = nil
		*(dest[5].(*time.Time)) = time.Now().Add(-time.Minute) // already expired
		return nil
	}}
	if _, err := LookupState(context.Background(), q, "stale"); !errors.Is(err, ErrUnknownState) {
		t.Fatalf("expired err = %v, want ErrUnknownState", err)
	}
}

func TestLookupState_PropagatesOtherError(t *testing.T) {
	q := &fakeQuerier{rowFn: func(_ ...any) error { return errors.New("db down") }}
	_, err := LookupState(context.Background(), q, "x")
	if err == nil || errors.Is(err, ErrUnknownState) || !strings.Contains(err.Error(), "db down") {
		t.Fatalf("err = %v, want raw db error", err)
	}
}

// ── Exchange: id_token verification + nonce + subject + email ──────────

func exchangeHelper(t *testing.T, idp *fakeIDP, claims map[string]any, pendingNonce string) (*Claims, error) {
	t.Helper()
	p := loadTestProvider(t, idp)
	idp.idToken = idp.mint(t, claims, nil, "")
	idp.includeIDToken = true
	return p.Exchange(context.Background(), "auth-code", &PendingRequest{
		Nonce:        pendingNonce,
		PKCEVerifier: "verifier",
	})
}

func TestExchange_HappyPath_NormalizesEmail(t *testing.T) {
	idp := newFakeIDP(t)
	c, err := exchangeHelper(t, idp, idp.baseClaims("nonce-1"), "nonce-1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if c.Email != "user@example.com" {
		t.Errorf("Email = %q, want lowercased+trimmed", c.Email)
	}
	if c.Subject != "user-sub-123" || !c.EmailVerified || c.PreferredUser != "tuser" {
		t.Errorf("claims = %+v", c)
	}
	if len(c.Groups) != 1 || c.Groups[0] != "admins" {
		t.Errorf("groups = %v", c.Groups)
	}
}

func TestExchange_RejectsNonceMismatch(t *testing.T) {
	idp := newFakeIDP(t)
	_, err := exchangeHelper(t, idp, idp.baseClaims("token-nonce"), "expected-nonce")
	if err == nil || !strings.Contains(err.Error(), "nonce mismatch") {
		t.Fatalf("err = %v, want nonce mismatch", err)
	}
}

func TestExchange_RejectsMissingIDToken(t *testing.T) {
	idp := newFakeIDP(t)
	p := loadTestProvider(t, idp)
	idp.includeIDToken = false // token response omits id_token
	_, err := p.Exchange(context.Background(), "code", &PendingRequest{Nonce: "n", PKCEVerifier: "v"})
	if err == nil || !strings.Contains(err.Error(), "missing id_token") {
		t.Fatalf("err = %v, want missing id_token", err)
	}
}

func TestExchange_RejectsBadSignature(t *testing.T) {
	idp := newFakeIDP(t)
	p := loadTestProvider(t, idp)
	alt, _ := rsa.GenerateKey(rand.Reader, 2048)
	idp.idToken = idp.mint(t, idp.baseClaims("n"), alt, idp.kid) // signed by a key not in JWKS
	idp.includeIDToken = true
	if _, err := p.Exchange(context.Background(), "code", &PendingRequest{Nonce: "n", PKCEVerifier: "v"}); err == nil || !strings.Contains(err.Error(), "verify id_token") {
		t.Fatalf("err = %v, want verify id_token failure", err)
	}
}

func TestExchange_RejectsWrongAudience(t *testing.T) {
	idp := newFakeIDP(t)
	claims := idp.baseClaims("n")
	claims["aud"] = "some-other-client"
	if _, err := exchangeHelper(t, idp, claims, "n"); err == nil || !strings.Contains(err.Error(), "verify id_token") {
		t.Fatalf("err = %v, want audience failure", err)
	}
}

func TestExchange_RejectsWrongIssuer(t *testing.T) {
	idp := newFakeIDP(t)
	claims := idp.baseClaims("n")
	claims["iss"] = "https://evil.example.com"
	if _, err := exchangeHelper(t, idp, claims, "n"); err == nil || !strings.Contains(err.Error(), "verify id_token") {
		t.Fatalf("err = %v, want issuer failure", err)
	}
}

func TestExchange_RequiresSubject(t *testing.T) {
	idp := newFakeIDP(t)
	claims := idp.baseClaims("n")
	delete(claims, "sub") // valid signature, but no subject anywhere
	if _, err := exchangeHelper(t, idp, claims, "n"); err == nil || !strings.Contains(err.Error(), "missing subject") {
		t.Fatalf("err = %v, want missing subject", err)
	}
}

func TestExchange_FallsBackToUserinfoForEmail(t *testing.T) {
	idp := newFakeIDP(t)
	claims := idp.baseClaims("n")
	delete(claims, "email") // id_token omits email => userinfo consulted
	idp.userinfoBody = map[string]any{"sub": "user-sub-123", "email": "Fallback@Example.COM"}
	c, err := exchangeHelper(t, idp, claims, "n")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if c.Email != "fallback@example.com" {
		t.Errorf("Email = %q, want userinfo fallback lowercased", c.Email)
	}
}

func TestExchange_PropagatesTokenEndpointError(t *testing.T) {
	idp := newFakeIDP(t)
	p := loadTestProvider(t, idp)
	idp.tokenStatus = http.StatusBadRequest
	if _, err := p.Exchange(context.Background(), "bad-code", &PendingRequest{Nonce: "n", PKCEVerifier: "v"}); err == nil || !strings.Contains(err.Error(), "exchange") {
		t.Fatalf("err = %v, want exchange failure", err)
	}
}

// ── Pure helpers ───────────────────────────────────────────────────────

func TestIsSafeReturnTo(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"/", true},
		{"/devices", true},
		{"/a/b?x=1", true},
		{"", false},
		{"devices", false},            // no leading slash
		{"//evil.example.com", false}, // scheme-relative
		{`/\evil.example.com`, false}, // backslash authority trick
		{"https://evil.example.com", false},
		{"http://evil.example.com", false},
		{"/\x7f\x01", false}, // control chars => url.Parse rejects
	}
	for _, c := range cases {
		if got := IsSafeReturnTo(c.in); got != c.want {
			t.Errorf("IsSafeReturnTo(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestPKCEChallenge_RFC7636Vector(t *testing.T) {
	// Appendix B of RFC 7636.
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const want = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := pkceChallenge(verifier); got != want {
		t.Errorf("pkceChallenge = %q, want %q", got, want)
	}
}

func TestRandomURLSafe_DistinctURLSafeNoPadding(t *testing.T) {
	a, err := randomURLSafe(32)
	if err != nil {
		t.Fatalf("randomURLSafe: %v", err)
	}
	b, err := randomURLSafe(32)
	if err != nil {
		t.Fatalf("randomURLSafe: %v", err)
	}
	if a == b {
		t.Error("two calls produced identical output")
	}
	if strings.ContainsAny(a, "=+/") {
		t.Errorf("output %q is not raw-url-safe", a)
	}
	raw, err := base64.RawURLEncoding.DecodeString(a)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("decoded %d bytes, want 32", len(raw))
	}
}
