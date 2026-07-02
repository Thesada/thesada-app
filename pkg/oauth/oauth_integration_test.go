//go:build integration

// Real-Postgres contracts for the OIDC auth-request state store. Start
// persists a single-use, expiring, PKCE-bound request row; LookupState
// consumes it exactly once. No mocked DB (AGENTS.md) - these run under the
// integration tag against a testcontainers TimescaleDB, on the same admin
// (BYPASSRLS) pool the service layer uses.
//
//	go test -tags integration -run TestOAuthState ./pkg/oauth/...
package oauth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/uuid"

	"thesada.app/app/pkg/oauth"
	"thesada.app/app/pkg/service/servicetest"
)

// discoveryIDP serves just enough OIDC discovery for LoadProvider to build a
// Provider. Start only reads the authorize endpoint; no token/JWKS round-trip.
func discoveryIDP(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                srv.URL,
			"authorization_endpoint":                srv.URL + "/authorize",
			"token_endpoint":                        srv.URL + "/token",
			"jwks_uri":                              srv.URL + "/jwks",
			"userinfo_endpoint":                     srv.URL + "/userinfo",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// seedProvider creates a tenant + enabled oauth_providers row, returning its id
// for use as ProviderRow.ID (the FK target of oauth_auth_requests.provider_id).
func seedProvider(t *testing.T, env *servicetest.Env, tenant, issuerURL string) uuid.UUID {
	t.Helper()
	env.SeedTenant(t, tenant)
	var id uuid.UUID
	if err := env.Super.QueryRow(context.Background(),
		`INSERT INTO oauth_providers (tenant_id, slug, display_name, kind, issuer_url, client_id, enabled)
		 VALUES ($1, 'kanidm-int', 'SSO', 'oidc', $2, 'client-int', true) RETURNING id`,
		tenant, issuerURL).Scan(&id); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	return id
}

func loadProvider(t *testing.T, idpURL string, pid uuid.UUID) *oauth.Provider {
	t.Helper()
	p, err := oauth.LoadProvider(context.Background(), oauth.ProviderRow{
		ID:        pid,
		Slug:      "kanidm-int",
		Kind:      "oidc",
		IssuerURL: idpURL,
		ClientID:  "client-int",
		Scopes:    []string{"openid", "email"},
	}, "https://app.example.test/")
	if err != nil {
		t.Fatalf("LoadProvider: %v", err)
	}
	return p
}

func TestOAuthState_StartPersistsAndLookupConsumes(t *testing.T) {
	env := servicetest.Start(t)
	idp := discoveryIDP(t)
	ctx := context.Background()
	pid := seedProvider(t, env, "oauth-state-a", idp.URL)
	p := loadProvider(t, idp.URL, pid)

	raw, err := p.Start(ctx, env.Pools.Admin, oauth.StartOpts{ReturnTo: "/dashboard"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	qp := mustQuery(t, raw)
	state := qp.Get("state")
	if state == "" || qp.Get("nonce") == "" {
		t.Fatal("authorize URL missing state/nonce")
	}
	if qp.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", qp.Get("code_challenge_method"))
	}

	// The persisted row matches the URL, and its verifier derives the challenge.
	var nonce, verifier, returnTo string
	var gotProvider uuid.UUID
	if err := env.Super.QueryRow(ctx,
		`SELECT provider_id, nonce, pkce_verifier, return_to FROM oauth_auth_requests WHERE state = $1`,
		state).Scan(&gotProvider, &nonce, &verifier, &returnTo); err != nil {
		t.Fatalf("read back persisted request: %v", err)
	}
	if gotProvider != pid || nonce != qp.Get("nonce") || returnTo != "/dashboard" {
		t.Errorf("persisted row mismatch: provider=%v nonce=%q return_to=%q", gotProvider, nonce, returnTo)
	}
	sum := sha256.Sum256([]byte(verifier))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); want != qp.Get("code_challenge") {
		t.Error("persisted pkce_verifier does not derive the URL code_challenge")
	}

	// LookupState consumes the row (single-use): first hit resolves, second misses.
	pr, err := oauth.LookupState(ctx, env.Pools.Admin, state)
	if err != nil {
		t.Fatalf("LookupState hit: %v", err)
	}
	if pr.ProviderID != pid || pr.Nonce != nonce || pr.PKCEVerifier != verifier || pr.ReturnTo != "/dashboard" {
		t.Errorf("resolved request mismatch: %+v", pr)
	}
	if _, err := oauth.LookupState(ctx, env.Pools.Admin, state); !errors.Is(err, oauth.ErrUnknownState) {
		t.Errorf("second lookup = %v, want ErrUnknownState (single-use)", err)
	}
}

func TestOAuthState_StartRejectsUnsafeReturnTo(t *testing.T) {
	env := servicetest.Start(t)
	idp := discoveryIDP(t)
	ctx := context.Background()
	pid := seedProvider(t, env, "oauth-state-b", idp.URL)
	p := loadProvider(t, idp.URL, pid)

	raw, err := p.Start(ctx, env.Pools.Admin, oauth.StartOpts{ReturnTo: "//evil.example.com"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	state := mustQuery(t, raw).Get("state")

	var returnTo string
	if err := env.Super.QueryRow(ctx,
		`SELECT return_to FROM oauth_auth_requests WHERE state = $1`, state).Scan(&returnTo); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if returnTo != "/" {
		t.Errorf("persisted return_to = %q, want / (open-redirect guard)", returnTo)
	}
}

func TestOAuthState_LookupUnknownAndExpired(t *testing.T) {
	env := servicetest.Start(t)
	ctx := context.Background()
	pid := seedProvider(t, env, "oauth-state-c", "https://idp.invalid/")

	if _, err := oauth.LookupState(ctx, env.Pools.Admin, "never-issued"); !errors.Is(err, oauth.ErrUnknownState) {
		t.Errorf("unknown state = %v, want ErrUnknownState", err)
	}

	// Expired row is treated as unknown even though it is still present.
	if _, err := env.Pools.Admin.Exec(ctx,
		`INSERT INTO oauth_auth_requests (state, provider_id, nonce, pkce_verifier, return_to, expires_at)
		 VALUES ('expired-state', $1, 'n', 'v', '/', now() - interval '1 minute')`, pid); err != nil {
		t.Fatalf("seed expired request: %v", err)
	}
	if _, err := oauth.LookupState(ctx, env.Pools.Admin, "expired-state"); !errors.Is(err, oauth.ErrUnknownState) {
		t.Errorf("expired state = %v, want ErrUnknownState", err)
	}
}

func mustQuery(t *testing.T, rawURL string) url.Values {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse authorize URL: %v", err)
	}
	return u.Query()
}
