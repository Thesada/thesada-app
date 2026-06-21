//go:build integration

// /api/v1 auth-handler integration tests. Drives the JSON
// login / logout / signup handlers through the api Server against a real
// TimescaleDB: password login mints a working bearer token + session cookie,
// bad creds 401, malformed input 400, logout revokes the bearer, and signup
// lands a waitlist row.
//
//	go test -tags integration -run TestAuthHandlers ./pkg/api/v1/...
package v1_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	apiv1 "thesada.app/app/pkg/api/v1"
	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

type loginResp struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	User      struct {
		ID           string `json:"id"`
		Email        string `json:"email"`
		TenantID     string `json:"tenant_id"`
		IsSuperAdmin bool   `json:"is_super_admin"`
	} `json:"user"`
}

// post sends a JSON request to srv and returns the recorder.
func post(srv http.Handler, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func TestAuthHandlers(t *testing.T) {
	env := servicetest.Start(t)
	srv := apiv1.New(env.Cfg, env.Services, nil)

	const tenant = "apiauth-a"
	env.SeedTenant(t, tenant)
	u, err := env.Services.Auth.CreateUser(tenant, "user@example.com", "User", false)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := env.Services.Auth.SetPassword(tenant, u.ID, "correct horse battery"); err != nil {
		t.Fatalf("set password: %v", err)
	}

	// --- login: happy -------------------------------------------------------
	rec := post(srv, "/auth/login", `{"email":"user@example.com","password":"correct horse battery"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login: got %d (%s), want 200", rec.Code, rec.Body.String())
	}
	var lr loginResp
	if err := json.Unmarshal(rec.Body.Bytes(), &lr); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if lr.Token == "" || lr.User.ID != u.ID.String() || lr.User.TenantID != tenant {
		t.Errorf("login body = %+v, want token + user %s/%s", lr, u.ID, tenant)
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "thesada_session=") {
		t.Errorf("login did not set the session cookie: %q", rec.Header().Get("Set-Cookie"))
	}
	// the issued bearer token must actually validate
	if got, err := env.Services.ApiTokens.ValidateToken(lr.Token); err != nil || got.ID != u.ID {
		t.Errorf("issued token did not validate: user=%v err=%v", got, err)
	}

	// --- login: bad password -> 401 ----------------------------------------
	if rec := post(srv, "/auth/login", `{"email":"user@example.com","password":"wrong"}`, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("bad password: got %d, want 401", rec.Code)
	}
	// --- login: unknown email -> 401, indistinguishable from wrong password -
	// (no user enumeration - see docs/invariants.md).
	if rec := post(srv, "/auth/login", `{"email":"nobody@example.com","password":"whatever"}`, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("unknown email: got %d, want 401 (no enumeration)", rec.Code)
	}
	// --- login: malformed / missing -> 400 ---------------------------------
	if rec := post(srv, "/auth/login", `not json`, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("bad JSON: got %d, want 400", rec.Code)
	}
	if rec := post(srv, "/auth/login", `{"email":"user@example.com"}`, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("missing password: got %d, want 400", rec.Code)
	}

	// --- logout with the bearer revokes it ----------------------------------
	if rec := post(srv, "/auth/logout", ``, map[string]string{"Authorization": "Bearer " + lr.Token}); rec.Code != http.StatusOK {
		t.Errorf("logout: got %d, want 200", rec.Code)
	}
	if _, err := env.Services.ApiTokens.ValidateToken(lr.Token); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("token still valid after logout: %v", err)
	}

	// --- signup lands a waitlist row ----------------------------------------
	if rec := post(srv, "/auth/signup", `{"email":"new@example.com","note":"hi"}`, nil); rec.Code != http.StatusOK {
		t.Errorf("signup: got %d (%s), want 200", rec.Code, rec.Body.String())
	}
	var n int
	if err := env.Super.QueryRow(context.Background(),
		`SELECT count(*) FROM waitlist WHERE email = $1`, "new@example.com").Scan(&n); err != nil {
		t.Fatalf("count waitlist: %v", err)
	}
	if n != 1 {
		t.Errorf("waitlist rows for new@example.com = %d, want 1", n)
	}
}
