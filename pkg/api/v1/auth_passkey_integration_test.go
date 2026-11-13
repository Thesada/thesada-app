//go:build integration

package v1_test

import (
	"net/http"
	"strings"
	"testing"

	apiv1 "thesada.app/app/pkg/api/v1"
	"thesada.app/app/pkg/service/servicetest"
	"thesada.app/app/pkg/webauthntest"
)

// TestAuthPasskey_APIRefusesAPasskeyOnlyAccount checks that the JSON logins,
// which cannot run a WebAuthn ceremony, never skip a passkey second factor.
// in: t. out: none.
func TestAuthPasskey_APIRefusesAPasskeyOnlyAccount(t *testing.T) {
	env := servicetest.Start(t)
	srv := apiv1.New(env.Cfg, env.Services, nil, nil)
	const tenant = "pk-api"
	env.SeedTenant(t, tenant)
	auth := env.Services.Auth

	u, err := auth.CreateUser(tenant, "pk-api@a.test", "pk", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.SetPassword(tenant, u.ID, "correct-horse"); err != nil {
		t.Fatal(err)
	}

	before := post(srv, "/auth/login", `{"email":"pk-api@a.test","password":"correct-horse"}`, nil)
	if before.Code != http.StatusOK {
		t.Fatalf("no second factor yet = %d %s", before.Code, before.Body.String())
	}

	key, err := webauthntest.New(servicetest.PasskeyRPID, servicetest.PasskeyOrigin)
	if err != nil {
		t.Fatal(err)
	}
	opts, token, _, err := auth.BeginPasskeyRegistration(tenant, u)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := key.Register(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.FinishPasskeyRegistration(tenant, u, token, "api key", resp); err != nil {
		t.Fatal(err)
	}

	login := post(srv, "/auth/login", `{"email":"pk-api@a.test","password":"correct-horse"}`, nil)
	if login.Code != http.StatusUnauthorized || !strings.Contains(login.Body.String(), "passkey_required") {
		t.Fatalf("password login = %d %s, want 401 passkey_required", login.Code, login.Body.String())
	}
	link, _, err := auth.CreateMagicLink(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	magic := post(srv, "/auth/magic-link/verify", `{"token":"`+link+`"}`, nil)
	if magic.Code != http.StatusUnauthorized || !strings.Contains(magic.Body.String(), "passkey_required") {
		t.Fatalf("magic link = %d %s, want 401 passkey_required", magic.Code, magic.Body.String())
	}
}
