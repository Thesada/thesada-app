//go:build integration

package v1_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	apiv1 "thesada.app/app/pkg/api/v1"
	"thesada.app/app/pkg/service/servicetest"
	"thesada.app/app/pkg/totp"
)

// TestAuthTOTP_APILogsChallengeAndRejectsABadSecret checks the JSON TOTP contract.
// in: t. out: none.
func TestAuthTOTP_APILogsChallengeAndRejectsABadSecret(t *testing.T) {
	env := servicetest.Start(t)
	srv := apiv1.New(env.Cfg, env.Services, nil, nil)
	const tenant = "totp-api"
	env.SeedTenant(t, tenant)
	auth := env.Services.Auth
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	raw, encoded, err := totp.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	u, err := auth.CreateUser(tenant, "totp-api@a.test", "totp", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.SetPassword(tenant, u.ID, "correct-horse"); err != nil {
		t.Fatal(err)
	}
	if err := auth.SetTOTPSecret(tenant, u.ID, encoded); err != nil {
		t.Fatal(err)
	}

	logs.Reset()
	empty := post(srv, "/auth/login", `{"email":"totp-api@a.test","password":"correct-horse"}`, nil)
	if empty.Code != http.StatusUnauthorized || !strings.Contains(empty.Body.String(), "totp_required") {
		t.Fatalf("empty code = %d %s", empty.Code, empty.Body.String())
	}
	if !strings.Contains(logs.String(), "from=password") || !strings.Contains(logs.String(), "to=challenged") {
		t.Fatalf("empty code log = %s", logs.String())
	}

	logs.Reset()
	good := post(srv, "/auth/login", `{"email":"totp-api@a.test","password":"correct-horse","code":"`+totp.Code(raw, time.Now())+`"}`, nil)
	if good.Code != http.StatusOK {
		t.Fatalf("good code = %d %s", good.Code, good.Body.String())
	}
	if !strings.Contains(logs.String(), "to=challenged") || !strings.Contains(logs.String(), "to=passed") {
		t.Fatalf("good code log = %s", logs.String())
	}

	linkUser, err := auth.CreateUser(tenant, "totp-link@a.test", "link", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.SetTOTPSecret(tenant, linkUser.ID, encoded); err != nil {
		t.Fatal(err)
	}
	token, _, err := auth.CreateMagicLink(linkUser.ID)
	if err != nil {
		t.Fatal(err)
	}
	logs.Reset()
	same := post(srv, "/auth/magic-link/verify", `{"token":"`+token+`","code":"`+totp.Code(raw, time.Now())+`"}`, nil)
	if same.Code != http.StatusOK {
		t.Fatalf("magic code = %d %s", same.Code, same.Body.String())
	}
	if !strings.Contains(logs.String(), "from=magic_link") || !strings.Contains(logs.String(), "to=challenged") || !strings.Contains(logs.String(), "to=passed") {
		t.Fatalf("magic log = %s", logs.String())
	}

	badUser, err := auth.CreateUser(tenant, "totp-badapi@a.test", "bad", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.SetPassword(tenant, badUser.ID, "correct-horse"); err != nil {
		t.Fatal(err)
	}
	if err := auth.SetTOTPSecret(tenant, badUser.ID, "!!!"); err != nil {
		t.Fatal(err)
	}
	corrupt := post(srv, "/auth/login", `{"email":"totp-badapi@a.test","password":"correct-horse","code":"123456"}`, nil)
	if corrupt.Code != http.StatusInternalServerError {
		t.Fatalf("corrupt secret = %d, want 500", corrupt.Code)
	}

	limited := false
	for i := 0; i < 40; i++ {
		req := httptest.NewRequest(http.MethodPost, "/auth/totp", strings.NewReader(`{"challenge":"nope","code":"123456"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.60:9"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("finish attempt %d = %d %s", i, rec.Code, rec.Body.String())
		}
	}
	if !limited {
		t.Fatal("api totp finish was not rate limited")
	}
}
