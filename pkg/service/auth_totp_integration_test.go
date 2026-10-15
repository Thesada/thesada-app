//go:build integration

package service_test

import (
	"errors"
	"testing"
	"time"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
	"thesada.app/app/pkg/totp"
)

func TestFinishTOTPLoginAny_AcceptsOneGoodCodeAndReturnsTheMethod(t *testing.T) {
	env := servicetest.Start(t)
	auth := env.Services.Auth
	const tenant = "totp-rt"
	env.SeedTenant(t, tenant)
	u := mustCreateUser(t, auth, tenant, "totp-rt@a.test")
	if err := auth.SetPassword(tenant, u.ID, "correct-horse"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	raw, encoded, err := totp.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.SetTOTPSecret(tenant, u.ID, encoded); err != nil {
		t.Fatalf("SetTOTPSecret: %v", err)
	}
	gotSecret, on, err := auth.TOTPSecret(tenant, u.ID)
	if err != nil || !on || gotSecret != encoded {
		t.Fatalf("TOTPSecret on=%v secret=%q err=%v", on, gotSecret, err)
	}

	token, _, err := auth.BeginTOTPLogin(tenant, u.ID, "magic_link")
	if err != nil {
		t.Fatalf("BeginTOTPLogin: %v", err)
	}
	good := totp.Code(raw, time.Now())
	bad := "000000"
	if bad == good {
		bad = "111111"
	}
	_, _, err = auth.FinishTOTPLoginAny(token, bad)
	if !errors.Is(err, service.ErrBadCredentials) {
		t.Fatalf("wrong code = %v, want ErrBadCredentials", err)
	}
	passed, method, err := auth.FinishTOTPLoginAny(token, good)
	if err != nil {
		t.Fatalf("good code: %v", err)
	}
	if passed.ID != u.ID || method != "magic_link" {
		t.Fatalf("passed id=%s method=%s", passed.ID, method)
	}
	if _, _, err := auth.FinishTOTPLoginAny(token, totp.Code(raw, time.Now())); !errors.Is(err, service.ErrExpired) {
		t.Fatalf("reuse = %v, want ErrExpired", err)
	}
}

func TestFinishTOTPLoginAny_CorruptSecretIsNotABadCode(t *testing.T) {
	env := servicetest.Start(t)
	auth := env.Services.Auth
	const tenant = "totp-bad"
	env.SeedTenant(t, tenant)
	u := mustCreateUser(t, auth, tenant, "totp-bad@a.test")
	if err := auth.SetTOTPSecret(tenant, u.ID, "!!!"); err != nil {
		t.Fatalf("SetTOTPSecret: %v", err)
	}
	token, _, err := auth.BeginTOTPLogin(tenant, u.ID, "password")
	if err != nil {
		t.Fatalf("BeginTOTPLogin: %v", err)
	}
	_, _, err = auth.FinishTOTPLoginAny(token, "123456")
	if err == nil || errors.Is(err, service.ErrBadCredentials) {
		t.Fatalf("corrupt secret = %v, want a decode error", err)
	}
}
