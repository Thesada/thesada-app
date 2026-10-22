//go:build integration

package service_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
	"thesada.app/app/pkg/totp"
)

// A TOTP code signs in once: a second login with the same code inside its
// validity window is refused, on the challenge path and the direct API path,
// and two parallel finishes of one challenge yield one session.
func TestTOTP_CodeSignsInOnce(t *testing.T) {
	env := servicetest.Start(t)
	auth := env.Services.Auth
	const tenant = "totp-replay"
	env.SeedTenant(t, tenant)
	u := mustCreateUser(t, auth, tenant, "replay@a.test")
	raw, encoded, err := totp.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := auth.SetTOTPSecret(tenant, u.ID, encoded); err != nil {
		t.Fatal(err)
	}
	code := totp.Code(raw, time.Now())

	first, _, _ := auth.BeginTOTPLogin(tenant, u.ID, "password")
	if _, _, err := auth.FinishTOTPLoginAny(first, code); err != nil {
		t.Fatalf("first login: %v", err)
	}
	second, _, _ := auth.BeginTOTPLogin(tenant, u.ID, "password")
	if _, _, err := auth.FinishTOTPLoginAny(second, code); !errors.Is(err, service.ErrBadCredentials) {
		t.Fatalf("replayed code on a new challenge = %v, want ErrBadCredentials", err)
	}
	if ok, err := auth.AcceptTOTPLogin(tenant, u.ID, encoded, code); err != nil || ok {
		t.Fatalf("replayed code on the API path = %v %v, want refused", ok, err)
	}

	// Parallel finishes: same fresh user and code, one challenge, one winner.
	v := mustCreateUser(t, auth, tenant, "race@a.test")
	rawV, encV, _ := totp.NewKey()
	if err := auth.SetTOTPSecret(tenant, v.ID, encV); err != nil {
		t.Fatal(err)
	}
	ch, _, _ := auth.BeginTOTPLogin(tenant, v.ID, "password")
	codeV := totp.Code(rawV, time.Now())
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := auth.FinishTOTPLoginAny(ch, codeV); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("parallel finishes won %d times, want 1", wins)
	}
}
