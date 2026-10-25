//go:build integration

package service_test

import (
	"context"
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
	var lost []error
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := auth.FinishTOTPLoginAny(ch, codeV)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				wins++
			} else {
				lost = append(lost, err)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("parallel finishes won %d times, want 1", wins)
	}
	for _, err := range lost {
		if !errors.Is(err, service.ErrExpired) && !errors.Is(err, service.ErrBadCredentials) {
			t.Fatalf("a losing finish = %v, want ErrExpired or ErrBadCredentials", err)
		}
	}
}

// A finish that loses the race on the user row reads the challenge as gone:
// ErrExpired, never an internal error. The test holds the row lock itself so
// the interleaving is forced, not hoped for.
func TestTOTP_LostRaceIsExpired(t *testing.T) {
	env := servicetest.Start(t)
	auth := env.Services.Auth
	const tenant = "totp-race"
	env.SeedTenant(t, tenant)
	u := mustCreateUser(t, auth, tenant, "lost@a.test")
	raw, encoded, _ := totp.NewKey()
	if err := auth.SetTOTPSecret(tenant, u.ID, encoded); err != nil {
		t.Fatal(err)
	}
	ch, _, _ := auth.BeginTOTPLogin(tenant, u.ID, "password")
	code := totp.Code(raw, time.Now())
	step, _, _ := totp.CheckStep(encoded, code, time.Now())

	ctx := context.Background()
	lock, err := env.Super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Rollback(ctx) }()
	if _, err := lock.Exec(ctx, `SELECT 1 FROM users WHERE id = $1 FOR UPDATE`, u.ID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, _, err := auth.FinishTOTPLoginAny(ch, code); done <- err }()
	for i := 0; ; i++ {
		var waiting int
		if err := env.Super.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE NOT granted`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		if i == 100 {
			t.Fatal("the finish never blocked on the user row")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Play the winner: take the step, consume the challenge, commit.
	if _, err := lock.Exec(ctx, `UPDATE users SET totp_last_step = $2 WHERE id = $1`, u.ID, step); err != nil {
		t.Fatal(err)
	}
	if _, err := lock.Exec(ctx, `DELETE FROM totp_challenges WHERE user_id = $1`, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := lock.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, service.ErrExpired) {
		t.Fatalf("lost race = %v, want ErrExpired", err)
	}
}
