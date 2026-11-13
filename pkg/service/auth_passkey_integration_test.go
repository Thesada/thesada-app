//go:build integration

package service_test

import (
	"context"
	"errors"
	"testing"

	"thesada.app/app/pkg/db"
	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
	"thesada.app/app/pkg/webauthntest"

	"github.com/jackc/pgx/v5"
)

// enrollPasskey runs a full registration ceremony with a software authenticator.
func enrollPasskey(t *testing.T, auth *service.AuthService, tenant string, u *service.User, name string) *webauthntest.Authenticator {
	t.Helper()
	key, err := webauthntest.New(servicetest.PasskeyRPID, servicetest.PasskeyOrigin)
	if err != nil {
		t.Fatal(err)
	}
	opts, token, _, err := auth.BeginPasskeyRegistration(tenant, u)
	if err != nil {
		t.Fatalf("BeginPasskeyRegistration: %v", err)
	}
	resp, err := key.Register(opts)
	if err != nil {
		t.Fatalf("authenticator register: %v", err)
	}
	if err := auth.FinishPasskeyRegistration(tenant, u, token, name, resp); err != nil {
		t.Fatalf("FinishPasskeyRegistration: %v", err)
	}
	return key
}

// passkeyLogin runs begin and finish for one challenge.
func passkeyLogin(t *testing.T, auth *service.AuthService, key *webauthntest.Authenticator, challenge string) (*service.User, string, error) {
	t.Helper()
	opts, err := auth.BeginPasskeyLoginAny(challenge)
	if err != nil {
		return nil, "", err
	}
	resp, err := key.Login(opts)
	if err != nil {
		t.Fatalf("authenticator login: %v", err)
	}
	return auth.FinishPasskeyLoginAny(challenge, resp)
}

func TestPasskey_EnrollLoginReplayRemove(t *testing.T) {
	env := servicetest.Start(t)
	auth := env.Services.Auth
	const tenant = "pk-a"
	env.SeedTenant(t, tenant)
	u := mustCreateUser(t, auth, tenant, "pk@a.test")
	if err := auth.SetPassword(tenant, u.ID, "correct-horse"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if !auth.PasskeysEnabled() {
		t.Fatal("test config must enable passkeys")
	}

	if secret, keys, err := auth.SecondFactors(tenant, u.ID); err != nil || secret != "" || keys {
		t.Fatalf("before enroll: secret=%q keys=%v err=%v", secret, keys, err)
	}
	key := enrollPasskey(t, auth, tenant, u, "Bench key")
	list, err := auth.ListPasskeys(tenant, u.ID)
	if err != nil || len(list) != 1 || list[0].Name != "Bench key" || list[0].LastUsedAt != nil {
		t.Fatalf("list after enroll: %+v err=%v", list, err)
	}
	if _, keys, err := auth.SecondFactors(tenant, u.ID); err != nil || !keys {
		t.Fatalf("after enroll keys=%v err=%v", keys, err)
	}

	t.Run("login passes and consumes the challenge", func(t *testing.T) {
		challenge, _, err := auth.BeginTOTPLogin(tenant, u.ID, "password")
		if err != nil {
			t.Fatal(err)
		}
		totpOn, keys, err := auth.PendingFactorsAny(challenge)
		if err != nil || totpOn || !keys {
			t.Fatalf("PendingFactorsAny totp=%v keys=%v err=%v", totpOn, keys, err)
		}
		got, method, err := passkeyLogin(t, auth, key, challenge)
		if err != nil || got.ID != u.ID || method != "password" {
			t.Fatalf("login: user=%v method=%q err=%v", got, method, err)
		}
		if _, err := auth.BeginPasskeyLoginAny(challenge); !errors.Is(err, service.ErrExpired) {
			t.Fatalf("reuse = %v, want ErrExpired", err)
		}
		list, _ := auth.ListPasskeys(tenant, u.ID)
		if list[0].LastUsedAt == nil {
			t.Fatal("last_used_at not set")
		}
	})

	t.Run("replayed sign count is refused", func(t *testing.T) {
		challenge, _, err := auth.BeginTOTPLogin(tenant, u.ID, "password")
		if err != nil {
			t.Fatal(err)
		}
		key.Counter-- // the next assertion repeats the counter the server stored
		if _, _, err := passkeyLogin(t, auth, key, challenge); !errors.Is(err, service.ErrBadCredentials) {
			t.Fatalf("replay = %v, want ErrBadCredentials", err)
		}
		// The ceremony is spent, the challenge survives for another try.
		if _, _, err := passkeyLogin(t, auth, key, challenge); err != nil {
			t.Fatalf("fresh assertion after a refused one: %v", err)
		}
	})

	t.Run("an assertion for another challenge is refused", func(t *testing.T) {
		c1, _, _ := auth.BeginTOTPLogin(tenant, u.ID, "password")
		c2, _, _ := auth.BeginTOTPLogin(tenant, u.ID, "password")
		opts, err := auth.BeginPasskeyLoginAny(c1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := auth.BeginPasskeyLoginAny(c2); err != nil {
			t.Fatal(err)
		}
		resp, _ := key.Login(opts)
		if _, _, err := auth.FinishPasskeyLoginAny(c2, resp); !errors.Is(err, service.ErrBadCredentials) {
			t.Fatalf("cross-challenge = %v, want ErrBadCredentials", err)
		}
	})

	t.Run("a second key cannot be the same credential", func(t *testing.T) {
		opts, token, _, err := auth.BeginPasskeyRegistration(tenant, u)
		if err != nil {
			t.Fatal(err)
		}
		resp, _ := key.Register(opts)
		if err := auth.FinishPasskeyRegistration(tenant, u, token, "dup", resp); !errors.Is(err, service.ErrBadCredentials) {
			t.Fatalf("same credential twice = %v, want ErrBadCredentials", err)
		}
	})

	t.Run("removal", func(t *testing.T) {
		list, _ := auth.ListPasskeys(tenant, u.ID)
		if err := auth.DeletePasskey(tenant, u.ID, list[0].ID); err != nil {
			t.Fatalf("DeletePasskey: %v", err)
		}
		if err := auth.DeletePasskey(tenant, u.ID, list[0].ID); !errors.Is(err, service.ErrNotFound) {
			t.Fatalf("second delete = %v, want ErrNotFound", err)
		}
		challenge, _, _ := auth.BeginTOTPLogin(tenant, u.ID, "password")
		if _, err := auth.BeginPasskeyLoginAny(challenge); !errors.Is(err, service.ErrBadCredentials) {
			t.Fatalf("login with no keys = %v, want ErrBadCredentials", err)
		}
	})
}

func TestPasskey_ConfirmPassword(t *testing.T) {
	env := servicetest.Start(t)
	auth := env.Services.Auth
	const tenant = "pk-pw"
	env.SeedTenant(t, tenant)
	u := mustCreateUser(t, auth, tenant, "pw@a.test")
	if err := auth.SetPassword(tenant, u.ID, "correct-horse"); err != nil {
		t.Fatal(err)
	}
	if ok, err := auth.ConfirmPassword(tenant, u.ID, "correct-horse"); err != nil || !ok {
		t.Fatalf("right password ok=%v err=%v", ok, err)
	}
	if ok, err := auth.ConfirmPassword(tenant, u.ID, "wrong"); err != nil || ok {
		t.Fatalf("wrong password ok=%v err=%v", ok, err)
	}
}

func TestPasskey_RLSIsolatesTenants(t *testing.T) {
	env := servicetest.Start(t)
	auth := env.Services.Auth
	env.SeedTenant(t, "pk-iso-a")
	env.SeedTenant(t, "pk-iso-b")
	a := mustCreateUser(t, auth, "pk-iso-a", "a@iso.test")
	mustCreateUser(t, auth, "pk-iso-b", "b@iso.test")
	enrollPasskey(t, auth, "pk-iso-a", a, "A key")

	// Tenant B's session reading A's user id sees nothing and deletes nothing.
	list, err := auth.ListPasskeys("pk-iso-b", a.ID)
	if err != nil || len(list) != 0 {
		t.Fatalf("B lists A's keys: %+v err=%v", list, err)
	}
	ownList, _ := auth.ListPasskeys("pk-iso-a", a.ID)
	if err := auth.DeletePasskey("pk-iso-b", a.ID, ownList[0].ID); !errors.Is(err, service.ErrNotFound) {
		t.Fatalf("B deletes A's key = %v, want ErrNotFound", err)
	}
	if has, err := auth.HasPasskeys("pk-iso-b", a.ID); err != nil || has {
		t.Fatalf("B sees A's keys has=%v err=%v", has, err)
	}

	// Raw insert under B's tenant naming A's user is refused by WITH CHECK.
	ctx := context.Background()
	err = db.WithTenant(ctx, env.Pools.App, "pk-iso-b", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO user_passkeys (user_id, credential_id, public_key, name)
			VALUES ($1, 'iso-x', '\x00', 'x')`, a.ID)
		return err
	})
	if err == nil {
		t.Fatal("tenant B inserted a passkey for tenant A's user")
	}
}
