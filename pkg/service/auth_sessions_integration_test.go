//go:build integration

// AuthService session integration tests. The
// security-critical session surface against a real TimescaleDB: create ->
// validate lifecycle, lifetime by auth method, garbage / expired rejection,
// the impersonation set/clear round-trip, and revoke. Token rotation (4h age
// gate) is left to the unit-level CAS logic - it needs time travel the
// lifecycle here deliberately avoids by keeping sessions fresh.
//
//	go test -tags integration -run TestAuthSessions ./pkg/service/...
package service_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

// TestAuthSessions drives CreateSession / ValidateSession / SetImpersonation /
// ClearImpersonation / RevokeSession end to end.
//
// in:  a migrated testcontainer env, two seeded tenants, one user in tenant A.
// out: asserts the happy lifecycle, magic-link's shorter lifetime, ErrNotFound
//
//	for garbage, ErrExpired for a backdated row, the impersonation round-trip,
//	and that a revoked token no longer validates.
func TestAuthSessions(t *testing.T) {
	env := servicetest.Start(t)
	auth := env.Services.Auth
	ctx := context.Background()

	const tA, tB = "asess-a", "asess-b"
	env.SeedTenant(t, tA)
	env.SeedTenant(t, tB)

	user, err := auth.CreateUser(tA, "u@a.test", "U", false)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// expireToken backdates a session's expires_at out-of-band so the next
	// ValidateSession takes the ErrExpired branch.
	expireToken := func(t *testing.T, token string) {
		t.Helper()
		h := sha256.Sum256([]byte(token))
		if _, err := env.Super.Exec(ctx,
			`UPDATE user_sessions SET expires_at = now() - interval '1 hour' WHERE token_hash = $1`,
			h[:]); err != nil {
			t.Fatalf("backdate session: %v", err)
		}
	}

	t.Run("create_then_validate", func(t *testing.T) {
		token, expires, err := auth.CreateSession(tA, user.ID, "password", "test-agent", "1.2.3.4")
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		if token == "" {
			t.Fatal("CreateSession returned empty token")
		}
		// Password sessions live ~30d; assert comfortably future.
		if d := time.Until(expires); d < 29*24*time.Hour {
			t.Errorf("password session expiry in %v, want ~30d", d)
		}
		sess, err := auth.ValidateSession(token)
		if err != nil {
			t.Fatalf("ValidateSession: %v", err)
		}
		if sess.User == nil || sess.User.ID != user.ID {
			t.Errorf("session user = %v, want %v", sess.User, user.ID)
		}
		if sess.ImpersonatedTenantID != nil {
			t.Errorf("fresh session impersonation = %v, want nil", *sess.ImpersonatedTenantID)
		}
		if sess.NewToken != "" {
			t.Errorf("fresh session rotated unexpectedly (NewToken set)")
		}
	})

	t.Run("magic_link_shorter_lifetime", func(t *testing.T) {
		_, expires, err := auth.CreateSession(tA, user.ID, "magic_link", "", "")
		if err != nil {
			t.Fatalf("CreateSession magic_link: %v", err)
		}
		// magic-link sessions live ~24h, far short of the password 30d.
		if d := time.Until(expires); d > 25*time.Hour {
			t.Errorf("magic_link session expiry in %v, want ~24h", d)
		}
	})

	t.Run("garbage_token_not_found", func(t *testing.T) {
		if _, err := auth.ValidateSession("not-a-real-token"); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("ValidateSession(garbage) = %v, want ErrNotFound", err)
		}
	})

	t.Run("expired_token", func(t *testing.T) {
		token, _, err := auth.CreateSession(tA, user.ID, "password", "", "")
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		expireToken(t, token)
		if _, err := auth.ValidateSession(token); !errors.Is(err, service.ErrExpired) {
			t.Errorf("ValidateSession(expired) = %v, want ErrExpired", err)
		}
	})

	t.Run("impersonation_set_and_clear", func(t *testing.T) {
		token, _, err := auth.CreateSession(tA, user.ID, "password", "", "")
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		sess, err := auth.ValidateSession(token)
		if err != nil {
			t.Fatalf("ValidateSession: %v", err)
		}

		if err := auth.SetImpersonation(sess.ID, tB); err != nil {
			t.Fatalf("SetImpersonation: %v", err)
		}
		got, err := auth.ValidateSession(token)
		if err != nil {
			t.Fatalf("ValidateSession after set: %v", err)
		}
		if got.ImpersonatedTenantID == nil || *got.ImpersonatedTenantID != tB {
			t.Errorf("impersonated tenant = %v, want %q", got.ImpersonatedTenantID, tB)
		}

		if err := auth.ClearImpersonation(sess.ID); err != nil {
			t.Fatalf("ClearImpersonation: %v", err)
		}
		got, err = auth.ValidateSession(token)
		if err != nil {
			t.Fatalf("ValidateSession after clear: %v", err)
		}
		if got.ImpersonatedTenantID != nil {
			t.Errorf("impersonation after clear = %v, want nil", *got.ImpersonatedTenantID)
		}
	})

	t.Run("revoke_invalidates", func(t *testing.T) {
		token, _, err := auth.CreateSession(tA, user.ID, "password", "", "")
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		if _, err := auth.ValidateSession(token); err != nil {
			t.Fatalf("pre-revoke ValidateSession: %v", err)
		}
		if err := auth.RevokeSession(token); err != nil {
			t.Fatalf("RevokeSession: %v", err)
		}
		if _, err := auth.ValidateSession(token); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("ValidateSession(revoked) = %v, want ErrNotFound", err)
		}
	})
}
