//go:build integration

// AuthService security-critical integration tests. Sessions,
// magic-link / reset-link, and password paths against a real TimescaleDB.
// CODE-GUIDELINES requires contract tests on the auth path - these encode the
// invariants from docs/invariants.md: session-token rotation, magic-link
// single-use (incl. under concurrency), reset single-winner, and tenant-scoped
// password verification.
//
// User CRUD + waitlist (the non-security AuthService surface) land in a
// follow-up step.
//
//	go test -tags integration -run TestAuthService ./pkg/service/...
package service_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

// mustCreateUser seeds a user and fails loud on error, returning the row.
func mustCreateUser(t *testing.T, auth *service.AuthService, tenantID, email string) *service.User {
	t.Helper()
	u, err := auth.CreateUser(tenantID, email, "", false)
	if err != nil {
		t.Fatalf("seed user %s/%s: %v", tenantID, email, err)
	}
	return u
}

func TestAuthService(t *testing.T) {
	env := servicetest.Start(t)
	auth := env.Services.Auth
	ctx := context.Background()

	const tA, tB = "auth-test-a", "auth-test-b"
	env.SeedTenant(t, tA)
	env.SeedTenant(t, tB)

	// --- sessions -----------------------------------------------------------

	t.Run("Session_create_validate_roundtrip", func(t *testing.T) {
		u := mustCreateUser(t, auth, tA, "sess-rt@a.test")
		token, _, err := auth.CreateSession(tA, u.ID, "password", "go-test", "")
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		sess, err := auth.ValidateSession(token)
		if err != nil || sess == nil {
			t.Fatalf("ValidateSession: sess %v err %v", sess, err)
		}
		if sess.User == nil || sess.User.ID != u.ID {
			t.Errorf("session user = %v, want %v", sess.User, u.ID)
		}
		if sess.NewToken != "" {
			t.Errorf("fresh session should not rotate, got NewToken %q", sess.NewToken)
		}
	})

	t.Run("Session_validate_unknown_token_ErrNotFound", func(t *testing.T) {
		if _, err := auth.ValidateSession("not-a-real-token"); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("ValidateSession(unknown) = %v, want ErrNotFound", err)
		}
	})

	t.Run("Session_expired_ErrExpired", func(t *testing.T) {
		u := mustCreateUser(t, auth, tA, "sess-exp@a.test")
		token, _, err := auth.CreateSession(tA, u.ID, "password", "go-test", "")
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		// Age the session past its expiry out-of-band (the API only mints
		// future-dated sessions).
		if _, err := env.Super.Exec(ctx,
			`UPDATE user_sessions SET expires_at = now() - interval '1 hour' WHERE user_id = $1`,
			u.ID); err != nil {
			t.Fatalf("age session: %v", err)
		}
		if _, err := auth.ValidateSession(token); !errors.Is(err, service.ErrExpired) {
			t.Errorf("ValidateSession(expired) = %v, want ErrExpired", err)
		}
	})

	t.Run("Session_rotates_after_interval", func(t *testing.T) {
		u := mustCreateUser(t, auth, tA, "sess-rot@a.test")
		oldToken, _, err := auth.CreateSession(tA, u.ID, "password", "go-test", "")
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		// Push rotated_at past the rotation interval so the next validation
		// mints a fresh token.
		if _, err := env.Super.Exec(ctx,
			`UPDATE user_sessions SET rotated_at = now() - interval '5 hours' WHERE user_id = $1`,
			u.ID); err != nil {
			t.Fatalf("age rotated_at: %v", err)
		}
		sess, err := auth.ValidateSession(oldToken)
		if err != nil {
			t.Fatalf("ValidateSession (rotation): %v", err)
		}
		if sess.NewToken == "" {
			t.Fatal("expected rotation to mint NewToken, got empty")
		}
		// New token validates; old token still validates within the grace window.
		if s2, err := auth.ValidateSession(sess.NewToken); err != nil || s2.User.ID != u.ID {
			t.Errorf("new token validate = %v err %v, want user %v", s2, err, u.ID)
		}
		if s3, err := auth.ValidateSession(oldToken); err != nil || s3.User.ID != u.ID {
			t.Errorf("old token within grace = %v err %v, want still valid", s3, err)
		}
	})

	t.Run("Session_revoke_then_invalid", func(t *testing.T) {
		u := mustCreateUser(t, auth, tA, "sess-rev@a.test")
		token, _, _ := auth.CreateSession(tA, u.ID, "password", "go-test", "")
		if err := auth.RevokeSession(token); err != nil {
			t.Fatalf("RevokeSession: %v", err)
		}
		if _, err := auth.ValidateSession(token); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("ValidateSession after revoke = %v, want ErrNotFound", err)
		}
	})

	t.Run("Session_impersonation_set_clear", func(t *testing.T) {
		u := mustCreateUser(t, auth, tA, "sess-imp@a.test")
		token, _, _ := auth.CreateSession(tA, u.ID, "password", "go-test", "")
		sess, _ := auth.ValidateSession(token)

		if err := auth.SetImpersonation(sess.ID, tB); err != nil {
			t.Fatalf("SetImpersonation: %v", err)
		}
		got, _ := auth.ValidateSession(token)
		if got.ImpersonatedTenantID == nil || *got.ImpersonatedTenantID != tB {
			t.Errorf("after Set, impersonated = %v, want %s", got.ImpersonatedTenantID, tB)
		}
		if err := auth.ClearImpersonation(sess.ID); err != nil {
			t.Fatalf("ClearImpersonation: %v", err)
		}
		got, _ = auth.ValidateSession(token)
		if got.ImpersonatedTenantID != nil {
			t.Errorf("after Clear, impersonated = %v, want nil", got.ImpersonatedTenantID)
		}
	})

	// --- magic link ---------------------------------------------------------

	t.Run("MagicLink_single_use", func(t *testing.T) {
		u := mustCreateUser(t, auth, tA, "ml-single@a.test")
		token, _, err := auth.CreateMagicLink(u.ID)
		if err != nil {
			t.Fatalf("CreateMagicLink: %v", err)
		}
		got, err := auth.ConsumeMagicLink(token)
		if err != nil || got == nil || got.ID != u.ID {
			t.Fatalf("first consume = %v err %v, want user %v", got, err, u.ID)
		}
		if _, err := auth.ConsumeMagicLink(token); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("second consume = %v, want ErrNotFound", err)
		}
	})

	t.Run("MagicLink_single_use_under_concurrent_requests", func(t *testing.T) {
		u := mustCreateUser(t, auth, tA, "ml-race@a.test")
		token, _, err := auth.CreateMagicLink(u.ID)
		if err != nil {
			t.Fatalf("CreateMagicLink: %v", err)
		}
		const racers = 8
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		wg.Add(racers)
		for i := 0; i < racers; i++ {
			go func() {
				defer wg.Done()
				user, cerr := auth.ConsumeMagicLink(token)
				if cerr == nil && user != nil {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if wins != 1 {
			t.Errorf("concurrent consume winners = %d, want exactly 1 (atomic single-winner)", wins)
		}
	})

	t.Run("MagicLink_expired_ErrExpired", func(t *testing.T) {
		u := mustCreateUser(t, auth, tA, "ml-exp@a.test")
		token, _, _ := auth.CreateMagicLink(u.ID)
		if _, err := env.Super.Exec(ctx,
			`UPDATE magic_link_tokens SET expires_at = now() - interval '1 hour' WHERE user_id = $1`,
			u.ID); err != nil {
			t.Fatalf("age token: %v", err)
		}
		if _, err := auth.ConsumeMagicLink(token); !errors.Is(err, service.ErrExpired) {
			t.Errorf("consume expired = %v, want ErrExpired", err)
		}
	})

	t.Run("MagicLink_wrong_purpose_rejected", func(t *testing.T) {
		u := mustCreateUser(t, auth, tA, "ml-purpose@a.test")
		// A reset-purpose token must not pass the login-consume path.
		resetTok, _, _ := auth.CreateResetLink(u.ID)
		if _, err := auth.ConsumeMagicLink(resetTok); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("consume reset token as login = %v, want ErrNotFound", err)
		}
	})

	t.Run("ResetLink_consume_then_mark_single_winner", func(t *testing.T) {
		u := mustCreateUser(t, auth, tA, "reset-mark@a.test")
		token, _, err := auth.CreateResetLink(u.ID)
		if err != nil {
			t.Fatalf("CreateResetLink: %v", err)
		}
		// ConsumeResetLink validates without consuming, twice in a row.
		got, tokenID, err := auth.ConsumeResetLink(token)
		if err != nil || got.ID != u.ID {
			t.Fatalf("ConsumeResetLink: got %v id %v err %v", got, tokenID, err)
		}
		if _, _, err := auth.ConsumeResetLink(token); err != nil {
			t.Errorf("second ConsumeResetLink (still unconsumed) = %v, want nil", err)
		}
		// MarkResetConsumed is the single-winner gate.
		if err := auth.MarkResetConsumed(tokenID); err != nil {
			t.Fatalf("MarkResetConsumed: %v", err)
		}
		if err := auth.MarkResetConsumed(tokenID); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("second MarkResetConsumed = %v, want ErrNotFound", err)
		}
		if _, _, err := auth.ConsumeResetLink(token); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("ConsumeResetLink after mark = %v, want ErrNotFound", err)
		}
	})

	// --- password -----------------------------------------------------------

	t.Run("Password_set_verify_correct_and_wrong", func(t *testing.T) {
		u := mustCreateUser(t, auth, tA, "pw@a.test")

		if has, err := auth.HasPassword(tA, u.ID); err != nil || has {
			t.Errorf("HasPassword before set = %v err %v, want false", has, err)
		}
		// No password yet -> verify must reject, not succeed-on-empty.
		if _, err := auth.VerifyPassword(tA, "pw@a.test", "anything"); !errors.Is(err, service.ErrBadCredentials) {
			t.Errorf("verify with no password set = %v, want ErrBadCredentials", err)
		}

		if err := auth.SetPassword(tA, u.ID, "correct-horse"); err != nil {
			t.Fatalf("SetPassword: %v", err)
		}
		if has, err := auth.HasPassword(tA, u.ID); err != nil || !has {
			t.Errorf("HasPassword after set = %v err %v, want true", has, err)
		}
		if got, err := auth.VerifyPassword(tA, "pw@a.test", "correct-horse"); err != nil || got.ID != u.ID {
			t.Errorf("verify correct = %v err %v, want user %v", got, err, u.ID)
		}
		if _, err := auth.VerifyPassword(tA, "pw@a.test", "wrong"); !errors.Is(err, service.ErrBadCredentials) {
			t.Errorf("verify wrong = %v, want ErrBadCredentials", err)
		}
	})

	t.Run("Password_verify_is_tenant_scoped", func(t *testing.T) {
		u := mustCreateUser(t, auth, tA, "pw-iso@a.test")
		if err := auth.SetPassword(tA, u.ID, "secret-pw"); err != nil {
			t.Fatalf("SetPassword: %v", err)
		}
		// Correct password but wrong tenant -> the user isn't visible, so it
		// must fail closed (RLS + WHERE tenant scope), never authenticate.
		if _, err := auth.VerifyPassword(tB, "pw-iso@a.test", "secret-pw"); !errors.Is(err, service.ErrBadCredentials) {
			t.Errorf("cross-tenant verify = %v, want ErrBadCredentials", err)
		}
	})
}
