//go:build integration

// AuthService magic-link / reset-token integration tests.
// The one-time-token surface against a real TimescaleDB: login create+consume
// (single-use), reset validate-then-mark (consume deferred to the password
// save), expiry, garbage rejection, and the purpose isolation that stops a
// leaked login link reaching the /reset flow (and vice versa).
//
//	go test -tags integration -run TestAuthMagicLink ./pkg/service/...
package service_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

// TestAuthMagicLink drives CreateMagicLink / CreateResetLink / ConsumeMagicLink
// / ConsumeResetLink / MarkResetConsumed end to end.
//
// in:  a migrated testcontainer env, one seeded tenant + user.
// out: asserts login single-use consume, reset validate->mark lifecycle,
//
//	ErrExpired on backdated tokens, ErrNotFound on garbage, and that a token
//	of one purpose is invalid for the other flow.
func TestAuthMagicLink(t *testing.T) {
	env := servicetest.Start(t)
	auth := env.Services.Auth
	ctx := context.Background()

	const tenant = "amagic-a"
	env.SeedTenant(t, tenant)
	user, err := auth.CreateUser(tenant, "u@a.test", "U", false)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}

	// expireToken backdates a token's expires_at out-of-band so the next
	// consume/validate takes the ErrExpired branch.
	expireToken := func(t *testing.T, token string) {
		t.Helper()
		h := sha256.Sum256([]byte(token))
		if _, err := env.Super.Exec(ctx,
			`UPDATE magic_link_tokens SET expires_at = now() - interval '1 hour' WHERE token_hash = $1`,
			h[:]); err != nil {
			t.Fatalf("backdate token: %v", err)
		}
	}

	t.Run("login_create_consume_single_use", func(t *testing.T) {
		token, expires, err := auth.CreateMagicLink(user.ID)
		if err != nil {
			t.Fatalf("CreateMagicLink: %v", err)
		}
		if d := time.Until(expires); d <= 0 || d > 16*time.Minute {
			t.Errorf("login token expiry in %v, want ~15m", d)
		}
		u, err := auth.ConsumeMagicLink(token)
		if err != nil {
			t.Fatalf("ConsumeMagicLink: %v", err)
		}
		if u == nil || u.ID != user.ID {
			t.Errorf("consumed user = %v, want %v", u, user.ID)
		}
		// Single-use: a second consume of the same token must fail.
		if _, err := auth.ConsumeMagicLink(token); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("re-consume = %v, want ErrNotFound", err)
		}
	})

	t.Run("login_garbage_and_expired", func(t *testing.T) {
		if _, err := auth.ConsumeMagicLink("not-a-real-token"); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("ConsumeMagicLink(garbage) = %v, want ErrNotFound", err)
		}
		token, _, err := auth.CreateMagicLink(user.ID)
		if err != nil {
			t.Fatalf("CreateMagicLink: %v", err)
		}
		expireToken(t, token)
		if _, err := auth.ConsumeMagicLink(token); !errors.Is(err, service.ErrExpired) {
			t.Errorf("ConsumeMagicLink(expired) = %v, want ErrExpired", err)
		}
	})

	t.Run("reset_validate_then_mark", func(t *testing.T) {
		token, expires, err := auth.CreateResetLink(user.ID)
		if err != nil {
			t.Fatalf("CreateResetLink: %v", err)
		}
		if d := time.Until(expires); d <= 0 || d > 31*time.Minute {
			t.Errorf("reset token expiry in %v, want ~30m", d)
		}
		// ConsumeResetLink does NOT consume - it may be called twice (GET
		// render then POST save) before MarkResetConsumed.
		u, tokenID, err := auth.ConsumeResetLink(token)
		if err != nil {
			t.Fatalf("ConsumeResetLink: %v", err)
		}
		if u == nil || u.ID != user.ID || tokenID == uuid.Nil {
			t.Errorf("ConsumeResetLink = user %v token %v, want %v non-nil", u, tokenID, user.ID)
		}
		if _, _, err := auth.ConsumeResetLink(token); err != nil {
			t.Errorf("second ConsumeResetLink (pre-mark) = %v, want nil", err)
		}
		// Mark consumed: now the link is spent.
		if err := auth.MarkResetConsumed(tokenID); err != nil {
			t.Fatalf("MarkResetConsumed: %v", err)
		}
		if _, _, err := auth.ConsumeResetLink(token); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("ConsumeResetLink(consumed) = %v, want ErrNotFound", err)
		}
		// Single-winner: a second mark on the same id loses.
		if err := auth.MarkResetConsumed(tokenID); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("second MarkResetConsumed = %v, want ErrNotFound", err)
		}
	})

	t.Run("reset_expired", func(t *testing.T) {
		token, _, err := auth.CreateResetLink(user.ID)
		if err != nil {
			t.Fatalf("CreateResetLink: %v", err)
		}
		expireToken(t, token)
		if _, _, err := auth.ConsumeResetLink(token); !errors.Is(err, service.ErrExpired) {
			t.Errorf("ConsumeResetLink(expired) = %v, want ErrExpired", err)
		}
	})

	t.Run("purpose_isolation", func(t *testing.T) {
		// A login token must not validate through the reset flow.
		loginTok, _, err := auth.CreateMagicLink(user.ID)
		if err != nil {
			t.Fatalf("CreateMagicLink: %v", err)
		}
		if _, _, err := auth.ConsumeResetLink(loginTok); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("ConsumeResetLink(login token) = %v, want ErrNotFound", err)
		}
		// ...and a reset token must not consume as a login.
		resetTok, _, err := auth.CreateResetLink(user.ID)
		if err != nil {
			t.Fatalf("CreateResetLink: %v", err)
		}
		if _, err := auth.ConsumeMagicLink(resetTok); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("ConsumeMagicLink(reset token) = %v, want ErrNotFound", err)
		}
	})
}
