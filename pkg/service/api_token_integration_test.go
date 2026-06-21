//go:build integration

// ApiTokenService integration tests. Issue / validate / revoke /
// list + expiry + tenant isolation against a real TimescaleDB. Encodes the
// bearer-token invariants: a token resolves to its owning user, a revoked or
// expired token is rejected, and the RLS policy keeps tokens tenant-scoped.
//
//	go test -tags integration -run TestApiTokenService ./pkg/service/...
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

func TestApiTokenService(t *testing.T) {
	env := servicetest.Start(t)
	tokens := env.Services.ApiTokens
	auth := env.Services.Auth

	const tA, tB = "apitok-a", "apitok-b"
	env.SeedTenant(t, tA)
	env.SeedTenant(t, tB)
	user := mustCreateUser(t, auth, tA, "owner@example.com")

	// --- issue + validate ---------------------------------------------------
	raw, expires, err := tokens.IssueToken(tA, user.ID, "phone")
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	if raw == "" {
		t.Fatal("IssueToken returned an empty token")
	}
	if d := time.Until(expires); d < 89*24*time.Hour || d > 91*24*time.Hour {
		t.Errorf("expiry %v out of the ~90d band", d)
	}

	got, err := tokens.ValidateToken(raw)
	if err != nil {
		t.Fatalf("ValidateToken(fresh): %v", err)
	}
	if got.ID != user.ID || got.TenantID != tA {
		t.Errorf("validated user = %v/%s, want %v/%s", got.ID, got.TenantID, user.ID, tA)
	}

	// --- list ---------------------------------------------------------------
	list, err := tokens.ListTokens(tA, user.ID)
	if err != nil {
		t.Fatalf("ListTokens: %v", err)
	}
	if len(list) != 1 || list[0].Name != "phone" || list[0].RevokedAt != nil {
		t.Errorf("ListTokens = %+v, want one live token named phone", list)
	}

	// --- tenant isolation: the wrong tenant GUC hides the row (RLS) ----------
	other, err := tokens.ListTokens(tB, user.ID)
	if err != nil {
		t.Fatalf("ListTokens(other tenant): %v", err)
	}
	if len(other) != 0 {
		t.Errorf("cross-tenant ListTokens leaked %d tokens", len(other))
	}

	// --- unknown token ------------------------------------------------------
	if _, err := tokens.ValidateToken("not-a-real-token"); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("ValidateToken(unknown) err = %v, want ErrNotFound", err)
	}

	// --- revoke -> validate rejects -----------------------------------------
	if err := tokens.RevokeToken(raw); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if _, err := tokens.ValidateToken(raw); !errors.Is(err, service.ErrNotFound) {
		t.Errorf("ValidateToken(revoked) err = %v, want ErrNotFound", err)
	}
	// RevokeToken is idempotent - a second call is a no-op, not an error.
	if err := tokens.RevokeToken(raw); err != nil {
		t.Errorf("RevokeToken(second) = %v, want nil", err)
	}

	// --- expired token (seeded directly with a past expiry) -----------------
	expiredRaw := "expired-token-value"
	h := sha256.Sum256([]byte(expiredRaw))
	if _, err := env.Super.Exec(context.Background(),
		`INSERT INTO api_tokens (user_id, token_hash, name, expires_at)
		 VALUES ($1, $2, 'old', now() - interval '1 hour')`,
		user.ID, h[:]); err != nil {
		t.Fatalf("seed expired token: %v", err)
	}
	if _, err := tokens.ValidateToken(expiredRaw); !errors.Is(err, service.ErrExpired) {
		t.Errorf("ValidateToken(expired) err = %v, want ErrExpired", err)
	}
}
