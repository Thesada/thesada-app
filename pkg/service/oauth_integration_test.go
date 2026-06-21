//go:build integration

// OAuthService integration tests. Provider listing,
// identity link/find/list/delete, email lookup, and the not-found paths against
// a real TimescaleDB. The OIDC-discovery success paths (LoadProviderBySlug/
// ByID success, StartProvider) need a live IdP and belong to a pkg/oauth
// harness, not here - only their pre-discovery DB branches are covered.
//
// Includes a guard for the per-tenant provider cascade footgun: dropping a
// provider row cascades to user_oauth_identities, so a secret rotation MUST be
// an UPDATE, never DELETE+INSERT (see feedback_oauth_providers_per_tenant).
//
//	go test -tags integration -run TestOAuth ./pkg/service/...
package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"thesada.app/app/pkg/oauth"
	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

// seedProvider inserts an oauth_providers row via the superuser pool. tenantID
// "" means a global (tenant_id NULL) provider. issuer_url is a dummy - these
// tests never reach OIDC discovery.
func seedProvider(t *testing.T, env *servicetest.Env, tenantID, slug, display, secret string, enabled bool) uuid.UUID {
	t.Helper()
	var tid any
	if tenantID != "" {
		tid = tenantID
	}
	var id uuid.UUID
	if err := env.Super.QueryRow(context.Background(),
		`INSERT INTO oauth_providers (tenant_id, slug, display_name, issuer_url, client_id, client_secret, enabled)
		 VALUES ($1, $2, $3, 'https://idp.test/issuer', 'client-x', $4, $5) RETURNING id`,
		tid, slug, display, secret, enabled).Scan(&id); err != nil {
		t.Fatalf("seed provider %s/%s: %v", tenantID, slug, err)
	}
	return id
}

func TestOAuth(t *testing.T) {
	env := servicetest.Start(t)
	oa := env.Services.OAuth
	users := env.Services.Auth // seeds users for identity links
	ctx := context.Background()

	const tA, tB = "oauth-a", "oauth-b"
	env.SeedTenant(t, tA)
	env.SeedTenant(t, tB)

	t.Run("ListEnabledProvidersForTenant_scoped", func(t *testing.T) {
		// Providers are per-tenant post-0015 (global rows were deleted and the
		// RLS policy scopes by tenant), so this asserts tenant scoping + the
		// enabled filter, not the vestigial NULL-tenant branch.
		seedProvider(t, env, tA, "ascoped", "A IdP", "s", true)
		seedProvider(t, env, tB, "bscoped", "B IdP", "s", true)
		seedProvider(t, env, tA, "disabled", "Disabled", "s", false)

		got, err := oa.ListEnabledProvidersForTenant(ctx, tA)
		if err != nil {
			t.Fatalf("ListEnabledProvidersForTenant: %v", err)
		}
		slugs := map[string]bool{}
		for _, p := range got {
			slugs[p.Slug] = true
		}
		if !slugs["ascoped"] {
			t.Errorf("want own-tenant provider, got %v", slugs)
		}
		if slugs["bscoped"] {
			t.Error("other tenant's provider leaked into the list")
		}
		if slugs["disabled"] {
			t.Error("disabled provider should be excluded")
		}
	})

	t.Run("ListEnabledProvidersForLogin_dedupes_slug_and_needs_secret", func(t *testing.T) {
		// Same slug under two tenant scopes -> DISTINCT ON (slug) collapses to one.
		seedProvider(t, env, tA, "logindup", "Dup IdP", "secret", true)
		seedProvider(t, env, tB, "logindup", "Dup IdP", "secret", true)
		// Enabled but secret-less -> excluded from the login surface.
		seedProvider(t, env, tA, "nosecret", "No Secret", "", true)

		got, err := oa.ListEnabledProvidersForLogin(ctx)
		if err != nil {
			t.Fatalf("ListEnabledProvidersForLogin: %v", err)
		}
		dupCount := 0
		for _, p := range got {
			if p.Slug == "logindup" {
				dupCount++
			}
			if p.Slug == "nosecret" {
				t.Error("secret-less provider should not appear on the login page")
			}
		}
		if dupCount != 1 {
			t.Errorf("slug 'logindup' appeared %d times, want exactly 1 (DISTINCT ON)", dupCount)
		}
	})

	t.Run("LoadProvider_not_found_paths", func(t *testing.T) {
		// Unknown slug, disabled provider, and secret-less provider all 404
		// before any OIDC discovery runs.
		if _, err := oa.LoadProviderBySlug(ctx, "no-such-slug", "", env.Cfg.BaseURL); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("unknown slug = %v, want ErrNotFound", err)
		}
		seedProvider(t, env, "", "off", "Off", "s", false)
		if _, err := oa.LoadProviderBySlug(ctx, "off", "", env.Cfg.BaseURL); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("disabled slug = %v, want ErrNotFound", err)
		}
		seedProvider(t, env, "", "secretless", "Secretless", "", true)
		if _, err := oa.LoadProviderBySlug(ctx, "secretless", "", env.Cfg.BaseURL); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("secret-less slug = %v, want ErrNotFound", err)
		}
		if _, err := oa.LoadProviderByID(ctx, uuid.New(), env.Cfg.BaseURL); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("unknown id = %v, want ErrNotFound", err)
		}
	})

	t.Run("LinkIdentity_FindByIdentity_and_conflict", func(t *testing.T) {
		pid := seedProvider(t, env, tA, "link-idp", "Link IdP", "s", true)
		u := mustCreateUser(t, users, tA, "link@a.test")

		if err := oa.LinkIdentity(ctx, u.ID, pid, "subject-123", "link@a.test"); err != nil {
			t.Fatalf("LinkIdentity: %v", err)
		}
		got, err := oa.FindUserByIdentity(ctx, pid, "subject-123")
		if err != nil || got.ID != u.ID {
			t.Fatalf("FindUserByIdentity = %v err %v, want %v", got, err, u.ID)
		}
		// Unknown subject -> ErrNotFound.
		if _, err := oa.FindUserByIdentity(ctx, pid, "nope"); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("FindUserByIdentity unknown = %v, want ErrNotFound", err)
		}
		// (provider, subject) is unique -> re-linking the same pair to another
		// user is a conflict.
		u2 := mustCreateUser(t, users, tA, "link2@a.test")
		if err := oa.LinkIdentity(ctx, u2.ID, pid, "subject-123", ""); !errors.Is(err, service.ErrConflict) {
			t.Errorf("duplicate link = %v, want ErrConflict", err)
		}
	})

	t.Run("ListIdentitiesForUser_and_DeleteIdentity_owner_scoped", func(t *testing.T) {
		pid := seedProvider(t, env, tA, "del-idp", "Del IdP", "s", true)
		owner := mustCreateUser(t, users, tA, "owner@a.test")
		other := mustCreateUser(t, users, tA, "other@a.test")
		if err := oa.LinkIdentity(ctx, owner.ID, pid, "owner-subj", ""); err != nil {
			t.Fatalf("LinkIdentity: %v", err)
		}

		list, err := oa.ListIdentitiesForUser(ctx, tA, owner.ID)
		if err != nil || len(list) != 1 || list[0].ProviderSlug != "del-idp" {
			t.Fatalf("ListIdentitiesForUser = %v err %v, want one del-idp row", list, err)
		}
		idID := list[0].ID

		// A non-owner cannot delete it.
		if err := oa.DeleteIdentity(ctx, tA, other.ID, idID); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("non-owner delete = %v, want ErrNotFound", err)
		}
		// Owner can.
		if err := oa.DeleteIdentity(ctx, tA, owner.ID, idID); err != nil {
			t.Fatalf("owner delete: %v", err)
		}
		// Already gone.
		if err := oa.DeleteIdentity(ctx, tA, owner.ID, idID); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("second delete = %v, want ErrNotFound", err)
		}
	})

	t.Run("FindUserByEmail_tenant_scoped", func(t *testing.T) {
		u := mustCreateUser(t, users, tB, "find-email@b.test")
		tenantB := tB
		// Hit: scoped to the user's own tenant.
		got, err := oa.FindUserByEmail(ctx, &tenantB, "find-email@b.test")
		if err != nil || got.ID != u.ID {
			t.Errorf("FindUserByEmail hit = %v err %v, want %v", got, err, u.ID)
		}
		// Miss: unknown email in the same tenant.
		if _, err := oa.FindUserByEmail(ctx, &tenantB, "ghost@nowhere.test"); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("FindUserByEmail miss = %v, want ErrNotFound", err)
		}
		// Cross-tenant: the email exists, but a different tenant must not resolve it.
		tenantA := tA
		if _, err := oa.FindUserByEmail(ctx, &tenantA, "find-email@b.test"); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("FindUserByEmail cross-tenant = %v, want ErrNotFound", err)
		}
		// Global provider (nil tenant) never auto-links by email.
		if _, err := oa.FindUserByEmail(ctx, nil, "find-email@b.test"); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("FindUserByEmail global = %v, want ErrNotFound", err)
		}
	})

	t.Run("LookupState_unknown_returns_ErrUnknownState", func(t *testing.T) {
		if _, err := oa.LookupState(ctx, "never-issued-state"); !errors.Is(err, oauth.ErrUnknownState) {
			t.Errorf("LookupState unknown = %v, want oauth.ErrUnknownState", err)
		}
	})

	t.Run("provider_delete_cascades_to_identities", func(t *testing.T) {
		// Footgun guard (feedback_oauth_providers_per_tenant): the
		// user_oauth_identities FK is ON DELETE CASCADE. Rotating a provider
		// secret via DELETE+INSERT therefore SILENTLY wipes every linked
		// identity - "lost SSO again". Rotation must be an UPDATE. This test
		// pins the cascade so the danger stays documented in code.
		pid := seedProvider(t, env, tA, "cascade-idp", "Cascade IdP", "s", true)
		u := mustCreateUser(t, users, tA, "cascade@a.test")
		if err := oa.LinkIdentity(ctx, u.ID, pid, "cascade-subj", ""); err != nil {
			t.Fatalf("LinkIdentity: %v", err)
		}
		if _, err := env.Super.Exec(ctx, `DELETE FROM oauth_providers WHERE id = $1`, pid); err != nil {
			t.Fatalf("delete provider: %v", err)
		}
		var n int
		if err := env.Super.QueryRow(ctx,
			`SELECT count(*) FROM user_oauth_identities WHERE user_id = $1`, u.ID).Scan(&n); err != nil {
			t.Fatalf("count identities: %v", err)
		}
		if n != 0 {
			t.Errorf("identities after provider delete = %d, want 0 (cascade) - rotate via UPDATE not DELETE+INSERT", n)
		}
	})
}

