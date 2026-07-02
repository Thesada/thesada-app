//go:build integration

// TenantService integration tests. Create/Get/List,
// slug validation, the in-memory slug cache (Refresh / ExistsBySlug), member
// counts, and delete with protected-slug guards.
//
//	go test -tags integration -run TestTenantService ./pkg/service/...
package service_test

import (
	"context"
	"errors"
	"testing"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

func TestTenantService(t *testing.T) {
	env := servicetest.Start(t)
	ten := env.Services.Tenants

	t.Run("ValidateSlug", func(t *testing.T) {
		if err := service.ValidateSlug("good-slug"); err != nil {
			t.Errorf("valid slug rejected: %v", err)
		}
		if err := service.ValidateSlug("ab"); !errors.Is(err, service.ErrInvalidSlug) {
			t.Errorf("too short = %v, want ErrInvalidSlug", err)
		}
		if err := service.ValidateSlug("UPPER"); !errors.Is(err, service.ErrInvalidSlug) {
			t.Errorf("uppercase = %v, want ErrInvalidSlug", err)
		}
		if err := service.ValidateSlug("admin"); !errors.Is(err, service.ErrReservedSlug) {
			t.Errorf("reserved = %v, want ErrReservedSlug", err)
		}
	})

	t.Run("Create_Get_List_and_cache", func(t *testing.T) {
		ct, err := ten.Create("tencreate", "Created Tenant")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if ct.ID != "tencreate" || ct.DisplayName != "Created Tenant" {
			t.Errorf("created = %+v, want tencreate/Created Tenant", ct)
		}
		// Create primes the cache.
		if !ten.ExistsBySlug("tencreate") {
			t.Error("ExistsBySlug false right after Create")
		}
		got, err := ten.Get("tencreate")
		if err != nil || got.ID != "tencreate" {
			t.Fatalf("Get = %v err %v", got, err)
		}
		list, err := ten.List()
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		found := false
		for _, x := range list {
			if x.ID == "tencreate" {
				found = true
			}
		}
		if !found {
			t.Error("List missing created tenant")
		}
	})

	t.Run("Create_validation_and_duplicate", func(t *testing.T) {
		if _, err := ten.Create("ab", ""); !errors.Is(err, service.ErrInvalidSlug) {
			t.Errorf("short slug = %v, want ErrInvalidSlug", err)
		}
		if _, err := ten.Create("system", ""); !errors.Is(err, service.ErrReservedSlug) {
			t.Errorf("reserved slug = %v, want ErrReservedSlug", err)
		}
		// Empty display name defaults to the slug.
		dt, err := ten.Create("tendefault", "")
		if err != nil || dt.DisplayName != "tendefault" {
			t.Fatalf("default display = %v err %v, want slug", dt, err)
		}
		// Duplicate slug.
		if _, err := ten.Create("tendefault", "x"); !errors.Is(err, service.ErrSlugTaken) {
			t.Errorf("duplicate = %v, want ErrSlugTaken", err)
		}
	})

	t.Run("Get_unknown_ErrNotFound", func(t *testing.T) {
		if _, err := ten.Get("no-such-tenant"); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("unknown Get = %v, want ErrNotFound", err)
		}
	})

	t.Run("Refresh_populates_cache_from_db", func(t *testing.T) {
		// SeedTenant writes the row directly, bypassing Create's cache update,
		// so the cache is stale until Refresh.
		env.SeedTenant(t, "tenrefresh")
		if ten.ExistsBySlug("tenrefresh") {
			t.Error("ExistsBySlug true before Refresh - unexpected cache hit")
		}
		if err := ten.Refresh(); err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		if !ten.ExistsBySlug("tenrefresh") {
			t.Error("ExistsBySlug false after Refresh")
		}
	})

	t.Run("CountMembers", func(t *testing.T) {
		if _, err := ten.Create("tencount", ""); err != nil {
			t.Fatalf("Create: %v", err)
		}
		mustCreateUser(t, env.Services.Auth, "tencount", "m1@count.test")
		mustCreateUser(t, env.Services.Auth, "tencount", "m2@count.test")
		mustUpsert(t, env.Services.Devices, "tencount", "cdev", "", "", "", "")

		users, devices, err := ten.CountMembers("tencount")
		if err != nil {
			t.Fatalf("CountMembers: %v", err)
		}
		if users != 2 || devices != 1 {
			t.Errorf("CountMembers = %d users %d devices, want 2/1", users, devices)
		}
	})

	t.Run("Delete_and_protected_guards", func(t *testing.T) {
		if _, err := ten.Create("tendelete", ""); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := ten.Delete("tendelete", "some-caller"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, err := ten.Get("tendelete"); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("Get after delete = %v, want ErrNotFound", err)
		}
		if ten.ExistsBySlug("tendelete") {
			t.Error("ExistsBySlug true after Delete")
		}
		// The bootstrap 'default' tenant and the caller's own seat are protected.
		if err := ten.Delete("default", "x"); !errors.Is(err, service.ErrTenantProtected) {
			t.Errorf("delete default = %v, want ErrTenantProtected", err)
		}
		if err := ten.Delete("self", "self"); !errors.Is(err, service.ErrTenantProtected) {
			t.Errorf("delete own seat = %v, want ErrTenantProtected", err)
		}
	})

	// Phase 3: tenant lifecycle wires the device-config-secrets DEK. The
	// harness runs with the feature ON (servicetest sets DeviceConfigKEK).
	t.Run("Create_provisions_tenant_DEK", func(t *testing.T) {
		ctx := context.Background()
		if _, err := ten.Create("tendekgen", ""); err != nil {
			t.Fatalf("Create: %v", err)
		}
		var n int
		if err := env.Super.QueryRow(ctx,
			`SELECT count(*) FROM tenant_dek WHERE tenant_id = $1`, "tendekgen").Scan(&n); err != nil {
			t.Fatalf("count DEK: %v", err)
		}
		if n != 1 {
			t.Errorf("tenant_dek rows after Create = %d, want 1 (DEK provisioned in the create tx)", n)
		}
	})

	t.Run("Delete_crypto_shreds_secrets", func(t *testing.T) {
		ctx := context.Background()
		const slug = "tenshred"
		if _, err := ten.Create(slug, ""); err != nil {
			t.Fatalf("Create: %v", err)
		}
		pk := mustUpsert(t, env.Services.Devices, slug, "shred-dev", "", "", "", "")
		if err := env.Services.Secrets.SetSecret(ctx, slug, pk, "wifi.password", "gone-soon"); err != nil {
			t.Fatalf("SetSecret: %v", err)
		}
		// Precondition: both the DEK and the secret exist.
		if got := countRows(t, env, ctx, "tenant_dek", slug); got != 1 {
			t.Fatalf("pre-delete tenant_dek = %d, want 1", got)
		}
		if got := countRows(t, env, ctx, "device_config_secrets", slug); got != 1 {
			t.Fatalf("pre-delete device_config_secrets = %d, want 1", got)
		}
		// Delete the tenant: the DEK row cascades away (crypto-shred) and the
		// ciphertext cascades with it - the value is now unrecoverable.
		if err := ten.Delete(slug, "some-caller"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if got := countRows(t, env, ctx, "tenant_dek", slug); got != 0 {
			t.Errorf("post-delete tenant_dek = %d, want 0 (DEK crypto-shredded)", got)
		}
		if got := countRows(t, env, ctx, "device_config_secrets", slug); got != 0 {
			t.Errorf("post-delete device_config_secrets = %d, want 0 (ciphertext cascaded)", got)
		}
	})
}

// countRows counts rows in a tenant-scoped table via the superuser pool
// (bypassing RLS) for delete-cascade assertions.
func countRows(t *testing.T, env *servicetest.Env, ctx context.Context, table, tenantID string) int {
	t.Helper()
	// Map the closed set of known tables to fully-static query literals so no
	// Go value is ever concatenated into SQL (pgx cannot bind an identifier).
	var q string
	switch table {
	case "tenant_dek":
		q = `SELECT count(*) FROM tenant_dek WHERE tenant_id = $1`
	case "device_config_secrets":
		q = `SELECT count(*) FROM device_config_secrets WHERE tenant_id = $1`
	default:
		t.Fatalf("countRows: unknown table %q", table)
	}
	var n int
	if err := env.Super.QueryRow(ctx, q, tenantID).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}
