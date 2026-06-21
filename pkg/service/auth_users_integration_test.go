//go:build integration

// AuthService user-CRUD integration tests. Lookup,
// create, update, toggle, delete, and the cross-tenant *Any variants against a
// real TimescaleDB. The security-critical session / magic-link / password
// surface lives in auth_integration_test.go; this is the management surface.
//
//	go test -tags integration -run TestAuthUsers ./pkg/service/...
package service_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

func TestAuthUsers(t *testing.T) {
	env := servicetest.Start(t)
	auth := env.Services.Auth

	const tA, tB = "auser-a", "auser-b"
	env.SeedTenant(t, tA)
	env.SeedTenant(t, tB)

	t.Run("CreateUser_fields_and_duplicate", func(t *testing.T) {
		u, err := auth.CreateUser(tA, "create@a.test", "Alice", true)
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if u.IsAdmin != true || u.DisplayName == nil || *u.DisplayName != "Alice" {
			t.Errorf("created user = admin %v name %v, want true/Alice", u.IsAdmin, u.DisplayName)
		}
		// Same tenant + email violates the unique constraint -> loud error.
		if _, err := auth.CreateUser(tA, "create@a.test", "", false); err == nil {
			t.Error("duplicate email in same tenant should error, got nil")
		}
	})

	t.Run("GetUserByEmail_hit_and_miss", func(t *testing.T) {
		u := mustCreateUser(t, auth, tA, "byemail@a.test")
		got, err := auth.GetUserByEmail(tA, "byemail@a.test")
		if err != nil || got.ID != u.ID {
			t.Fatalf("GetUserByEmail hit = %v err %v, want %v", got, err, u.ID)
		}
		if _, err := auth.GetUserByEmail(tA, "nobody@a.test"); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("GetUserByEmail miss = %v, want ErrNotFound", err)
		}
	})

	t.Run("GetUserByEmailAnyTenant_crosses_tenant", func(t *testing.T) {
		u := mustCreateUser(t, auth, tB, "anyemail@b.test")
		got, err := auth.GetUserByEmailAnyTenant("anyemail@b.test")
		if err != nil || got.ID != u.ID || got.TenantID != tB {
			t.Errorf("GetUserByEmailAnyTenant = %v err %v, want %v in %s", got, err, u.ID, tB)
		}
	})

	t.Run("GetUserByID_tenant_scoped", func(t *testing.T) {
		u := mustCreateUser(t, auth, tA, "byid@a.test")
		if got, err := auth.GetUserByID(tA, u.ID); err != nil || got.ID != u.ID {
			t.Fatalf("GetUserByID own tenant = %v err %v", got, err)
		}
		// Same pk, wrong tenant -> not visible.
		if _, err := auth.GetUserByID(tB, u.ID); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("GetUserByID cross-tenant = %v, want ErrNotFound", err)
		}
		if _, err := auth.GetUserByID(tA, uuid.New()); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("GetUserByID unknown = %v, want ErrNotFound", err)
		}
	})

	t.Run("GetUserByIDAny_crosses_tenant", func(t *testing.T) {
		u := mustCreateUser(t, auth, tB, "byidany@b.test")
		got, err := auth.GetUserByIDAny(u.ID)
		if err != nil || got.TenantID != tB {
			t.Errorf("GetUserByIDAny = %v err %v, want tenant %s", got, err, tB)
		}
	})

	t.Run("EnsureAdminUser_creates_superadmin_then_idempotent", func(t *testing.T) {
		u, err := auth.EnsureAdminUser(tA, "boot@a.test")
		if err != nil {
			t.Fatalf("EnsureAdminUser create: %v", err)
		}
		if !u.IsSuperAdmin || !u.IsAdmin {
			t.Errorf("bootstrap user = super %v admin %v, want both true", u.IsSuperAdmin, u.IsAdmin)
		}
		again, err := auth.EnsureAdminUser(tA, "boot@a.test")
		if err != nil || again.ID != u.ID {
			t.Errorf("EnsureAdminUser idempotent = %v err %v, want same id %v", again, err, u.ID)
		}
	})

	t.Run("PromoteSuperAdmin", func(t *testing.T) {
		u := mustCreateUser(t, auth, tA, "promote@a.test")
		if u.IsSuperAdmin {
			t.Fatal("new user should not be super-admin")
		}
		if err := auth.PromoteSuperAdmin(u.ID); err != nil {
			t.Fatalf("PromoteSuperAdmin: %v", err)
		}
		got, _ := auth.GetUserByIDAny(u.ID)
		if !got.IsSuperAdmin {
			t.Error("user not super-admin after promote")
		}
	})

	t.Run("VerifyPasswordAnyTenant", func(t *testing.T) {
		u := mustCreateUser(t, auth, tA, "pwany@a.test")
		if err := auth.SetPassword(tA, u.ID, "any-tenant-pw"); err != nil {
			t.Fatalf("SetPassword: %v", err)
		}
		got, err := auth.VerifyPasswordAnyTenant("pwany@a.test", "any-tenant-pw")
		if err != nil || got.ID != u.ID {
			t.Errorf("VerifyPasswordAnyTenant correct = %v err %v", got, err)
		}
		if _, err := auth.VerifyPasswordAnyTenant("pwany@a.test", "wrong"); !errors.Is(err, service.ErrBadCredentials) {
			t.Errorf("VerifyPasswordAnyTenant wrong = %v, want ErrBadCredentials", err)
		}
	})

	t.Run("ListUsersByTenant_scoped", func(t *testing.T) {
		const tc = "auser-c"
		env.SeedTenant(t, tc)
		mustCreateUser(t, auth, tc, "c1@c.test")
		mustCreateUser(t, auth, tc, "c2@c.test")
		mustCreateUser(t, auth, tA, "not-in-c@a.test")

		list, err := auth.ListUsersByTenant(tc)
		if err != nil {
			t.Fatalf("ListUsersByTenant: %v", err)
		}
		if len(list) != 2 {
			t.Errorf("ListUsersByTenant(%s) = %d, want 2", tc, len(list))
		}
		for _, u := range list {
			if u.TenantID != tc {
				t.Errorf("list leaked tenant %q", u.TenantID)
			}
		}
	})

	t.Run("UpdateDisplayName_and_TelegramChatID", func(t *testing.T) {
		u := mustCreateUser(t, auth, tA, "upd@a.test")
		if err := auth.UpdateDisplayName(tA, u.ID, "Renamed"); err != nil {
			t.Fatalf("UpdateDisplayName: %v", err)
		}
		got, _ := auth.GetUserByID(tA, u.ID)
		if got.DisplayName == nil || *got.DisplayName != "Renamed" {
			t.Errorf("display name = %v, want Renamed", got.DisplayName)
		}
		if err := auth.UpdateTelegramChatID(tA, u.ID, "12345"); err != nil {
			t.Fatalf("UpdateTelegramChatID set: %v", err)
		}
		got, _ = auth.GetUserByID(tA, u.ID)
		if got.TelegramChatID == nil || *got.TelegramChatID != "12345" {
			t.Errorf("telegram = %v, want 12345", got.TelegramChatID)
		}
		// Empty string clears to NULL.
		if err := auth.UpdateTelegramChatID(tA, u.ID, ""); err != nil {
			t.Fatalf("UpdateTelegramChatID clear: %v", err)
		}
		got, _ = auth.GetUserByID(tA, u.ID)
		if got.TelegramChatID != nil {
			t.Errorf("telegram after clear = %v, want nil", got.TelegramChatID)
		}
	})

	t.Run("UpdateUser_and_ToggleAdmin", func(t *testing.T) {
		u := mustCreateUser(t, auth, tA, "toggle@a.test")
		if err := auth.UpdateUser(tA, u.ID, "Updated", true); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		got, _ := auth.GetUserByID(tA, u.ID)
		if !got.IsAdmin || got.DisplayName == nil || *got.DisplayName != "Updated" {
			t.Errorf("after UpdateUser = admin %v name %v, want true/Updated", got.IsAdmin, got.DisplayName)
		}
		// Toggle flips and returns the new value.
		v, err := auth.ToggleAdmin(tA, u.ID)
		if err != nil || v != false {
			t.Errorf("ToggleAdmin = %v err %v, want false", v, err)
		}
		v, _ = auth.ToggleAdmin(tA, u.ID)
		if v != true {
			t.Errorf("ToggleAdmin again = %v, want true", v)
		}
	})

	t.Run("DeleteUser_cascades_sessions", func(t *testing.T) {
		u := mustCreateUser(t, auth, tA, "del@a.test")
		token, _, err := auth.CreateSession(tA, u.ID, "password", "go-test", "")
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		if err := auth.DeleteUser(tA, u.ID); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
		if _, err := auth.GetUserByID(tA, u.ID); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("GetUserByID after delete = %v, want ErrNotFound", err)
		}
		// FK cascade: the user's session is gone too.
		if _, err := auth.ValidateSession(token); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("session after user delete = %v, want ErrNotFound (cascade)", err)
		}
	})

	t.Run("DeleteUser_refuses_superadmin", func(t *testing.T) {
		u := mustCreateUser(t, auth, tA, "super-del@a.test")
		if err := auth.PromoteSuperAdmin(u.ID); err != nil {
			t.Fatalf("PromoteSuperAdmin: %v", err)
		}
		if err := auth.DeleteUser(tA, u.ID); !errors.Is(err, service.ErrSuperAdminProtected) {
			t.Errorf("DeleteUser(super-admin) = %v, want ErrSuperAdminProtected", err)
		}
		// Refused, not silently swallowed: the row is still there.
		if _, err := auth.GetUserByID(tA, u.ID); err != nil {
			t.Errorf("super-admin gone after refused delete: %v", err)
		}
	})
}
