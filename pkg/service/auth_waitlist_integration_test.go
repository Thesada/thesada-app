//go:build integration

// AuthService waitlist integration tests. Add (idempotent),
// list/count (cross-tenant admin), convert-to-user (single-winner), and delete.
//
//	go test -tags integration -run TestAuthWaitlist ./pkg/service/...
package service_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

func TestAuthWaitlist(t *testing.T) {
	env := servicetest.Start(t)
	auth := env.Services.Auth

	const tA, tB = "wl-a", "wl-b"
	env.SeedTenant(t, tA)
	env.SeedTenant(t, tB)

	t.Run("AddToWaitlist_idempotent", func(t *testing.T) {
		id1, err := auth.AddToWaitlist(tA, "wl1@a.test", "wants in")
		if err != nil {
			t.Fatalf("AddToWaitlist: %v", err)
		}
		// Same tenant+email returns the existing row, not a new one.
		id2, err := auth.AddToWaitlist(tA, "wl1@a.test", "again")
		if err != nil {
			t.Fatalf("AddToWaitlist repeat: %v", err)
		}
		if id1 != id2 {
			t.Errorf("idempotent add changed id: %v -> %v", id1, id2)
		}
	})

	t.Run("Count_and_List_reflect_pending", func(t *testing.T) {
		before, err := auth.CountPendingWaitlist()
		if err != nil {
			t.Fatalf("CountPendingWaitlist: %v", err)
		}
		_, _ = auth.AddToWaitlist(tA, "wl-list-a@a.test", "")
		_, _ = auth.AddToWaitlist(tB, "wl-list-b@b.test", "")
		after, err := auth.CountPendingWaitlist()
		if err != nil {
			t.Fatalf("CountPendingWaitlist after: %v", err)
		}
		if after != before+2 {
			t.Errorf("count delta = %d, want +2", after-before)
		}

		list, err := auth.ListPendingWaitlist()
		if err != nil {
			t.Fatalf("ListPendingWaitlist: %v", err)
		}
		// Cross-tenant view: both tenants' entries present.
		seen := map[string]bool{}
		for _, w := range list {
			seen[w.Email] = true
		}
		if !seen["wl-list-a@a.test"] || !seen["wl-list-b@b.test"] {
			t.Errorf("list missing cross-tenant entries, got %v", seen)
		}
	})

	t.Run("ConvertWaitlistEntry_creates_user_single_winner", func(t *testing.T) {
		id, err := auth.AddToWaitlist(tA, "convert@a.test", "Convert Me")
		if err != nil {
			t.Fatalf("AddToWaitlist: %v", err)
		}
		// Empty target tenant defaults to the entry's own tenant.
		u, err := auth.ConvertWaitlistEntry(id, "", false)
		if err != nil {
			t.Fatalf("ConvertWaitlistEntry: %v", err)
		}
		if u.TenantID != tA || u.Email != "convert@a.test" {
			t.Errorf("converted user = %s/%s, want %s/convert@a.test", u.TenantID, u.Email, tA)
		}
		// The new user is real and resolvable.
		if got, err := auth.GetUserByID(tA, u.ID); err != nil || got == nil {
			t.Errorf("converted user not found: %v %v", got, err)
		}
		// Converting again is a no-op miss - the row is no longer pending.
		if _, err := auth.ConvertWaitlistEntry(id, "", false); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("second convert = %v, want ErrNotFound", err)
		}
	})

	t.Run("ConvertWaitlistEntry_target_tenant_override", func(t *testing.T) {
		id, _ := auth.AddToWaitlist(tA, "cross-convert@a.test", "")
		u, err := auth.ConvertWaitlistEntry(id, tB, true)
		if err != nil {
			t.Fatalf("ConvertWaitlistEntry override: %v", err)
		}
		if u.TenantID != tB || !u.IsAdmin {
			t.Errorf("override convert = %s admin %v, want %s/true", u.TenantID, u.IsAdmin, tB)
		}
	})

	t.Run("DeleteWaitlistEntry_pending_then_missing", func(t *testing.T) {
		id, _ := auth.AddToWaitlist(tA, "delete-me@a.test", "")
		if err := auth.DeleteWaitlistEntry(id); err != nil {
			t.Fatalf("DeleteWaitlistEntry: %v", err)
		}
		// Already gone -> ErrNotFound.
		if err := auth.DeleteWaitlistEntry(id); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("second delete = %v, want ErrNotFound", err)
		}
		// Unknown id -> ErrNotFound.
		if err := auth.DeleteWaitlistEntry(uuid.New()); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("delete unknown = %v, want ErrNotFound", err)
		}
	})

	t.Run("DeleteWaitlistEntry_converted_is_not_pending", func(t *testing.T) {
		id, _ := auth.AddToWaitlist(tA, "converted-then-delete@a.test", "")
		if _, err := auth.ConvertWaitlistEntry(id, "", false); err != nil {
			t.Fatalf("convert: %v", err)
		}
		// Delete only removes still-pending rows; a converted one is ErrNotFound.
		if err := auth.DeleteWaitlistEntry(id); !errors.Is(err, service.ErrNotFound) {
			t.Errorf("delete converted = %v, want ErrNotFound", err)
		}
	})
}
