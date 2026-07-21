//go:build integration

// Certificate issue-lifecycle integration tests (0027): pending rows are
// invisible to every live-cert reader, Activate is the only door to
// 'active', MarkFailed parks a dead attempt, and any re-Issue supersedes
// the prior cert inside the persist tx (one live cert per device stays an
// invariant). Grandfathered pre-0027 rows (no explicit status) must keep
// reading as live.
//
//	go test -tags integration -run TestCertificateLifecycle ./pkg/service/...
package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

func TestCertificateLifecycle(t *testing.T) {
	env := servicetest.Start(t)
	certs := env.Services.Certificates
	dev := env.Services.Devices
	ctx := context.Background()

	const tA = "cert-lc-a"
	env.SeedTenant(t, tA)

	nb := time.Now().Add(-time.Hour)
	na := time.Now().Add(24 * time.Hour)
	const pem = "-----BEGIN CERTIFICATE-----\nlifecycletest\n-----END CERTIFICATE-----"

	// unrevokedCount reads the invariant directly: how many revoked=false
	// rows exist for a device, regardless of status.
	unrevokedCount := func(t *testing.T, pk uuid.UUID) int {
		t.Helper()
		var n int
		if err := env.Super.QueryRow(ctx,
			`SELECT count(*) FROM device_certificates WHERE device_pk = $1 AND revoked = false`,
			pk).Scan(&n); err != nil {
			t.Fatalf("count unrevoked: %v", err)
		}
		return n
	}

	t.Run("pending_row_is_not_live", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "lc-pending", "", "", "", "")
		certID, err := certs.IssuePending(ctx, tA, pk, "lc-serial-p", "lc-cn-p", nb, na, pem)
		if err != nil {
			t.Fatalf("IssuePending: %v", err)
		}
		if certID == 0 {
			t.Fatal("IssuePending returned id 0")
		}
		// No live-cert reader may see a pending row.
		if got, err := certs.GetActive(ctx, tA, pk); err != nil || got != nil {
			t.Errorf("GetActive on pending = %v err %v, want nil nil", got, err)
		}
		if tid, found, _ := certs.FindActivePairingTenant(ctx, "lc-pending"); found || tid != "" {
			t.Errorf("FindActivePairingTenant on pending = %q %v, want \"\" false", tid, found)
		}
		d, _ := dev.GetByID(pk, tA)
		if d.PairedAt != nil {
			t.Errorf("paired_at = %v with only a pending cert, want nil", d.PairedAt)
		}
		// The history listing still shows it, carrying the status.
		list, err := certs.ListByDevice(ctx, tA, pk)
		if err != nil || len(list) != 1 || list[0].Status != service.CertStatusPending {
			t.Errorf("ListByDevice = %+v err %v, want one pending row", list, err)
		}
	})

	t.Run("activate_flips_live_and_paired", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "lc-activate", "", "", "", "")
		certID, err := certs.IssuePending(ctx, tA, pk, "lc-serial-a", "lc-cn-a", nb, na, pem)
		if err != nil {
			t.Fatalf("IssuePending: %v", err)
		}
		if err := certs.Activate(ctx, tA, certID, pk); err != nil {
			t.Fatalf("Activate: %v", err)
		}
		got, err := certs.GetActive(ctx, tA, pk)
		if err != nil || got == nil {
			t.Fatalf("GetActive after Activate = %v err %v, want cert", got, err)
		}
		if got.ID != certID || got.Status != service.CertStatusActive {
			t.Errorf("active cert = id %d status %q, want id %d status active", got.ID, got.Status, certID)
		}
		if tid, found, _ := certs.FindActivePairingTenant(ctx, "lc-activate"); !found || tid != tA {
			t.Errorf("FindActivePairingTenant = %q %v, want %s true", tid, found, tA)
		}
		d, _ := dev.GetByID(pk, tA)
		if d.PairedAt == nil {
			t.Error("paired_at not set by Activate")
		}
		// Re-activating a finalized row is refused.
		if err := certs.Activate(ctx, tA, certID, pk); !errors.Is(err, service.ErrCertNotPending) {
			t.Errorf("second Activate = %v, want ErrCertNotPending", err)
		}
	})

	t.Run("mark_failed_stays_dark", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "lc-failed", "", "", "", "")
		certID, err := certs.IssuePending(ctx, tA, pk, "lc-serial-f", "lc-cn-f", nb, na, pem)
		if err != nil {
			t.Fatalf("IssuePending: %v", err)
		}
		if err := certs.MarkFailed(ctx, tA, certID); err != nil {
			t.Fatalf("MarkFailed: %v", err)
		}
		if got, _ := certs.GetActive(ctx, tA, pk); got != nil {
			t.Errorf("GetActive on failed = %+v, want nil", got)
		}
		if _, found, _ := certs.FindActivePairingTenant(ctx, "lc-failed"); found {
			t.Error("FindActivePairingTenant found a failed cert")
		}
		list, _ := certs.ListByDevice(ctx, tA, pk)
		if len(list) != 1 || list[0].Status != service.CertStatusFailed {
			t.Errorf("ListByDevice = %+v, want one failed row", list)
		}
		// A failed row cannot be resurrected.
		if err := certs.Activate(ctx, tA, certID, pk); !errors.Is(err, service.ErrCertNotPending) {
			t.Errorf("Activate on failed = %v, want ErrCertNotPending", err)
		}
		if err := certs.MarkFailed(ctx, tA, certID); !errors.Is(err, service.ErrCertNotPending) {
			t.Errorf("second MarkFailed = %v, want ErrCertNotPending", err)
		}
	})

	t.Run("reissue_supersedes_prior_active", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "lc-supersede", "", "", "", "")
		if err := certs.Issue(ctx, tA, pk, "lc-serial-s1", "lc-cn-s", nb, na, pem); err != nil {
			t.Fatalf("Issue: %v", err)
		}
		// New attempt while an active cert exists: the persist tx revokes it.
		certID, err := certs.IssuePending(ctx, tA, pk, "lc-serial-s2", "lc-cn-s", nb, na, pem)
		if err != nil {
			t.Fatalf("IssuePending over active: %v", err)
		}
		if n := unrevokedCount(t, pk); n != 1 {
			t.Errorf("unrevoked rows after supersede = %d, want 1", n)
		}
		if got, _ := certs.GetActive(ctx, tA, pk); got != nil {
			t.Errorf("GetActive mid-supersede = %+v, want nil (old revoked, new pending)", got)
		}
		d, _ := dev.GetByID(pk, tA)
		if d.PairedAt != nil {
			t.Errorf("paired_at = %v mid-supersede, want nil", d.PairedAt)
		}
		if err := certs.Activate(ctx, tA, certID, pk); err != nil {
			t.Fatalf("Activate: %v", err)
		}
		got, _ := certs.GetActive(ctx, tA, pk)
		if got == nil || got.SerialHex != "lc-serial-s2" {
			t.Errorf("active after supersede = %+v, want lc-serial-s2", got)
		}
	})

	t.Run("reissue_supersedes_failed_leftover", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "lc-retry", "", "", "", "")
		certID1, err := certs.IssuePending(ctx, tA, pk, "lc-serial-r1", "lc-cn-r", nb, na, pem)
		if err != nil {
			t.Fatalf("IssuePending 1: %v", err)
		}
		if err := certs.MarkFailed(ctx, tA, certID1); err != nil {
			t.Fatalf("MarkFailed: %v", err)
		}
		// Operator re-clicks: the failed row is revoked, the retry proceeds.
		certID2, err := certs.IssuePending(ctx, tA, pk, "lc-serial-r2", "lc-cn-r", nb, na, pem)
		if err != nil {
			t.Fatalf("IssuePending 2: %v", err)
		}
		if err := certs.Activate(ctx, tA, certID2, pk); err != nil {
			t.Fatalf("Activate retry: %v", err)
		}
		if n := unrevokedCount(t, pk); n != 1 {
			t.Errorf("unrevoked rows after retry = %d, want 1", n)
		}
		// The stale first attempt cannot be activated anymore.
		if err := certs.Activate(ctx, tA, certID1, pk); !errors.Is(err, service.ErrCertNotPending) {
			t.Errorf("Activate superseded row = %v, want ErrCertNotPending", err)
		}
	})

	t.Run("direct_issue_never_accumulates", func(t *testing.T) {
		// The API pair path calls Issue twice in a row (double-click, retry):
		// the revoke-prior guard must keep exactly one live cert.
		pk := mustUpsert(t, dev, tA, "lc-direct", "", "", "", "")
		if err := certs.Issue(ctx, tA, pk, "lc-serial-d1", "lc-cn-d", nb, na, pem); err != nil {
			t.Fatalf("Issue 1: %v", err)
		}
		if err := certs.Issue(ctx, tA, pk, "lc-serial-d2", "lc-cn-d", nb, na, pem); err != nil {
			t.Fatalf("Issue 2: %v", err)
		}
		if n := unrevokedCount(t, pk); n != 1 {
			t.Errorf("unrevoked rows after double Issue = %d, want 1", n)
		}
		got, _ := certs.GetActive(ctx, tA, pk)
		if got == nil || got.SerialHex != "lc-serial-d2" {
			t.Errorf("active = %+v, want the newest (lc-serial-d2)", got)
		}
	})

	t.Run("grandfathered_row_reads_live", func(t *testing.T) {
		// A row inserted without an explicit status models the pre-0027
		// population (the ALTER backfilled them via DEFAULT 'active'):
		// readers must keep treating it as live.
		pk := mustUpsert(t, dev, tA, "lc-legacy", "", "", "", "")
		if _, err := env.Super.Exec(ctx,
			`INSERT INTO device_certificates (device_pk, serial_hex, cn, not_before, not_after, cert_pem)
			 VALUES ($1, 'lc-serial-legacy', 'lc-cn-legacy', $2, $3, $4)`,
			pk, nb, na, pem); err != nil {
			t.Fatalf("seed legacy row: %v", err)
		}
		got, err := certs.GetActive(ctx, tA, pk)
		if err != nil || got == nil || got.Status != service.CertStatusActive {
			t.Errorf("GetActive on legacy row = %+v err %v, want status active", got, err)
		}
		if tid, found, _ := certs.FindActivePairingTenant(ctx, "lc-legacy"); !found || tid != tA {
			t.Errorf("FindActivePairingTenant legacy = %q %v, want %s true", tid, found, tA)
		}
	})

	t.Run("revoke_clears_pending_and_failed_too", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "lc-revoke-all", "", "", "", "")
		if _, err := certs.IssuePending(ctx, tA, pk, "lc-serial-ra", "lc-cn-ra", nb, na, pem); err != nil {
			t.Fatalf("IssuePending: %v", err)
		}
		if err := certs.Revoke(ctx, tA, pk); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		if n := unrevokedCount(t, pk); n != 0 {
			t.Errorf("unrevoked rows after Revoke = %d, want 0 (pending swept too)", n)
		}
	})
}
