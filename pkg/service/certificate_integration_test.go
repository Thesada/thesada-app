//go:build integration

// CertificateService integration tests. Device mTLS cert
// issue / revoke / active-lookup / list, plus FindActivePairingTenant - the
// cross-tenant pairing discovery that backs the "MQTT topic tenant must match
// the device's active pairing tenant" invariant (docs/invariants.md).
//
//	go test -tags integration -run TestCertificateService ./pkg/service/...
package service_test

import (
	"context"
	"testing"
	"time"

	"thesada.app/app/pkg/service/servicetest"
)

func TestCertificateService(t *testing.T) {
	env := servicetest.Start(t)
	certs := env.Services.Certificates
	dev := env.Services.Devices
	ctx := context.Background()

	const tA, tB = "cert-a", "cert-b"
	env.SeedTenant(t, tA)
	env.SeedTenant(t, tB)

	nb := time.Now().Add(-time.Hour)
	na := time.Now().Add(24 * time.Hour)
	const pem = "-----BEGIN CERTIFICATE-----\ntestcert\n-----END CERTIFICATE-----"

	t.Run("Issue_GetActive_marks_device_paired", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "cert-dev-1", "", "", "", "")
		if err := certs.Issue(ctx, tA, pk, "serial-1", "cn-dev-1", nb, na, pem); err != nil {
			t.Fatalf("Issue: %v", err)
		}
		got, err := certs.GetActive(ctx, tA, pk)
		if err != nil || got == nil {
			t.Fatalf("GetActive = %v err %v, want cert", got, err)
		}
		if got.SerialHex != "serial-1" || got.CN != "cn-dev-1" || got.Revoked {
			t.Errorf("active cert = %+v, want serial-1/cn-dev-1/not-revoked", got)
		}
		// Issue marks the device paired.
		d, _ := dev.GetByID(pk, tA)
		if d.PairedAt == nil {
			t.Error("device paired_at not set after Issue")
		}
	})

	t.Run("GetActive_none_returns_nil", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "cert-dev-none", "", "", "", "")
		if got, err := certs.GetActive(ctx, tA, pk); err != nil || got != nil {
			t.Errorf("GetActive no cert = %v err %v, want nil nil", got, err)
		}
	})

	t.Run("Revoke_clears_active_and_paired_keeps_history", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "cert-dev-rev", "", "", "", "")
		if err := certs.Issue(ctx, tA, pk, "serial-rev", "cn-rev", nb, na, pem); err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if err := certs.Revoke(ctx, tA, pk); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		if got, _ := certs.GetActive(ctx, tA, pk); got != nil {
			t.Error("GetActive after revoke should be nil")
		}
		d, _ := dev.GetByID(pk, tA)
		if d.PairedAt != nil {
			t.Errorf("device paired_at = %v after revoke, want nil", d.PairedAt)
		}
		// History is retained: the revoked row still lists.
		list, err := certs.ListByDevice(ctx, tA, pk)
		if err != nil || len(list) != 1 || !list[0].Revoked {
			t.Errorf("ListByDevice = %v err %v, want one revoked cert", list, err)
		}
	})

	t.Run("ListByDevice_orders_newest_first", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "cert-dev-list", "", "", "", "")
		if err := certs.Issue(ctx, tA, pk, "serial-list-1", "cn1", nb, na, pem); err != nil {
			t.Fatalf("Issue 1: %v", err)
		}
		if err := certs.Revoke(ctx, tA, pk); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		if err := certs.Issue(ctx, tA, pk, "serial-list-2", "cn2", nb, na, pem); err != nil {
			t.Fatalf("Issue 2: %v", err)
		}
		list, err := certs.ListByDevice(ctx, tA, pk)
		if err != nil {
			t.Fatalf("ListByDevice: %v", err)
		}
		if len(list) != 2 {
			t.Fatalf("ListByDevice len = %d, want 2", len(list))
		}
		if list[0].SerialHex != "serial-list-2" {
			t.Errorf("first row serial = %q, want serial-list-2 (newest first)", list[0].SerialHex)
		}
	})

	t.Run("FindActivePairingTenant_discovers_paired_tenant", func(t *testing.T) {
		// Unknown device -> not found, MQTT path treats topic tenant as authoritative.
		if tid, found, err := certs.FindActivePairingTenant(ctx, "never-paired"); err != nil || found || tid != "" {
			t.Errorf("unknown device = %q %v err %v, want \"\" false", tid, found, err)
		}

		// Paired into tenant A -> discovered as A regardless of caller context.
		pkA := mustUpsert(t, dev, tA, "paired-dev", "", "", "", "")
		if err := certs.Issue(ctx, tA, pkA, "serial-pair-a", "cn-pair", nb, na, pem); err != nil {
			t.Fatalf("Issue: %v", err)
		}
		tid, found, err := certs.FindActivePairingTenant(ctx, "paired-dev")
		if err != nil || !found || tid != tA {
			t.Errorf("FindActivePairingTenant = %q %v err %v, want %s true", tid, found, err, tA)
		}

		// After revoke the gate falls open again (no active pairing).
		if err := certs.Revoke(ctx, tA, pkA); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		if tid, found, _ := certs.FindActivePairingTenant(ctx, "paired-dev"); found || tid != "" {
			t.Errorf("after revoke = %q %v, want \"\" false", tid, found)
		}

		// A different device paired into tenant B resolves to B - cross-tenant
		// discovery is the whole point.
		pkB := mustUpsert(t, dev, tB, "paired-dev-b", "", "", "", "")
		if err := certs.Issue(ctx, tB, pkB, "serial-pair-b", "cn-pair-b", nb, na, pem); err != nil {
			t.Fatalf("Issue B: %v", err)
		}
		if tid, found, _ := certs.FindActivePairingTenant(ctx, "paired-dev-b"); !found || tid != tB {
			t.Errorf("tenant-B pairing = %q %v, want %s true", tid, found, tB)
		}
	})

	t.Run("RLS_tenant_isolation", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "cert-iso", "", "", "", "")
		if err := certs.Issue(ctx, tA, pk, "serial-iso", "cn-iso", nb, na, pem); err != nil {
			t.Fatalf("Issue: %v", err)
		}
		// Tenant B cannot see tenant A's cert by the same device pk.
		if got, err := certs.GetActive(ctx, tB, pk); err != nil || got != nil {
			t.Errorf("cross-tenant GetActive = %v err %v, want nil", got, err)
		}
		if list, err := certs.ListByDevice(ctx, tB, pk); err != nil || len(list) != 0 {
			t.Errorf("cross-tenant ListByDevice = %v err %v, want empty", list, err)
		}
	})
}
