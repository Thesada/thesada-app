//go:build integration

package service_test

import (
	"context"
	"testing"
	"time"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

func TestRevocationStatus(t *testing.T) {
	env := servicetest.Start(t)
	certs := env.Services.Certificates
	dev := env.Services.Devices
	ctx := context.Background()

	const tenant = "cert-status"
	const deviceID = "thesada-aabbccddeeff"
	const pub = "abababababababababababababababababababababababababababababababab"
	const other = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	env.SeedTenant(t, tenant)
	pk := mustUpsert(t, dev, tenant, deviceID, "", "", "", "")

	nb := time.Now().Add(-time.Hour)
	na := time.Now().Add(24 * time.Hour)
	const pem = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"

	if err := certs.IssueWithIdentity(ctx, tenant, pk, "ab", "cn", nb, na, pem, pub); err != nil {
		t.Fatalf("IssueWithIdentity: %v", err)
	}

	got, serial, err := certs.RevocationStatus(ctx, deviceID, pub, "00ab")
	if err != nil || got != service.EnrollStatusActive || serial != "ab" {
		t.Fatalf("padded serial = %s %s err %v, want active ab", got, serial, err)
	}
	if got, _, err = certs.RevocationStatus(ctx, deviceID, other, "ab"); err != nil || got != service.EnrollStatusUnknown {
		t.Fatalf("wrong key = %s err %v", got, err)
	}
	if got, _, err = certs.RevocationStatus(ctx, deviceID, pub, "cd"); err != nil || got != service.EnrollStatusUnknown {
		t.Fatalf("unknown serial = %s err %v", got, err)
	}

	if err := certs.Issue(ctx, tenant, pk, "cd", "cn2", nb, na, pem); err != nil {
		t.Fatalf("Issue without identity: %v", err)
	}
	if got, _, err = certs.RevocationStatus(ctx, deviceID, pub, "cd"); err != nil || got != service.EnrollStatusUnknown {
		t.Fatalf("cert with no pubkey = %s err %v", got, err)
	}
	if got, _, err = certs.RevocationStatus(ctx, deviceID, pub, "ab"); err != nil || got != service.EnrollStatusRevoked {
		t.Fatalf("superseded serial = %s err %v, want revoked", got, err)
	}

	if err := certs.Revoke(ctx, tenant, pk); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if got, _, err = certs.RevocationStatus(ctx, deviceID, pub, "cd"); err != nil || got != service.EnrollStatusUnknown {
		t.Fatalf("revoked cert with no pubkey = %s err %v", got, err)
	}

	if err := dev.DeleteByID(ctx, tenant, pk); err != nil {
		t.Fatalf("DeleteByID: %v", err)
	}
	var left int
	if err := env.Super.QueryRow(ctx, `SELECT count(*) FROM device_certificates WHERE serial_hex = 'ab'`).Scan(&left); err != nil {
		t.Fatalf("count certs: %v", err)
	}
	if left != 0 {
		t.Fatalf("cert row survived delete, count = %d", left)
	}
	if got, _, err = certs.RevocationStatus(ctx, deviceID, pub, "ab"); err != nil || got != service.EnrollStatusRevoked {
		t.Fatalf("tombstone = %s err %v, want revoked", got, err)
	}
	if got, _, err = certs.RevocationStatus(ctx, deviceID, other, "ab"); err != nil || got != service.EnrollStatusUnknown {
		t.Fatalf("tombstone wrong key = %s err %v", got, err)
	}
	if got, _, err = certs.RevocationStatus(ctx, deviceID, pub, "cd"); err != nil || got != service.EnrollStatusUnknown {
		t.Fatalf("null-pubkey serial must not be tombstoned, got %s err %v", got, err)
	}
}
