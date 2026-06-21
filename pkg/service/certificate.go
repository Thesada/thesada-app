// Auto-extracted from service.go on 2026-05-05.
// Lives in package service. Imports cleaned by goimports.
package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/db"
)

// ---------------------------------------------------------------------------
// CertificateService - per-device mTLS client certificates
// ---------------------------------------------------------------------------

// CertificateService manages X.509 client certificates for device mTLS
// authentication. Certificates are signed by the app's internal CA and
// stored for tracking and revocation.
type CertificateService struct {
	cfg   *config.Config
	pools db.Pools
}

// Issue stores a newly signed device certificate. The cert PEM is stored
// for reference; the private key is NOT stored server-side.
//
// Tenant-scoped through WithTenant: both the device_certificates INSERT and
// the devices UPDATE run under the same tx + app.tenant_id GUC, so the RLS
// policies reject a write whose tenantID does not own the device. Atomic -
// a failed paired_at update rolls back the cert row.
//
// in: ctx, tenant_id, device pk, serial hex, CN, not_before, not_after, cert PEM.
// out: error.
func (s *CertificateService) Issue(ctx context.Context, tenantID string, devicePk uuid.UUID, serialHex, cn string, notBefore, notAfter time.Time, certPEM string) error {
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO device_certificates (device_pk, serial_hex, cn, not_before, not_after, cert_pem)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			devicePk, serialHex, cn, notBefore, notAfter, certPEM); err != nil {
			return err
		}
		// Mark device as paired
		_, err := tx.Exec(ctx,
			`UPDATE devices SET paired_at = NOW() WHERE id = $1`, devicePk)
		return err
	})
}

// Revoke marks the active certificate for a device as revoked and clears
// the paired_at timestamp. Tenant-scoped through WithTenant; both updates
// run atomically under the app.tenant_id GUC.
// in: ctx, tenant_id, device pk. out: error.
func (s *CertificateService) Revoke(ctx context.Context, tenantID string, devicePk uuid.UUID) error {
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`UPDATE device_certificates SET revoked = true, revoked_at = NOW()
			 WHERE device_pk = $1 AND revoked = false`, devicePk); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`UPDATE devices SET paired_at = NULL WHERE id = $1`, devicePk)
		return err
	})
}

// GetActive returns the active (non-revoked) certificate for a device.
// Tenant-scoped through WithTenant: with RLS on, a devicePk from another
// tenant simply returns no rows.
// in: ctx, tenant_id, device pk. out: *DeviceCertificate or nil.
func (s *CertificateService) GetActive(ctx context.Context, tenantID string, devicePk uuid.UUID) (*DeviceCertificate, error) {
	const query = `
		SELECT id, device_pk, serial_hex, cn, not_before, not_after, cert_pem, revoked, revoked_at, created_at
		FROM device_certificates
		WHERE device_pk = $1 AND revoked = false
		ORDER BY created_at DESC LIMIT 1`
	var dc DeviceCertificate
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, devicePk).Scan(
			&dc.ID, &dc.DevicePK, &dc.SerialHex, &dc.CN, &dc.NotBefore, &dc.NotAfter,
			&dc.CertPEM, &dc.Revoked, &dc.RevokedAt, &dc.CreatedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &dc, nil
}

// FindActivePairingTenant returns the tenant_id of the device that holds
// an active (non-revoked) certificate for the given firmware-claimed
// device_id, regardless of which tenant the caller thinks the message
// belongs to. Used by the MQTT receive path to reject topic traffic that
// claims a different tenant than the one this device was paired into:
// without this check, a misconfigured broker ACL plus an existing target
// tenant slug is enough to auto-create a duplicate device row in the
// wrong tenant.
//
// Returns "", false if no paired (non-revoked) certificate exists for
// this device_id - meaning this device has never paired, or its last
// pairing was revoked. In both cases the MQTT handler treats the
// incoming topic tenant as authoritative and proceeds.
//
// Cross-tenant BY DESIGN: the whole purpose is to discover which tenant a
// device_id is paired into, so there is no tenantID to scope by - the
// answer IS the tenantID. Runs through WithAdminAudit on the BYPASSRLS
// pool. Without this, an RLS policy with no app.tenant_id GUC would return
// zero rows and the gate would silently fall open.
// in: ctx, firmware-claimed device_id string. out: paired tenant slug, found bool, error.
func (s *CertificateService) FindActivePairingTenant(ctx context.Context, deviceID string) (string, bool, error) {
	const query = `
		SELECT d.tenant_id
		FROM device_certificates c
		JOIN devices d ON d.id = c.device_pk
		WHERE d.device_id = $1 AND c.revoked = false
		ORDER BY c.created_at DESC LIMIT 1`
	var tenantID string
	found := false
	err := db.WithAdminAudit(ctx, s.pools.Admin, "certificate.find_active_pairing_tenant",
		func(tx pgx.Tx) error {
			scanErr := tx.QueryRow(ctx, query, deviceID).Scan(&tenantID)
			if errors.Is(scanErr, pgx.ErrNoRows) {
				return nil
			}
			if scanErr != nil {
				return scanErr
			}
			found = true
			return nil
		})
	if err != nil {
		return "", false, err
	}
	return tenantID, found, nil
}

// ListByDevice returns all certificates (including revoked) for a device.
// Tenant-scoped through WithTenant.
// in: ctx, tenant_id, device pk. out: []DeviceCertificate.
func (s *CertificateService) ListByDevice(ctx context.Context, tenantID string, devicePk uuid.UUID) ([]DeviceCertificate, error) {
	const query = `
		SELECT id, device_pk, serial_hex, cn, not_before, not_after, cert_pem, revoked, revoked_at, created_at
		FROM device_certificates
		WHERE device_pk = $1
		ORDER BY created_at DESC`
	var out []DeviceCertificate
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, devicePk)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var dc DeviceCertificate
			if err := rows.Scan(&dc.ID, &dc.DevicePK, &dc.SerialHex, &dc.CN, &dc.NotBefore, &dc.NotAfter,
				&dc.CertPEM, &dc.Revoked, &dc.RevokedAt, &dc.CreatedAt); err != nil {
				return err
			}
			out = append(out, dc)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
