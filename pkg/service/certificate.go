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
//
// Issue lifecycle (0027): a cert row is born 'pending', flips to 'active'
// once delivery is confirmed, or to 'failed' when the push errors out.
// Only revoked = false AND status = 'active' counts as a live cert; the
// pending/failed states exist so a mid-push crash never leaves a certed
// device the DB does not know about.
type CertificateService struct {
	cfg   *config.Config
	pools db.Pools
}

// Certificate lifecycle states (device_certificates.status).
const (
	// CertStatusPending is a persisted cert whose MQTT push has not been
	// confirmed yet. Not live: readers skip it.
	CertStatusPending = "pending"
	// CertStatusActive is the one live state - push confirmed, or the cert
	// was handed to the caller synchronously (JSON API pair path).
	CertStatusActive = "active"
	// CertStatusFailed is a persisted cert whose push failed. Kept for the
	// audit trail; superseded (revoked) by the next Issue for the device.
	CertStatusFailed = "failed"
)

// ErrCertNotPending means Activate/MarkFailed found no pending row to flip:
// the cert was already finalized, revoked, or superseded by a newer Issue.
var ErrCertNotPending = errors.New("certificate: no pending row to flip")

// issueTx supersedes any prior unrevoked cert for the device and inserts
// the new row in the given status, all on the caller's tx. The revoke-prior
// guard is what keeps "one live cert per device" an invariant instead of a
// convention: without it every Issue click accumulates another
// revoked = false row and GetActive just picks the newest.
// in: ctx, tx, device pk, serial hex, CN, validity window, cert PEM, status.
// out: new cert row id, error.
func issueTx(ctx context.Context, tx pgx.Tx, devicePk uuid.UUID, serialHex, cn string, notBefore, notAfter time.Time, certPEM, status string) (int64, error) {
	if _, err := tx.Exec(ctx,
		`UPDATE device_certificates SET revoked = true, revoked_at = NOW()
		 WHERE device_pk = $1 AND revoked = false`, devicePk); err != nil {
		return 0, err
	}
	var id int64
	err := tx.QueryRow(ctx,
		`INSERT INTO device_certificates (device_pk, serial_hex, cn, not_before, not_after, cert_pem, status)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING id`,
		devicePk, serialHex, cn, notBefore, notAfter, certPEM, status).Scan(&id)
	return id, err
}

// Issue stores a newly signed device certificate as 'active' and marks the
// device paired. For flows where the caller receives the cert material in
// the same exchange (JSON API pair), so persist and delivery are one step.
// The push-then-confirm admin flow uses IssuePending/Activate instead.
// The cert PEM is stored for reference; the private key is NOT stored
// server-side.
//
// Tenant-scoped through WithTenant: the supersede UPDATE, the
// device_certificates INSERT, and the devices UPDATE run under the same tx
// + app.tenant_id GUC, so the RLS policies reject a write whose tenantID
// does not own the device. Atomic - a failed paired_at update rolls the
// cert row back. Any prior unrevoked cert is revoked in the same tx.
//
// in: ctx, tenant_id, device pk, serial hex, CN, not_before, not_after, cert PEM.
// out: error.
func (s *CertificateService) Issue(ctx context.Context, tenantID string, devicePk uuid.UUID, serialHex, cn string, notBefore, notAfter time.Time, certPEM string) error {
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		if _, err := issueTx(ctx, tx, devicePk, serialHex, cn, notBefore, notAfter, certPEM, CertStatusActive); err != nil {
			return err
		}
		// Mark device as paired
		_, err := tx.Exec(ctx,
			`UPDATE devices SET paired_at = NOW() WHERE id = $1`, devicePk)
		return err
	})
}

// IssuePending persists a newly signed certificate as 'pending' BEFORE the
// MQTT push, so a mid-push failure leaves a queryable row instead of a
// certed device the DB never heard of. Any prior unrevoked cert (active,
// or a pending/failed leftover from an earlier attempt) is revoked in the
// same tx - re-running Issue supersedes, it never accumulates. paired_at
// is cleared here and only set again by Activate: pairing truth follows
// the live cert.
// in: ctx, tenant_id, device pk, serial hex, CN, not_before, not_after, cert PEM.
// out: new cert row id (for Activate/MarkFailed), error.
func (s *CertificateService) IssuePending(ctx context.Context, tenantID string, devicePk uuid.UUID, serialHex, cn string, notBefore, notAfter time.Time, certPEM string) (int64, error) {
	var id int64
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		var err error
		if id, err = issueTx(ctx, tx, devicePk, serialHex, cn, notBefore, notAfter, certPEM, CertStatusPending); err != nil {
			return err
		}
		_, err = tx.Exec(ctx,
			`UPDATE devices SET paired_at = NULL WHERE id = $1`, devicePk)
		return err
	})
	if err != nil {
		return 0, err
	}
	return id, nil
}

// Activate flips a pending cert to 'active' and marks the device paired,
// once the MQTT push has been confirmed. Guarded on status = 'pending' so
// a stale caller (superseded or already-finalized row) gets
// ErrCertNotPending instead of silently resurrecting an old cert.
// in: ctx, tenant_id, cert row id, device pk. out: error.
func (s *CertificateService) Activate(ctx context.Context, tenantID string, certID int64, devicePk uuid.UUID) error {
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE device_certificates SET status = $1
			 WHERE id = $2 AND status = $3 AND revoked = false`,
			CertStatusActive, certID, CertStatusPending)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrCertNotPending
		}
		_, err = tx.Exec(ctx,
			`UPDATE devices SET paired_at = NOW() WHERE id = $1`, devicePk)
		return err
	})
}

// MarkFailed flips a pending cert to 'failed' after a push error. The row
// stays for the audit trail; the next Issue for the device revokes it.
// paired_at was already cleared by IssuePending, so the device reads
// unpaired - which matches what the operator saw fail.
// in: ctx, tenant_id, cert row id. out: error (ErrCertNotPending if the
// row was already finalized or superseded).
func (s *CertificateService) MarkFailed(ctx context.Context, tenantID string, certID int64) error {
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE device_certificates SET status = $1
			 WHERE id = $2 AND status = $3`,
			CertStatusFailed, certID, CertStatusPending)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrCertNotPending
		}
		return nil
	})
}

// Revoke marks every unrevoked certificate for a device as revoked
// (including pending/failed leftovers) and clears the paired_at timestamp.
// Tenant-scoped through WithTenant; both updates run atomically under the
// app.tenant_id GUC.
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

// GetActive returns the live (non-revoked, status='active') certificate
// for a device. Pending/failed rows are invisible here: a cert that never
// finished its push must not read as paired. Tenant-scoped through
// WithTenant: with RLS on, a devicePk from another tenant simply returns
// no rows.
// in: ctx, tenant_id, device pk. out: *DeviceCertificate or nil.
func (s *CertificateService) GetActive(ctx context.Context, tenantID string, devicePk uuid.UUID) (*DeviceCertificate, error) {
	const query = `
		SELECT id, device_pk, serial_hex, cn, not_before, not_after, cert_pem, revoked, revoked_at, status, created_at
		FROM device_certificates
		WHERE device_pk = $1 AND revoked = false AND status = 'active'
		ORDER BY created_at DESC LIMIT 1`
	var dc DeviceCertificate
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, devicePk).Scan(
			&dc.ID, &dc.DevicePK, &dc.SerialHex, &dc.CN, &dc.NotBefore, &dc.NotAfter,
			&dc.CertPEM, &dc.Revoked, &dc.RevokedAt, &dc.Status, &dc.CreatedAt)
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
// a live (non-revoked, status='active') certificate for the given
// firmware-claimed device_id, regardless of which tenant the caller thinks
// the message belongs to. Used by the MQTT receive path to reject topic
// traffic that claims a different tenant than the one this device was
// paired into: without this check, a misconfigured broker ACL plus an
// existing target tenant slug is enough to auto-create a duplicate device
// row in the wrong tenant.
//
// Returns "", false if no live certificate exists for this device_id -
// meaning this device has never paired, its last pairing was revoked, or
// an issue is still mid-push (pending) / failed. In all cases the MQTT
// handler treats the incoming topic tenant as authoritative and proceeds.
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
		WHERE d.device_id = $1 AND c.revoked = false AND c.status = 'active'
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

// ListByDevice returns all certificates (including revoked and
// pending/failed) for a device. Tenant-scoped through WithTenant.
// in: ctx, tenant_id, device pk. out: []DeviceCertificate.
func (s *CertificateService) ListByDevice(ctx context.Context, tenantID string, devicePk uuid.UUID) ([]DeviceCertificate, error) {
	const query = `
		SELECT id, device_pk, serial_hex, cn, not_before, not_after, cert_pem, revoked, revoked_at, status, created_at
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
				&dc.CertPEM, &dc.Revoked, &dc.RevokedAt, &dc.Status, &dc.CreatedAt); err != nil {
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
