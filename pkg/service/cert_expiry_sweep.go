package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/db"
)

// CertExpiryWarning is how long before a device certificate's not_after the
// cert_expiring alert is raised. Nothing renews certificates; the fix is a
// re-pair, so the warning has to come early enough for someone to do it.
const CertExpiryWarning = 30 * 24 * time.Hour

type certExpiryCandidate struct {
	tenantID string
	devicePk uuid.UUID
	deviceID string
	serial   string
	notAfter time.Time
}

// RaiseCertExpiriesAny inserts one warn alert per active device certificate
// that expires within CertExpiryWarning, keyed by serial so it is raised once,
// and clears the alert once that certificate is no longer the active one.
// in: ctx. out: none (logs per device).
func (s *AlertService) RaiseCertExpiriesAny(ctx context.Context) {
	var batch []certExpiryCandidate
	err := db.WithAdminAudit(ctx, s.pools.Admin, "alert cert expiry sweep", func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			UPDATE device_alerts a SET cleared_at = now()
			 WHERE a.code = 'cert_expiring' AND a.cleared_at IS NULL
			   AND NOT EXISTS (
			     SELECT 1 FROM device_certificates c
			      WHERE c.serial_hex = a.raw->>'serial'
			        AND NOT c.revoked AND c.status = 'active')`); err != nil {
			return fmt.Errorf("clear cert expiry: %w", err)
		}
		rows, err := tx.Query(ctx, `
			SELECT d.tenant_id, d.id, d.device_id, c.serial_hex, c.not_after
			  FROM device_certificates c
			  JOIN devices d ON d.id = c.device_pk
			 WHERE NOT c.revoked AND c.status = 'active'
			   AND c.not_after <= now() + $1::interval
			   AND NOT EXISTS (
			     SELECT 1 FROM device_alerts a
			      WHERE a.device_pk = d.id AND a.code = 'cert_expiring'
			        AND a.raw->>'serial' = c.serial_hex)
			 ORDER BY c.not_after
			 LIMIT $2`,
			fmt.Sprintf("%d hours", int(CertExpiryWarning/time.Hour)), absenceBatchLimit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r certExpiryCandidate
			if err := rows.Scan(&r.tenantID, &r.devicePk, &r.deviceID, &r.serial, &r.notAfter); err != nil {
				return err
			}
			batch = append(batch, r)
		}
		return rows.Err()
	})
	if err != nil {
		slog.Error("alert cert expiry scan failed", "err", err)
		return
	}
	for _, r := range batch {
		raw, err := json.Marshal(map[string]string{
			"kind":      "cert_expiring",
			"serial":    r.serial,
			"not_after": r.notAfter.UTC().Format(time.RFC3339),
		})
		if err != nil {
			slog.Error("alert cert expiry encode failed", "device", r.deviceID, "err", err)
			continue
		}
		msg := "client certificate expires " + r.notAfter.UTC().Format("2006-01-02") + "; re-pair the device before then"
		id, err := s.InsertAlert(ctx, r.tenantID, r.devicePk, "warn", "cert_expiring", msg, raw)
		if errors.Is(err, ErrDuplicateAlert) {
			continue
		}
		if err != nil {
			slog.Error("alert cert expiry insert failed", "device", r.deviceID, "err", err)
			continue
		}
		slog.Info("alert.cert_expiring.raised", "tenant", r.tenantID, "device", r.deviceID,
			"serial", r.serial, "not_after", r.notAfter, "alert_id", id)
	}
}
