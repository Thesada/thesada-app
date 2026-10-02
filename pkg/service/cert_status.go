package service

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/db"
)

// RevocationStatus answers a signed cert-status check. Lookup is by
// canonical serial, across tenants, because the device has no tenant to
// present. The admin pool is the bypass path; the decision itself is
// CertRevocationAnswer.
// in: ctx, device id, lowercase-hex pubkey, serial (canonical or padded).
// out: active, revoked, or unknown, and the canonical serial. Error only
// when the serial is not canonical or the database read fails.
func (s *CertificateService) RevocationStatus(ctx context.Context, deviceID, pubkeyHex, serial string) (string, string, error) {
	canonical, ok := CanonicalCertSerial(serial)
	if !ok {
		return "", "", errors.New("cert status: serial not canonical")
	}
	var row *CertStatusRow
	var tomb *CertSerialTombstone
	err := db.WithAdminAudit(ctx, s.pools.Admin, "cert revocation status", func(tx pgx.Tx) error {
		var got CertStatusRow
		var pub *string
		qerr := tx.QueryRow(ctx, `
			SELECT c.revoked, c.status, c.pubkey_hex, d.device_id
			  FROM device_certificates c
			  JOIN devices d ON d.id = c.device_pk
			 WHERE c.serial_hex = $1`, canonical).Scan(
			&got.Revoked, &got.Status, &pub, &got.DeviceID)
		if qerr == nil {
			if pub != nil {
				got.PubkeyHex = *pub
			}
			row = &got
			return nil
		}
		if !errors.Is(qerr, pgx.ErrNoRows) {
			return qerr
		}
		var t CertSerialTombstone
		terr := tx.QueryRow(ctx, `
			SELECT device_id, pubkey_hex
			  FROM device_cert_serial_tombstones
			 WHERE serial_hex = $1`, canonical).Scan(&t.DeviceID, &t.PubkeyHex)
		if terr == nil {
			tomb = &t
			return nil
		}
		if errors.Is(terr, pgx.ErrNoRows) {
			return nil
		}
		return terr
	})
	if err != nil {
		return "", "", err
	}
	return CertRevocationAnswer(deviceID, pubkeyHex, row, tomb), canonical, nil
}
