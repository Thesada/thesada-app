// Re-keys the bare legacy wifi.password device row once to wifi.password:<primary SSID>, lazily on a
// current device read and by the migrate-legacy-wifi sweep. A bare row left behind is inert.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/db"
	"thesada.app/app/pkg/secrets"
)

// LegacyWifiOutcome is what a re-key did with one device's bare row.
type LegacyWifiOutcome string

const (
	// LegacyNone - the device has no bare row.
	LegacyNone LegacyWifiOutcome = ""
	// LegacyRekeyed - the bare row moved to wifi.password:<primary>.
	LegacyRekeyed LegacyWifiOutcome = "rekeyed"
	// LegacyDuplicate - a per-SSID row for the primary already existed, the bare row was deleted (Q3).
	LegacyDuplicate LegacyWifiOutcome = "duplicate"
	// LegacyNoSSID - no primary SSID is known, the bare row stays inert.
	LegacyNoSSID LegacyWifiOutcome = "no_ssid"
	// LegacyUndecryptable - the bare row does not decrypt, it stays inert and is logged.
	LegacyUndecryptable LegacyWifiOutcome = "undecryptable"
)

// rekeyLegacyWifiTx moves the device's bare wifi.password row to wifi.password:<primary> in tx, which
// holds the device row lock: decrypt under the old AAD, encrypt under the new one, delete the bare row.
func (s *SecretService) rekeyLegacyWifiTx(ctx context.Context, tx pgx.Tx, tenantID string, devicePk uuid.UUID, primary string) (LegacyWifiOutcome, error) {
	var blob []byte
	err := tx.QueryRow(ctx,
		`SELECT ciphertext FROM device_config_secrets WHERE device_pk = $1 AND field = $2`,
		devicePk, LegacyWifiPassword).Scan(&blob)
	if errors.Is(err, pgx.ErrNoRows) {
		return LegacyNone, nil
	}
	if err != nil {
		return LegacyNone, fmt.Errorf("read legacy wifi row: %w", err)
	}
	target := WifiSecretField(primary)
	if target == "" {
		return LegacyNoSSID, nil
	}
	var exists bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM device_config_secrets WHERE device_pk = $1 AND field = $2)`,
		devicePk, target).Scan(&exists); err != nil {
		return LegacyNone, fmt.Errorf("look up %s: %w", target, err)
	}
	outcome := LegacyDuplicate
	if !exists {
		dek, err := s.tenantDEK(ctx, tx, tenantID)
		if err != nil {
			return LegacyNone, err
		}
		pt, err := secrets.DecryptSecret(dek, blob, secretAAD(tenantID, devicePk, LegacyWifiPassword))
		if err != nil {
			slog.Error("device_secret.legacy_wifi_undecryptable", "device", devicePk, "err", err)
			return LegacyUndecryptable, nil
		}
		if err := s.setSecretTx(ctx, tx, tenantID, devicePk, target, string(pt)); err != nil {
			return LegacyNone, fmt.Errorf("store %s: %w", target, err)
		}
		outcome = LegacyRekeyed
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM device_config_secrets WHERE device_pk = $1 AND field = $2`, devicePk, LegacyWifiPassword); err != nil {
		return LegacyNone, fmt.Errorf("delete legacy wifi row: %w", err)
	}
	slog.Info("device_secret.legacy_wifi_"+string(outcome), "device", devicePk, "field", target)
	return outcome, nil
}

// LegacyWifiResult is the summary of a migrate-legacy-wifi sweep.
type LegacyWifiResult struct {
	Devices       int // devices scanned
	Rekeyed       int // bare rows moved to their primary SSID
	Duplicates    int // bare rows deleted beside a per-SSID row
	NoSSID        int // bare rows left inert, no stored config names a network
	Undecryptable int // bare rows left inert, they do not decrypt
}

// MigrateLegacyWifi re-keys every device's bare wifi.password row to the primary SSID of its stored
// config.json, one tx per device under the device row lock. Idempotent. in: ctx, services. out: summary, error.
func MigrateLegacyWifi(ctx context.Context, sec *SecretService, devices *DeviceService, files *DeviceFilesService) (LegacyWifiResult, error) {
	var res LegacyWifiResult
	if !sec.Enabled() {
		return res, ErrSecretsDisabled
	}
	all, err := devices.ListAllForAdmin(ctx)
	if err != nil {
		return res, fmt.Errorf("migrate-legacy-wifi: list devices: %w", err)
	}
	for _, d := range all {
		res.Devices++
		snap, err := files.Latest(ctx, d.TenantID, d.ID, "config.json")
		if err != nil {
			return res, fmt.Errorf("migrate-legacy-wifi: read config %s/%s: %w", d.TenantID, d.DeviceID, err)
		}
		primary := ""
		if snap != nil {
			primary = primaryWifiSSID(snap.Content)
		}
		var outcome LegacyWifiOutcome
		err = db.WithTenant(ctx, sec.pools.App, d.TenantID, func(tx pgx.Tx) error {
			if err := lockDeviceConfig(ctx, tx, d.ID, nil, nil); err != nil {
				return err
			}
			var err error
			outcome, err = sec.rekeyLegacyWifiTx(ctx, tx, d.TenantID, d.ID, primary)
			return err
		})
		if err != nil {
			return res, fmt.Errorf("migrate-legacy-wifi: %s/%s: %w", d.TenantID, d.DeviceID, err)
		}
		switch outcome {
		case LegacyRekeyed:
			res.Rekeyed++
		case LegacyDuplicate:
			res.Duplicates++
		case LegacyNoSSID:
			res.NoSSID++
		case LegacyUndecryptable:
			res.Undecryptable++
		}
	}
	return res, nil
}
