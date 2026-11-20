// Re-keys the bare legacy wifi.password device row once to wifi.password:<primary SSID>, lazily on a
// current device read and by the migrate-legacy-wifi sweep. A bare row left behind is inert.
package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

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
	// LegacyDropped - the stored config.json names another primary SSID, the bare row was deleted.
	LegacyDropped LegacyWifiOutcome = "dropped"
)

// rekeyLegacyWifiTx moves the device's bare wifi.password row to wifi.password:<primary> in tx, which
// holds the device row lock: decrypt under the old AAD, encrypt under the new one flagged rekeyed, delete the bare row.
// When stored, the primary SSID of the config.json the app held before, names another network, the bare row is deleted.
func (s *SecretService) rekeyLegacyWifiTx(ctx context.Context, tx pgx.Tx, tenantID string, devicePk uuid.UUID, primary, stored string) (LegacyWifiOutcome, error) {
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
	if stored != "" && stored != primary {
		if _, err := tx.Exec(ctx,
			`DELETE FROM device_config_secrets WHERE device_pk = $1 AND field = $2`, devicePk, LegacyWifiPassword); err != nil {
			return LegacyNone, fmt.Errorf("delete legacy wifi row: %w", err)
		}
		slog.Info("device_secret.legacy_wifi_dropped", "device", devicePk, "reason", "primary ssid changed")
		return LegacyDropped, nil
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
		if err := s.writeSecretTx(ctx, tx, tenantID, devicePk, target, string(pt), true); err != nil {
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

// ErrWifiSecretChanged - the WiFi password row changed after its mark was taken, so DropClearedWifi kept it.
var ErrWifiSecretChanged = errors.New("secret: wifi password changed since the clear")

// WifiSecretMark is a device WiFi password row, and the bare legacy row, as they stood before a Clear on
// device. The sealed blob carries a fresh nonce on every write, so an equal blob is the same write.
type WifiSecretMark struct {
	blob   []byte
	legacy []byte
}

// MarkWifiSecret reads the device's row for field and its bare legacy row before the device clear, under
// the device row lock so no re-key lands between the two. No row is a mark too. in: ctx, tenant, device, field. out: mark, error.
func (s *SecretService) MarkWifiSecret(ctx context.Context, tenantID string, devicePk uuid.UUID, field string) (WifiSecretMark, error) {
	var m WifiSecretMark
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		if err := lockDeviceConfig(ctx, tx, devicePk, nil, nil); err != nil {
			return err
		}
		var err error
		if m.blob, _, err = wifiSecretRowTx(ctx, tx, devicePk, field); err != nil {
			return err
		}
		m.legacy, _, err = wifiSecretRowTx(ctx, tx, devicePk, LegacyWifiPassword)
		return err
	})
	return m, err
}

// wifiSecretRowTx returns the sealed blob of the device's row for field and its re-key flag, nil without a row.
func wifiSecretRowTx(ctx context.Context, tx pgx.Tx, devicePk uuid.UUID, field string) ([]byte, bool, error) {
	var blob []byte
	var rekeyed bool
	err := tx.QueryRow(ctx,
		`SELECT ciphertext, rekeyed FROM device_config_secrets WHERE device_pk = $1 AND field = $2`,
		devicePk, field).Scan(&blob, &rekeyed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read %s: %w", field, err)
	}
	return blob, rekeyed, nil
}

// DropClearedWifi deletes the store rows for a WiFi password the device verified empty, in one tx under
// the device row lock: the per-SSID row, and the bare legacy row unless the stored config.json names another
// primary SSID, so a later re-key cannot bring the password back. A per-SSID row written after mark is kept
// and the call returns ErrWifiSecretChanged, unless the re-key of the marked bare row wrote it and nothing since.
// in: ctx, tenant, device, field, mark. out: error.
func (s *SecretService) DropClearedWifi(ctx context.Context, tenantID string, devicePk uuid.UUID, field string, mark WifiSecretMark) error {
	ssid, ok := strings.CutPrefix(field, WifiPasswordPrefix)
	if !ok || ssid == "" || !validSecretField(field) {
		return fmt.Errorf("secret: %q is not a per-SSID WiFi password", field)
	}
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		if err := lockDeviceConfig(ctx, tx, devicePk, nil, nil); err != nil {
			return err
		}
		blob, rekeyed, err := wifiSecretRowTx(ctx, tx, devicePk, field)
		if err != nil {
			return err
		}
		rekeyedSinceMark := rekeyed && mark.blob == nil && mark.legacy != nil
		if blob != nil && !bytes.Equal(blob, mark.blob) && !rekeyedSinceMark {
			return ErrWifiSecretChanged
		}
		if _, err := tx.Exec(ctx,
			`DELETE FROM device_config_secrets WHERE device_pk = $1 AND field = $2`, devicePk, field); err != nil {
			return fmt.Errorf("delete %s: %w", field, err)
		}
		var content string
		reason := "primary ssid"
		err = tx.QueryRow(ctx,
			`SELECT content FROM device_files WHERE device_pk = $1 AND path = 'config.json'`, devicePk).Scan(&content)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			reason = "no stored config"
		case err != nil:
			return fmt.Errorf("read stored config.json: %w", err)
		case primaryWifiSSID(content) == "":
			reason = "no primary ssid"
		case primaryWifiSSID(content) != ssid:
			return nil
		}
		tag, err := tx.Exec(ctx,
			`DELETE FROM device_config_secrets WHERE device_pk = $1 AND field = $2`, devicePk, LegacyWifiPassword)
		if err != nil {
			return fmt.Errorf("delete legacy wifi row: %w", err)
		}
		if tag.RowsAffected() > 0 {
			slog.Info("device_secret.legacy_wifi_cleared", "device", devicePk, "field", field, "reason", reason)
		}
		return nil
	})
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
			outcome, err = sec.rekeyLegacyWifiTx(ctx, tx, d.TenantID, d.ID, primary, primary)
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
