// Orders device reads of config.json against config changes and keeps the open WiFi
// markers the write guard reads. Kept in the database, on the database clock (0048).
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/db"
)

// ReadStart is the database clock before a device read is sent, handed to
// UpsertFromDevice with what the read returned. in: ctx, tenant. out: start, error.
func (s *DeviceFilesService) ReadStart(ctx context.Context, tenantID string) (time.Time, error) {
	var t time.Time
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&t)
	})
	return t, err
}

// MarkConfigChanged records a config.json change on the device. Reads started earlier
// store nothing, markers seen earlier stop counting. in: ctx, tenant, device. out: error.
func (s *DeviceFilesService) MarkConfigChanged(ctx context.Context, tenantID string, devicePk uuid.UUID) error {
	return s.MarkConfigChanging(ctx, tenantID, devicePk, 0)
}

// MarkConfigChanging records a change that may land for up to window: the stamp is now plus
// window, so reads and markers in it stay stale even when no closing MarkConfigChanged commits.
// in: ctx, tenant, device, window. out: error.
func (s *DeviceFilesService) MarkConfigChanging(ctx context.Context, tenantID string, devicePk uuid.UUID, window time.Duration) error {
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		// Locked first, so the stamp is taken after a refresh holding the row committed.
		if err := lockDeviceConfig(ctx, tx, devicePk, nil, nil); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`UPDATE devices SET config_changed_at = clock_timestamp() + $2 * interval '1 millisecond' WHERE id = $1`,
			devicePk, window.Milliseconds())
		return err
	})
}

// lockDeviceConfig locks the device row for one config change or read, and reads
// its order stamps into changedAt and readAt when they are not nil.
func lockDeviceConfig(ctx context.Context, tx pgx.Tx, devicePk uuid.UUID, changedAt, readAt **time.Time) error {
	var c, r *time.Time
	err := tx.QueryRow(ctx,
		`SELECT config_changed_at, config_read_at FROM devices WHERE id = $1 FOR UPDATE`, devicePk).Scan(&c, &r)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("device %s not found", devicePk)
	}
	if err != nil {
		return fmt.Errorf("lock device %s: %w", devicePk, err)
	}
	if changedAt != nil {
		*changedAt = c
	}
	if readAt != nil {
		*readAt = r
	}
	return nil
}

// UpsertFromDevice is Upsert for content the device reported or confirmed. config.json runs in one
// tx under the device row lock: a stale read writes nothing, a current one refreshes the store too.
func (s *DeviceFilesService) UpsertFromDevice(ctx context.Context, tenantID string, devicePk uuid.UUID, path, content, sha256hex, source string, createdBy *uuid.UUID, readStart time.Time) error {
	if !isConfigJSON(path) {
		return s.Upsert(ctx, tenantID, devicePk, path, content, sha256hex, source, createdBy)
	}
	if readStart.IsZero() {
		return errors.New("device read of config.json without a read start")
	}
	blanked, err := blankedContent(path, content)
	if err != nil {
		return err
	}
	stale := false
	err = db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		var changedAt, readAt *time.Time
		if err := lockDeviceConfig(ctx, tx, devicePk, &changedAt, &readAt); err != nil {
			return err
		}
		if (changedAt != nil && !changedAt.Before(readStart)) || (readAt != nil && readAt.After(readStart)) {
			stale = true
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE devices SET config_read_at = $2 WHERE id = $1`, devicePk, readStart); err != nil {
			return err
		}
		if s.secrets != nil && s.secrets.Enabled() {
			if err := s.refreshStoreTx(ctx, tx, tenantID, devicePk, content, source, readStart); err != nil {
				return err
			}
		}
		return upsertTx(ctx, tx, devicePk, path, blanked, sha256hex, source, createdBy)
	})
	if err == nil && stale {
		slog.Info("device.read.stale_dropped", "device", devicePk, "source", source)
	}
	return err
}

// refreshStoreTx fills only fields the store has nothing for, as the firmware resolves NVS first (C1),
// and sets the device's markers to the networks this read shows open.
func (s *DeviceFilesService) refreshStoreTx(ctx context.Context, tx pgx.Tx, tenantID string, devicePk uuid.UUID, content, source string, seenAt time.Time) error {
	found := extractConfigSecrets(content)
	primary := WifiSecretField(primaryWifiSSID(content))
	for _, field := range slices.Sorted(maps.Keys(found)) {
		has, err := storedForReadTx(ctx, tx, devicePk, field, primary)
		if err != nil {
			return fmt.Errorf("look up device secret %s: %w", field, err)
		}
		if has {
			continue
		}
		if err := s.secrets.setSecretTx(ctx, tx, tenantID, devicePk, field, found[field]); err != nil {
			return fmt.Errorf("store device secret %s: %w", field, err)
		}
	}
	// Non-nil: ANY over a NULL array matches nothing, and NOT of that deletes nothing.
	open := []string{}
	for _, ssid := range openWifiSSIDs(content) {
		// A stored password is in NVS, which the firmware reads before the file's "".
		has, err := storedForReadTx(ctx, tx, devicePk, WifiSecretField(ssid), primary)
		if err != nil {
			return fmt.Errorf("look up device secret %s: %w", WifiSecretField(ssid), err)
		}
		if !has {
			open = append(open, ssid)
		}
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM device_open_networks WHERE device_pk = $1 AND NOT (ssid = ANY($2::text[]))`,
		devicePk, open); err != nil {
		return fmt.Errorf("drop open networks: %w", err)
	}
	for _, ssid := range open {
		if _, err := tx.Exec(ctx, `
			INSERT INTO device_open_networks (tenant_id, device_pk, ssid, seen_at, source)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (device_pk, ssid) DO UPDATE SET seen_at = EXCLUDED.seen_at, source = EXCLUDED.source`,
			tenantID, devicePk, ssid, seenAt, source); err != nil {
			return fmt.Errorf("record open network: %w", err)
		}
	}
	return nil
}

// storedForReadTx is hasSecretTx, plus the legacy bare row for primary (wifi.password:<primary
// SSID>), where provisioning puts it in NVS. out: stored, error.
func storedForReadTx(ctx context.Context, tx pgx.Tx, devicePk uuid.UUID, field, primary string) (bool, error) {
	has, err := hasSecretTx(ctx, tx, devicePk, field)
	if err != nil || has || field == "" || field != primary {
		return has, err
	}
	return hasSecretTx(ctx, tx, devicePk, LegacyWifiPassword)
}

// OpenNetworkCurrent reports whether a device read showed ssid open after the
// device's last config change. in: ctx, tenant, device, ssid. out: open, error.
func (s *DeviceFilesService) OpenNetworkCurrent(ctx context.Context, tenantID string, devicePk uuid.UUID, ssid string) (bool, error) {
	var open bool
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT EXISTS (
			    SELECT 1 FROM device_open_networks o
			      JOIN devices d ON d.id = o.device_pk
			     WHERE o.device_pk = $1 AND o.ssid = $2
			       AND (d.config_changed_at IS NULL OR o.seen_at > d.config_changed_at))`,
			devicePk, ssid).Scan(&open)
	})
	return open, err
}
