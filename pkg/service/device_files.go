// Owns the reads/writes for the device-file tables: device_files (canonical
// current state), device_file_history (immutable change log), and
// device_file_observations (drift telemetry). Replaced the single legacy
// snapshots table.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/db"
)

// DeviceFilesService owns the canonical-state + history + drift-observation
// tables introduced by migration 0012. Replaces ConfigSnapshotService for
// new code paths.
type DeviceFilesService struct {
	cfg     *config.Config
	pools   db.Pools
	secrets *SecretService

	// Per-device order: a device read stores secrets only when no write landed since
	// it started. orderMu guards the map only. In memory, which holds for one app instance.
	orderMu sync.Mutex
	devs    map[uuid.UUID]*deviceOrder
}

// deviceOrder serialises one device's store refreshes and writes. untrusted marks a
// config change the store could not follow, cleared by the next current read.
type deviceOrder struct {
	mu        sync.Mutex
	gen       atomic.Uint64
	untrusted atomic.Bool
}

func (s *DeviceFilesService) order(devicePk uuid.UUID) *deviceOrder {
	s.orderMu.Lock()
	defer s.orderMu.Unlock()
	if s.devs == nil {
		s.devs = make(map[uuid.UUID]*deviceOrder)
	}
	d, ok := s.devs[devicePk]
	if !ok {
		d = &deviceOrder{}
		s.devs[devicePk] = d
	}
	return d
}

// ReadToken is taken before a device read asks for content, and handed to
// UpsertFromDevice with what the read returned. out: the device's write generation.
func (s *DeviceFilesService) ReadToken(devicePk uuid.UUID) uint64 {
	return s.order(devicePk).gen.Load()
}

// WriteLanded marks a confirmed write, after any store running for the device. Older
// reads keep their snapshot but leave the store alone. out: token for the write's upsert.
func (s *DeviceFilesService) WriteLanded(devicePk uuid.UUID) uint64 {
	d := s.order(devicePk)
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.gen.Add(1)
}

// DistrustOpenNetworks marks the device's open-network markers as stale: the guard
// refuses empty WiFi passwords until a current device read refreshes the store.
func (s *DeviceFilesService) DistrustOpenNetworks(devicePk uuid.UUID) {
	s.order(devicePk).untrusted.Store(true)
}

// OpenNetworksTrusted reports whether the open-network markers follow the device.
func (s *DeviceFilesService) OpenNetworksTrusted(devicePk uuid.UUID) bool {
	return !s.order(devicePk).untrusted.Load()
}

// UpsertFromDevice is Upsert for content read from the device itself (config.dump,
// the drift pull) or written to it and confirmed. Before config.json is blanked it
// hands every secret, and every open WiFi network as "", to the encrypted store, so
// the write guard can tell an open network from a blanked one (#88). token comes
// from ReadToken or WriteLanded: content older than the last landed write leaves
// the store alone. Operator-supplied content goes through plain Upsert.
// in: ctx, tenantID, devicePk, path, content, sha256, source, createdBy, token. out: error.
func (s *DeviceFilesService) UpsertFromDevice(ctx context.Context, tenantID string, devicePk uuid.UUID, path, content, sha256hex, source string, createdBy *uuid.UUID, token uint64) error {
	if isConfigJSON(path) && s.secrets != nil && s.secrets.Enabled() {
		if err := s.storeDeviceSecrets(ctx, tenantID, devicePk, content, token); err != nil {
			return err
		}
	}
	return s.Upsert(ctx, tenantID, devicePk, path, content, sha256hex, source, createdBy)
}

// storeDeviceSecrets runs under the device lock, so a write cannot land between the
// token check and the stores. in: ctx, tenant, device, content, token. out: error.
func (s *DeviceFilesService) storeDeviceSecrets(ctx context.Context, tenantID string, devicePk uuid.UUID, content string, token uint64) error {
	d := s.order(devicePk)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.gen.Load() != token {
		slog.Info("device read older than the last write, secrets left as they are", "device", devicePk)
		return nil
	}
	for field, value := range deviceConfigSecrets(content) {
		// A value the store already resolves to stays as it is, so a device on the
		// tenant default keeps inheriting instead of turning into an override.
		cur, origin, err := s.secrets.Resolve(ctx, tenantID, devicePk, field)
		if err != nil {
			return fmt.Errorf("resolve device secret %s: %w", field, err)
		}
		if origin != OriginUnset && cur == value {
			continue
		}
		// Fail before the snapshot is blanked, or the value is lost to the store.
		if err := s.secrets.SetSecret(ctx, tenantID, devicePk, field, value); err != nil {
			return fmt.Errorf("store device secret %s: %w", field, err)
		}
	}
	d.untrusted.Store(false)
	return nil
}

// ForgetOpenNetworks drops the open-network markers of every WiFi network named in
// content. After a write whose store refresh failed, an unknown network is refused,
// a stale "open" would not be. Stored passwords stay. in: ctx, tenant, device, content. out: error.
func (s *DeviceFilesService) ForgetOpenNetworks(ctx context.Context, tenantID string, devicePk uuid.UUID, content string) error {
	if s.secrets == nil || !s.secrets.Enabled() {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(content), &m); err != nil {
		return fmt.Errorf("forget open networks: %w", err)
	}
	fields := make([]string, 0)
	for _, ssid := range WifiNetworkSSIDs(m) {
		fields = append(fields, WifiSecretField(ssid))
	}
	return s.forgetOpen(ctx, tenantID, devicePk, fields)
}

// ForgetAllOpenNetworks drops every open-network marker of the device, for a config
// change whose content the app never saw (a CLI rename or delete). in: ctx, tenant, device. out: error.
func (s *DeviceFilesService) ForgetAllOpenNetworks(ctx context.Context, tenantID string, devicePk uuid.UUID) error {
	if s.secrets == nil || !s.secrets.Enabled() {
		return nil
	}
	stored, err := s.secrets.Status(ctx, tenantID, devicePk)
	if err != nil {
		return fmt.Errorf("forget open networks: %w", err)
	}
	fields := make([]string, 0)
	for f, set := range stored {
		if set && IsWifiPasswordField(f) {
			fields = append(fields, f)
		}
	}
	return s.forgetOpen(ctx, tenantID, devicePk, fields)
}

func (s *DeviceFilesService) forgetOpen(ctx context.Context, tenantID string, devicePk uuid.UUID, fields []string) error {
	d := s.order(devicePk)
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, field := range fields {
		v, found, err := s.secrets.Reveal(ctx, tenantID, devicePk, field)
		if err != nil {
			return fmt.Errorf("forget open networks: %w", err)
		}
		if found && v == "" {
			if _, err := s.secrets.ClearDeviceSecret(ctx, tenantID, devicePk, field); err != nil {
				return fmt.Errorf("forget open networks: %w", err)
			}
		}
	}
	return nil
}

func isConfigJSON(path string) bool { return path == "config.json" || path == "/config.json" }

// Upsert writes the canonical current state for (devicePk, path) and, if
// the sha differs from the prior canonical row, appends a history entry
// with prev_sha256 set to the prior sha. Atomic via a single transaction.
//
// Tenant-scoped through WithTenant: device_files is RLS-policed transitive
// via device_pk -> devices.tenant_id; device_file_history is direct on a
// denormalized tenant_id (0014 trigger). Both writes plus the prior-sha
// read run inside the one app.tenant_id-scoped tx.
//
// in:  ctx, tenantID, devicePk, path, content, sha256, source, createdBy (nil for system)
// out: error if either table write failed
func (s *DeviceFilesService) Upsert(ctx context.Context, tenantID string, devicePk uuid.UUID, path, content, sha256hex, source string, createdBy *uuid.UUID) error {
	// Never persist plaintext device-config secrets. Blank the sensitive
	// fields in config.json before it reaches device_files / history; every
	// write + ingest path funnels through here, so this is the one chokepoint.
	// sha256hex is left as the device fingerprint (drift key) - blanking the
	// stored copy must not read as drift - and the real values live encrypted
	// in device_config_secrets.
	if isConfigJSON(path) {
		blanked, _, err := blankConfigSecrets(content)
		if err != nil {
			return fmt.Errorf("blank config secrets: %w", err)
		}
		content = blanked
	}
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		// Read prior canonical sha (NULL if first insert).
		var prev *string
		err := tx.QueryRow(ctx,
			`SELECT sha256 FROM device_files WHERE device_pk = $1 AND path = $2`,
			devicePk, path).Scan(&prev)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}

		// Upsert canonical row.
		_, err = tx.Exec(ctx,
			`INSERT INTO device_files (device_pk, path, content, sha256, source, updated_at, updated_by)
			 VALUES ($1, $2, $3, $4, $5, NOW(), $6)
			 ON CONFLICT (device_pk, path) DO UPDATE
			   SET content = EXCLUDED.content,
			       sha256 = EXCLUDED.sha256,
			       source = EXCLUDED.source,
			       updated_at = EXCLUDED.updated_at,
			       updated_by = EXCLUDED.updated_by`,
			devicePk, path, content, sha256hex, source, createdBy)
		if err != nil {
			return err
		}

		// Append history on sha change OR whenever the source is an operator-
		// initiated write. First-ever-write counts as change (prev is nil, so
		// prev != current). Operator writes always log even with identical
		// bytes so the audit trail records the human action - re-pushing the
		// same config after a device round-trip would otherwise silently
		// dedupe against the prior read snapshot and disappear from history.
		if prev == nil || *prev != sha256hex || source == "write" {
			_, err = tx.Exec(ctx,
				`INSERT INTO device_file_history
				   (device_pk, path, content, sha256, prev_sha256, source, created_by, created_at)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
				devicePk, path, content, sha256hex, prev, source, createdBy)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// Latest returns the canonical current row for (devicePk, path), or nil
// if the device has no entry for this path yet. Tenant-scoped via WithTenant.
//
// in:  ctx, tenantID, devicePk, path
// out: *DeviceFile or nil; error on DB fault
func (s *DeviceFilesService) Latest(ctx context.Context, tenantID string, devicePk uuid.UUID, path string) (*DeviceFile, error) {
	const q = `
		SELECT device_pk, path, content, sha256, source, updated_at, updated_by
		FROM device_files
		WHERE device_pk = $1 AND path = $2`
	var f DeviceFile
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, q, devicePk, path).Scan(
			&f.DevicePK, &f.Path, &f.Content, &f.SHA256, &f.Source, &f.UpdatedAt, &f.UpdatedBy)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// LatestSHA returns just the canonical sha256 for (devicePk, path).
// Empty string + nil error when no canonical row exists yet (drift checker
// treats that as "needs first pull"). Tenant-scoped via WithTenant.
//
// in:  ctx, tenantID, devicePk, path
// out: sha256 hex string ("" if missing); error on DB fault
func (s *DeviceFilesService) LatestSHA(ctx context.Context, tenantID string, devicePk uuid.UUID, path string) (string, error) {
	var hash string
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT sha256 FROM device_files WHERE device_pk = $1 AND path = $2`,
			devicePk, path).Scan(&hash)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return hash, nil
}

// History returns the last N history rows for (devicePk, path), newest
// first. Drives the version-history UI.
//
// in:  ctx, tenantID, devicePk, path, limit
// out: history slice (oldest at end)
func (s *DeviceFilesService) History(ctx context.Context, tenantID string, devicePk uuid.UUID, path string, limit int) ([]DeviceFileHistory, error) {
	rows, _, err := s.HistoryPage(ctx, tenantID, devicePk, path, limit, 0)
	return rows, err
}

// HistoryPage returns one page of history rows for (devicePk, path) and
// the total row count so the UI can wire Prev/Next + page indicator.
// Newest-first. Tenant-scoped via WithTenant; count + page run in one tx.
// in:  ctx, tenantID, devicePk, path, limit, offset.
// out: rows in this page, total rows for the (devicePk, path), error.
func (s *DeviceFilesService) HistoryPage(ctx context.Context, tenantID string, devicePk uuid.UUID, path string, limit, offset int) ([]DeviceFileHistory, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 250 {
		limit = 250
	}
	if offset < 0 {
		offset = 0
	}

	var total int
	var out []DeviceFileHistory
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM device_file_history
			  WHERE device_pk = $1 AND path = $2`,
			devicePk, path).Scan(&total); err != nil {
			return err
		}

		const q = `
			SELECT id, device_pk, path, content, sha256, prev_sha256, source, created_by, created_at
			FROM device_file_history
			WHERE device_pk = $1 AND path = $2
			ORDER BY created_at DESC
			LIMIT $3 OFFSET $4`
		rows, err := tx.Query(ctx, q, devicePk, path, limit, offset)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var h DeviceFileHistory
			if err := rows.Scan(&h.ID, &h.DevicePK, &h.Path, &h.Content, &h.SHA256,
				&h.PrevSHA256, &h.Source, &h.CreatedBy, &h.CreatedAt); err != nil {
				return err
			}
			out = append(out, h)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// RecordObservation appends a drift telemetry row. No content payload -
// just hash + timestamp. Cheap; insert per device_info publish if you want
// a long-term drift trail. Currently unused on the hot path (drift compares
// against device_files.sha256 directly), but here for the dashboard graphs
// of "what hash did we see when".
//
// in:  ctx, tenantID, devicePk, path, reportedSHA
// out: error on DB fault
func (s *DeviceFilesService) RecordObservation(ctx context.Context, tenantID string, devicePk uuid.UUID, path, reportedSHA string) error {
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO device_file_observations (device_pk, path, reported_sha256, observed_at)
			 VALUES ($1, $2, $3, NOW())`,
			devicePk, path, reportedSHA)
		return err
	})
}

// PruneHistory deletes history rows beyond the retention limit for one
// (device, path). Keeps the most recent N. Mirrors ConfigSnapshotService
// retention semantics.
//
// in:  ctx, tenantID, devicePk, path
// out: error on DB fault
func (s *DeviceFilesService) PruneHistory(ctx context.Context, tenantID string, devicePk uuid.UUID, path string) error {
	retention := s.cfg.ConfigSnapshotRetention
	if retention <= 0 {
		retention = 100
	}
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`DELETE FROM device_file_history
			 WHERE device_pk = $1 AND path = $2
			   AND id NOT IN (
			     SELECT id FROM device_file_history
			     WHERE device_pk = $1 AND path = $2
			     ORDER BY created_at DESC LIMIT $3
			   )`,
			devicePk, path, retention)
		return err
	})
}
