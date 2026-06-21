// Owns the reads/writes for the device-file tables: device_files (canonical
// current state), device_file_history (immutable change log), and
// device_file_observations (drift telemetry). Replaced the single legacy
// snapshots table.
package service

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/db"
)

// DeviceFilesService owns the canonical-state + history + drift-observation
// tables introduced by migration 0012. Replaces ConfigSnapshotService for
// new code paths.
type DeviceFilesService struct {
	cfg   *config.Config
	pools db.Pools
}

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
