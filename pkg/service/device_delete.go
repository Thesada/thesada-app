// Device deletion - DB-only path. The full cascade (cert revoke, dynsec
// teardown, retained MQTT clear) is orchestrated in the web handler so the
// service layer stays pure.
package service

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/db"
)

// DeleteByID removes a device row by primary key. Every FK that references
// devices(id) declares ON DELETE CASCADE (verified across migrations
// 0001/0008/0012), so this single statement also drops:
//
//   - device_telemetry (TimescaleDB hypertable; per-row delete across chunks)
//   - device_alerts
//   - subscriptions (alert subscriptions; nullable FK preserves wildcards)
//   - device_certificates (the row stays referenced by audit logs only)
//   - device_files / device_file_history / device_file_observations
//
// Continuous aggregates (device_telemetry_hourly / _daily) are NOT cascaded;
// they're materialized views and lag until the next refresh or retention sweep.
// Acceptable by design: query results filter on now-deleted device_pk
// and surface no rows in the UI anyway.
//
// Tenant-scoped through WithTenant so the RLS policy on `devices` evaluates
// app.tenant_id and rejects a delete whose tenantID does not own the row.
// The WHERE clause still pins the primary key; the GUC is the policy-layer
// backstop. ErrNoTenant if tenantID is empty.
//
// in: ctx, tenant_id, device pk. out: error from pgx.
func (s *DeviceService) DeleteByID(ctx context.Context, tenantID string, id uuid.UUID) error {
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM devices WHERE id = $1`, id)
		return err
	})
}
