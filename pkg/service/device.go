// Auto-extracted from service.go on 2026-05-05.
// Lives in package service. Imports cleaned by goimports.
package service

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/db"
)

// DeviceService handles device registry and pairing.
type DeviceService struct {
	cfg   *config.Config
	pools db.Pools
}

// Upsert creates or updates a device record by tenant+device_id, bumping
// last_seen_at to NOW() because the caller has live evidence the device is
// alive (live sensor reading, alert, online presence, info publish).
// Empty string fields are NOT overwritten - COALESCE keeps the existing
// row's value when the caller passes "".
// in: tenant_id, device_id, display_name, firmware_version, hardware_type.
// out: device primary key (UUID), error if any.
func (s *DeviceService) Upsert(tenantID, deviceID, displayName, firmwareVersion, hardwareType, mqttTopicPrefix string) (uuid.UUID, error) {
	return s.upsertCore(tenantID, deviceID, displayName, firmwareVersion, hardwareType, mqttTopicPrefix, true)
}

// UpsertSeen creates the device row if missing without touching last_seen_at.
// Used for retained-message replays at app reconnect, and for "offline"
// presence payloads - both of which are NOT live activity and must not
// move the "last seen alive" pointer forward.
// in: tenant_id, device_id, display_name, firmware_version, hardware_type, mqtt_topic_prefix.
// out: device primary key (UUID), error if any.
func (s *DeviceService) UpsertSeen(tenantID, deviceID, displayName, firmwareVersion, hardwareType, mqttTopicPrefix string) (uuid.UUID, error) {
	return s.upsertCore(tenantID, deviceID, displayName, firmwareVersion, hardwareType, mqttTopicPrefix, false)
}

// BumpSeenIfExists updates last_seen_at = NOW() on an existing device row
// without creating a new row if it's missing. Returns the device pk if
// found, or uuid.Nil + false if the device is unknown - used by the MQTT
// ingest path for status/sensor/alert messages so topics from non-thesada
// clients (ESPHome, legacy HAOS sensors) don't auto-create device rows.
// Real thesada devices show up via the info path (which carries firmware
// fields and calls Upsert directly).
// in: tenant_id, device_id. out: device pk (uuid.Nil if not found), found bool, error.
func (s *DeviceService) BumpSeenIfExists(tenantID, deviceID string) (uuid.UUID, bool, error) {
	const query = `
		UPDATE devices SET last_seen_at = NOW()
		WHERE tenant_id = $1 AND device_id = $2
		RETURNING id`
	var id uuid.UUID
	found := false
	werr := db.WithTenant(context.Background(), s.pools.App, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(context.Background(), query, tenantID, deviceID).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		return nil
	})
	if werr != nil {
		return uuid.Nil, false, werr
	}
	return id, found, nil
}

// upsertCore is the shared INSERT ... ON CONFLICT path. When bumpSeen is
// false the last_seen_at column is left unchanged on UPDATE, and on INSERT
// it falls back to NULL (a brand new device with no live signal yet has
// no real last_seen_at to claim).
// in: tenant_id, device_id, display_name, firmware_version, hardware_type, mqtt_topic_prefix, bumpSeen.
// out: device primary key (UUID), error.
func (s *DeviceService) upsertCore(tenantID, deviceID, displayName, firmwareVersion, hardwareType, mqttTopicPrefix string, bumpSeen bool) (uuid.UUID, error) {
	var query string
	if bumpSeen {
		query = `
			INSERT INTO devices (tenant_id, device_id, display_name, firmware_version, hardware_type, mqtt_topic_prefix, last_seen_at)
			VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), NULLIF($5, ''), NULLIF($6, ''), NOW())
			ON CONFLICT (tenant_id, device_id) DO UPDATE SET
				display_name      = COALESCE(NULLIF(EXCLUDED.display_name, ''),      devices.display_name),
				firmware_version  = COALESCE(NULLIF(EXCLUDED.firmware_version, ''),  devices.firmware_version),
				hardware_type     = COALESCE(NULLIF(EXCLUDED.hardware_type, ''),     devices.hardware_type),
				mqtt_topic_prefix = COALESCE(NULLIF(EXCLUDED.mqtt_topic_prefix, ''), devices.mqtt_topic_prefix),
				last_seen_at      = NOW()
			RETURNING id`
	} else {
		query = `
			INSERT INTO devices (tenant_id, device_id, display_name, firmware_version, hardware_type, mqtt_topic_prefix, last_seen_at)
			VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), NULLIF($5, ''), NULLIF($6, ''), NULL)
			ON CONFLICT (tenant_id, device_id) DO UPDATE SET
				display_name      = COALESCE(NULLIF(EXCLUDED.display_name, ''),      devices.display_name),
				firmware_version  = COALESCE(NULLIF(EXCLUDED.firmware_version, ''),  devices.firmware_version),
				hardware_type     = COALESCE(NULLIF(EXCLUDED.hardware_type, ''),     devices.hardware_type),
				mqtt_topic_prefix = COALESCE(NULLIF(EXCLUDED.mqtt_topic_prefix, ''), devices.mqtt_topic_prefix)
			RETURNING id`
	}

	var id uuid.UUID
	err := db.WithTenant(context.Background(), s.pools.App, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), query, tenantID, deviceID, displayName, firmwareVersion, hardwareType, mqttTopicPrefix).Scan(&id)
	})
	return id, err
}

// GetByID returns a device by primary key, scoped to a tenant so that a valid
// UUID from one tenant cannot be fetched by a user in another tenant.
// Callers in super-admin context pass the impersonated tenant; tenant-scoped
// callers pass CurrentUser().TenantID.
// in: device pk, tenant_id. out: *devices row or nil if not found in that tenant.
func (s *DeviceService) GetByID(id uuid.UUID, tenantID string) (*Device, error) {
	const query = `
		SELECT id, tenant_id, owner_user_id, device_id, pairing_key, paired_at, display_name,
		       hardware_type, firmware_version, last_seen_at, mqtt_topic_prefix, created_at
		FROM devices WHERE id = $1 AND tenant_id = $2`

	var d Device
	err := db.WithTenant(context.Background(), s.pools.App, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), query, id, tenantID).Scan(
			&d.ID, &d.TenantID, &d.OwnerUserID, &d.DeviceID, &d.PairingKey, &d.PairedAt,
			&d.DisplayName, &d.HardwareType, &d.FirmwareVersion, &d.LastSeenAt,
			&d.MQTTTopicPrefix, &d.CreatedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// GetByDeviceID returns a device by tenant and device_id.
// in: tenant_id, device_id. out: *devices row or nil if not found.
func (s *DeviceService) GetByDeviceID(tenantID, deviceID string) (*Device, error) {
	const query = `
		SELECT id, tenant_id, owner_user_id, device_id, pairing_key, paired_at, display_name,
		       hardware_type, firmware_version, last_seen_at, mqtt_topic_prefix, created_at
		FROM devices WHERE tenant_id = $1 AND device_id = $2`

	var d Device
	err := db.WithTenant(context.Background(), s.pools.App, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(context.Background(), query, tenantID, deviceID).Scan(
			&d.ID, &d.TenantID, &d.OwnerUserID, &d.DeviceID, &d.PairingKey, &d.PairedAt,
			&d.DisplayName, &d.HardwareType, &d.FirmwareVersion, &d.LastSeenAt,
			&d.MQTTTopicPrefix, &d.CreatedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// GetByIDAny returns a device by primary key without any tenant scoping.
// Only call from super-admin-gated handlers (admin panel, cross-tenant
// device detail view). Tenant-scoped callers must use GetByID.
//
// Cross-tenant BY DESIGN - runs through WithAdminAudit on the BYPASSRLS
// pool. With RLS on, the App pool would need the GUC set, and a super-admin
// looking at an arbitrary device has no single tenant to scope by.
// in: ctx, device pk. out: *devices row or nil.
func (s *DeviceService) GetByIDAny(ctx context.Context, id uuid.UUID) (*Device, error) {
	const query = `
		SELECT id, tenant_id, owner_user_id, device_id, pairing_key, paired_at, display_name,
		       hardware_type, firmware_version, last_seen_at, mqtt_topic_prefix, created_at
		FROM devices WHERE id = $1`
	var d Device
	err := db.WithAdminAudit(ctx, s.pools.Admin, "device.get_by_id_any", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, id).Scan(
			&d.ID, &d.TenantID, &d.OwnerUserID, &d.DeviceID, &d.PairingKey, &d.PairedAt,
			&d.DisplayName, &d.HardwareType, &d.FirmwareVersion, &d.LastSeenAt,
			&d.MQTTTopicPrefix, &d.CreatedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// ListAllForAdmin returns every device row across every tenant, ordered by
// tenant then last_seen_at DESC. Used by the super-admin device reassignment
// UI. Do not call from a tenant-scoped handler - use ListByTenant.
//
// Cross-tenant BY DESIGN - runs through WithAdminAudit on the BYPASSRLS pool.
// in: ctx. out: []devices or empty slice, error.
func (s *DeviceService) ListAllForAdmin(ctx context.Context) ([]Device, error) {
	const query = `
		SELECT d.id, d.tenant_id, d.owner_user_id, d.device_id, d.pairing_key, d.paired_at, d.display_name,
		       d.hardware_type, d.firmware_version, d.last_seen_at, d.mqtt_topic_prefix, d.created_at,
		       up.value_num::bigint, up.received_at
		FROM devices d
		LEFT JOIN LATERAL (
			SELECT value_num, received_at FROM device_telemetry
			WHERE device_pk = d.id AND metric = 'uptime'
			ORDER BY received_at DESC LIMIT 1
		) up ON TRUE
		ORDER BY d.tenant_id, d.last_seen_at DESC NULLS LAST`
	var out []Device
	err := db.WithAdminAudit(ctx, s.pools.Admin, "device.list_all_for_admin", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d Device
			if err := rows.Scan(&d.ID, &d.TenantID, &d.OwnerUserID, &d.DeviceID, &d.PairingKey, &d.PairedAt,
				&d.DisplayName, &d.HardwareType, &d.FirmwareVersion, &d.LastSeenAt,
				&d.MQTTTopicPrefix, &d.CreatedAt, &d.LastUptimeSeconds, &d.LastUptimeAt); err != nil {
				return err
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Reassign moves a device row from one tenant to another. Fails if the
// target tenant does not exist or if the target tenant already has a device
// with the same device_id (unique constraint violation). The caller is
// responsible for updating the on-device mqtt.topic_prefix out-of-band so
// the device starts publishing on the new tenant's prefix.
//
// Cross-tenant BY DESIGN - runs through WithAdminAudit on the BYPASSRLS
// pool. Under the App pool the devices RLS policy WITH CHECK would reject
// the UPDATE: the new tenant_id never matches the GUC (whichever tenant
// was set, the row is being moved to a different one).
// in: ctx, device pk, target tenant slug. out: error.
func (s *DeviceService) Reassign(ctx context.Context, id uuid.UUID, targetTenant string) error {
	return db.WithAdminAudit(ctx, s.pools.Admin, "device.reassign", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE devices SET tenant_id = $1 WHERE id = $2`, targetTenant, id)
		return err
	})
}

// ListByTenant returns all devices for a tenant.
// in: tenant_id. out: []devices or empty slice.
func (s *DeviceService) ListByTenant(tenantID string) ([]Device, error) {
	const query = `
		SELECT d.id, d.tenant_id, d.owner_user_id, d.device_id, d.pairing_key, d.paired_at, d.display_name,
		       d.hardware_type, d.firmware_version, d.last_seen_at, d.mqtt_topic_prefix, d.created_at,
		       up.value_num::bigint, up.received_at
		FROM devices d
		LEFT JOIN LATERAL (
			SELECT value_num, received_at FROM device_telemetry
			WHERE device_pk = d.id AND metric = 'uptime'
			ORDER BY received_at DESC LIMIT 1
		) up ON TRUE
		WHERE d.tenant_id = $1 ORDER BY d.last_seen_at DESC`

	var result []Device
	err := db.WithTenant(context.Background(), s.pools.App, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(context.Background(), query, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d Device
			if err := rows.Scan(&d.ID, &d.TenantID, &d.OwnerUserID, &d.DeviceID, &d.PairingKey, &d.PairedAt,
				&d.DisplayName, &d.HardwareType, &d.FirmwareVersion, &d.LastSeenAt,
				&d.MQTTTopicPrefix, &d.CreatedAt, &d.LastUptimeSeconds, &d.LastUptimeAt); err != nil {
				return err
			}
			result = append(result, d)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// RLS NOTE: deleted_device_tombstones now carries a direct
// RLS policy (p_deleted_device_tombstones_tenant in 0016). The three
// Tombstone* methods run under db.WithTenant; the table's tenant_id column
// is policed by app.tenant_id like any other direct-tenant table. The
// app-level WHERE tenant_id = $1 clauses stay as belt + suspenders.

// Tombstone records a deleted device so the MQTT ingest path can drop the
// retained-replay payloads that the broker keeps emitting at every
// app-reconnect. Topic prefix is captured so the ingest path can publish
// empty-retained on the offending topic to clear the broker record once it
// is observed. Re-inserting on conflict refreshes deleted_at + topic prefix
// in case the operator deletes and re-deletes the same device id.
// in: tenant id, device id, topic prefix. out: error.
func (s *DeviceService) Tombstone(ctx context.Context, tenantID, deviceID, topicPrefix string) error {
	const query = `
		INSERT INTO deleted_device_tombstones (tenant_id, device_id, topic_prefix)
		VALUES ($1, $2, $3)
		ON CONFLICT (tenant_id, device_id) DO UPDATE SET
			topic_prefix = EXCLUDED.topic_prefix,
			deleted_at   = NOW()`
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, query, tenantID, deviceID, topicPrefix)
		return err
	})
}

// IsTombstoned reports whether (tenant, device) has an active tombstone.
// in: tenant id, device id. out: bool, error.
func (s *DeviceService) IsTombstoned(ctx context.Context, tenantID, deviceID string) (bool, error) {
	const query = `
		SELECT 1 FROM deleted_device_tombstones
		WHERE tenant_id = $1 AND device_id = $2`
	var found bool
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		var n int
		err := tx.QueryRow(ctx, query, tenantID, deviceID).Scan(&n)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		return nil
	})
	return found, err
}

// RemoveTombstone drops the tombstone row, called when live (non-retained)
// traffic from the same device id arrives - the device was reflashed or
// re-paired and is allowed back in. No-op when the row does not exist.
// in: tenant id, device id. out: error.
func (s *DeviceService) RemoveTombstone(ctx context.Context, tenantID, deviceID string) error {
	const query = `DELETE FROM deleted_device_tombstones WHERE tenant_id = $1 AND device_id = $2`
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, query, tenantID, deviceID)
		return err
	})
}
