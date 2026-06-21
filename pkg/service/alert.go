// Auto-extracted from service.go on 2026-05-05.
// Lives in package service. Imports cleaned by goimports.
package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/db"
)

// AlertSubscription maps to the alert_subscriptions table.
type AlertSubscription struct {
	ID          uuid.UUID  `json:"id"`
	UserID      uuid.UUID  `json:"user_id"`
	DevicePK    *uuid.UUID `json:"device_pk"`
	Channel     string     `json:"channel"`
	MinSeverity string     `json:"min_severity"`
	CreatedAt   time.Time  `json:"created_at"`
}

// AlertService handles device_alerts ingest and alert_subscriptions CRUD.
type AlertService struct {
	cfg   *config.Config
	pools db.Pools
}

// InsertAlert inserts a new alert and returns its id.
// Tenant-scoped through WithTenant: device_alerts is RLS-policed transitive
// via device_pk -> devices.tenant_id. Called from the MQTT ingest path with
// the tenant pinned from the topic.
// in: ctx, tenantID, device_pk, severity, code, message, raw JSON.
// out: alert id or error.
func (s *AlertService) InsertAlert(ctx context.Context, tenantID string, devicePk uuid.UUID, severity, code, message string, rawJSON []byte) (int64, error) {
	const query = `
		INSERT INTO device_alerts (device_pk, received_at, severity, code, message, raw, delivered_email, delivered_telegram)
		VALUES ($1, NOW(), $2, $3, $4, $5, false, false)
		RETURNING id`

	var id int64
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, devicePk, severity, code, message, rawJSON).Scan(&id)
	})
	return id, err
}

// RecentAlerts returns the last N alerts for a device, filtered by optional severity.
// Tenant-scoped through WithTenant.
// in: ctx, tenantID, device_pk, severity (optional), limit. out: []device_alerts rows.
func (s *AlertService) RecentAlerts(ctx context.Context, tenantID string, devicePk uuid.UUID, severity string, limit int) ([]device_alerts, error) {
	query := `
		SELECT id, device_pk, received_at, severity, code, message, raw, delivered_email, delivered_telegram
		FROM device_alerts WHERE device_pk = $1`
	args := []interface{}{devicePk}
	if severity != "" {
		args = append(args, severity)
		query += fmt.Sprintf(" AND severity = $%d", len(args))
	}
	args = append(args, limit)
	query += fmt.Sprintf(" ORDER BY received_at DESC LIMIT $%d", len(args))

	var alerts []device_alerts
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a device_alerts
			if err := rows.Scan(&a.ID, &a.DevicePK, &a.ReceivedAt, &a.Severity, &a.Code, &a.Message, &a.Raw, &a.DeliveredEmail, &a.DeliveredTelegram); err != nil {
				return err
			}
			alerts = append(alerts, a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return alerts, nil
}

// RecentByTenant returns the latest N alerts across all devices in a tenant,
// joined with the device_id text for display. Tenant-scoped through WithTenant.
// in: ctx, tenant_id, limit. out: rows with embedded device_id and device_pk.
func (s *AlertService) RecentByTenant(ctx context.Context, tenantID string, limit int) ([]TenantAlertRow, error) {
	const query = `
		SELECT a.id, a.device_pk, d.device_id, a.received_at, a.severity, a.code, a.message
		FROM device_alerts a
		JOIN devices d ON d.id = a.device_pk
		WHERE d.tenant_id = $1
		ORDER BY a.received_at DESC
		LIMIT $2`

	var out []TenantAlertRow
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r TenantAlertRow
			if err := rows.Scan(&r.ID, &r.DevicePK, &r.DeviceID, &r.ReceivedAt, &r.Severity, &r.Code, &r.Message); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListSubscriptions returns all alert subscriptions for a user.
// Tenant-scoped through WithTenant: alert_subscriptions is RLS-policed
// transitive via user_id -> users.tenant_id.
// in: ctx, tenantID, user_id. out: []AlertSubscription.
func (s *AlertService) ListSubscriptions(ctx context.Context, tenantID string, userID uuid.UUID) ([]AlertSubscription, error) {
	const query = `
		SELECT id, user_id, device_pk, channel, min_severity, created_at
		FROM alert_subscriptions WHERE user_id = $1 ORDER BY created_at`
	var out []AlertSubscription
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sub AlertSubscription
			if err := rows.Scan(&sub.ID, &sub.UserID, &sub.DevicePK, &sub.Channel,
				&sub.MinSeverity, &sub.CreatedAt); err != nil {
				return err
			}
			out = append(out, sub)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CreateSubscription creates a new alert subscription. Tenant-scoped via WithTenant.
// in: ctx, tenantID, user_id, device_pk (nil=all devices), channel, min_severity. out: error.
func (s *AlertService) CreateSubscription(ctx context.Context, tenantID string, userID uuid.UUID, devicePK *uuid.UUID, channel, minSeverity string) error {
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO alert_subscriptions (user_id, device_pk, channel, min_severity)
			 VALUES ($1, $2, $3, $4)`, userID, devicePK, channel, minSeverity)
		return err
	})
}

// DeleteSubscription removes an alert subscription owned by a user.
// Tenant-scoped via WithTenant.
// in: ctx, tenantID, subscription id, user_id (ownership check). out: error.
func (s *AlertService) DeleteSubscription(ctx context.Context, tenantID string, subID, userID uuid.UUID) error {
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`DELETE FROM alert_subscriptions WHERE id = $1 AND user_id = $2`, subID, userID)
		return err
	})
}
