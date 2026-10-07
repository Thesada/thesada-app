package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

var (
	ErrQuotaUsers   = errors.New("tenant user cap reached")
	ErrQuotaDevices = errors.New("tenant device cap reached")
	ErrQuotaEvents  = errors.New("tenant event cap reached")
)

// quotaFull is the shared comparison. A non-positive max is off.
// in: current count, cap. out: true when a new row must be refused.
func quotaFull(count, max int) bool {
	return max > 0 && count >= max
}

// lockTenantQuota serializes a cap check with the write in the same transaction.
// in: tx, tenant slug. out: error when the lock cannot be taken.
func lockTenantQuota(ctx context.Context, tx pgx.Tx, tenant string) error {
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, tenant); err != nil {
		return fmt.Errorf("quota tenant lock: %w", err)
	}
	return nil
}

// quotaAllowUser refuses a new user once the tenant is at the cap.
// in: tx, tenant, cap. out: ErrQuotaUsers or a query error.
func quotaAllowUser(ctx context.Context, tx pgx.Tx, tenant string, max int) error {
	if max <= 0 {
		return nil
	}
	if err := lockTenantQuota(ctx, tx, tenant); err != nil {
		return err
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM users WHERE tenant_id = $1`, tenant).Scan(&n); err != nil {
		return fmt.Errorf("quota users: %w", err)
	}
	if quotaFull(n, max) {
		return ErrQuotaUsers
	}
	return nil
}

// quotaAllowDevice refuses a device id this tenant does not already have.
// in: tx, tenant, device id, cap. out: ErrQuotaDevices or a query error.
func quotaAllowDevice(ctx context.Context, tx pgx.Tx, tenant, deviceID string, max int) error {
	if max <= 0 {
		return nil
	}
	if err := lockTenantQuota(ctx, tx, tenant); err != nil {
		return err
	}
	var exists bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM devices WHERE tenant_id = $1 AND device_id = $2)`,
		tenant, deviceID).Scan(&exists); err != nil {
		return fmt.Errorf("quota devices: %w", err)
	}
	if exists {
		return nil
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM devices WHERE tenant_id = $1`, tenant).Scan(&n); err != nil {
		return fmt.Errorf("quota devices: %w", err)
	}
	if quotaFull(n, max) {
		return ErrQuotaDevices
	}
	return nil
}

// quotaAllowEvent refuses a new alert once the last day is at the cap.
// in: tx, tenant, cap. out: ErrQuotaEvents or a query error.
func quotaAllowEvent(ctx context.Context, tx pgx.Tx, tenant string, max int) error {
	if max <= 0 {
		return nil
	}
	if err := lockTenantQuota(ctx, tx, tenant); err != nil {
		return err
	}
	var n int
	err := tx.QueryRow(ctx, `
		SELECT count(*) FROM device_alerts a
		JOIN devices d ON d.id = a.device_pk
		WHERE d.tenant_id = $1 AND a.received_at > now() - interval '24 hours'`, tenant).Scan(&n)
	if err != nil {
		return fmt.Errorf("quota events: %w", err)
	}
	if quotaFull(n, max) {
		return ErrQuotaEvents
	}
	return nil
}
