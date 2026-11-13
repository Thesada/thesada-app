package service

import (
	"context"
	"errors"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/db"
)

// DefaultSubscriptionSeverity is the floor of the subscription pairing creates.
const DefaultSubscriptionSeverity = "warn"

// ensureTenantSubscriptionTx gives a tenant with no alert subscription one on
// pairing: the device owner (the claiming user), else the oldest tenant admin,
// else the oldest user, on all devices at warn, on their account email. It runs
// in a savepoint so a failure here never undoes the pairing, only logs.
// in: ctx, the pairing tx (tenant-scoped), tenant id, device pk. out: none.
func ensureTenantSubscriptionTx(ctx context.Context, tx pgx.Tx, tenantID string, devicePk uuid.UUID) {
	sp, err := tx.Begin(ctx)
	if err == nil {
		var userID uuid.UUID
		userID, err = defaultSubscriptionTx(ctx, sp, tenantID, devicePk)
		if err == nil {
			err = sp.Commit(ctx)
		}
		if err == nil && userID != uuid.Nil {
			slog.Info("alert.subscription.default_created",
				"tenant", tenantID, "device_pk", devicePk, "user_id", userID, "min_severity", DefaultSubscriptionSeverity)
			return
		}
		if err != nil {
			_ = sp.Rollback(ctx)
		}
	}
	if err != nil {
		slog.Error("alert.subscription.default_failed", "tenant", tenantID, "device_pk", devicePk, "err", err)
	}
}

// subCoversPaired keeps subscription rows (alias s) that cover all devices or a paired one.
const subCoversPaired = `(s.device_pk IS NULL OR EXISTS (
	SELECT 1 FROM devices d WHERE d.id = s.device_pk AND d.paired_at IS NOT NULL))`

// defaultSubscriptionTx does the work. Two pairings in one tenant serialize on
// an advisory lock, so only the first one subscribes.
// out: the subscribed user, uuid.Nil when the tenant already has a subscription or no user.
func defaultSubscriptionTx(ctx context.Context, tx pgx.Tx, tenantID string, devicePk uuid.UUID) (uuid.UUID, error) {
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended('alert_default_sub:' || $1, 0))`, tenantID); err != nil {
		return uuid.Nil, err
	}
	var has bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM alert_subscriptions s JOIN users u ON u.id = s.user_id
		                WHERE u.tenant_id = $1 AND `+subCoversPaired+`)`, tenantID).Scan(&has); err != nil || has {
		return uuid.Nil, err
	}
	var userID uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT u.id FROM users u
		  LEFT JOIN devices d ON d.id = $2 AND d.owner_user_id = u.id
		 WHERE u.tenant_id = $1
		 ORDER BY (d.id IS NOT NULL) DESC, u.is_admin DESC, u.is_super_admin, u.created_at, u.id
		 LIMIT 1`, tenantID, devicePk).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		slog.Warn("alert.subscription.default_skipped", "tenant", tenantID, "device_pk", devicePk, "reason", "no_user")
		return uuid.Nil, nil
	}
	if err != nil {
		return uuid.Nil, err
	}
	channelID, err := accountEmailChannelTx(ctx, tx, userID)
	if err != nil {
		return uuid.Nil, err
	}
	if err := insertSubscriptionTx(ctx, tx, userID, nil, channelID, DefaultSubscriptionSeverity); err != nil {
		return uuid.Nil, err
	}
	return userID, nil
}

// AlertCoverage reports whether the tenant has a paired device and how many of
// its users have a subscription on an enabled channel. Paired with zero
// subscribers means alerts reach nobody.
// in: ctx, tenant id. out: has paired device, subscriber count, error.
func (s *AlertService) AlertCoverage(ctx context.Context, tenantID string) (bool, int, error) {
	var paired bool
	var subs int
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM devices WHERE tenant_id = $1 AND paired_at IS NOT NULL),
			       (SELECT count(DISTINCT s.user_id) FROM alert_subscriptions s
			          JOIN users u ON u.id = s.user_id
			          JOIN notification_channels c ON c.id = s.channel_id AND c.enabled
			         WHERE u.tenant_id = $1 AND `+subCoversPaired+`)`, tenantID).Scan(&paired, &subs)
	})
	return paired, subs, err
}
