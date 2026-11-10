package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/db"
)

// NotificationChannel maps to notification_channels: one destination of a user.
type NotificationChannel struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	Kind      string    `json:"kind"`
	Target    string    `json:"target"`
	Label     string    `json:"label"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	// FollowsAccount: the target is the account's current email, not stored here.
	FollowsAccount bool `json:"follows_account"`
}

// channelTargetSQL is the live target: the account email for a follows_account row.
const channelTargetSQL = `CASE WHEN c.follows_account THEN u.email::text ELSE c.target END`

// ErrBadChannelTarget means the target does not fit the channel kind.
var ErrBadChannelTarget = errors.New("bad channel target")

// ErrNoChannel means the user has no channel of the kind a subscription asked for.
var ErrNoChannel = errors.New("no channel of that kind")

// maxChannelsPerUser bounds the list a settings page renders.
const maxChannelsPerUser = 20

var telegramChatIDRe = regexp.MustCompile(`^-?[0-9]{1,20}$`)

// NormalizeChannelTarget checks target against kind and returns the stored form.
// in: kind, raw target, webhook allowlist. out: target or ErrBadChannelTarget / ErrBadWebhook.
func NormalizeChannelTarget(kind, target string, allow []*net.IPNet) (string, error) {
	target = strings.TrimSpace(target)
	switch kind {
	case "email":
		a, err := mail.ParseAddress(target)
		if err != nil || a.Address != target || a.Name != "" {
			return "", ErrBadChannelTarget
		}
		return target, nil
	case "telegram":
		if !telegramChatIDRe.MatchString(target) {
			return "", ErrBadChannelTarget
		}
		return target, nil
	case "webhook":
		if err := WebhookDestinationError("webhook", target, allow); err != nil {
			return "", err
		}
		return target, nil
	default:
		return "", ErrBadChannelTarget
	}
}

func (s *AlertService) webhookAllow() []*net.IPNet {
	if s.cfg == nil {
		return nil
	}
	return s.cfg.WebhookAllowNets
}

// ListChannels returns a user's channels, oldest first.
// in: ctx, tenant, user. out: channels, error.
func (s *AlertService) ListChannels(ctx context.Context, tenantID string, userID uuid.UUID) ([]NotificationChannel, error) {
	var out []NotificationChannel
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT c.id, c.user_id, c.kind, `+channelTargetSQL+`, c.label, c.enabled, c.created_at, c.follows_account
			FROM notification_channels c JOIN users u ON u.id = c.user_id
			WHERE c.user_id = $1 ORDER BY c.follows_account DESC, c.created_at, c.id`, userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c NotificationChannel
			if err := rows.Scan(&c.ID, &c.UserID, &c.Kind, &c.Target, &c.Label, &c.Enabled, &c.CreatedAt, &c.FollowsAccount); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list channels: %w", err)
	}
	return out, nil
}

// CreateChannel adds a channel, or returns the existing one with the same kind and target.
// in: ctx, tenant, user, kind, target, label. out: channel id, error.
func (s *AlertService) CreateChannel(ctx context.Context, tenantID string, userID uuid.UUID, kind, target, label string) (uuid.UUID, error) {
	target, err := NormalizeChannelTarget(kind, target, s.webhookAllow())
	if err != nil {
		return uuid.Nil, err
	}
	var id uuid.UUID
	err = db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		id, err = createChannelTx(ctx, tx, userID, kind, target, strings.TrimSpace(label))
		return err
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("create channel: %w", err)
	}
	return id, nil
}

func createChannelTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID, kind, target, label string) (uuid.UUID, error) {
	var id uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT id FROM notification_channels WHERE user_id = $1 AND kind = $2 AND target = $3`,
		userID, kind, target).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, err
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM notification_channels WHERE user_id = $1`, userID).Scan(&n); err != nil {
		return uuid.Nil, err
	}
	if n >= maxChannelsPerUser {
		return uuid.Nil, fmt.Errorf("at most %d channels", maxChannelsPerUser)
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO notification_channels (user_id, kind, target, label)
		VALUES ($1, $2, $3, $4) RETURNING id`, userID, kind, target, label).Scan(&id)
	return id, err
}

// UpdateChannel changes target, label and enabled of a user's own channel.
// The account email channel keeps its target, only label and enabled change.
// Subscriptions on it keep their mirror columns in step for a rollback.
// in: ctx, tenant, user, channel id, target, label, enabled. out: error, ErrNotFound when not the user's.
func (s *AlertService) UpdateChannel(ctx context.Context, tenantID string, userID, channelID uuid.UUID, target, label string, enabled bool) error {
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		var kind string
		var follows bool
		if err := tx.QueryRow(ctx, `SELECT kind, follows_account FROM notification_channels WHERE id = $1 AND user_id = $2`,
			channelID, userID).Scan(&kind, &follows); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if follows {
			_, err := tx.Exec(ctx, `UPDATE notification_channels SET label = $1, enabled = $2 WHERE id = $3 AND user_id = $4`,
				strings.TrimSpace(label), enabled, channelID, userID)
			return err
		}
		t, err := NormalizeChannelTarget(kind, target, s.webhookAllow())
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE notification_channels SET target = $1, label = $2, enabled = $3
			WHERE id = $4 AND user_id = $5`, t, strings.TrimSpace(label), enabled, channelID, userID); err != nil {
			return err
		}
		if kind == "webhook" {
			_, err = tx.Exec(ctx, `UPDATE alert_subscriptions SET destination = $1 WHERE channel_id = $2`, t, channelID)
		}
		return err
	})
}

// SetChannelEnabled switches one of the user's channels on or off.
// in: ctx, tenant, user, channel id, enabled. out: error, ErrNotFound when not the user's.
func (s *AlertService) SetChannelEnabled(ctx context.Context, tenantID string, userID, channelID uuid.UUID, enabled bool) error {
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE notification_channels SET enabled = $1 WHERE id = $2 AND user_id = $3`,
			enabled, channelID, userID)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}

// DeleteChannel removes a user's channel and the subscriptions that use it.
// in: ctx, tenant, user, channel id. out: error, ErrNotFound when not the user's.
func (s *AlertService) DeleteChannel(ctx context.Context, tenantID string, userID, channelID uuid.UUID) error {
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM notification_channels WHERE id = $1 AND user_id = $2`, channelID, userID)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}

// CreateChannelSubscription subscribes one of the user's channels to alerts.
// in: ctx, tenant, user, device pk (nil = all), channel id, min severity. out: error.
func (s *AlertService) CreateChannelSubscription(ctx context.Context, tenantID string, userID uuid.UUID, devicePK *uuid.UUID, channelID uuid.UUID, minSeverity string) error {
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		return insertSubscriptionTx(ctx, tx, userID, devicePK, channelID, minSeverity)
	})
}

// insertSubscriptionTx writes a subscription on channelID and mirrors kind and
// webhook URL into the old columns, which a rollback to 26.11.4 still reads.
func insertSubscriptionTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID, devicePK *uuid.UUID, channelID uuid.UUID, minSeverity string) error {
	var kind, target string
	if err := tx.QueryRow(ctx, `SELECT kind, target FROM notification_channels WHERE id = $1 AND user_id = $2`,
		channelID, userID).Scan(&kind, &target); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	var dest any
	if kind == "webhook" {
		dest = target
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO alert_subscriptions (user_id, device_pk, channel, min_severity, destination, channel_id)
		VALUES ($1, $2, $3, $4, $5, $6)`, userID, devicePK, kind, minSeverity, dest, channelID)
	return err
}

// accountEmailChannelTx returns the user's follows_account email channel,
// turning a plain channel on the current address into it, or creating it.
func accountEmailChannelTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (uuid.UUID, error) {
	var id uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM notification_channels WHERE user_id = $1 AND follows_account`, userID).Scan(&id)
	if err == nil || !errors.Is(err, pgx.ErrNoRows) {
		return id, err
	}
	err = tx.QueryRow(ctx, `
		UPDATE notification_channels c SET follows_account = true
		  FROM users u
		 WHERE u.id = c.user_id AND c.user_id = $1 AND c.kind = 'email' AND c.target = u.email::text
		RETURNING c.id`, userID).Scan(&id)
	if err == nil || !errors.Is(err, pgx.ErrNoRows) {
		return id, err
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO notification_channels (user_id, kind, target, follows_account)
		SELECT id, 'email', email::text, true FROM users WHERE id = $1
		RETURNING id`, userID).Scan(&id)
	return id, err
}

// channelForKindTx finds the channel a kind-only subscription means: the account
// address for email, the oldest telegram channel, or the webhook URL given.
func channelForKindTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID, kind, destination string) (uuid.UUID, error) {
	switch kind {
	case "email":
		return accountEmailChannelTx(ctx, tx, userID)
	case "telegram":
		var id uuid.UUID
		err := tx.QueryRow(ctx, `
			SELECT id FROM notification_channels WHERE user_id = $1 AND kind = 'telegram'
			ORDER BY created_at, id LIMIT 1`, userID).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, ErrNoChannel
		}
		return id, err
	case "webhook":
		return createChannelTx(ctx, tx, userID, "webhook", destination, "")
	default:
		return uuid.Nil, ErrBadChannelTarget
	}
}
