package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/db"
)

// TrendRule maps to alert_rules (kind trend). DevicePK nil = every device of the tenant.
type TrendRule struct {
	ID        uuid.UUID  `json:"id"`
	DevicePK  *uuid.UUID `json:"device_pk,omitempty"`
	DeviceID  string     `json:"device_id,omitempty"`
	Metric    string     `json:"metric"`
	Direction string     `json:"direction"`
	Delta     float64    `json:"delta"`
	WindowS   int        `json:"window_s"`
	Severity  string     `json:"severity"`
	Enabled   bool       `json:"enabled"`
	CreatedAt time.Time  `json:"created_at"`
}

// Trend rule bounds, kept in step with the 0045 CHECKs.
const (
	TrendWindowMin = 60
	TrendWindowMax = 7 * 24 * 3600
	trendMetricMax = 64
)

// ErrTrendRuleInvalid wraps every validation refusal, so handlers can show the text.
var ErrTrendRuleInvalid = errors.New("invalid trend rule")

// Slash-separated segments: ingest keeps a sensor sub-path whole ("current/house_pump").
var trendMetricRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]+(/[A-Za-z0-9_.:-]+)*$`)

// ValidateTrendRule checks a rule before it is stored.
// in: rule. out: nil, or an error wrapping ErrTrendRuleInvalid.
func ValidateTrendRule(r TrendRule) error {
	bad := func(msg string) error { return fmt.Errorf("%w: %s", ErrTrendRuleInvalid, msg) }
	switch {
	case r.Metric == "" || len(r.Metric) > trendMetricMax || !trendMetricRe.MatchString(r.Metric):
		return bad("metric must be a telemetry metric name")
	case r.Direction != "rise" && r.Direction != "fall" && r.Direction != "either":
		return bad("direction must be rise, fall or either")
	case !(r.Delta > 0) || math.IsInf(r.Delta, 0):
		return bad("change must be a positive number")
	case r.WindowS < TrendWindowMin || r.WindowS > TrendWindowMax:
		return bad("window must be between 1 minute and 7 days")
	case r.Severity != "info" && r.Severity != "warn" && r.Severity != "crit":
		return bad("severity must be info, warn or crit")
	}
	return nil
}

// TrendFires reports whether the move from past to now meets the rule.
// in: direction, minimum change, past value, new value. out: true when the rule fires.
func TrendFires(direction string, delta, past, now float64) bool {
	d := now - past
	switch direction {
	case "rise":
		return d >= delta
	case "fall":
		return -d >= delta
	case "either":
		return math.Abs(d) >= delta
	}
	return false
}

// trendAction is what one reading does to one rule's state.
type trendAction int

const (
	trendNone   trendAction = iota
	trendRaise              // no open alert, condition holds
	trendRefire             // open alert older than the window, condition still holds
	trendClear              // open alert, condition no longer holds
)

// trendStep decides the action for one rule. No baseline means no decision.
// in: fires, baseline known, open alert, open alert age, window. out: action.
func trendStep(fires, haveBaseline, open bool, openAge, window time.Duration) trendAction {
	switch {
	case !haveBaseline:
		return trendNone
	case fires && !open:
		return trendRaise
	case fires && openAge >= window:
		return trendRefire
	case !fires && open:
		return trendClear
	}
	return trendNone
}

// trendEvalQuery is the whole per-reading cost: the matching rules, each with
// its baseline (newest sample between 2 windows and 1 window ago) and its open alert.
const trendEvalQuery = `
	SELECT r.id, r.direction, r.delta, r.window_s, r.severity,
	       past.value_num, open.id, open.received_at
	FROM alert_rules r
	LEFT JOIN LATERAL (
	    SELECT t.value_num FROM device_telemetry t
	    WHERE t.device_pk = $2 AND t.metric = $3 AND t.value_num IS NOT NULL
	      AND t.received_at <= now() - make_interval(secs => r.window_s)
	      AND t.received_at >= now() - make_interval(secs => 2 * r.window_s)
	    ORDER BY t.received_at DESC LIMIT 1) past ON true
	LEFT JOIN LATERAL (
	    SELECT a.id, a.received_at FROM device_alerts a
	    WHERE a.device_pk = $2 AND a.code LIKE 'trend.%' AND a.cleared_at IS NULL
	      AND a.raw->>'rule' = r.id::text
	    ORDER BY a.received_at DESC LIMIT 1) open ON true
	WHERE r.tenant_id = $1 AND r.enabled AND r.metric = $3
	  AND (r.device_pk IS NULL OR r.device_pk = $2)`

type trendRow struct {
	ruleID    uuid.UUID
	direction string
	delta     float64
	windowS   int
	severity  string
	past      *float64
	openID    *int64
	openAt    *time.Time
}

// EvaluateTrends checks one new numeric reading against the tenant's trend rules
// and raises, re-raises or clears trend alerts. One query when nothing changes.
// in: ctx, tenant, device pk, device id (for the message), metric, new value.
// out: ids of alerts raised, for dispatch.
func (s *AlertService) EvaluateTrends(ctx context.Context, tenantID string, devicePk uuid.UUID, metric string, value float64) ([]int64, error) {
	var rows []trendRow
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		rs, err := tx.Query(ctx, trendEvalQuery, tenantID, devicePk, metric)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var r trendRow
			if err := rs.Scan(&r.ruleID, &r.direction, &r.delta, &r.windowS, &r.severity, &r.past, &r.openID, &r.openAt); err != nil {
				return err
			}
			rows = append(rows, r)
		}
		return rs.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("trend evaluate: %w", err)
	}
	var raised []int64
	now := time.Now()
	for _, r := range rows {
		fires := r.past != nil && TrendFires(r.direction, r.delta, *r.past, value)
		var age time.Duration
		if r.openAt != nil {
			age = now.Sub(*r.openAt)
		}
		window := time.Duration(r.windowS) * time.Second
		switch trendStep(fires, r.past != nil, r.openID != nil, age, window) {
		case trendRaise:
			if id, ok := s.raiseTrend(ctx, tenantID, devicePk, metric, r, value); ok {
				raised = append(raised, id)
			}
		case trendRefire:
			if err := s.clearTrend(ctx, tenantID, *r.openID); err != nil {
				slog.Error("alert.trend.clear_failed", "rule", r.ruleID, "err", err)
				continue
			}
			if id, ok := s.raiseTrend(ctx, tenantID, devicePk, metric, r, value); ok {
				raised = append(raised, id)
			}
		case trendClear:
			if err := s.clearTrend(ctx, tenantID, *r.openID); err != nil {
				slog.Error("alert.trend.clear_failed", "rule", r.ruleID, "err", err)
			}
		}
	}
	return raised, nil
}

// raiseTrend inserts one trend alert. Failures are logged, not returned, so one
// bad rule does not hide the others.
// in: ctx, tenant, device pk, metric, rule row, new value. out: alert id, ok.
func (s *AlertService) raiseTrend(ctx context.Context, tenantID string, devicePk uuid.UUID, metric string, r trendRow, value float64) (int64, bool) {
	// "at" keeps a new episode with the same numbers out of the payload dedup.
	raw, err := json.Marshal(map[string]any{
		"kind": "trend", "rule": r.ruleID.String(), "metric": metric,
		"from": *r.past, "to": value, "window_s": r.windowS,
		"at": time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		slog.Error("alert.trend.encode_failed", "rule", r.ruleID, "err", err)
		return 0, false
	}
	verb := "rose"
	if value < *r.past {
		verb = "fell"
	}
	msg := fmt.Sprintf("%s %s %s in %s (%s to %s)", metric, verb,
		fmtTrendNum(math.Abs(value-*r.past)), TrendWindowText(r.windowS), fmtTrendNum(*r.past), fmtTrendNum(value))
	id, err := s.InsertAlert(ctx, tenantID, devicePk, r.severity, "trend."+metric, msg, raw)
	if errors.Is(err, ErrDuplicateAlert) {
		return 0, false
	}
	if err != nil {
		slog.Error("alert.trend.insert_failed", "rule", r.ruleID, "err", err)
		return 0, false
	}
	slog.Info("alert.trend.raised", "tenant", tenantID, "rule", r.ruleID, "alert_id", id)
	return id, true
}

// clearTrend marks one open trend alert finished.
// in: ctx, tenant, alert id. out: error.
func (s *AlertService) clearTrend(ctx context.Context, tenantID string, alertID int64) error {
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE device_alerts SET cleared_at = now()
			WHERE id = $1 AND cleared_at IS NULL`, alertID)
		return err
	})
}

func fmtTrendNum(v float64) string {
	return strings.TrimSuffix(strings.TrimRight(fmt.Sprintf("%.2f", v), "0"), ".")
}

// TrendWindowText renders a window in seconds as h, min or s.
// in: seconds. out: text like "10 min".
func TrendWindowText(s int) string {
	switch {
	case s%3600 == 0:
		return fmt.Sprintf("%d h", s/3600)
	case s%60 == 0:
		return fmt.Sprintf("%d min", s/60)
	}
	return fmt.Sprintf("%d s", s)
}

// ListTrendRules returns the tenant's trend rules, newest first, with the device id.
// in: ctx, tenant. out: rules.
func (s *AlertService) ListTrendRules(ctx context.Context, tenantID string) ([]TrendRule, error) {
	var out []TrendRule
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		rs, err := tx.Query(ctx, `
			SELECT r.id, r.device_pk, coalesce(d.device_id, ''), r.metric, r.direction,
			       r.delta, r.window_s, r.severity, r.enabled, r.created_at
			FROM alert_rules r LEFT JOIN devices d ON d.id = r.device_pk
			WHERE r.kind = 'trend' ORDER BY r.created_at DESC`)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var r TrendRule
			if err := rs.Scan(&r.ID, &r.DevicePK, &r.DeviceID, &r.Metric, &r.Direction,
				&r.Delta, &r.WindowS, &r.Severity, &r.Enabled, &r.CreatedAt); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rs.Err()
	})
	return out, err
}

// ErrTrendDevice: the rule names a device the tenant cannot see.
var ErrTrendDevice = errors.New("device not found")

// CreateTrendRule validates and stores a rule. A device must be visible to the tenant
// (the FK check alone would accept another tenant's device).
// in: ctx, tenant, rule. out: new id or error.
func (s *AlertService) CreateTrendRule(ctx context.Context, tenantID string, r TrendRule) (uuid.UUID, error) {
	if err := ValidateTrendRule(r); err != nil {
		return uuid.Nil, err
	}
	var id uuid.UUID
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		if r.DevicePK != nil {
			var one int
			if err := tx.QueryRow(ctx, `SELECT 1 FROM devices WHERE id = $1 AND tenant_id = $2`,
				*r.DevicePK, tenantID).Scan(&one); errors.Is(err, pgx.ErrNoRows) {
				return ErrTrendDevice
			} else if err != nil {
				return err
			}
		}
		return tx.QueryRow(ctx, `
			INSERT INTO alert_rules (tenant_id, device_pk, kind, metric, direction, delta, window_s, severity)
			VALUES ($1, $2, 'trend', $3, $4, $5, $6, $7) RETURNING id`,
			tenantID, r.DevicePK, r.Metric, r.Direction, r.Delta, r.WindowS, r.Severity).Scan(&id)
	})
	return id, err
}

// ErrTrendRuleNotFound: no such rule in this tenant.
var ErrTrendRuleNotFound = errors.New("rule not found")

// SetTrendRuleEnabled switches a rule on or off. Switching off clears its open alerts.
// in: ctx, tenant, rule id, enabled. out: error.
func (s *AlertService) SetTrendRuleEnabled(ctx context.Context, tenantID string, id uuid.UUID, enabled bool) error {
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE alert_rules SET enabled = $2 WHERE id = $1`, id, enabled)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrTrendRuleNotFound
		}
		if enabled {
			return nil
		}
		return clearRuleAlerts(ctx, tx, id)
	})
}

// DeleteTrendRule removes a rule and clears its open alerts. History stays.
// in: ctx, tenant, rule id. out: error.
func (s *AlertService) DeleteTrendRule(ctx context.Context, tenantID string, id uuid.UUID) error {
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		if err := clearRuleAlerts(ctx, tx, id); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM alert_rules WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrTrendRuleNotFound
		}
		return nil
	})
}

func clearRuleAlerts(ctx context.Context, tx pgx.Tx, ruleID uuid.UUID) error {
	_, err := tx.Exec(ctx, `UPDATE device_alerts SET cleared_at = now()
		WHERE code LIKE 'trend.%' AND cleared_at IS NULL AND raw->>'rule' = $1`, ruleID.String())
	return err
}

// TrendMetrics lists numeric metric names the tenant's devices reported in the
// last 30 days, from the daily aggregate, for the rule form.
// in: ctx, tenant. out: sorted metric names.
func (s *AlertService) TrendMetrics(ctx context.Context, tenantID string) ([]string, error) {
	var out []string
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		rs, err := tx.Query(ctx, `
			SELECT DISTINCT h.metric FROM device_telemetry_daily h
			JOIN devices d ON d.id = h.device_pk
			WHERE d.tenant_id = $1 AND h.bucket >= now() - interval '30 days'
			ORDER BY 1 LIMIT 200`, tenantID)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var m string
			if err := rs.Scan(&m); err != nil {
				return err
			}
			out = append(out, m)
		}
		return rs.Err()
	})
	return out, err
}
