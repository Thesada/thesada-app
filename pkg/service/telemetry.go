// Auto-extracted from service.go on 2026-05-05.
// Lives in package service. Imports cleaned by goimports.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/db"
)

// TelemetryService handles ingest and query of device_telemetry.
type TelemetryService struct {
	cfg   *config.Config
	pools db.Pools
}

// RecordTelemetry inserts a sensor reading. valueNum is nullable so
// string-only metrics (IP, battery state, wifi SSID) land as value_text
// with a NULL value_num instead of a misleading 0.
//
// Tenant-scoped through WithTenant: device_telemetry is RLS-policed
// transitive via device_pk -> devices.tenant_id. Called from the MQTT
// ingest path with the tenant pinned from the topic.
// in: ctx, tenantID, device_pk, metric name, *value_num (nil for text), value_text, raw JSON.
// out: telemetry id or error.
func (s *TelemetryService) RecordTelemetry(ctx context.Context, tenantID string, devicePk uuid.UUID, metric string, valueNum *float64, valueText string, rawJSON []byte) (int64, error) {
	const query = `
		INSERT INTO device_telemetry (device_pk, received_at, metric, value_num, value_text, raw)
		VALUES ($1, NOW(), $2, $3, $4, $5)
		RETURNING id`

	// Some legacy firmware publishes unquoted strings (e.g. "Discharging") that
	// are valid MQTT payloads but not valid JSON. Wrap them as a JSON string
	// literal so the JSONB column still accepts the raw payload.
	stored := rawJSON
	if !json.Valid(rawJSON) {
		if wrapped, err := json.Marshal(string(rawJSON)); err == nil {
			stored = wrapped
		} else {
			stored = []byte("null")
		}
	}

	var id int64
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, devicePk, metric, valueNum, valueText, stored).Scan(&id)
	})
	return id, err
}

// LatestPerMetric returns the most recent telemetry row per distinct metric
// for a single device. Used by the device-detail "current values" panel as a
// replacement for the legacy heartbeat columns (rssi/heap_free/uptime_s) which
// firmware v1.3.x no longer publishes inside the status JSON; everything is
// emitted on `sensor/<metric>` topics and lands in device_telemetry.
// in: ctx, tenantID, device_pk. out: one device_telemetry row per metric, latest first.
func (s *TelemetryService) LatestPerMetric(ctx context.Context, tenantID string, devicePk uuid.UUID) ([]device_telemetry, error) {
	const query = `
		SELECT DISTINCT ON (metric)
		       id, device_pk, received_at, metric, value_num, value_text, raw
		FROM device_telemetry
		WHERE device_pk = $1
		ORDER BY metric, received_at DESC`
	var tel []device_telemetry
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, devicePk)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t device_telemetry
			if err := rows.Scan(&t.ID, &t.DevicePK, &t.ReceivedAt, &t.Metric, &t.ValueNum, &t.ValueText, &t.Raw); err != nil {
				return err
			}
			tel = append(tel, t)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return tel, nil
}

// HistoryPoint is a single bucketed row on a chart: timestamp + avg/min/max.
// Nullable to pass through gaps where no raw readings exist in a bucket.
type HistoryPoint struct {
	T   time.Time
	Avg *float64
	Min *float64
	Max *float64
}

// HistorySeries bundles a set of points with enough metadata for the
// frontend to label the chart.
type HistorySeries struct {
	Metric string
	Range  string
	Points []HistoryPoint
}

// ErrInvalidRange is returned by History when the caller passes a range that
// is not in the fixed vocabulary. The handler translates to 400.
var ErrInvalidRange = errors.New("invalid range")

// rangeBucketRaw maps short-window ranges to (bucket_width, duration) pairs
// used against the raw hypertable with SQL-side time_bucket.
var rangeBucketRaw = map[string]struct {
	bucket   string
	duration string
}{
	"1h":  {"1 minute", "1 hour"},
	"6h":  {"5 minutes", "6 hours"},
	"24h": {"20 minutes", "1 day"},
}

// rangeDurationCagg maps medium-window ranges to the cagg window duration.
// Both use device_telemetry_hourly; 90d uses device_telemetry_daily.
var rangeDurationCagg = map[string]string{
	"7d":  "1 week",
	"30d": "1 month",
}

// History returns a bucketed time-series for a single metric on a single
// device. Source table is chosen by range:
//   - 1h/6h/24h -> raw hypertable with SQL time_bucket
//   - 7d/30d    -> device_telemetry_hourly continuous aggregate
//   - 90d       -> device_telemetry_daily continuous aggregate
//
// Only numeric metrics return useful data (text-only rows are filtered at
// ingest by storing value_num=NULL, and the caggs already exclude them).
//
// Tenant-scoped through WithTenant. RLS NOTE: the 1h/6h/24h ranges
// hit device_telemetry which has a transitive RLS policy - the GUC enforces
// isolation. The 7d/30d/90d ranges read the device_telemetry_hourly /
// _daily continuous aggregates, which have NO RLS policy (0016 covers base
// tables only; matview RLS is a separate question). For those ranges the
// WHERE device_pk filter is the only isolation. Tracked as a gap to close
// alongside the 0016 addendum. WithTenant is still applied
// uniformly: harmless for the cagg path, load-bearing for the raw path.
// in: ctx, tenantID, device_pk, metric, range label. out: *HistorySeries, error.
func (s *TelemetryService) History(ctx context.Context, tenantID string, devicePk uuid.UUID, metric, rangeName string) (*HistorySeries, error) {
	if metric == "" {
		return nil, ErrInvalidRange
	}
	var (
		query string
		args  []interface{}
	)
	switch rangeName {
	case "1h", "6h", "24h":
		r := rangeBucketRaw[rangeName]
		query = `
			SELECT time_bucket($1::interval, received_at) AS b,
			       AVG(value_num), MIN(value_num), MAX(value_num)
			FROM device_telemetry
			WHERE device_pk = $2 AND metric = $3
			  AND received_at > now() - $4::interval
			  AND value_num IS NOT NULL
			GROUP BY b
			ORDER BY b`
		args = []interface{}{r.bucket, devicePk, metric, r.duration}
	case "7d", "30d":
		window := rangeDurationCagg[rangeName]
		query = `
			SELECT bucket, avg_val, min_val, max_val
			FROM device_telemetry_hourly
			WHERE device_pk = $1 AND metric = $2
			  AND bucket > now() - $3::interval
			ORDER BY bucket`
		args = []interface{}{devicePk, metric, window}
	case "90d":
		query = `
			SELECT bucket, avg_val, min_val, max_val
			FROM device_telemetry_daily
			WHERE device_pk = $1 AND metric = $2
			  AND bucket > now() - interval '90 days'
			ORDER BY bucket`
		args = []interface{}{devicePk, metric}
	default:
		return nil, ErrInvalidRange
	}

	series := &HistorySeries{Metric: metric, Range: rangeName}
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p HistoryPoint
			if err := rows.Scan(&p.T, &p.Avg, &p.Min, &p.Max); err != nil {
				return err
			}
			series.Points = append(series.Points, p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return series, nil
}

// RecentTelemetry returns the last N telemetry rows for a device, filtered by optional metric.
// Tenant-scoped through WithTenant.
// in: ctx, tenantID, device_pk, metric (optional, "" = all), limit. out: []device_telemetry rows.
func (s *TelemetryService) RecentTelemetry(ctx context.Context, tenantID string, devicePk uuid.UUID, metric string, limit int) ([]device_telemetry, error) {
	query := `
		SELECT id, device_pk, received_at, metric, value_num, value_text, raw
		FROM device_telemetry WHERE device_pk = $1`
	args := []interface{}{devicePk}
	if metric != "" {
		args = append(args, metric)
		query += fmt.Sprintf(" AND metric = $%d", len(args))
	}
	args = append(args, limit)
	query += fmt.Sprintf(" ORDER BY received_at DESC LIMIT $%d", len(args))

	var tel []device_telemetry
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t device_telemetry
			if err := rows.Scan(&t.ID, &t.DevicePK, &t.ReceivedAt, &t.Metric, &t.ValueNum, &t.ValueText, &t.Raw); err != nil {
				return err
			}
			tel = append(tel, t)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return tel, nil
}

// DeleteSensorTelemetry removes every telemetry row for a (device_pk, metric)
// tuple. Used by the device-detail "delete sensor" affordance to clean up
// stale-after-rename rows that linger after an autodiscovered sensor name is
// reassigned. Continuous aggregates (device_telemetry_hourly /
// _daily) are NOT cascaded - they're materialized views and lag until the
// next refresh / retention sweep, same trade-off as device delete.
// Tenant-scoped through WithTenant.
// in: ctx, tenantID, device_pk, metric. out: deleted-row count, error.
func (s *TelemetryService) DeleteSensorTelemetry(ctx context.Context, tenantID string, devicePk uuid.UUID, metric string) (int64, error) {
	var affected int64
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`DELETE FROM device_telemetry WHERE device_pk = $1 AND metric = $2`,
			devicePk, metric)
		if err != nil {
			return err
		}
		affected = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return 0, err
	}
	return affected, nil
}
