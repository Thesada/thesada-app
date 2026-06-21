//go:build integration

// TelemetryService integration tests. The
// TimescaleDB-specific surface: hypertable ingest + per-metric latest, raw
// time_bucket history, continuous-aggregate history, recent rows, and
// per-sensor delete. Container runs with background workers off, so the cagg
// path is exercised with an explicit refresh_continuous_aggregate.
//
//	go test -tags integration -run TestTelemetryService ./pkg/service/...
package service_test

import (
	"context"
	"errors"
	"testing"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

func TestTelemetryService(t *testing.T) {
	env := servicetest.Start(t)
	tel := env.Services.Telemetry
	dev := env.Services.Devices
	ctx := context.Background()

	const tA, tB = "tel-a", "tel-b"
	env.SeedTenant(t, tA)
	env.SeedTenant(t, tB)

	num := func(f float64) *float64 { return &f }

	t.Run("Record_numeric_and_text_then_LatestPerMetric", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "tel-dev-1", "", "", "", "")
		if _, err := tel.RecordTelemetry(ctx, tA, pk, "temp", num(20.0), "", []byte("20")); err != nil {
			t.Fatalf("record temp 1: %v", err)
		}
		if _, err := tel.RecordTelemetry(ctx, tA, pk, "temp", num(22.0), "", []byte("22")); err != nil {
			t.Fatalf("record temp 2: %v", err)
		}
		// Text-only metric: value_num nil + a non-JSON payload that must be
		// wrapped so the JSONB column accepts it.
		if _, err := tel.RecordTelemetry(ctx, tA, pk, "battery_state", nil, "Discharging", []byte("Discharging")); err != nil {
			t.Fatalf("record text: %v", err)
		}

		latest, err := tel.LatestPerMetric(ctx, tA, pk)
		if err != nil {
			t.Fatalf("LatestPerMetric: %v", err)
		}
		byMetric := map[string]*float64{}
		var textSeen bool
		for _, r := range latest {
			byMetric[r.Metric] = r.ValueNum
			if r.Metric == "battery_state" && r.ValueText != nil && *r.ValueText == "Discharging" {
				textSeen = true
			}
		}
		if byMetric["temp"] == nil || *byMetric["temp"] != 22.0 {
			t.Errorf("latest temp = %v, want 22.0 (newest)", byMetric["temp"])
		}
		if !textSeen {
			t.Error("text metric battery_state=Discharging not returned")
		}
	})

	t.Run("RecentTelemetry_limit_and_metric_filter", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "tel-dev-recent", "", "", "", "")
		for i := 0; i < 5; i++ {
			if _, err := tel.RecordTelemetry(ctx, tA, pk, "rssi", num(float64(-40-i)), "", []byte("x")); err != nil {
				t.Fatalf("record %d: %v", i, err)
			}
		}
		if _, err := tel.RecordTelemetry(ctx, tA, pk, "heap", num(1000), "", []byte("x")); err != nil {
			t.Fatalf("record heap: %v", err)
		}
		// Limit caps the result.
		got, err := tel.RecentTelemetry(ctx, tA, pk, "", 3)
		if err != nil || len(got) != 3 {
			t.Fatalf("RecentTelemetry limit = %d (err %v), want 3", len(got), err)
		}
		// Metric filter narrows to one series.
		rssi, err := tel.RecentTelemetry(ctx, tA, pk, "rssi", 100)
		if err != nil {
			t.Fatalf("RecentTelemetry rssi: %v", err)
		}
		if len(rssi) != 5 {
			t.Errorf("rssi rows = %d, want 5", len(rssi))
		}
		for _, r := range rssi {
			if r.Metric != "rssi" {
				t.Errorf("metric filter leaked %q", r.Metric)
			}
		}
	})

	t.Run("History_raw_range_buckets", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "tel-dev-hist", "", "", "", "")
		for _, v := range []float64{10, 20, 30} {
			if _, err := tel.RecordTelemetry(ctx, tA, pk, "temp", num(v), "", []byte("x")); err != nil {
				t.Fatalf("record: %v", err)
			}
		}
		series, err := tel.History(ctx, tA, pk, "temp", "1h")
		if err != nil {
			t.Fatalf("History 1h: %v", err)
		}
		if series.Metric != "temp" || series.Range != "1h" {
			t.Errorf("series meta = %s/%s, want temp/1h", series.Metric, series.Range)
		}
		if len(series.Points) == 0 {
			t.Fatal("History 1h returned no points")
		}
		// All three readings land in the same minute bucket: avg 20, min 10, max 30.
		var p *service.HistoryPoint
		for i := range series.Points {
			if series.Points[i].Avg != nil {
				p = &series.Points[i]
				break
			}
		}
		if p == nil || p.Avg == nil || *p.Avg != 20 || *p.Min != 10 || *p.Max != 30 {
			t.Errorf("bucket = %+v, want avg 20 min 10 max 30", p)
		}
	})

	t.Run("History_invalid_inputs", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "tel-dev-bad", "", "", "", "")
		if _, err := tel.History(ctx, tA, pk, "", "1h"); !errors.Is(err, service.ErrInvalidRange) {
			t.Errorf("empty metric = %v, want ErrInvalidRange", err)
		}
		if _, err := tel.History(ctx, tA, pk, "temp", "nonsense"); !errors.Is(err, service.ErrInvalidRange) {
			t.Errorf("bad range = %v, want ErrInvalidRange", err)
		}
	})

	t.Run("History_cagg_ranges", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "tel-dev-cagg", "", "", "", "")
		for _, v := range []float64{5, 15, 25} {
			if _, err := tel.RecordTelemetry(ctx, tA, pk, "temp", num(v), "", []byte("x")); err != nil {
				t.Fatalf("record: %v", err)
			}
		}
		// Background workers are off in the test container, so materialize the
		// hourly cagg by hand before reading the 7d range.
		if _, err := env.Super.Exec(ctx,
			`CALL refresh_continuous_aggregate('device_telemetry_hourly', NULL, NULL)`); err != nil {
			t.Fatalf("refresh hourly cagg: %v", err)
		}
		s7, err := tel.History(ctx, tA, pk, "temp", "7d")
		if err != nil {
			t.Fatalf("History 7d: %v", err)
		}
		if len(s7.Points) == 0 {
			t.Error("History 7d returned no points after cagg refresh")
		}
		// 90d reads the daily cagg - assert the SQL/columns are valid (no error,
		// well-formed series) even without forcing a daily refresh.
		s90, err := tel.History(ctx, tA, pk, "temp", "90d")
		if err != nil || s90 == nil || s90.Range != "90d" {
			t.Errorf("History 90d = %v err %v, want valid series", s90, err)
		}
	})

	t.Run("DeleteSensorTelemetry", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "tel-dev-del", "", "", "", "")
		for i := 0; i < 3; i++ {
			if _, err := tel.RecordTelemetry(ctx, tA, pk, "doomed", num(1), "", []byte("x")); err != nil {
				t.Fatalf("record: %v", err)
			}
		}
		n, err := tel.DeleteSensorTelemetry(ctx, tA, pk, "doomed")
		if err != nil || n != 3 {
			t.Fatalf("DeleteSensorTelemetry = %d err %v, want 3", n, err)
		}
		left, _ := tel.RecentTelemetry(ctx, tA, pk, "doomed", 10)
		if len(left) != 0 {
			t.Errorf("rows after delete = %d, want 0", len(left))
		}
	})

	t.Run("scoped_by_device_pk_not_rls", func(t *testing.T) {
		// No RLS on device_telemetry (compressed hypertable, see 0016); tenant
		// isolation is upstream via the tenant-scoped device_pk lookup. Here the
		// guarantee is just per-device_pk scoping.
		pk1 := mustUpsert(t, dev, tA, "tel-scope-1", "", "", "", "")
		pk2 := mustUpsert(t, dev, tA, "tel-scope-2", "", "", "", "")
		if _, err := tel.RecordTelemetry(ctx, tA, pk1, "temp", num(1), "", []byte("x")); err != nil {
			t.Fatalf("record pk1: %v", err)
		}
		if _, err := tel.RecordTelemetry(ctx, tA, pk2, "temp", num(2), "", []byte("x")); err != nil {
			t.Fatalf("record pk2: %v", err)
		}
		got, err := tel.LatestPerMetric(ctx, tA, pk1)
		if err != nil {
			t.Fatalf("LatestPerMetric: %v", err)
		}
		if len(got) == 0 {
			t.Fatal("expected pk1 telemetry")
		}
		for _, r := range got {
			if r.DevicePK != pk1 {
				t.Errorf("LatestPerMetric(pk1) returned device %v, want only %v", r.DevicePK, pk1)
			}
		}
	})
}
