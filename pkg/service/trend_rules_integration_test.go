//go:build integration

package service_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/db"
	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

// seedReading inserts one numeric reading at now minus ago.
func seedReading(t *testing.T, env *servicetest.Env, dev uuid.UUID, metric string, v float64, ago time.Duration) {
	t.Helper()
	if _, err := env.Super.Exec(context.Background(),
		`INSERT INTO device_telemetry (device_pk, received_at, metric, value_num)
		 VALUES ($1, now() - $2::interval, $3, $4)`,
		dev, ago.String(), metric, v); err != nil {
		t.Fatal(err)
	}
}

func trendAlerts(t *testing.T, env *servicetest.Env, dev uuid.UUID) (total, open int) {
	t.Helper()
	if err := env.Super.QueryRow(context.Background(),
		`SELECT count(*), count(*) FILTER (WHERE cleared_at IS NULL)
		 FROM device_alerts WHERE device_pk = $1 AND code LIKE 'trend.%'`, dev).Scan(&total, &open); err != nil {
		t.Fatal(err)
	}
	return total, open
}

func trendDevice(t *testing.T, env *servicetest.Env, tenant, id string) uuid.UUID {
	t.Helper()
	pk, err := env.Services.Devices.Upsert(tenant, id, "", "", "", "thesada/"+tenant+"/"+id)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

// TestTrendRules_FireOnceSuppressClearRefire walks one rule through its states
// and checks the slow fall and the other tenant stay quiet.
func TestTrendRules_FireOnceSuppressClearRefire(t *testing.T) {
	env := servicetest.Start(t)
	ctx := context.Background()
	alerts := env.Services.Alerts
	env.SeedTenant(t, "trend-a")
	env.SeedTenant(t, "trend-b")
	boiler := trendDevice(t, env, "trend-a", "thesada-trend-boiler")
	slow := trendDevice(t, env, "trend-a", "thesada-trend-slow")
	other := trendDevice(t, env, "trend-b", "thesada-trend-other")

	// Tenant-wide rule in A: temp.boiler falls 5 or more within 10 min.
	if _, err := alerts.CreateTrendRule(ctx, "trend-a", service.TrendRule{
		Metric: "temp.boiler", Direction: "fall", Delta: 5, WindowS: 600, Severity: "warn",
	}); err != nil {
		t.Fatal(err)
	}
	for _, d := range []uuid.UUID{boiler, slow, other} {
		seedReading(t, env, d, "temp.boiler", 60, 12*time.Minute)
	}

	ids, err := alerts.EvaluateTrends(ctx, "trend-a", boiler, "temp.boiler", 54)
	if err != nil || len(ids) != 1 {
		t.Fatalf("falling series: ids=%v err=%v, want one alert", ids, err)
	}
	if ids, _ := alerts.EvaluateTrends(ctx, "trend-a", boiler, "temp.boiler", 53); len(ids) != 0 {
		t.Fatalf("re-fire inside the window raised %v", ids)
	}
	if total, open := trendAlerts(t, env, boiler); total != 1 || open != 1 {
		t.Fatalf("after suppression total=%d open=%d, want 1/1", total, open)
	}

	if ids, _ := alerts.EvaluateTrends(ctx, "trend-a", slow, "temp.boiler", 57); len(ids) != 0 {
		t.Fatalf("slow fall under the threshold raised %v", ids)
	}
	if ids, _ := alerts.EvaluateTrends(ctx, "trend-b", other, "temp.boiler", 40); len(ids) != 0 {
		t.Fatalf("tenant A's rule fired for tenant B: %v", ids)
	}
	if total, _ := trendAlerts(t, env, other); total != 0 {
		t.Fatalf("tenant B got %d trend alerts", total)
	}

	// Recovery clears the open alert.
	if _, err := alerts.EvaluateTrends(ctx, "trend-a", boiler, "temp.boiler", 60); err != nil {
		t.Fatal(err)
	}
	if total, open := trendAlerts(t, env, boiler); total != 1 || open != 0 {
		t.Fatalf("after recovery total=%d open=%d, want 1/0", total, open)
	}

	// Still falling a window later re-raises, and the old one stays cleared.
	ids, _ = alerts.EvaluateTrends(ctx, "trend-a", boiler, "temp.boiler", 54)
	if len(ids) != 1 {
		t.Fatalf("second episode raised %v", ids)
	}
	if _, err := env.Super.Exec(ctx, `UPDATE device_alerts SET received_at = now() - interval '11 minutes' WHERE id = $1`, ids[0]); err != nil {
		t.Fatal(err)
	}
	if ids, _ := alerts.EvaluateTrends(ctx, "trend-a", boiler, "temp.boiler", 53); len(ids) != 1 {
		t.Fatalf("re-fire past the window raised %v, want one", ids)
	}
	if total, open := trendAlerts(t, env, boiler); total != 3 || open != 1 {
		t.Fatalf("after re-fire total=%d open=%d, want 3/1", total, open)
	}
}

// TestTrendRules_TenantIsolation checks CRUD stays inside the tenant.
func TestTrendRules_TenantIsolation(t *testing.T) {
	env := servicetest.Start(t)
	ctx := context.Background()
	alerts := env.Services.Alerts
	env.SeedTenant(t, "trend-a")
	env.SeedTenant(t, "trend-b")
	devA := trendDevice(t, env, "trend-a", "thesada-iso-a")
	rule := service.TrendRule{Metric: "volt.battery", Direction: "fall", Delta: 0.5, WindowS: 3600, Severity: "crit"}

	r := rule
	r.DevicePK = &devA
	idA, err := alerts.CreateTrendRule(ctx, "trend-a", r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alerts.CreateTrendRule(ctx, "trend-b", r); !errors.Is(err, service.ErrTrendDevice) {
		t.Fatalf("B on A's device: want ErrTrendDevice, got %v", err)
	}
	if list, _ := alerts.ListTrendRules(ctx, "trend-b"); len(list) != 0 {
		t.Fatalf("B lists %d of A's rules", len(list))
	}
	if err := alerts.SetTrendRuleEnabled(ctx, "trend-b", idA, false); !errors.Is(err, service.ErrTrendRuleNotFound) {
		t.Fatalf("B toggles A's rule: %v", err)
	}
	if err := alerts.DeleteTrendRule(ctx, "trend-b", idA); !errors.Is(err, service.ErrTrendRuleNotFound) {
		t.Fatalf("B deletes A's rule: %v", err)
	}
	list, err := alerts.ListTrendRules(ctx, "trend-a")
	if err != nil || len(list) != 1 || list[0].DeviceID != "thesada-iso-a" || !list[0].Enabled {
		t.Fatalf("A's list = %+v err=%v", list, err)
	}
	if err := alerts.SetTrendRuleEnabled(ctx, "trend-a", idA, false); err != nil {
		t.Fatal(err)
	}
	if err := alerts.DeleteTrendRule(ctx, "trend-a", idA); err != nil {
		t.Fatal(err)
	}
	if _, err := alerts.CreateTrendRule(ctx, "trend-a", service.TrendRule{Metric: "x", Direction: "up", Delta: 1, WindowS: 600, Severity: "warn"}); !errors.Is(err, service.ErrTrendRuleInvalid) {
		t.Fatalf("invalid rule: %v", err)
	}
}

// countTracer counts the statements an evaluation sends.
type countTracer struct {
	mu   sync.Mutex
	sqls []string
}

func (c *countTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	c.mu.Lock()
	c.sqls = append(c.sqls, d.SQL)
	c.mu.Unlock()
	return ctx
}

func (c *countTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// work returns the statements other than transaction and tenant setup.
func (c *countTracer) work() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, s := range c.sqls {
		l := strings.ToLower(strings.TrimSpace(s))
		if l == "begin" || l == "commit" || l == "rollback" || strings.Contains(l, "set_config") {
			continue
		}
		out = append(out, s)
	}
	return out
}

// TestTrendRules_OneQueryPerReading pins the per-reading cost when nothing changes.
func TestTrendRules_OneQueryPerReading(t *testing.T) {
	env := servicetest.Start(t)
	ctx := context.Background()
	env.SeedTenant(t, "trend-q")
	dev := trendDevice(t, env, "trend-q", "thesada-trend-q")
	for _, m := range []string{"temp.a", "temp.b"} {
		if _, err := env.Services.Alerts.CreateTrendRule(ctx, "trend-q", service.TrendRule{
			Metric: m, Direction: "either", Delta: 5, WindowS: 600, Severity: "warn",
		}); err != nil {
			t.Fatal(err)
		}
	}
	seedReading(t, env, dev, "temp.a", 20, 12*time.Minute)

	tr := &countTracer{}
	traced := servicetest.OpenAsTraced(t, env.BaseURL, "thesada_app", tr)
	svcs, err := service.New(env.Cfg, db.Pools{App: traced, Admin: env.Pools.Admin})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []float64{21, 22, 19} {
		if _, err := svcs.Alerts.EvaluateTrends(ctx, "trend-q", dev, "temp.a", v); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svcs.Alerts.EvaluateTrends(ctx, "trend-q", dev, "temp.none", 1); err != nil {
		t.Fatal(err)
	}
	if got := tr.work(); len(got) != 4 {
		t.Fatalf("4 readings sent %d statements, want 4:\n%s", len(got), strings.Join(got, "\n---\n"))
	}
}
