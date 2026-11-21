//go:build integration

package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

func capRule(metric string, dev *uuid.UUID) service.TrendRule {
	return service.TrendRule{DevicePK: dev, Metric: metric, Direction: "fall", Delta: 5, WindowS: 600, Severity: "warn"}
}

// TestTrendRules_TenantCap: rules up to the cap land, the next one is refused with the cap in
// the text, a disabled rule still counts, a delete frees a slot and another tenant is unaffected.
func TestTrendRules_TenantCap(t *testing.T) {
	env := servicetest.Start(t)
	env.Cfg.QuotaTrendRules = 3
	ctx := context.Background()
	alerts := env.Services.Alerts
	env.SeedTenant(t, "cap-a")
	env.SeedTenant(t, "cap-b")
	dev := trendDevice(t, env, "cap-a", "thesada-cap-a")

	rules := []service.TrendRule{capRule("temp.a", nil), capRule("temp.b", &dev), capRule("temp.c", &dev)}
	ids := make([]uuid.UUID, 0, len(rules))
	for _, r := range rules {
		id, err := alerts.CreateTrendRule(ctx, "cap-a", r)
		if err != nil {
			t.Fatalf("rule %s under the cap: %v", r.Metric, err)
		}
		ids = append(ids, id)
	}
	_, err := alerts.CreateTrendRule(ctx, "cap-a", capRule("temp.d", nil))
	if !errors.Is(err, service.ErrQuotaTrendRules) || !strings.Contains(err.Error(), "3") {
		t.Fatalf("rule past the cap: %v, want ErrQuotaTrendRules naming 3", err)
	}
	if err := alerts.SetTrendRuleEnabled(ctx, "cap-a", ids[0], false); err != nil {
		t.Fatal(err)
	}
	if _, err := alerts.CreateTrendRule(ctx, "cap-a", capRule("temp.d", &dev)); !errors.Is(err, service.ErrQuotaTrendRules) {
		t.Fatalf("a disabled rule freed a slot: %v", err)
	}
	if err := alerts.SetTrendRuleEnabled(ctx, "cap-a", ids[0], true); err != nil {
		t.Fatalf("enable at the cap: %v", err)
	}
	for i := range 3 {
		if _, err := alerts.CreateTrendRule(ctx, "cap-b", capRule("temp.b"+string(rune('a'+i)), nil)); err != nil {
			t.Fatalf("tenant B rule %d: %v", i, err)
		}
	}
	if err := alerts.DeleteTrendRule(ctx, "cap-a", ids[1]); err != nil {
		t.Fatal(err)
	}
	if _, err := alerts.CreateTrendRule(ctx, "cap-a", capRule("temp.d", nil)); err != nil {
		t.Fatalf("after a delete: %v", err)
	}
	if list, _ := alerts.ListTrendRules(ctx, "cap-a"); len(list) != 3 {
		t.Fatalf("tenant A lists %d rules, want 3", len(list))
	}

	env.Cfg.QuotaTrendRules = 0
	if _, err := alerts.CreateTrendRule(ctx, "cap-a", capRule("temp.e", nil)); err != nil {
		t.Fatalf("a zero cap is off: %v", err)
	}
}

// TestTrendRules_OverCapKeepsWorking: a tenant already above the cap keeps every rule listed,
// evaluated and switchable, it only cannot add one.
func TestTrendRules_OverCapKeepsWorking(t *testing.T) {
	env := servicetest.Start(t)
	env.Cfg.QuotaTrendRules = 2
	ctx := context.Background()
	alerts := env.Services.Alerts
	env.SeedTenant(t, "cap-over")
	dev := trendDevice(t, env, "cap-over", "thesada-cap-over")
	for i := range 4 {
		if _, err := env.Super.Exec(ctx, `
			INSERT INTO alert_rules (tenant_id, device_pk, kind, metric, direction, delta, window_s, severity)
			VALUES ('cap-over', NULL, 'trend', 'temp.boiler', 'fall', $1, 600, 'warn')`, 1+i); err != nil {
			t.Fatal(err)
		}
	}
	list, err := alerts.ListTrendRules(ctx, "cap-over")
	if err != nil || len(list) != 4 {
		t.Fatalf("over-cap list: %d rules, err %v, want 4", len(list), err)
	}
	seedReading(t, env, dev, "temp.boiler", 60, 12*time.Minute)
	ids, err := alerts.EvaluateTrends(ctx, "cap-over", dev, "temp.boiler", 50)
	if err != nil || len(ids) != 4 {
		t.Fatalf("over-cap evaluation raised %v err %v, want 4 alerts", ids, err)
	}
	if err := alerts.SetTrendRuleEnabled(ctx, "cap-over", list[0].ID, false); err != nil {
		t.Fatalf("disable over the cap: %v", err)
	}
	if err := alerts.SetTrendRuleEnabled(ctx, "cap-over", list[0].ID, true); err != nil {
		t.Fatalf("enable over the cap: %v", err)
	}
	if _, err := alerts.CreateTrendRule(ctx, "cap-over", capRule("temp.new", nil)); !errors.Is(err, service.ErrQuotaTrendRules) {
		t.Fatalf("add over the cap: %v, want ErrQuotaTrendRules", err)
	}
}
