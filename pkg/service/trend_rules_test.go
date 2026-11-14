package service

import (
	"errors"
	"math"
	"testing"
	"time"
)

func TestValidateTrendRule(t *testing.T) {
	ok := TrendRule{Metric: "temp.boiler", Direction: "fall", Delta: 5, WindowS: 600, Severity: "warn"}
	if err := ValidateTrendRule(ok); err != nil {
		t.Fatalf("valid rule refused: %v", err)
	}
	// MQTT ingest keeps the whole sensor sub-path as the metric name.
	for _, m := range []string{"current/house_pump", "temperature/28ff0a/temp_c"} {
		r := ok
		r.Metric = m
		if err := ValidateTrendRule(r); err != nil {
			t.Errorf("metric %q refused: %v", m, err)
		}
	}
	bad := map[string]func(*TrendRule){
		"leading slash":     func(r *TrendRule) { r.Metric = "/current" },
		"trailing slash":    func(r *TrendRule) { r.Metric = "current/" },
		"empty segment":     func(r *TrendRule) { r.Metric = "current//pump" },
		"empty metric":      func(r *TrendRule) { r.Metric = "" },
		"metric with space": func(r *TrendRule) { r.Metric = "temp boiler" },
		"long metric":       func(r *TrendRule) { r.Metric = string(make([]byte, 65)) },
		"direction":         func(r *TrendRule) { r.Direction = "down" },
		"zero delta":        func(r *TrendRule) { r.Delta = 0 },
		"negative delta":    func(r *TrendRule) { r.Delta = -1 },
		"NaN delta":         func(r *TrendRule) { r.Delta = math.NaN() },
		"inf delta":         func(r *TrendRule) { r.Delta = math.Inf(1) },
		"short window":      func(r *TrendRule) { r.WindowS = 59 },
		"long window":       func(r *TrendRule) { r.WindowS = TrendWindowMax + 1 },
		"severity":          func(r *TrendRule) { r.Severity = "high" },
	}
	for name, mut := range bad {
		r := ok
		mut(&r)
		if err := ValidateTrendRule(r); !errors.Is(err, ErrTrendRuleInvalid) {
			t.Errorf("%s: want ErrTrendRuleInvalid, got %v", name, err)
		}
	}
}

func TestTrendFires(t *testing.T) {
	cases := []struct {
		dir              string
		delta, past, now float64
		want             bool
	}{
		{"fall", 5, 60, 54, true},
		{"fall", 5, 60, 55, true},
		{"fall", 5, 60, 56, false},
		{"fall", 5, 60, 70, false},
		{"rise", 0.5, 3.0, 3.6, true},
		{"rise", 0.5, 3.0, 2.0, false},
		{"either", 5, 60, 54, true},
		{"either", 5, 60, 66, true},
		{"either", 5, 60, 62, false},
		{"bogus", 1, 0, 100, false},
	}
	for _, c := range cases {
		if got := TrendFires(c.dir, c.delta, c.past, c.now); got != c.want {
			t.Errorf("%s %v %v->%v = %v, want %v", c.dir, c.delta, c.past, c.now, got, c.want)
		}
	}
}

func TestTrendStep(t *testing.T) {
	w := 10 * time.Minute
	cases := []struct {
		name                  string
		fires, baseline, open bool
		age                   time.Duration
		want                  trendAction
	}{
		{"no baseline never acts", true, false, true, time.Hour, trendNone},
		{"fires, nothing open", true, true, false, 0, trendRaise},
		{"fires, open inside window", true, true, true, 5 * time.Minute, trendNone},
		{"fires, open past window", true, true, true, w, trendRefire},
		{"stops, open", false, true, true, time.Minute, trendClear},
		{"stops, nothing open", false, true, false, 0, trendNone},
	}
	for _, c := range cases {
		if got := trendStep(c.fires, c.baseline, c.open, c.age, w); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestTrendFormat(t *testing.T) {
	if got := fmtTrendNum(6.2); got != "6.2" {
		t.Errorf("fmtTrendNum(6.2) = %q", got)
	}
	if got := fmtTrendNum(5); got != "5" {
		t.Errorf("fmtTrendNum(5) = %q", got)
	}
	for s, want := range map[int]string{3600: "1 h", 600: "10 min", 90: "90 s"} {
		if got := TrendWindowText(s); got != want {
			t.Errorf("TrendWindowText(%d) = %q, want %q", s, got, want)
		}
	}
}
