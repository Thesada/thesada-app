package web

import (
	"strings"
	"testing"
	"time"
)

func TestMetricLeaf(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"battery/percent", "percent"},
		{"uptime", "uptime"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := metricLeaf(tt.in); got != tt.want {
			t.Errorf("metricLeaf(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestMetricUnit(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"sensor/temperature/probe", " °"},
		{"sensor/humidity/probe", " %"},
		{"power/current/ct1", " A"},
		{"power/voltage/bus", " V"},
		{"power/power/load", " W"},
		{"battery/percent", " %"},
		{"wifi/rssi", " dBm"},
		{"heap/free", ""},
	}
	for _, tt := range tests {
		if got := metricUnit(tt.in); got != tt.want {
			t.Errorf("metricUnit(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestDerefOrDash(t *testing.T) {
	s := "owb"
	empty := ""
	if got := derefStringOrDash(nil); got != "-" {
		t.Errorf("nil string = %q", got)
	}
	if got := derefStringOrDash(&empty); got != "-" {
		t.Errorf("empty string = %q", got)
	}
	if got := derefStringOrDash(&s); got != "owb" {
		t.Errorf("string = %q", got)
	}
	if got := derefString(nil); got != "" {
		t.Errorf("derefString nil = %q", got)
	}
	if got := derefString(&empty); got != "" {
		t.Errorf("derefString empty = %q", got)
	}
	n := 3
	zero := 0
	if got := derefIntOrDash(nil); got != "-" {
		t.Errorf("nil int = %q", got)
	}
	if got := derefIntOrDash(&zero); got != "0" {
		t.Errorf("zero int = %q", got)
	}
	if got := derefIntOrDash(&n); got != "3" {
		t.Errorf("int = %q", got)
	}
	var big int64 = 42
	var zero64 int64
	if got := derefInt64OrDash(nil); got != "-" {
		t.Errorf("nil int64 = %q", got)
	}
	if got := derefInt64OrDash(&zero64); got != "0" {
		t.Errorf("zero int64 = %q", got)
	}
	if got := derefInt64OrDash(&big); got != "42" {
		t.Errorf("int64 = %q", got)
	}
}

func TestFreshness_UnseenIsUnknownAndAgeBandsAreLiveThenStaleThenOffline(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	if label, _ := freshnessState(nil, now); label != "unknown" {
		t.Fatalf("nil = %q", label)
	}
	zero := time.Time{}
	if label, _ := freshnessState(&zero, now); label != "unknown" {
		t.Fatalf("zero = %q", label)
	}
	live := now.Add(-freshnessLive)
	if label, _ := freshnessState(&live, now); label != "live" {
		t.Fatalf("5m = %q", label)
	}
	stale := now.Add(-freshnessLive - time.Second)
	if label, _ := freshnessState(&stale, now); label != "stale" {
		t.Fatalf("5m1s = %q", label)
	}
	edge := now.Add(-freshnessOffline)
	if label, _ := freshnessState(&edge, now); label != "stale" {
		t.Fatalf("15m = %q", label)
	}
	off := now.Add(-freshnessOffline - time.Second)
	if label, _ := freshnessState(&off, now); label != "offline" {
		t.Fatalf("15m1s = %q", label)
	}
	future := now.Add(time.Minute)
	if label, _ := freshnessState(&future, now); label != "live" {
		t.Fatalf("future = %q", label)
	}
}

func TestUptimeLive(t *testing.T) {
	now := time.Now()
	if got := uptimeLive(nil, nil); got != "-" {
		t.Errorf("both nil = %q", got)
	}
	secs := int64(10)
	if got := uptimeLive(&secs, nil); got != "-" {
		t.Errorf("nil timestamp = %q", got)
	}
	if got := uptimeLive(nil, &now); got != "-" {
		t.Errorf("nil seconds = %q", got)
	}

	neg := int64(-100000)
	if got := uptimeLive(&neg, &now); got != "0m" {
		t.Errorf("negative total = %q, want 0m", got)
	}

	day := int64(90000)
	if got := uptimeLive(&day, &now); !strings.HasPrefix(got, "1d 1h ") {
		t.Errorf("day bucket = %q", got)
	}

	freshAt := time.Now().Add(-14 * time.Minute)
	fresh := int64(0)
	if got := uptimeLive(&fresh, &freshAt); got != "14m" {
		t.Errorf("14m sample = %q, want 14m", got)
	}

	staleAt := time.Now().Add(-16 * time.Minute)
	if got := uptimeLive(&fresh, &staleAt); got != "16m (old)" {
		t.Errorf("16m sample = %q, want 16m (old)", got)
	}
}
