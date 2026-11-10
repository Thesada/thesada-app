//go:build integration

package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestTrendRuleAdd_RefusesBadInput: a bad field is a 400 with readable text and stores nothing.
func TestTrendRuleAdd_RefusesBadInput(t *testing.T) {
	f := seedCrossTenant(t)
	good := url.Values{"metric": {"temp.boiler"}, "direction": {"fall"}, "delta": {"5"},
		"window": {"10"}, "unit": {"min"}, "severity": {"warn"}}
	cases := map[string]func(url.Values){
		"delta not a number": func(v url.Values) { v.Set("delta", "five") },
		"zero delta":         func(v url.Values) { v.Set("delta", "0") },
		"window too long":    func(v url.Values) { v.Set("window", "169"); v.Set("unit", "h") },
		"unknown unit":       func(v url.Values) { v.Set("unit", "d") },
		"direction":          func(v url.Values) { v.Set("direction", "down") },
		"metric":             func(v url.Values) { v.Set("metric", "temp boiler") },
		"device":             func(v url.Values) { v.Set("device", "not-a-uuid") },
	}
	for name, mut := range cases {
		v := url.Values{}
		for k, vals := range good {
			v[k] = append([]string(nil), vals...)
		}
		mut(v)
		rec := postAuthed(t, f.srv, "/alerts/rules/add", v, f.owner, "")
		if rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), "invalid trend rule") {
			t.Errorf("%s: status %d body %q, want 400 with plain text", name, rec.Code, rec.Body.String())
		}
	}
	if n := f.count(t, `SELECT count(*) FROM alert_rules WHERE metric = 'temp.boiler'`); n != 0 {
		t.Fatalf("bad input stored %d rules", n)
	}
	if rec := postAuthed(t, f.srv, "/alerts/rules/add", good, f.owner, ""); rec.Code != http.StatusSeeOther {
		t.Fatalf("good rule: status %d", rec.Code)
	}
	if rec := getAs(f.srv, "/alerts", f.owner); !strings.Contains(rec.Body.String(), "fall 5 in 10 min") {
		t.Fatal("alerts page does not show the new rule")
	}
}
