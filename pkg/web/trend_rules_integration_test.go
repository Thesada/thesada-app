//go:build integration

package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// TestTrendRuleAdd_RefusesBadInput: a bad field is a 400 with readable text and stores nothing.
func TestTrendRuleAdd_RefusesBadInput(t *testing.T) {
	f := seedCrossTenant(t)
	good := url.Values{"metric": {"temp.boiler"}, "direction": {"fall"}, "delta": {"5"},
		"window": {"10"}, "unit": {"min"}, "severity": {"warn"}, "device": {f.device.String()}}
	cases := map[string]func(url.Values){
		"delta not a number": func(v url.Values) { v.Set("delta", "five") },
		"zero delta":         func(v url.Values) { v.Set("delta", "0") },
		"window too long":    func(v url.Values) { v.Set("window", "169"); v.Set("unit", "h") },
		"unknown unit":       func(v url.Values) { v.Set("unit", "d") },
		"direction":          func(v url.Values) { v.Set("direction", "down") },
		"metric":             func(v url.Values) { v.Set("metric", "temp/+") },
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

// TestTrendRules_Roles: the Lua rules check. A plain tenant user only views, the device
// owner changes rules on their device, only a tenant admin adds a tenant-wide rule.
func TestTrendRules_Roles(t *testing.T) {
	f := seedCrossTenant(t)
	_, viewer := tenantSession(t, f, "viewer@ct-a.test", false)
	_, admin := tenantSession(t, f, "admin@ct-a.test", true)
	onDevice := url.Values{"metric": {"ct.roles"}, "direction": {"rise"}, "delta": {"2"},
		"window": {"10"}, "unit": {"min"}, "severity": {"warn"}, "device": {f.device.String()}}
	tenantWide := url.Values{"metric": {"ct.wide"}, "direction": {"rise"}, "delta": {"2"},
		"window": {"10"}, "unit": {"min"}, "severity": {"warn"}}

	for name, form := range map[string]url.Values{"device rule": onDevice, "tenant-wide rule": tenantWide} {
		if rec := postAuthed(t, f.srv, "/alerts/rules/add", form, viewer, ""); rec.Code != http.StatusForbidden {
			t.Errorf("viewer add %s: status %d, want 403", name, rec.Code)
		}
	}
	for _, action := range []string{"toggle", "delete"} {
		path := "/alerts/rules/" + f.rules[action].String() + "/" + action
		if rec := postAuthed(t, f.srv, path, url.Values{}, viewer, ""); rec.Code != http.StatusForbidden {
			t.Errorf("viewer %s: status %d, want 403", action, rec.Code)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM alert_rules WHERE metric IN ('ct.roles', 'ct.wide')`); n != 0 {
		t.Fatalf("viewer stored %d rules", n)
	}
	if n := f.count(t, `SELECT count(*) FROM alert_rules WHERE id = $1 AND enabled`, f.rules["toggle"]); n != 1 {
		t.Fatal("viewer switched a rule off")
	}
	page := getAs(f.srv, "/alerts", viewer).Body.String()
	if strings.Contains(page, "/alerts/rules/add") || strings.Contains(page, "/toggle") {
		t.Error("viewer page offers rule controls")
	}

	if rec := postAuthed(t, f.srv, "/alerts/rules/add", tenantWide, f.owner, ""); rec.Code != http.StatusForbidden {
		t.Errorf("device owner tenant-wide add: status %d, want 403", rec.Code)
	}
	if rec := postAuthed(t, f.srv, "/alerts/rules/add", onDevice, f.owner, ""); rec.Code != http.StatusSeeOther {
		t.Errorf("device owner add on own device: status %d, want 303", rec.Code)
	}
	if rec := postAuthed(t, f.srv, "/alerts/rules/add", tenantWide, admin, ""); rec.Code != http.StatusSeeOther {
		t.Errorf("admin tenant-wide add: status %d, want 303", rec.Code)
	}
	if n := f.count(t, `SELECT count(*) FROM alert_rules WHERE metric IN ('ct.roles', 'ct.wide')`); n != 2 {
		t.Fatalf("allowed adds stored %d rules, want 2", n)
	}
}

// TestTrendRuleAdd_RefusesPastTheTenantCap: the add past the cap is a 400 naming the cap and stores nothing.
func TestTrendRuleAdd_RefusesPastTheTenantCap(t *testing.T) {
	f := seedCrossTenant(t)
	have := f.count(t, `SELECT count(*) FROM alert_rules WHERE tenant_id = $1`, ctTenantA)
	f.env.Cfg.QuotaTrendRules = have
	form := url.Values{"metric": {"ct.cap"}, "direction": {"rise"}, "delta": {"2"},
		"window": {"10"}, "unit": {"min"}, "severity": {"warn"}, "device": {f.device.String()}}
	rec := postAuthed(t, f.srv, "/alerts/rules/add", form, f.owner, "")
	want := "at most " + strconv.Itoa(have) + " trend rules"
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), want) {
		t.Fatalf("add past the cap: status %d body %q, want 400 with %q", rec.Code, rec.Body.String(), want)
	}
	if n := f.count(t, `SELECT count(*) FROM alert_rules WHERE metric = 'ct.cap'`); n != 0 {
		t.Fatalf("refused add stored %d rules", n)
	}
	f.env.Cfg.QuotaTrendRules = have + 1
	if rec := postAuthed(t, f.srv, "/alerts/rules/add", form, f.owner, ""); rec.Code != http.StatusSeeOther {
		t.Fatalf("add under the cap: status %d", rec.Code)
	}
}
