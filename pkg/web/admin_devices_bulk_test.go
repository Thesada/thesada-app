// Tests for /admin/devices/bulk dispatch + empty-list early-returns.
// The hot path (publish to N devices) needs a real MQTT client + a
// Devices service backed by Postgres, so it lands in the testcontainer
// suite. These tests cover the input-validation edges that don't touch
// services or mqtt.
package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newServerForBulkTest() *Server { return &Server{} }

// postForm builds a POST /admin/devices/bulk request whose body is the
// urlencoded form and ContentType is set so r.ParseForm() reads PostForm.
func postForm(form url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/admin/devices/bulk", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestAdminDevicesBulk_UnknownAction(t *testing.T) {
	s := newServerForBulkTest()
	rec := httptest.NewRecorder()
	form := url.Values{"action": {"definitely-not-a-real-action"}}
	s.handleAdminDevicesBulk(rec, postForm(form))
	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "error=unknown") {
		t.Errorf("Location = %q, want error=unknown+...", loc)
	}
}

func TestAdminDevicesBulk_OTA_NoSelection(t *testing.T) {
	s := newServerForBulkTest()
	rec := httptest.NewRecorder()
	form := url.Values{"action": {"ota"}}
	s.handleAdminDevicesBulk(rec, postForm(form))
	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "error=no+devices+selected") {
		t.Errorf("Location = %q, want error=no+devices+selected", loc)
	}
}

// The hot path - bad-uuid -> failure counter, lookup -> publish - lives in
// pkg/service-backed integration tests because it
// touches both services.Devices and *mqtt.Client.

// Slice 2: bulk reassign edge cases. Same input-validation tier as the
// other tests here; the hot path (Reassign loop with PG) lives in the
// integration test suite.

func TestAdminDevicesBulk_Reassign_NoSelection(t *testing.T) {
	s := newServerForBulkTest()
	rec := httptest.NewRecorder()
	form := url.Values{"action": {"reassign"}, "target_tenant": {"some-tenant"}}
	s.handleAdminDevicesBulk(rec, postForm(form))
	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "error=no+devices+selected") {
		t.Errorf("Location = %q, want error=no+devices+selected", loc)
	}
}

// target_tenant missing entirely: short-circuits before any device lookup.
// Doesn't depend on services.Tenants because the empty-string branch
// returns early.
func TestAdminDevicesBulk_Reassign_EmptyTarget(t *testing.T) {
	s := newServerForBulkTest()
	rec := httptest.NewRecorder()
	form := url.Values{
		"action":     {"reassign"},
		"device_ids": {"00000000-0000-0000-0000-000000000001"},
	}
	s.handleAdminDevicesBulk(rec, postForm(form))
	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "error=unknown+tenant") {
		t.Errorf("Location = %q, want error=unknown+tenant", loc)
	}
}

// Slice 3 (bulk delete) input-validation edges. Cross-tenant gate + the
// per-device cascade hot path live in the integration test suite since they touch
// services.Devices.GetByIDAny + Certificates + mqtt + DB cascade.

func TestAdminDevicesBulk_Delete_NoSelection(t *testing.T) {
	s := newServerForBulkTest()
	rec := httptest.NewRecorder()
	form := url.Values{"action": {"delete"}}
	s.handleAdminDevicesBulk(rec, postForm(form))
	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "error=no+devices+selected") {
		t.Errorf("Location = %q, want error=no+devices+selected", loc)
	}
}

// The recovery gate refuses exactly one shape: a paired device, no usable
// path back onto the broker, and no operator override.
func TestDestructiveAllowed_RefusesOnlyPairedUnusableNoOverride(t *testing.T) {
	cases := []struct {
		paired, usable, override, want bool
	}{
		{false, false, false, true},
		{false, false, true, true},
		{false, true, false, true},
		{false, true, true, true},
		{true, false, false, false},
		{true, false, true, true},
		{true, true, false, true},
		{true, true, true, true},
	}
	for _, c := range cases {
		if got := destructiveAllowed(c.paired, c.usable, c.override); got != c.want {
			t.Errorf("destructiveAllowed(paired=%v usable=%v override=%v) = %v, want %v",
				c.paired, c.usable, c.override, got, c.want)
		}
	}
}

// Acceptance is recorded only when the override was what let the operation
// through: paired, unusable, ticked. Nothing else counts.
func TestSerialRecoveryAccepted_OnlyWhenOverrideDidTheWork(t *testing.T) {
	usable := recoveryVerdict{usable: true}
	broken := recoveryVerdict{reason: "disabled"}
	cases := []struct {
		name     string
		paired   bool
		v        recoveryVerdict
		override bool
		want     bool
	}{
		{"unpaired, broken path, no tick", false, broken, false, false},
		{"unpaired, broken path, ticked anyway", false, broken, true, false},
		{"paired, usable path, ticked anyway", true, usable, true, false},
		{"paired, broken path, ticked", true, broken, true, true},
	}
	for _, c := range cases {
		if got := serialRecoveryAccepted(c.paired, c.v, c.override); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
