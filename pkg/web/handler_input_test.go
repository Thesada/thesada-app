// Handler bad-input coverage. Every {id}-bearing handler
// rejects a malformed id before it touches services, so these run against a
// bare &Server{} with nil deps. The happy path + the post-lookup branches
// (bad json, missing fields, cross-tenant gates) need a real device row and
// land in the Phase 3 testcontainer suite.
//
// Handlers are called unwrapped (not through the mux): the auth gate is the
// mux wrapper's job - audited in routes_test.go - so a direct call exercises
// the handler body's own validation in isolation.
package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// reqWithPathValue builds a request carrying a single path placeholder, as the
// mux would have populated it before dispatch.
func reqWithPathValue(method, key, val string) *http.Request {
	r := httptest.NewRequest(method, "/", nil)
	r.SetPathValue(key, val)
	return r
}

// postFormPath builds a urlencoded POST whose body is parseable by ParseForm
// and which carries one path placeholder.
func postFormPath(method, key, val, body string) *http.Request {
	r := httptest.NewRequest(method, "/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue(key, val)
	return r
}

// badUUIDCases: each handler given an unparseable id must short-circuit with
// the documented status before any service call. wantCode differs per handler
// by design - the /admin/devices/{id}/config/* family answers 400 ("bad
// device id") while the delete/pair/waitlist/tenant-user family answers 404 so
// the resource tree stays non-discoverable.
func TestHandlers_BadUUID(t *testing.T) {
	s := &Server{}
	cases := []struct {
		name     string
		key      string
		method   string
		handler  func(http.ResponseWriter, *http.Request)
		wantCode int
	}{
		{"DeviceSensorDelete", "id", http.MethodPost, s.handleDeviceSensorDelete, http.StatusNotFound},
		{"AdminDeviceConfig", "id", http.MethodGet, s.handleAdminDeviceConfig, http.StatusNotFound},
		{"AdminDeviceConfigCmd", "id", http.MethodPost, s.handleAdminDeviceConfigCmd, http.StatusBadRequest},
		{"AdminDeviceConfigWrite", "id", http.MethodPost, s.handleAdminDeviceConfigWrite, http.StatusBadRequest},
		{"AdminDeviceConfigSnapshot", "id", http.MethodPost, s.handleAdminDeviceConfigSnapshot, http.StatusBadRequest},
		{"AdminDeviceConfigHistory", "id", http.MethodGet, s.handleAdminDeviceConfigHistory, http.StatusBadRequest},
		{"AdminDeviceSecrets", "id", http.MethodGet, s.handleAdminDeviceSecrets, http.StatusNotFound},
		{"AdminDeviceSecretsSet", "id", http.MethodPost, s.handleAdminDeviceSecretsSet, http.StatusNotFound},
		{"AdminDevicePairIssue", "id", http.MethodPost, s.handleAdminDevicePairIssue, http.StatusNotFound},
		{"AdminDevicePairRevoke", "id", http.MethodPost, s.handleAdminDevicePairRevoke, http.StatusNotFound},
		{"AdminDeviceDelete", "id", http.MethodPost, s.handleAdminDeviceDelete, http.StatusNotFound},
		{"AdminWaitlistConvert", "id", http.MethodPost, s.handleAdminWaitlistConvert, http.StatusNotFound},
		{"AdminWaitlistDelete", "id", http.MethodPost, s.handleAdminWaitlistDelete, http.StatusNotFound},
		{"AdminTenantUserToggle", "user_id", http.MethodPost, s.handleAdminTenantUserToggle, http.StatusNotFound},
		{"AdminTenantUserDelete", "user_id", http.MethodPost, s.handleAdminTenantUserDelete, http.StatusNotFound},
		{"AdminTenantUserEdit", "user_id", http.MethodGet, s.handleAdminTenantUserEdit, http.StatusNotFound},
		{"AdminTenantUserUpdate", "user_id", http.MethodPost, s.handleAdminTenantUserUpdate, http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.handler(rec, reqWithPathValue(tc.method, tc.key, "not-a-uuid"))
			if rec.Code != tc.wantCode {
				t.Errorf("%s bad uuid = %d, want %d", tc.name, rec.Code, tc.wantCode)
			}
		})
	}
}

// handleAdminDeviceConfigCmdResult reads its id from the query string, not the
// path, with a distinct empty vs malformed split - covered separately.
func TestAdminDeviceConfigCmdResult_BadID(t *testing.T) {
	s := &Server{}
	t.Run("missing id", func(t *testing.T) {
		rec := httptest.NewRecorder()
		s.handleAdminDeviceConfigCmdResult(rec, httptest.NewRequest(http.MethodGet, "/admin/devices/x/config/cmd/result", nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("missing id = %d, want 400", rec.Code)
		}
	})
	t.Run("bad id", func(t *testing.T) {
		rec := httptest.NewRecorder()
		s.handleAdminDeviceConfigCmdResult(rec, httptest.NewRequest(http.MethodGet, "/admin/devices/x/config/cmd/result?id=not-a-uuid", nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("bad id = %d, want 400", rec.Code)
		}
	})
}

// handleDeviceSensorDelete has two post-uuid, pre-service validation branches
// (metric required, confirm mismatch). A valid uuid gets past the parse; both
// branches redirect before any Devices/Telemetry call, so nil services are
// safe here too.
func TestDeviceSensorDelete_FormValidation(t *testing.T) {
	s := &Server{}
	const validID = "00000000-0000-0000-0000-000000000001"

	t.Run("metric required", func(t *testing.T) {
		rec := httptest.NewRecorder()
		r := reqWithPathValue(http.MethodPost, "id", validID)
		s.handleDeviceSensorDelete(rec, r)
		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", rec.Code)
		}
		if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=metric+required") {
			t.Errorf("Location = %q, want error=metric+required", loc)
		}
	})

	t.Run("confirm mismatch", func(t *testing.T) {
		rec := httptest.NewRecorder()
		r := postFormPath(http.MethodPost, "id", validID, "metric=temp&confirm_metric=other")
		s.handleDeviceSensorDelete(rec, r)
		if rec.Code != http.StatusFound {
			t.Fatalf("status = %d, want 302", rec.Code)
		}
		if loc := rec.Header().Get("Location"); !strings.Contains(loc, "error=confirm+metric+did+not+match") {
			t.Errorf("Location = %q, want confirm-mismatch error", loc)
		}
	})
}
