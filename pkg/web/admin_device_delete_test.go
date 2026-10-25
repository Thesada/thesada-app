// Tests for /admin/devices/{id}/delete input-validation edges.
// The hot path - revoke -> dynsec -> CASCADE delete - lives in the
// integration testcontainer suite because it touches Certificates, mqtt, and
// the FK CASCADE chain in real Postgres.
package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Bad UUID in path returns 404. Doesn't depend on any service because the
// uuid.Parse failure short-circuits before the lookup.
func TestAdminDeviceDelete_BadUUID(t *testing.T) {
	s := newServerForBulkTest()
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/admin/devices/not-a-uuid/delete", strings.NewReader(""))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// http.ServeMux's path-pattern wildcard isn't populated when we call
	// the handler directly; set it manually so r.PathValue("id") returns
	// the bad value the parse should reject.
	r.SetPathValue("id", "not-a-uuid")
	s.handleAdminDeviceDelete(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}
