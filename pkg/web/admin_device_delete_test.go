// Tests for /admin/devices/{id}/delete input-validation edges.
// The hot path - revoke -> dynsec -> CASCADE delete - lives in the
// integration testcontainer suite because it touches Certificates, mqtt, and
// the FK CASCADE chain in real Postgres.
package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
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

// Valid UUID for a device that doesn't exist also returns 404 (GetByIDAny
// returns nil). Catches the case where the handler is invoked with a stale
// id that's already been deleted.
func TestAdminDeviceDelete_UnknownDevice(t *testing.T) {
	// This path exercises s.services.Devices.GetByIDAny which needs a
	// non-nil service bundle + db connection. Skip: covered in the
	// integration suite once a PG testcontainer is wired.
	t.Skip("integration coverage: needs PG testcontainer")
}

// confirm_device_id mismatch redirects with error and never touches services.
// Skipped here because GetByIDAny requires a real DB; covered in integration.
func TestAdminDeviceDelete_ConfirmMismatch(t *testing.T) {
	t.Skip("integration coverage: confirm gate runs after device lookup which needs PG")
}

// _ = url.Values{} keeps the import in scope when the integration-coverage
// stubs above are the only callers; harmless when uncommented for real tests.
var _ = url.Values{}
