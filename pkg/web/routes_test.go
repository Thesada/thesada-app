// Route-wiring audit. authmw_test proves the RequireAuth /
// RequireSuperAdmin gates work; this proves every gated route is actually
// wrapped in one. A handler registered without its gate would execute on an
// anonymous request instead of redirecting - the regression this catches.
//
// Anonymous requests are driven through s.mux directly (not s.handler, which
// also threads csrf + cookie resolution). Both gates redirect an anonymous
// caller to /login with 302, so the assertion is uniform: a route that does
// NOT redirect is missing its wrapper.
package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// gatedRoutes is the full set of routes that must reject anonymous callers.
// Keep in sync with routes() - a new gated route added there without a row
// here simply isn't audited (and vice-versa a row here for a deleted route
// fails fast at request time). {id}/{slug} segments use any placeholder; the
// gate fires before path parsing so the value is irrelevant.
var gatedRoutes = []struct {
	method string
	path   string
}{
	// RequireAuth
	{http.MethodGet, "/devices"},
	{http.MethodGet, "/devices/x"},
	{http.MethodGet, "/devices/x/chart.json"},
	{http.MethodPost, "/devices/x/sensors/delete"},
	{http.MethodGet, "/alerts"},
	{http.MethodGet, "/settings"},
	{http.MethodPost, "/settings/profile"},
	{http.MethodPost, "/settings/password"},
	{http.MethodPost, "/settings/notifications/add"},
	{http.MethodPost, "/settings/notifications/delete"},
	{http.MethodPost, "/settings/oauth/x/unlink"},

	// RequireSuperAdmin
	{http.MethodGet, "/admin"},
	{http.MethodGet, "/admin/tenants"},
	{http.MethodPost, "/admin/tenants"},
	{http.MethodPost, "/admin/tenants/acme/delete"},
	{http.MethodGet, "/admin/tenants/acme/users"},
	{http.MethodPost, "/admin/tenants/acme/users"},
	{http.MethodGet, "/admin/tenants/acme/users/x/edit"},
	{http.MethodPost, "/admin/tenants/acme/users/x/edit"},
	{http.MethodPost, "/admin/tenants/acme/users/x/send-reset"},
	{http.MethodPost, "/admin/tenants/acme/users/x/toggle-admin"},
	{http.MethodPost, "/admin/tenants/acme/users/x/delete"},
	{http.MethodGet, "/admin/devices"},
	{http.MethodPost, "/admin/devices/bulk"},
	{http.MethodPost, "/admin/devices/x/reassign"},
	{http.MethodPost, "/admin/devices/x/delete"},
	{http.MethodGet, "/admin/devices/pair"},
	{http.MethodPost, "/admin/devices/x/pair/issue"},
	{http.MethodPost, "/admin/devices/x/pair/revoke"},
	{http.MethodGet, "/admin/ca.crt"},
	{http.MethodGet, "/admin/mqtt"},
	{http.MethodGet, "/admin/mqtt/ws"},
	{http.MethodGet, "/admin/waitlist"},
	{http.MethodPost, "/admin/waitlist/x/convert"},
	{http.MethodPost, "/admin/waitlist/x/delete"},
	{http.MethodGet, "/admin/devices/x/config"},
	{http.MethodPost, "/admin/devices/x/config/cmd"},
	{http.MethodGet, "/admin/devices/x/config/cmd/result"},
	{http.MethodPost, "/admin/devices/x/config/write"},
	{http.MethodPost, "/admin/devices/x/config/snapshot"},
	{http.MethodGet, "/admin/devices/x/config/history"},
	{http.MethodGet, "/admin/devices/x/secrets"},
	{http.MethodPost, "/admin/devices/x/secrets/set"},
	{http.MethodPost, "/admin/impersonate/acme"},
	{http.MethodPost, "/admin/impersonate"},
	{http.MethodGet, "/admin/debug"},
}

// newMuxOnlyServer builds a Server with just the mux + routes wired. No
// services / templates: every assertion here hits the auth gate, which
// rejects before any handler body runs, so the nil deps are never touched.
func newMuxOnlyServer() *Server {
	s := &Server{mux: http.NewServeMux()}
	s.routes()
	return s
}

func TestGatedRoutes_RejectAnonymous(t *testing.T) {
	s := newMuxOnlyServer()
	for _, rt := range gatedRoutes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(rt.method, rt.path, nil)
			s.mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusFound {
				t.Fatalf("anonymous %s %s = %d, want 302 (missing auth wrapper?)",
					rt.method, rt.path, rec.Code)
			}
			if loc := rec.Header().Get("Location"); loc != "/login" {
				t.Errorf("Location = %q, want /login", loc)
			}
		})
	}
}
