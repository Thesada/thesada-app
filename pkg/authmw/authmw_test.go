// Authmw middleware coverage. RequireAuth + RequireSuperAdmin
// are the gate every /admin and /api/v1 route inherits, so testing the
// gate once covers the auth-fail half of every gated handler.
package authmw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service"
)

// withSession returns a request whose context carries sess. Mirrors what
// Middleware does on a valid cookie. Used by tests so they don't need a
// real AuthService / DB.
func withSession(r *http.Request, sess *service.Session) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), sessionKey, sess))
}

func newSession(isSuper bool, impersonate *string) *service.Session {
	return &service.Session{
		ID: uuid.New(),
		User: &service.User{
			ID:           uuid.New(),
			TenantID:     "acme",
			Email:        "u@example.com",
			IsSuperAdmin: isSuper,
		},
		ImpersonatedTenantID: impersonate,
	}
}

// nextCalled returns a handler that records whether it was invoked.
func nextCalled(called *bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		*called = true
		w.WriteHeader(http.StatusOK)
	}
}

func TestRequireAuth_Anonymous_RedirectsToLogin(t *testing.T) {
	called := false
	h := RequireAuth(nextCalled(&called))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/devices", nil)
	h(rec, req)
	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want %q", loc, "/login")
	}
	if called {
		t.Error("next should not have been called for anonymous request")
	}
}

func TestRequireAuth_Authenticated_PassesThrough(t *testing.T) {
	called := false
	h := RequireAuth(nextCalled(&called))
	rec := httptest.NewRecorder()
	req := withSession(httptest.NewRequest(http.MethodGet, "/devices", nil), newSession(false, nil))
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !called {
		t.Error("next should have been called")
	}
}

func TestRequireSuperAdmin_Anonymous_RedirectsToLogin(t *testing.T) {
	called := false
	h := RequireSuperAdmin(nextCalled(&called))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	h(rec, req)
	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want %d (redirect to login)", rec.Code, http.StatusFound)
	}
	if called {
		t.Error("next should not have been called")
	}
}

func TestRequireSuperAdmin_RegularUser_404(t *testing.T) {
	// Per authmw.go: 404 (not 403) so the admin surface does not advertise
	// its existence to tenant-scoped users.
	called := false
	h := RequireSuperAdmin(nextCalled(&called))
	rec := httptest.NewRecorder()
	req := withSession(httptest.NewRequest(http.MethodGet, "/admin", nil), newSession(false, nil))
	h(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if called {
		t.Error("next should not have been called for non-super-admin")
	}
}

func TestRequireSuperAdmin_SuperAdmin_PassesThrough(t *testing.T) {
	called := false
	h := RequireSuperAdmin(nextCalled(&called))
	rec := httptest.NewRecorder()
	req := withSession(httptest.NewRequest(http.MethodGet, "/admin", nil), newSession(true, nil))
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !called {
		t.Error("next should have been called for super-admin")
	}
}

func TestCurrentUser_NoSession(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if u := CurrentUser(r); u != nil {
		t.Errorf("CurrentUser = %+v, want nil", u)
	}
	if s := CurrentSession(r); s != nil {
		t.Errorf("CurrentSession = %+v, want nil", s)
	}
}

func TestCurrentUser_WithSession(t *testing.T) {
	sess := newSession(false, nil)
	r := withSession(httptest.NewRequest(http.MethodGet, "/", nil), sess)
	u := CurrentUser(r)
	if u == nil || u.Email != "u@example.com" {
		t.Errorf("CurrentUser = %+v, want session user", u)
	}
	if got := CurrentSession(r); got != sess {
		t.Errorf("CurrentSession mismatch")
	}
}

func TestEffectiveTenantID(t *testing.T) {
	other := "other-tenant"
	cases := []struct {
		name string
		sess *service.Session
		want string
	}{
		{"anonymous", nil, ""},
		{"regular user", newSession(false, nil), "acme"},
		{"super admin no impersonate", newSession(true, nil), "acme"},
		{"super admin impersonating", newSession(true, &other), "other-tenant"},
		{"super admin empty impersonate string", newSession(true, ptr("")), "acme"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.sess != nil {
				r = withSession(r, tc.sess)
			}
			if got := EffectiveTenantID(r); got != tc.want {
				t.Errorf("EffectiveTenantID = %q, want %q", got, tc.want)
			}
		})
	}
}

func ptr(s string) *string { return &s }
