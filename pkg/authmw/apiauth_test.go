// JSON-gate coverage. RequireAuthJSON / RequireSuperAdminJSON
// are the auth-fail half of every gated /api/v1 handler, so testing the gate
// once covers it everywhere. Reuses withSession / newSession / nextCalled from
// authmw_test.go (same package).
package authmw

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireAuthJSON_Anonymous_401(t *testing.T) {
	called := false
	h := RequireAuthJSON(nextCalled(&called))
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: got %d, want 401", rec.Code)
	}
	if called {
		t.Error("handler ran for an anonymous caller")
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type %q, want application/json", ct)
	}
}

func TestRequireAuthJSON_Authed_PassThrough(t *testing.T) {
	called := false
	h := RequireAuthJSON(nextCalled(&called))
	rec := httptest.NewRecorder()
	req := withSession(httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil), newSession(false, nil))
	h(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("authed: got %d, want 200", rec.Code)
	}
	if !called {
		t.Error("handler did not run for an authenticated caller")
	}
}

func TestRequireSuperAdminJSON(t *testing.T) {
	cases := []struct {
		name    string
		session bool
		isSuper bool
		want    int
		runs    bool
	}{
		{"anonymous", false, false, http.StatusUnauthorized, false},
		{"non-admin", true, false, http.StatusForbidden, false},
		{"super-admin", true, true, http.StatusOK, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			h := RequireSuperAdminJSON(nextCalled(&called))
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/x/pair", nil)
			if tc.session {
				req = withSession(req, newSession(tc.isSuper, nil))
			}
			h(rec, req)

			if rec.Code != tc.want {
				t.Errorf("got %d, want %d", rec.Code, tc.want)
			}
			if called != tc.runs {
				t.Errorf("handler ran=%v, want %v", called, tc.runs)
			}
		})
	}
}

func TestBearerToken(t *testing.T) {
	cases := []struct {
		header string
		want   string
	}{
		{"Bearer abc123", "abc123"},
		{"bearer abc123", "abc123"}, // case-insensitive scheme
		{"Bearer   spaced", "spaced"},
		{"Basic abc123", ""},
		{"Bearer ", ""}, // scheme only, no token
		{"", ""},
		{"abc123", ""},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if tc.header != "" {
			req.Header.Set("Authorization", tc.header)
		}
		if got := BearerToken(req); got != tc.want {
			t.Errorf("BearerToken(%q) = %q, want %q", tc.header, got, tc.want)
		}
	}
}
