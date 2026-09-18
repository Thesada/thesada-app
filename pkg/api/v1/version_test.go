// Contracts for GET /version: public, unauthenticated JSON with version,
// commit, and build_time.
// SPDX-License-Identifier: AGPL-3.0-only
package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"thesada.app/app/pkg/buildinfo"
)

func TestVersion_PublicJSON(t *testing.T) {
	s := &Server{mux: http.NewServeMux()}
	s.routes()
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/version", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("version = %d, want 200", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, k := range []string{"version", "commit", "build_time"} {
		if body[k] == "" {
			t.Fatalf("missing %q in %v", k, body)
		}
	}
	// Defaults without ldflags.
	if body["version"] != "dev" || body["commit"] != "unknown" {
		t.Fatalf("defaults = %v, want version=dev commit=unknown", body)
	}
}

func TestStripReleaseTagPrefix(t *testing.T) {
	cases := []struct{ in, want string }{
		{"26.09.1", "26.09.1"},
		{"v26.09.1", "26.09.1"},
		{"dev", "dev"},
		{"", ""},
	}
	for _, c := range cases {
		if got := stripReleaseTagPrefix(c.in); got != c.want {
			t.Fatalf("stripReleaseTagPrefix(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestVersion_UsesBuildinfo(t *testing.T) {
	prevV, prevC, prevT := buildinfo.Version, buildinfo.Commit, buildinfo.BuildTime
	t.Cleanup(func() {
		buildinfo.Version, buildinfo.Commit, buildinfo.BuildTime = prevV, prevC, prevT
	})
	buildinfo.Version = "v26.09.1"
	buildinfo.Commit = "abc1234"
	buildinfo.BuildTime = "2026-09-17T00:00:00Z"

	s := &Server{mux: http.NewServeMux()}
	s.routes()
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/version", nil))
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if body["version"] != "26.09.1" {
		t.Fatalf("version = %q, want 26.09.1 (v stripped)", body["version"])
	}
	if body["commit"] != "abc1234" || body["build_time"] != "2026-09-17T00:00:00Z" {
		t.Fatalf("body = %v", body)
	}
}
