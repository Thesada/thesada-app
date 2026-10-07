package web

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPWAManifest(t *testing.T) {
	raw, err := fs.ReadFile(staticFS, "static/manifest.webmanifest")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Name            string `json:"name"`
		Display         string `json:"display"`
		ThemeColor      string `json:"theme_color"`
		BackgroundColor string `json:"background_color"`
		StartURL        string `json:"start_url"`
		Icons           []struct {
			Src   string `json:"src"`
			Sizes string `json:"sizes"`
			Type  string `json:"type"`
		} `json:"icons"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m.Name != "thesada" || m.Display != "standalone" || m.ThemeColor != "#0f172a" {
		t.Fatalf("manifest identity = %+v", m)
	}
	if m.StartURL != "/" {
		t.Fatalf("start_url %q", m.StartURL)
	}
	if len(m.Icons) < 2 || m.Icons[0].Type != "image/png" {
		t.Fatalf("icons = %+v", m.Icons)
	}
	for _, icon := range m.Icons {
		if _, err := fs.Stat(staticFS, strings.TrimPrefix(icon.Src, "/")); err != nil {
			t.Errorf("icon %s: %v", icon.Src, err)
		}
	}
}

func TestServiceWorkerCachesShellOnly(t *testing.T) {
	raw, err := fs.ReadFile(staticFS, "static/sw.js")
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, forbidden := range []string{"/devices", "/api/", "/alerts", "/admin"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("service worker mentions %q; device data must not be cached", forbidden)
		}
	}
	if !strings.Contains(body, "/static/offline.html") {
		t.Fatal("service worker must fall back to the offline shell")
	}
	if !strings.Contains(body, "mode === \"navigate\"") && !strings.Contains(body, "mode === 'navigate'") {
		t.Fatal("service worker must treat navigations as network-only")
	}
}

func TestLayoutInstallTags(t *testing.T) {
	raw, err := fs.ReadFile(templatesFS, "templates/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, need := range []string{
		`rel="manifest"`,
		`rel="apple-touch-icon"`,
		`name="theme-color"`,
		`name="viewport"`,
		`apple-mobile-web-app-capable`,
		`serviceWorker.register("/sw.js")`,
	} {
		if !strings.Contains(body, need) {
			t.Errorf("layout missing %s", need)
		}
	}
}

func TestServiceWorkerRoute(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	s.handleServiceWorker(rec, httptest.NewRequest(http.MethodGet, "/sw.js", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/javascript" {
		t.Fatalf("content-type %q", ct)
	}
	if got := rec.Header().Get("Service-Worker-Allowed"); got != "/" {
		t.Fatalf("scope header %q", got)
	}
}
