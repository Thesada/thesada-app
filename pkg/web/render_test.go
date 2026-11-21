package web

import (
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"thesada.app/app/pkg/buildinfo"
)

// A template that fails part way must answer a clean 500, not a 200 carrying
// the half page it had written.
func TestRender_MidTemplateErrorIsCleanServerError(t *testing.T) {
	broken := template.Must(template.New("layout.html").Funcs(template.FuncMap{
		"fail": func() (string, error) { return "", errors.New("boom") },
	}).Parse(`{{define "layout"}}<p>half a page</p>{{fail}}{{end}}`))
	s := &Server{templates: map[string]*template.Template{"broken.html": broken}}

	rec := httptest.NewRecorder()
	s.render(rec, httptest.NewRequest(http.MethodGet, "/", nil), "broken.html", nil)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "half a page") {
		t.Fatalf("body carries the partial render: %q", rec.Body.String())
	}
}

// A page rendered with an error status still says it is HTML.
func TestRenderStatus_KeepsContentType(t *testing.T) {
	s := &Server{}
	s.parseTemplates()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/devices/claim", strings.NewReader("device_id=abc"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.claimError(rec, req, "wrong code")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if ct := rec.Result().Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want text/html; charset=utf-8", ct)
	}
	if !strings.Contains(rec.Body.String(), "wrong code") {
		t.Fatal("error message not rendered")
	}
}

// Every ?err= code the settings page is sent back with has words on the page.
func TestSettingsRendersIdentityNotFound(t *testing.T) {
	s := &Server{}
	s.parseTemplates()
	var buf strings.Builder
	data := map[string]interface{}{"OAuthError": "identity_not_found", "SaveError": "identity_not_found"}
	if err := s.templates["settings.html"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "already removed") {
		t.Fatal("identity_not_found renders no message")
	}
}

// An admin viewing another tenant is told alert rules stay in their home tenant (#81).
func TestSettingsSaysAlertsStayHomeWhileViewing(t *testing.T) {
	s := &Server{}
	s.parseTemplates()
	render := func(effective string) string {
		var buf strings.Builder
		data := map[string]interface{}{"EffectiveTenantID": effective, "HomeTenantID": "default"}
		if err := s.templates["settings.html"].ExecuteTemplate(&buf, "layout", data); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	if got := render("bearberry-humpf"); !strings.Contains(got, "only cover devices in default") {
		t.Fatal("viewing another tenant gives no alert-scope note")
	}
	if got := render("default"); strings.Contains(got, "only cover devices in") {
		t.Fatal("note shows in the home tenant")
	}
}

// The footer names the running build, never a placeholder.
func TestRender_FooterShowsBuildVersion(t *testing.T) {
	old := buildinfo.Version
	buildinfo.Version = "26.99.1"
	t.Cleanup(func() { buildinfo.Version = old })
	s := &Server{}
	s.parseTemplates()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/devices/claim", strings.NewReader("device_id=abc"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.claimError(rec, req, "wrong code")

	body := rec.Body.String()
	if !strings.Contains(body, "thesada-app 26.99.1") || strings.Contains(body, "dev build") {
		t.Fatalf("footer does not show the build version: %q", body[strings.LastIndex(body, "<footer"):])
	}
}
