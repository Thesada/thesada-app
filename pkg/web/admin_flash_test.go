package web

import (
	"bytes"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"thesada.app/app/pkg/service"
)

func TestAdminFlashIgnoresUnregisteredText(t *testing.T) {
	q, err := url.ParseQuery("ok=you+have+been+hacked&error=%3Cscript%3E")
	if err != nil {
		t.Fatal(err)
	}
	ok, bad := adminFlash(q)
	if ok != "" || bad != "" {
		t.Fatalf("unregistered codes must render nothing, got %q %q", ok, bad)
	}
}

func TestAdminFlashRendersRegisteredText(t *testing.T) {
	q, err := url.ParseQuery(flashAdminDeleted.query() + "&" + flashAdminEnrollReset.query())
	if err != nil {
		t.Fatal(err)
	}
	ok, bad := adminFlash(q)
	if ok == "" || bad == "" {
		t.Fatalf("registered codes must render, got %q %q", ok, bad)
	}
	if ok == "deleted" || bad == "enroll_reset_failed" {
		t.Fatal("the page must show the text, not the code")
	}
}

func TestAdminFlashRendersEveryRegisteredError(t *testing.T) {
	q, err := url.ParseQuery(flashAdminEnrollReset.query() + "&" + flashAdminBrokerLive.query() + "&error=nope")
	if err != nil {
		t.Fatal(err)
	}
	_, bad := adminFlash(q)
	want := adminFlashText["error"][flashAdminEnrollReset.code] + " " + adminFlashText["error"][flashAdminBrokerLive.code]
	if bad != want {
		t.Errorf("error text = %q, want exactly %q", bad, want)
	}
}

// An admin redirect that writes ?ok= or ?error= text by hand lands on a page
// that renders registered codes only, so the operator sees nothing. Every
// admin flash goes through a registered code's on() or query().
func TestAdminRedirectsUseRegisteredFlashCodes(t *testing.T) {
	files, err := filepath.Glob("admin*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("glob admin*.go: %v (%d files)", err, len(files))
	}
	re := regexp.MustCompile(`"[^"]*[?&](ok|error)=[^"]*"`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAll(src, -1) {
			t.Errorf("%s: hand-written flash %s, register a code in admin_flash.go", f, m)
		}
	}
}

// The user edit page shows the result of the reset mail it redirects back with.
func TestAdminUserEditRendersFlash(t *testing.T) {
	s := &Server{}
	s.parseTemplates()
	for _, f := range []adminFlashCode{flashUserResetSent, flashUserResetSMTP} {
		ok, bad := adminFlash(url.Values{f.key: {f.code}})
		data := map[string]interface{}{
			"Tenant":   service.Tenant{ID: "t"},
			"EditUser": &service.User{Email: "a@example.com"},
			"Flash":    ok,
			"FlashErr": bad,
		}
		var buf bytes.Buffer
		if err := s.templates["admin-tenant-user-edit.html"].ExecuteTemplate(&buf, "layout", data); err != nil {
			t.Fatal(err)
		}
		if want := adminFlashText[f.key][f.code]; !strings.Contains(buf.String(), want) {
			t.Errorf("%s=%s: page does not show %q", f.key, f.code, want)
		}
	}
}
