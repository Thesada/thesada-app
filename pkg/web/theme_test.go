package web

import (
	"bytes"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service"
)

// theme.js runs in head before the stylesheet, so the first paint already
// has the stored theme. A deferred or late script flashes the wrong one.
func TestLayoutLoadsThemeBeforeStylesheet(t *testing.T) {
	raw, err := fs.ReadFile(templatesFS, "templates/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	tag := `<script src="/static/js/theme.js"></script>`
	i, css := strings.Index(body, tag), strings.Index(body, `<link rel="stylesheet" href="/static/css/app.css">`)
	if i < 0 || css < 0 || i > css || i > strings.Index(body, "</head>") {
		t.Error("layout must load theme.js synchronously in head before app.css")
	}
	if !strings.Contains(body, `<header class="theme-fixed `) || !strings.Contains(body, `<nav class="theme-follow `) {
		t.Error("header bar must keep its dark palette while its nav follows the theme")
	}
}

func TestOfflinePageAndShellCarryTheme(t *testing.T) {
	page, err := staticFS.ReadFile("static/offline.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(page), `<script src="/static/js/theme.js"></script>`) {
		t.Error("offline page must load theme.js")
	}
	sw, err := staticFS.ReadFile("static/sw.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sw), `"/static/js/theme.js"`) {
		t.Error("service worker shell must cache theme.js")
	}
	if strings.Contains(string(sw), `"thesada-shell-v2"`) {
		t.Error("shell cache name must change when the shell list changes")
	}
}

func TestSettingsOffersThreeThemes(t *testing.T) {
	s := &Server{}
	s.parseTemplates()
	var buf bytes.Buffer
	data := map[string]interface{}{"User": &service.User{ID: uuid.New(), TenantID: "acme"}, "CSRFToken": "tok", "CSPNonce": "n"}
	if err := s.templates["settings.html"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, c := range []string{"light", "dark", "system"} {
		if !strings.Contains(out, `data-act="setTheme" data-arg="`+c+`" data-theme-option="`+c+`"`) {
			t.Errorf("settings missing the %s theme button", c)
		}
	}
}

func TestDarkPaletteFlipsTokens(t *testing.T) {
	raw, err := os.ReadFile("../../assets/css/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(raw)
	for _, need := range []string{
		`[data-theme="dark"] :is(body, .theme-follow)`,
		`[data-theme="dark"] .theme-fixed`,
		"--color-white: var(--light-slate-900)",
		"--color-slate-900: var(--light-slate-100)",
		"color-scheme: dark",
	} {
		if !strings.Contains(css, need) {
			t.Errorf("app.css missing %q", need)
		}
	}
}

// Light, Dark and System persist, System follows the OS live, bad storage
// falls back to System.
func TestThemeScript(t *testing.T) {
	node := nodeOrSkip(t)
	script, err := staticFS.ReadFile("static/js/theme.js")
	if err != nil {
		t.Fatal(err)
	}
	runNodeHarness(t, node, string(script), "testdata/theme_script.js")
}
