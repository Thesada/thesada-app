package web

import (
	"strings"
	"testing"
)

// The config page renders text the device controls (file names, CLI output,
// relayed device errors). None of it may be concatenated into HTML unescaped,
// or a device can run script in the super-admin's session.
func TestAdminConfigEscapesDeviceText(t *testing.T) {
	raw, err := templatesFS.ReadFile("templates/admin-device-config.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(raw)
	if !strings.Contains(page, "function esc(") {
		t.Fatal("esc() helper missing")
	}
	for _, unescaped := range []string{
		`' + (resp.output || []).join(`,
		`'<pre class="font-mono text-xs text-slate-700">' +
        (resp.output`,
		`' + (e.message || e) + '`,
		`' + display + '`,
		`' + size + '`,
		`' + s.source + '`,
	} {
		if strings.Contains(page, unescaped) {
			t.Errorf("device text reaches innerHTML unescaped: %q", unescaped)
		}
	}
}
