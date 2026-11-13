package web

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// inlineHandler matches an on* attribute inside a tag, which the nonce CSP blocks.
var inlineHandler = regexp.MustCompile(`(?is)<[a-z][^<>]*\son[a-z]+\s*=`)

// Every template wires events through the nonced layout listeners
// (data-confirm, data-submit, data-act, data-autosubmit), never inline.
func TestTemplatesCarryNoInlineHandlers(t *testing.T) {
	entries, err := fs.ReadDir(templatesFS, "templates")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		raw, err := templatesFS.ReadFile("templates/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range inlineHandler.FindAllString(string(raw), -1) {
			t.Errorf("%s: inline handler the CSP blocks: %q", e.Name(), m)
		}
	}
}

// The enabled toggle submits on change and Remove asks first, both through
// the nonced layout listeners, since the CSP blocks inline handlers.
func TestLayoutFormListenersAutosubmitAndConfirm(t *testing.T) {
	runScriptHarness(t, "admin-mqtt.html", map[string]interface{}{
		"DefaultPattern": "thesada/acme/#", "TopicRoot": "thesada",
	}, "data-autosubmit", "testdata/form_events_script.js")
}
