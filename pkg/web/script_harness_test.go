package web

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service"
)

var inlineScript = regexp.MustCompile(`(?s)<script nonce="[^"]*">(.*?)</script>`)

// The chart script keeps only the latest response and refetches after a
// preserved live swap. Runs under node against a stub DOM in testdata.
func TestChartScriptLatestWinsAndRefetches(t *testing.T) {
	runScriptHarness(t, "device-detail.html", map[string]interface{}{
		"Device": sampleDevice(), "NumericMetrics": []string{"temp/boiler", "temp/room"}, "BackHref": "/devices", "BackLabel": "All devices",
	}, "/chart.json?metric=", "testdata/chart_script.js")
}

// The MQTT page keeps one current WebSocket: no second socket while one is
// connecting, and a replaced socket's events leave the new one alone.
func TestMqttScriptKeepsOneSocket(t *testing.T) {
	runScriptHarness(t, "admin-mqtt.html", map[string]interface{}{
		"DefaultPattern": "thesada/acme/#", "TopicRoot": "thesada",
	}, "/admin/mqtt/ws", "testdata/mqtt_script.js")
}

// runScriptHarness renders page, pulls the inline script containing marker
// and runs it under node with the harness. Skips when node is missing.
func runScriptHarness(t *testing.T, page string, data map[string]interface{}, marker, harnessPath string) {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not on PATH")
	}
	s := &Server{}
	s.parseTemplates()
	data["User"] = &service.User{ID: uuid.New(), TenantID: "acme"}
	data["CSRFToken"] = "tok"
	data["CSPNonce"] = "nonce"
	var buf bytes.Buffer
	if err := s.templates[page].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatal(err)
	}
	var script string
	for _, m := range inlineScript.FindAllStringSubmatch(buf.String(), -1) {
		if strings.Contains(m[1], marker) {
			script = m[1]
		}
	}
	if script == "" {
		t.Fatalf("script with %q not found in %s", marker, page)
	}
	// Read the harness here so go test's cache sees it change.
	harness, err := os.ReadFile(harnessPath)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "page.js")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "harness.js"), harness, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, filepath.Join(dir, "harness.js"), path).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
}
