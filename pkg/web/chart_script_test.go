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
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not on PATH")
	}
	s := &Server{}
	s.parseTemplates()
	data := map[string]interface{}{
		"Device": sampleDevice(), "NumericMetrics": []string{"temp/boiler", "temp/room"}, "BackHref": "/devices", "BackLabel": "All devices",
		"User": &service.User{ID: uuid.New(), TenantID: "acme"}, "CSRFToken": "tok", "CSPNonce": "nonce",
	}
	var buf bytes.Buffer
	if err := s.templates["device-detail.html"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatal(err)
	}
	var script string
	for _, m := range inlineScript.FindAllStringSubmatch(buf.String(), -1) {
		if strings.Contains(m[1], "/chart.json?metric=") {
			script = m[1]
		}
	}
	if script == "" {
		t.Fatal("chart script not found")
	}
	path := filepath.Join(t.TempDir(), "chart.js")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, "testdata/chart_script.js", path).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
}
