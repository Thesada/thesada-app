package web

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service"
)

// Scripts inside a swapped block come back with the partial response's nonce,
// which the page's CSP refuses, so #device-live must carry none.
func TestDeviceLiveBlockCarriesNoScript(t *testing.T) {
	s := &Server{}
	s.parseTemplates()
	data := map[string]interface{}{
		"Device":         sampleDevice(),
		"NumericMetrics": []string{"temp/boiler"},
		"BackHref":       "/devices",
		"BackLabel":      "All devices",
		"User":           &service.User{ID: uuid.New(), TenantID: "acme"},
		"CSRFToken":      "tok",
		"CSPNonce":       "nonce",
	}
	var buf bytes.Buffer
	if err := s.templates["device-detail.html"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatal(err)
	}
	body := buf.String()
	live := divBlock(t, body, `<div id="device-live">`)
	if strings.Contains(live, "<script") {
		t.Error("#device-live contains a <script>")
	}
	if !strings.Contains(live, `id="chart-card" hx-preserve`) {
		t.Error("chart card must be hx-preserve so a live swap keeps the drawn chart")
	}
	if !strings.Contains(body, "/chart.json?metric=") {
		t.Error("chart script missing from the page")
	}
}

// divBlock returns the element that opens with start, through its matching </div>.
func divBlock(t *testing.T, html, start string) string {
	t.Helper()
	i := strings.Index(html, start)
	if i < 0 {
		t.Fatalf("%s not found", start)
	}
	depth := 0
	for j := i; j < len(html); j++ {
		switch {
		case strings.HasPrefix(html[j:], "<div"):
			depth++
		case strings.HasPrefix(html[j:], "</div>"):
			depth--
			if depth == 0 {
				return html[i : j+len("</div>")]
			}
		}
	}
	t.Fatalf("%s never closes", start)
	return ""
}
