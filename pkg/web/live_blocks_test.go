package web

import (
	"bytes"
	"io/fs"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service"
)

// A live block listens with from:body, so the socket bridge must dispatch on
// body: an event dispatched on document never reaches a body listener.
func TestLiveBlocksHearTheSocket(t *testing.T) {
	raw, err := fs.ReadFile(templatesFS, "templates/layout.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `document.body.dispatchEvent(new CustomEvent("thesada:event"`) {
		t.Fatal("layout must dispatch thesada:event on document.body")
	}
	for _, page := range []string{"devices.html", "alerts.html", "device-detail.html"} {
		raw, err := fs.ReadFile(templatesFS, "templates/"+page)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), `hx-trigger="thesada:event from:body`) {
			t.Errorf("%s: live block must listen for thesada:event from:body", page)
		}
	}
}

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

// A live swap rebuilds its whole block, so every <details> and scroll box in
// one needs a unique data-keep key for the layout to carry its state over.
func TestLiveBlocksKeyTheirState(t *testing.T) {
	s := &Server{}
	s.parseTemplates()
	type row struct {
		Metric     string
		ValueNum   *float64
		ValueText  *string
		ReceivedAt time.Time
	}
	v := 21.5
	now := time.Now().UTC()
	rows := []row{
		{Metric: "uptime", ValueNum: &v, ReceivedAt: now},
		{Metric: "battery/percent", ValueNum: &v, ReceivedAt: now},
		{Metric: "wifi/rssi", ValueNum: &v, ReceivedAt: now},
	}
	user := &service.User{ID: uuid.New(), TenantID: "acme"}
	dev := sampleDevice()
	cases := []struct {
		page, block string
		data        map[string]interface{}
		minKeyed    int
	}{
		{"device-detail.html", `<div id="device-live">`, map[string]interface{}{
			"Device": dev, "Latest": rows, "Telemetry": rows, "NumericMetrics": []string{"uptime"},
		}, 7},
		{"devices.html", `<div id="devices-live">`, map[string]interface{}{
			"Devices": []service.Device{dev},
		}, 1},
		{"alerts.html", `<div id="alerts-live">`, map[string]interface{}{
			"Alerts": []service.TenantAlertRow{{DevicePK: dev.ID, DeviceID: dev.DeviceID, Severity: "warn", Message: "m", ReceivedAt: now}},
		}, 0},
	}
	tag := regexp.MustCompile(`<(details|div)\b[^>]*>`)
	key := regexp.MustCompile(`data-keep="([^"]+)"`)
	scroller := regexp.MustCompile(`\boverflow-(?:[xy]-)?(?:auto|scroll)\b`)
	for _, c := range cases {
		c.data["User"], c.data["CSRFToken"], c.data["CSPNonce"] = user, "tok", "nonce"
		var buf bytes.Buffer
		if err := s.templates[c.page].ExecuteTemplate(&buf, "layout", c.data); err != nil {
			t.Fatalf("%s: %v", c.page, err)
		}
		seen := map[string]bool{}
		for _, m := range tag.FindAllStringSubmatch(divBlock(t, buf.String(), c.block), -1) {
			if m[1] != "details" && !scroller.MatchString(m[0]) {
				continue
			}
			k := key.FindStringSubmatch(m[0])
			switch {
			case k == nil:
				t.Errorf("%s: %s has no data-keep", c.page, m[0])
			case seen[k[1]]:
				t.Errorf("%s: data-keep %q is not unique", c.page, k[1])
			default:
				seen[k[1]] = true
			}
		}
		if len(seen) < c.minKeyed {
			t.Errorf("%s: %d keyed elements, want at least %d", c.page, len(seen), c.minKeyed)
		}
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
