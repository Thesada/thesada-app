package web

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service"
)

func TestSortKeys(t *testing.T) {
	if sortUnix(nil) != "" || sortInt64(nil) != "" || sortUptime(nil, nil) != "" {
		t.Fatal("unset samples must sort last")
	}
	when := time.Unix(1_700_000_000, 0).UTC()
	if sortUnix(&when) != "1700000000" || sortUnixTime(when) != "1700000000" {
		t.Fatalf("unix key %q %q", sortUnix(&when), sortUnixTime(when))
	}
	secs := int64(30)
	if sortUptime(&secs, &when) == "" {
		t.Fatal("uptime key empty")
	}
}

func sampleDevice() service.Device {
	now := time.Now().UTC().Truncate(time.Second)
	up := int64(90)
	owner := uuid.New()
	name := "pump"
	hw := "esp32"
	fw := "1.2.3"
	topic := "thesada/acme/dev"
	heap := int64(1000)
	rssi := int64(-40)
	return service.Device{
		ID:                uuid.New(),
		TenantID:          "acme",
		OwnerUserID:       &owner,
		DeviceID:          "thesada-aabb",
		DisplayName:       &name,
		HardwareType:      &hw,
		FirmwareVersion:   &fw,
		LastSeenAt:        &now,
		PairedAt:          &now,
		MQTTTopicPrefix:   &topic,
		CreatedAt:         now,
		LastUptimeSeconds: &up,
		LastUptimeAt:      &now,
		LastHeapFree:      &heap,
		LastRSSI:          &rssi,
	}
}

func TestDevicesTableRendersBothViews(t *testing.T) {
	s := &Server{}
	s.parseTemplates()
	dev := sampleDevice()
	user := &service.User{ID: uuid.New(), TenantID: "acme"}
	base := map[string]interface{}{
		"Devices":   []service.Device{dev},
		"User":      user,
		"CSRFToken": "tok",
		"CSPNonce":  "nonce",
	}
	for _, page := range []string{"devices.html", "admin-devices.html"} {
		data := map[string]interface{}{}
		for k, v := range base {
			data[k] = v
		}
		if page == "admin-devices.html" {
			data["Tenants"] = []service.Tenant{{ID: "acme"}}
		}
		var buf bytes.Buffer
		if err := s.templates[page].ExecuteTemplate(&buf, "layout", data); err != nil {
			t.Fatalf("%s: %v", page, err)
		}
		body := buf.String()
		for _, want := range []string{
			"/static/js/devices-table.js",
			"data-devices-table=",
			"data-devices-filter=",
			"data-col=\"heap\"",
			"data-sort=\"-40\"",
			"thesada-aabb",
			"esp32",
			">live<",
			`data-freshness="`,
			`data-live-ms="300000"`,
			`data-offline-ms="900000"`,
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s missing %q", page, want)
			}
		}
	}
}
