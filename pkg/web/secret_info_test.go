// Unit coverage for parsing firmware `secret.info` presence output into
// per-field device NVS state. Pure - no MQTT, no DB.
package web

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"thesada.app/app/pkg/service"
)

func TestParseSecretInfo(t *testing.T) {
	cases := []struct {
		name   string
		output []string
		want   map[string]string
	}{
		{
			name: "nvs and config/none classified",
			output: []string{
				"mqtt.password          nvs",
				"telegram.bot_token     config/none",
				"web.password           nvs",
				"wifi.ap_password       config/none",
				"wifi.password:HomeNet  nvs",
			},
			want: map[string]string{
				"mqtt.password":         "nvs",
				"telegram.bot_token":    "config",
				"web.password":          "nvs",
				"wifi.ap_password":      "config",
				"wifi.password:HomeNet": "nvs",
			},
		},
		{
			name: "ssid with spaces keeps the whole field",
			output: []string{
				"wifi.password:My Home Net nvs",
				"wifi.password:Guest 2   config/none",
			},
			want: map[string]string{
				"wifi.password:My Home Net": "nvs",
				"wifi.password:Guest 2":     "config",
			},
		},
		{
			name:   "blank and short lines ignored",
			output: []string{"", "   ", "mqtt.password nvs", "garbage"},
			want:   map[string]string{"mqtt.password": "nvs"},
		},
		{
			name:   "empty output yields empty map",
			output: nil,
			want:   map[string]string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseSecretInfo(tc.output)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parseSecretInfo() = %v, want %v", got, tc.want)
			}
		})
	}
}

// secret.info reports "config/none": the device cannot tell a config.json value
// from a blank one, so the page must not claim the value is in config.
func TestDeviceSecretsPageLabelsConfigOrNone(t *testing.T) {
	s := &Server{}
	s.parseTemplates()
	data := map[string]interface{}{
		"Device":         &service.Device{DeviceID: "d1"},
		"Fields":         []secretFieldStatus{{Field: "web.password", DevState: "config"}},
		"DeviceReported": true,
	}
	var buf bytes.Buffer
	if err := s.templates["admin-device-secrets.html"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), ">config/none</span>") {
		t.Fatal("device state badge does not say config/none")
	}
}
