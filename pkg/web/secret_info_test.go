// Unit coverage for parsing firmware `secret.info` presence output into
// per-field device NVS state. Pure - no MQTT, no DB.
package web

import (
	"reflect"
	"testing"
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
