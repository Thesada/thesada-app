package web

import (
	"errors"
	"strings"
	"testing"
)

// A config.json with blanked secrets never reaches the device (#85). An empty
// WiFi password goes through only when the store knows that network as open (#88).
func TestConfigWriteRefusal(t *testing.T) {
	open := func(f string) (bool, error) { return f == "wifi.password:cafe", nil }

	blank := `{"mqtt":{"password":""}}`
	for _, p := range []string{"config.json", "/config.json"} {
		if msg := configWriteRefusal(p, blank, open); !strings.Contains(msg, "secret") {
			t.Errorf("%s with blank secrets: %q, want a refusal", p, msg)
		}
	}
	if msg := configWriteRefusal("/config.json", `{"mqtt":{"password":"x"}}`, nil); msg != "" {
		t.Errorf("config with secrets refused: %q", msg)
	}
	if msg := configWriteRefusal("/scripts/main.lua", blank, nil); msg != "" {
		t.Errorf("script refused: %q", msg)
	}
	for _, bad := range []string{`{"mqtt":`, `not json at all`, `[]`} {
		if msg := configWriteRefusal("/config.json", bad, open); msg == "" {
			t.Errorf("%q: config.json that is not one JSON object must be refused", bad)
		}
	}

	wifi := func(ssid string) string {
		return `{"wifi":{"networks":[{"ssid":"home","password":"pw"},{"ssid":"` + ssid + `","password":""}]}}`
	}
	if msg := configWriteRefusal("/config.json", wifi("cafe"), open); msg != "" {
		t.Errorf("known open network refused: %q", msg)
	}
	if msg := configWriteRefusal("/config.json", wifi("office"), open); msg == "" {
		t.Error("empty password the store does not know as open must be refused")
	}
	if msg := configWriteRefusal("/config.json", wifi("cafe"), nil); msg == "" {
		t.Error("without a store lookup every empty secret must be refused")
	}
	failing := func(string) (bool, error) { return false, errors.New("db down") }
	if msg := configWriteRefusal("/config.json", wifi("cafe"), failing); msg == "" {
		t.Error("a failed store lookup must refuse, not allow")
	}
	if msg := configWriteRefusal("/config.json", `{"wifi":{"networks":[{"password":""}]}}`, open); msg == "" {
		t.Error("empty password without an SSID must be refused")
	}
}
