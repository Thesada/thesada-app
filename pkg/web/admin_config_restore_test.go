package web

import (
	"strings"
	"testing"
)

// A config.json with blanked secrets never reaches the device (#85).
func TestConfigWriteRefusal(t *testing.T) {
	blank := `{"mqtt":{"password":""}}`
	for _, p := range []string{"config.json", "/config.json"} {
		if msg := configWriteRefusal(p, blank); !strings.Contains(msg, "secret") {
			t.Errorf("%s with blank secrets: %q, want a refusal", p, msg)
		}
	}
	if msg := configWriteRefusal("/config.json", `{"mqtt":{"password":"x"}}`); msg != "" {
		t.Errorf("config with secrets refused: %q", msg)
	}
	if msg := configWriteRefusal("/scripts/main.lua", blank); msg != "" {
		t.Errorf("script refused: %q", msg)
	}
	if msg := configWriteRefusal("/config.json", `{"mqtt":`); msg == "" {
		t.Error("unparseable config.json must be refused")
	}
}
