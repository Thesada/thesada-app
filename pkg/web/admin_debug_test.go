// Tests for the /admin/debug sanitizer. Confirm sensitive
// keys are masked, plain keys are not, and no secret leaks make it
// through the renderer when the full config is dumped.
package web

import (
	"strings"
	"testing"

	"thesada.app/app/pkg/config"
)

func TestSanitizeConfig_MasksSensitiveKeys(t *testing.T) {
	type oauthBlock struct {
		KanidmClientID     string
		KanidmClientSecret string
	}
	type mqttBlock struct {
		Broker string
		Token  string
	}
	type fixture struct {
		DBPassword string
		MQTT       mqttBlock
		OAuth      oauthBlock
		Hostname   string
		PublicURL  string
	}
	f := fixture{
		DBPassword: "should-be-masked-1",
		MQTT:       mqttBlock{Broker: "mqtt.thesada.app", Token: "should-be-masked-2"},
		OAuth:      oauthBlock{KanidmClientID: "client-id-public", KanidmClientSecret: "should-be-masked-3"},
		Hostname:   "host.example.com",
		PublicURL:  "https://app.thesada.io",
	}
	rows := sanitizeConfig(&f)

	got := map[string]string{}
	for _, r := range rows {
		got[r.Key] = r.Value
	}

	mustMasked := []string{"DBPassword", "MQTT.Token", "OAuth.KanidmClientSecret"}
	for _, k := range mustMasked {
		v, ok := got[k]
		if !ok {
			t.Fatalf("expected key %q in output, got %v", k, got)
		}
		if v != "***" {
			t.Errorf("%s = %q, want \"***\"", k, v)
		}
	}

	mustPlain := map[string]string{
		"MQTT.Broker":          "mqtt.thesada.app",
		"OAuth.KanidmClientID": "client-id-public",
		"Hostname":             "host.example.com",
		"PublicURL":            "https://app.thesada.io",
	}
	for k, want := range mustPlain {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}

	// Confirmed by joining the entire row set: no plaintext secret
	// substring leaks through.
	all := joinRows(rows)
	for _, leak := range []string{"should-be-masked-1", "should-be-masked-2", "should-be-masked-3"} {
		if strings.Contains(all, leak) {
			t.Errorf("plaintext secret %q leaked into rendered output: %s", leak, all)
		}
	}
}

func TestSanitizeConfig_RedactsDSNPassword(t *testing.T) {
	cfg := &config.Config{
		DatabaseURL:  "postgres://thesada:supersecret@db.internal:5432/thesada_app",
		CookieSecret: "this-should-be-masked-by-key-name",
	}
	rows := sanitizeConfig(cfg)
	got := map[string]string{}
	for _, r := range rows {
		got[r.Key] = r.Value
	}

	if got["DatabaseURL"] != "postgres://thesada:***@db.internal:5432/thesada_app" {
		t.Errorf("DatabaseURL = %q, want password redacted", got["DatabaseURL"])
	}
	if got["CookieSecret"] != "***" {
		t.Errorf("CookieSecret = %q, want \"***\"", got["CookieSecret"])
	}

	all := joinRows(rows)
	for _, leak := range []string{"supersecret", "this-should-be-masked-by-key-name"} {
		if strings.Contains(all, leak) {
			t.Errorf("plaintext secret %q leaked: %s", leak, all)
		}
	}
}

func TestSensitiveKeyRE_MatchesEnding(t *testing.T) {
	cases := map[string]bool{
		"Password":           true,
		"password":           true,
		"DBPassword":         true,
		"AuthToken":          true,
		"APIKey":             true,
		"PassPhrase":         true,
		"AWSCredential":      true,
		"Username":           false,
		"BrokerURL":          false,
		"PasswordHashEnable": false, // ends in Enable, not a sensitive suffix
		"KeyID":              false,
		// Device-config root-key fields: they end in "KEK", which "key$" does
		// not match, so they must be caught by the "kek" token. Regression for
		// the /admin/debug KEK-leak finding.
		"DeviceConfigKEK":    true,
		"DeviceConfigNewKEK": true,
	}
	for in, want := range cases {
		got := sensitiveKeyRE.MatchString(in)
		if got != want {
			t.Errorf("sensitiveKeyRE(%q) = %v, want %v", in, got, want)
		}
	}
}

// joinRows concatenates row keys + values into one string for greppable
// leak assertions.
func joinRows(rows []debugRow) string {
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(r.Key)
		b.WriteString("=")
		b.WriteString(r.Value)
		b.WriteString("\n")
	}
	return b.String()
}
