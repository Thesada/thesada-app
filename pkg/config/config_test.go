package config

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// TestValidate_CookieSecretFloor pins the security contract that a weak session
// signing secret aborts startup by default and only proceeds with the explicit
// THESADA_ALLOW_WEAK_SECRET override.
func TestValidate_CookieSecretFloor(t *testing.T) {
	const strong = "0123456789abcdef0123456789abcdef" // 32 bytes
	const weak = "short"

	cases := []struct {
		name     string
		secret   string
		override string
		wantErr  bool
	}{
		{"empty_is_required", "", "", true},
		{"weak_without_override_fails", weak, "", true},
		{"weak_with_override_passes", weak, "1", false},
		{"weak_with_false_override_fails", weak, "0", true},
		{"strong_passes", strong, "", false},
		{"strong_ignores_override", strong, "1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("THESADA_ALLOW_WEAK_SECRET", tc.override)
			c := &Config{DatabaseURL: "postgres://x", CookieSecret: tc.secret}
			err := c.validate()
			if tc.wantErr && err == nil {
				t.Fatalf("validate() = nil, want error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validate() = %v, want nil", err)
			}
		})
	}
}

// TestValidate_WeakSecretErrorIsActionable checks the failure names the override
// so an operator hitting it at boot knows the escape hatch without reading code.
func TestValidate_WeakSecretErrorIsActionable(t *testing.T) {
	t.Setenv("THESADA_ALLOW_WEAK_SECRET", "")
	c := &Config{DatabaseURL: "postgres://x", CookieSecret: "short"}
	err := c.validate()
	if err == nil {
		t.Fatal("validate() = nil, want error")
	}
	if !strings.Contains(err.Error(), "THESADA_ALLOW_WEAK_SECRET") {
		t.Errorf("error %q does not name the override env var", err.Error())
	}
}

// TestParseTrustedProxies covers IPs, CIDRs, empty, and loud failure on junk.
func TestParseTrustedProxies(t *testing.T) {
	if got, err := parseTrustedProxies(""); err != nil || got != nil {
		t.Errorf("empty = %v / %v, want nil/nil", got, err)
	}
	got, err := parseTrustedProxies(" 10.0.0.0/8 , 192.168.66.10 ")
	if err != nil {
		t.Fatalf("valid list errored: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d nets, want 2", len(got))
	}
	if !got[0].Contains(net.ParseIP("10.1.2.3")) {
		t.Error("CIDR 10.0.0.0/8 should contain 10.1.2.3")
	}
	if !got[1].Contains(net.ParseIP("192.168.66.10")) || got[1].Contains(net.ParseIP("192.168.66.11")) {
		t.Error("bare IP should parse to a single-host net")
	}
	for _, bad := range []string{"garbage", "10.0.0.0/99", "999.1.1.1", ",", "10.0.0.10,", "10.0.0.10,,10.0.0.11"} {
		if _, err := parseTrustedProxies(bad); err == nil {
			t.Errorf("parseTrustedProxies(%q) = nil error, want failure", bad)
		}
	}
}

// TestEnvBool covers the truthy set used by override flags.
func TestEnvBool(t *testing.T) {
	truthy := []string{"1", "true", "TRUE", "Yes", "on"}
	falsy := []string{"", "0", "false", "no", "off", "maybe"}
	for _, v := range truthy {
		t.Setenv("THESADA_TEST_BOOL", v)
		if !envBool("THESADA_TEST_BOOL") {
			t.Errorf("envBool(%q) = false, want true", v)
		}
	}
	for _, v := range falsy {
		t.Setenv("THESADA_TEST_BOOL", v)
		if envBool("THESADA_TEST_BOOL") {
			t.Errorf("envBool(%q) = true, want false", v)
		}
	}
}

func unsetEnv(t *testing.T, key string) {
	t.Helper()
	prev, had := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("unset %s: %v", key, err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(key, prev)
			return
		}
		_ = os.Unsetenv(key)
	})
}

// TestEnvOrInt pins the silent fallback: a missing or unparseable value
// returns the fallback instead of failing startup.
func TestEnvOrInt(t *testing.T) {
	const key = "THESADA_TEST_INT"
	const fallback = 7
	unsetEnv(t, key)
	if got := envOrInt(key, fallback); got != fallback {
		t.Errorf("unset = %d, want %d", got, fallback)
	}
	t.Setenv(key, "42")
	if got := envOrInt(key, fallback); got != 42 {
		t.Errorf("valid = %d, want 42", got)
	}
	t.Setenv(key, "12x")
	if got := envOrInt(key, fallback); got != fallback {
		t.Errorf("malformed = %d, want fallback %d", got, fallback)
	}
}

// TestEnvOrDuration pins the same fallback, including a bare number with no
// unit, which time.ParseDuration rejects.
func TestEnvOrDuration(t *testing.T) {
	const key = "THESADA_TEST_DURATION"
	fallback := 5 * time.Second
	unsetEnv(t, key)
	if got := envOrDuration(key, fallback); got != fallback {
		t.Errorf("unset = %s, want %s", got, fallback)
	}
	t.Setenv(key, "2m")
	if got := envOrDuration(key, fallback); got != 2*time.Minute {
		t.Errorf("valid = %s, want 2m", got)
	}
	t.Setenv(key, "nope")
	if got := envOrDuration(key, fallback); got != fallback {
		t.Errorf("malformed = %s, want fallback %s", got, fallback)
	}
	t.Setenv(key, "30")
	if got := envOrDuration(key, fallback); got != fallback {
		t.Errorf("bare number = %s, want fallback %s", got, fallback)
	}
}

func TestDeviceBrokerHostIgnoresTheAppURL(t *testing.T) {
	c := &Config{MQTTBrokerURL: "tls://mosquitto:8883", MQTTDeviceHost: "mqtt.example.com"}
	if got := c.DeviceBrokerHost(); got != "mqtt.example.com" {
		t.Fatalf("device host = %q", got)
	}
	if got := c.BrokerHost(); got != "mosquitto" {
		t.Fatalf("app host = %q, the internal URL must stay as it is", got)
	}
	c.MQTTDeviceHost = ""
	if got := c.DeviceBrokerHost(); got != "" {
		t.Fatalf("unset device host = %q, want empty", got)
	}
	c.MQTTDeviceHost = "mqtt.example.com:8884"
	if got := c.DeviceBrokerHost(); got != "" {
		t.Fatalf("a host with a port = %q, want empty", got)
	}
	if got := (*Config)(nil).DeviceBrokerHost(); got != "" {
		t.Fatalf("nil config = %q", got)
	}
}
