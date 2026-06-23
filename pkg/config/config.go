// Package config loads runtime configuration from environment variables.
// No config library, just os.Getenv with sensible defaults.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the full runtime configuration for thesada-app.
// All fields are populated from environment variables in Load.
type Config struct {
	HTTPAddr    string
	DatabaseURL string

	// DatabaseURLAdmin (BYPASSRLS) and DatabaseURLMQTT (NOBYPASSRLS, ingest only)
	// default to DatabaseURL so a single-role deployment still works.
	DatabaseURLAdmin string
	DatabaseURLMQTT  string

	MQTTBrokerURL string // e.g. tls://mqtt.thesada.app:8883
	MQTTUsername  string
	MQTTPassword  string
	MQTTClientID  string
	MQTTTopicRoot string // default "thesada"

	SMTPHost     string
	SMTPPort     string
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string

	TelegramBotToken string

	BaseURL      string // public base URL for magic links, e.g. https://app.example.com
	CookieSecret string // signs session cookies, must be >= 32 bytes
	AdminEmail   string // if set, bootstraps this user as admin on startup

	// TrustedProxies are peer networks whose X-Forwarded-For is honoured for
	// client-IP resolution (logging, per-IP rate limit). Empty = use RemoteAddr.
	TrustedProxies []*net.IPNet

	ConfigSnapshotRetention int    // max snapshots per device+path, default 100
	CADir                   string // directory for CA keypair, default /etc/thesada-app/ca

	// CAKeyPassphrase encrypts the on-disk CA key (AES-256-GCM/scrypt envelope).
	// Empty = plaintext PEM + startup warning. Source from systemd Credential or sealed env.
	CAKeyPassphrase string

	// CLIRequestTimeout bounds the MQTT CLI response goroutine; generous to cover
	// SIM7080 cellular backoff (up to 40 s) plus broker RTT. Default 120s.
	CLIRequestTimeout time.Duration
}

// Load reads all THESADA_* environment variables into a Config.
// in: none (reads os.Environ). out: *Config or error if a required var is missing.
func Load() (*Config, error) {
	c := &Config{
		HTTPAddr:                envOr("THESADA_HTTP_ADDR", ":8080"),
		DatabaseURL:             os.Getenv("THESADA_DATABASE_URL"),
		DatabaseURLAdmin:        envOr("THESADA_DATABASE_URL_ADMIN", os.Getenv("THESADA_DATABASE_URL")),
		DatabaseURLMQTT:         envOr("THESADA_DATABASE_URL_MQTT", os.Getenv("THESADA_DATABASE_URL")),
		MQTTBrokerURL:           os.Getenv("THESADA_MQTT_URL"),
		MQTTUsername:            os.Getenv("THESADA_MQTT_USER"),
		MQTTPassword:            os.Getenv("THESADA_MQTT_PASS"),
		MQTTClientID:            envOr("THESADA_MQTT_CLIENT_ID", "thesada-app"),
		MQTTTopicRoot:           envOr("THESADA_MQTT_TOPIC_ROOT", "thesada"),
		SMTPHost:                os.Getenv("THESADA_SMTP_HOST"),
		SMTPPort:                envOr("THESADA_SMTP_PORT", "587"),
		SMTPUsername:            os.Getenv("THESADA_SMTP_USER"),
		SMTPPassword:            os.Getenv("THESADA_SMTP_PASS"),
		SMTPFrom:                os.Getenv("THESADA_SMTP_FROM"),
		TelegramBotToken:        os.Getenv("THESADA_TELEGRAM_BOT_TOKEN"),
		BaseURL:                 envOr("THESADA_BASE_URL", "http://localhost:8080"),
		CookieSecret:            os.Getenv("THESADA_COOKIE_SECRET"),
		AdminEmail:              os.Getenv("THESADA_ADMIN_EMAIL"),
		ConfigSnapshotRetention: envOrInt("THESADA_CONFIG_SNAPSHOT_RETENTION", 100),
		CADir:                   envOr("THESADA_CA_DIR", "/opt/thesada-app/ca"),
		CAKeyPassphrase:         os.Getenv("THESADA_CA_KEY_PASSPHRASE"),
		CLIRequestTimeout:       envOrDuration("THESADA_CLI_REQUEST_TIMEOUT", 120*time.Second),
	}
	tp, err := parseTrustedProxies(os.Getenv("THESADA_TRUSTED_PROXIES"))
	if err != nil {
		return nil, err
	}
	c.TrustedProxies = tp
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// parseTrustedProxies parses a comma-separated list of IPs and CIDRs into
// networks; a bare IP becomes a single-host net. Loud failure on a bad entry.
// in: env value. out: networks (nil when empty), error.
func parseTrustedProxies(s string) ([]*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var nets []*net.IPNet
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			_, n, err := net.ParseCIDR(part)
			if err != nil {
				return nil, fmt.Errorf("THESADA_TRUSTED_PROXIES: invalid CIDR %q: %w", part, err)
			}
			nets = append(nets, n)
			continue
		}
		ip := net.ParseIP(part)
		if ip == nil {
			return nil, fmt.Errorf("THESADA_TRUSTED_PROXIES: invalid IP %q", part)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return nets, nil
}

// validate checks that all required fields are populated.
// in: receiver. out: error describing the first missing field, or nil.
func (c *Config) validate() error {
	if c.DatabaseURL == "" {
		return errors.New("THESADA_DATABASE_URL is required")
	}
	if c.CookieSecret == "" {
		return errors.New("THESADA_COOKIE_SECRET is required")
	}
	if l := len(c.CookieSecret); l < minCookieSecretLen {
		// Safe by default: abort unless an operator explicitly opts a known-weak
		// secret back in (e.g. to boot an old deployment while rotating).
		if !envBool("THESADA_ALLOW_WEAK_SECRET") {
			return fmt.Errorf("THESADA_COOKIE_SECRET is %d bytes, want >= %d; rotate it or set THESADA_ALLOW_WEAK_SECRET=1 to override", l, minCookieSecretLen)
		}
		slog.Warn("config.weak_cookie_secret", "len", l, "want_min", minCookieSecretLen, "override", "THESADA_ALLOW_WEAK_SECRET")
	}
	return nil
}

// minCookieSecretLen is the minimum byte length for the session signing secret;
// shorter aborts startup unless THESADA_ALLOW_WEAK_SECRET is set.
const minCookieSecretLen = 32

// envOr returns the env var if set and non-empty, otherwise the fallback.
// in: env key, fallback string. out: resolved string.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// envBool reports whether the env var is set truthy (1/true/yes/on, case-insensitive).
func envBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// envOrInt returns the env var parsed as int, or the fallback on missing/bad value.
// in: env key, fallback int. out: resolved int.
func envOrInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

// envOrDuration returns the env var parsed as a Go duration string
// (e.g. "120s", "2m"), or the fallback on missing/bad value.
// in: env key, fallback duration. out: resolved duration.
func envOrDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
