// Package config loads runtime configuration from environment variables.
// No config library, just os.Getenv with sensible defaults.
package config

import (
	"errors"
	"log/slog"
	"os"
	"strconv"
	"time"
)

// Config is the full runtime configuration for thesada-app.
// All fields are populated from environment variables in Load.
type Config struct {
	HTTPAddr    string
	DatabaseURL string

	// Phase 0 of the RLS rollout. Each role maps to its own pool:
	//   DatabaseURLAdmin - thesada_app_admin role (BYPASSRLS)
	//   DatabaseURLMQTT  - thesada_app_mqtt role (NOBYPASSRLS, ingest only)
	// Defaults to DatabaseURL for back-compat so a single-role deployment
	// still works through phase 0 without infra changes.
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

	ConfigSnapshotRetention int    // max snapshots per device+path, default 100
	CADir                   string // directory for CA keypair, default /etc/thesada-app/ca

	// CAKeyPassphrase encrypts the on-disk CA private key. When empty,
	// the key file is plaintext PEM and Bootstrap emits a startup warning.
	// When non-empty, the key file is a THESADA-CAKEY-V1 encrypted
	// envelope (AES-256-GCM under scrypt-derived KEK). The passphrase
	// itself is consumed at boot and never persisted by the app; source
	// it from systemd Credential / k8s Secret / sealed env at deploy.
	CAKeyPassphrase string

	// CLIRequestTimeout bounds the goroutine that waits for a device's
	// MQTT CLI response. Generous enough to cover a SIM7080 cellular
	// fallback mid-backoff (10s -> 20s -> 40s) plus broker RTT. Frontend
	// polls until this budget plus a small grace expires. Default 120s.
	CLIRequestTimeout time.Duration
}

// Load reads all THESADA_* environment variables into a Config.
// in: none (reads os.Environ). out: *Config or error if a required var is missing.
func Load() (*Config, error) {
	c := &Config{
		HTTPAddr:         envOr("THESADA_HTTP_ADDR", ":8080"),
		DatabaseURL:      os.Getenv("THESADA_DATABASE_URL"),
		DatabaseURLAdmin: envOr("THESADA_DATABASE_URL_ADMIN", os.Getenv("THESADA_DATABASE_URL")),
		DatabaseURLMQTT:  envOr("THESADA_DATABASE_URL_MQTT", os.Getenv("THESADA_DATABASE_URL")),
		MQTTBrokerURL:    os.Getenv("THESADA_MQTT_URL"),
		MQTTUsername:     os.Getenv("THESADA_MQTT_USER"),
		MQTTPassword:     os.Getenv("THESADA_MQTT_PASS"),
		MQTTClientID:     envOr("THESADA_MQTT_CLIENT_ID", "thesada-app"),
		MQTTTopicRoot:    envOr("THESADA_MQTT_TOPIC_ROOT", "thesada"),
		SMTPHost:         os.Getenv("THESADA_SMTP_HOST"),
		SMTPPort:         envOr("THESADA_SMTP_PORT", "587"),
		SMTPUsername:     os.Getenv("THESADA_SMTP_USER"),
		SMTPPassword:     os.Getenv("THESADA_SMTP_PASS"),
		SMTPFrom:         os.Getenv("THESADA_SMTP_FROM"),
		TelegramBotToken: os.Getenv("THESADA_TELEGRAM_BOT_TOKEN"),
		BaseURL:          envOr("THESADA_BASE_URL", "http://localhost:8080"),
		CookieSecret:     os.Getenv("THESADA_COOKIE_SECRET"),
		AdminEmail:               os.Getenv("THESADA_ADMIN_EMAIL"),
		ConfigSnapshotRetention: envOrInt("THESADA_CONFIG_SNAPSHOT_RETENTION", 100),
		CADir:                   envOr("THESADA_CA_DIR", "/opt/thesada-app/ca"),
		CAKeyPassphrase:         os.Getenv("THESADA_CA_KEY_PASSPHRASE"),
		CLIRequestTimeout:       envOrDuration("THESADA_CLI_REQUEST_TIMEOUT", 120*time.Second),
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
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
		// Warn, don't fail: tightening this to a hard error could brick an
		// existing deployment on restart. Revisit once deploys are confirmed
		// compliant. See README / struct doc - 32 bytes is the documented floor.
		slog.Warn("config.weak_cookie_secret", "len", l, "want_min", minCookieSecretLen)
	}
	return nil
}

// minCookieSecretLen is the documented minimum byte length for the session
// signing secret. Shorter values warn at boot but do not block startup.
const minCookieSecretLen = 32

// envOr returns the env var if set and non-empty, otherwise the fallback.
// in: env key, fallback string. out: resolved string.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
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
