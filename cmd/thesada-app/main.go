// Command thesada-app is the single-binary entry point for the platform.
// It wires the Postgres pool, the service layer, the MQTT subscriber, the
// WebSocket hub, and the two HTTP frontends (HTMX web + JSON /api/v1/).
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"thesada.app/app/migrations"
	"thesada.app/app/pkg/alerts"
	apiv1 "thesada.app/app/pkg/api/v1"
	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/db"
	"thesada.app/app/pkg/httpsec"
	"thesada.app/app/pkg/mailer"
	"thesada.app/app/pkg/mqtt"
	"thesada.app/app/pkg/pki"
	"thesada.app/app/pkg/secrets"
	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/web"
	"thesada.app/app/pkg/ws"
)

// main is the process entry point.
// in: none. out: process exit code (0 on clean shutdown, 1 on startup failure).
func main() {
	setupLogger()

	cfg := mustLoadConfig()
	rootCtx, cancel := newSignalContext()
	defer cancel()

	// Three role-scoped pools. Phase 0: admin/mqtt URLs default to
	// DatabaseURL via config, so today every field of pools points at the
	// same underlying connection (thesada_app role). Phase 1 swaps Admin
	// to a BYPASSRLS connection string and MQTT to the dedicated ingest
	// pool without rewiring the service layer.
	pool := mustOpenDB(rootCtx, cfg.DatabaseURL)
	defer pool.Close()
	adminPool := pool
	mqttPool := pool
	if cfg.DatabaseURLAdmin != "" && cfg.DatabaseURLAdmin != cfg.DatabaseURL {
		adminPool = mustOpenDB(rootCtx, cfg.DatabaseURLAdmin)
		defer adminPool.Close()
	}
	if cfg.DatabaseURLMQTT != "" && cfg.DatabaseURLMQTT != cfg.DatabaseURL {
		mqttPool = mustOpenDB(rootCtx, cfg.DatabaseURLMQTT)
		defer mqttPool.Close()
	}
	pools := db.Pools{App: pool, Admin: adminPool, MQTT: mqttPool}

	// One-shot subcommands dispatch early and exit. The `migrate` subcommand
	// runs the embedded schema migrations against the connected
	// db, then exits 0 on success / non-zero on any failure. Wired into the
	// CI deploy workflow before the binary symlink swap so a broken
	// migration aborts the deploy with the old binary still serving.
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		if err := migrations.Apply(rootCtx, pool); err != nil {
			slog.Error("migrate failed", "err", err)
			os.Exit(1)
		}
		return
	}

	// `ca-encrypt` rewrites the on-disk CA key from plaintext PEM to the
	// THESADA-CAKEY-V1 encrypted envelope using THESADA_CA_KEY_PASSPHRASE.
	// A backup of the plaintext form lands at ca.key.plaintext.bak; the
	// operator deletes it once they have verified the encrypted load
	// works under the new passphrase. Idempotent: if the on-disk file is
	// already the encrypted envelope, the subcommand exits 0 with a log
	// line and no file movement.
	if len(os.Args) > 1 && os.Args[1] == "ca-encrypt" {
		if err := pki.EncryptKeyOnDisk(cfg.CADir, cfg.CAKeyPassphrase); err != nil {
			slog.Error("ca-encrypt failed", "dir", cfg.CADir, "err", err)
			os.Exit(1)
		}
		slog.Info("ca-encrypt done", "dir", cfg.CADir)
		return
	}

	services, err := service.New(cfg, pools)
	if err != nil {
		slog.Error("service init failed", "err", err)
		os.Exit(1)
	}

	// Service-backed one-shot subcommands. Placed after service.New (they need
	// the service layer) but before the MQTT/HTTP wiring, and each returns
	// without ever starting the server. Mirror the migrate/ca-encrypt shape:
	// log on success, os.Exit(1) on error.
	//
	// `backfill-secrets` migrates existing app-managed devices into the
	// encrypted secret store: read each device's stored config, move any
	// plaintext secrets into device_config_secrets, and re-blank the config.
	if len(os.Args) > 1 && os.Args[1] == "backfill-secrets" {
		res, err := service.BackfillDeviceSecrets(rootCtx, services.Secrets, services.Devices, services.DeviceFiles)
		if err != nil {
			slog.Error("backfill-secrets failed", "err", err)
			os.Exit(1)
		}
		slog.Info("backfill-secrets done",
			"devices_scanned", res.Devices, "devices_migrated", res.DevicesMigrated, "secrets_written", res.Secrets)
		return
	}

	// `rotate-kek` re-wraps every tenant DEK from the live root KEK
	// (THESADA_DEVICE_CONFIG_KEK) under a new one (THESADA_DEVICE_CONFIG_KEK_NEW).
	// After it succeeds the operator swaps the live key to the new value and
	// restarts. Device-config-secret ciphertext is untouched.
	if len(os.Args) > 1 && os.Args[1] == "rotate-kek" {
		if cfg.DeviceConfigNewKEK == "" {
			slog.Error("rotate-kek requires THESADA_DEVICE_CONFIG_KEK_NEW to be set")
			os.Exit(1)
		}
		newKeyring, err := secrets.NewKeyring(cfg.DeviceConfigNewKEK)
		if err != nil {
			slog.Error("rotate-kek: THESADA_DEVICE_CONFIG_KEK_NEW invalid", "err", err)
			os.Exit(1)
		}
		res, err := services.Secrets.RotateRootKEK(rootCtx, newKeyring)
		if err != nil {
			slog.Error("rotate-kek failed", "err", err)
			os.Exit(1)
		}
		next := "re-run rotate-kek until rotated=0, then set THESADA_DEVICE_CONFIG_KEK to the new key and restart"
		if res.Rotated == 0 {
			next = "all DEKs on the new key: set THESADA_DEVICE_CONFIG_KEK to the new key and restart promptly"
		}
		slog.Info("rotate-kek done", "rotated", res.Rotated, "already_new", res.AlreadyNew, "next", next)
		return
	}

	// Warm the tenant slug and settings caches before routing starts.
	// Fatal on first load so a mis-seeded db is caught at boot, not on first
	// MQTT publish.
	if err := services.Tenants.Refresh(); err != nil {
		slog.Error("tenant cache refresh failed", "err", err)
		os.Exit(1)
	}
	if err := services.Settings.Refresh(); err != nil {
		slog.Error("settings cache refresh failed", "err", err)
		os.Exit(1)
	}
	// Bootstrap the internal CA for per-device mTLS certificates.
	// On first boot generates ECDSA P-256 CA keypair + self-signed cert.
	// On subsequent boots loads from disk. When THESADA_CA_KEY_PASSPHRASE
	// is set the on-disk key is encrypted with AES-256-GCM under a
	// scrypt-derived KEK; the warning surface flags any deployment still
	// running plaintext-on-disk so operators see exactly which file to
	// rotate. Empty passphrase keeps the legacy plaintext path working.
	ca, warn, err := pki.Bootstrap(cfg.CADir, cfg.CAKeyPassphrase)
	if err != nil {
		slog.Error("CA bootstrap failed", "dir", cfg.CADir, "err", err)
		os.Exit(1)
	}
	if warn != nil {
		slog.Warn("CA bootstrap warning",
			"warn", warn.Error(),
			"hint", "set THESADA_CA_KEY_PASSPHRASE to encrypt the CA key at rest; run `thesada-app ca-encrypt` once to rewrite the on-disk key")
	}
	slog.Info("CA loaded", "cn", ca.Cert.Subject.CommonName, "expires", ca.Cert.NotAfter.Format("2006-01-02"))

	mail := mailer.New(cfg)
	notifier := alerts.New(cfg, pools, mail)
	notifier.StartRedispatcher(rootCtx)
	hub := ws.New(cfg)

	bootstrapAdmin(cfg, services)

	mqttClient := mustStartMQTT(rootCtx, cfg, pool, notifier, hub, services)
	defer mqttClient.Stop()

	httpServer := buildHTTPServer(cfg, services, hub, mail, mqttClient, ca, pool)
	runHTTPServer(httpServer, cancel)

	<-rootCtx.Done()
	slog.Info("shutdown requested")
	gracefulShutdown(httpServer)
	slog.Info("bye")
}

// setupLogger installs a JSON slog handler as the process default.
// in: none. out: none (mutates package-level slog default).
func setupLogger() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
}

// mustLoadConfig loads env-derived config or exits on failure.
// in: none. out: validated *config.Config.
func mustLoadConfig() *config.Config {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config load failed", "err", err)
		os.Exit(1)
	}
	return cfg
}

// newSignalContext returns a context cancelled on SIGINT or SIGTERM.
// in: none. out: ctx + cancel func the caller must defer.
func newSignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
}

// mustOpenDB opens the pgx pool and pings the database, exiting on failure.
// in: ctx, postgres URL. out: live *db.Pool the caller must Close.
func mustOpenDB(ctx context.Context, url string) *db.Pool {
	pool, err := db.Open(ctx, url)
	if err != nil {
		slog.Error("db open failed", "err", err)
		os.Exit(1)
	}
	if err := db.Ping(ctx, pool); err != nil {
		slog.Error("db ping failed", "err", err)
		os.Exit(1)
	}
	return pool
}

// mustStartMQTT brings up the MQTT subscriber, exiting on failure.
// in: ctx, cfg, db pool, alerts notifier, ws hub, services. out: running *mqtt.Client the caller must Stop.
func mustStartMQTT(ctx context.Context, cfg *config.Config, pool *db.Pool,
	notifier *alerts.Notifier, hub *ws.Hub, services *service.Services) *mqtt.Client {
	c, err := mqtt.Start(ctx, cfg, pool, notifier, hub, services)
	if err != nil {
		slog.Error("mqtt start failed", "err", err)
		os.Exit(1)
	}
	return c
}

// buildHTTPServer constructs the *http.Server with both frontends mounted.
// /api/v1/ -> JSON API, /ws -> WebSocket hub, everything else -> HTMX dashboard.
// The mqtt client is passed through so the super-admin /admin/mqtt shell can
// register taps and publish through the shared paho connection.
// in: cfg, services bundle, ws hub, mailer, mqtt client, app db pool (health probe). out: configured *http.Server.
func buildHTTPServer(cfg *config.Config, services *service.Services, hub *ws.Hub, mail *mailer.Mailer, mqttClient *mqtt.Client, ca *pki.CA, pool *db.Pool) *http.Server {
	root := http.NewServeMux()

	api := apiv1.New(cfg, services, ca)
	api.SetHealthProbes(
		func(ctx context.Context) error { return db.Ping(ctx, pool) },
		mqttClient.Status,
	)
	// Resolve a bearer token OR the session cookie so the JSON per-route guards
	// (authmw.RequireAuthJSON / RequireSuperAdminJSON) see a *Session in context.
	apiWithAuth := authmw.APIMiddleware(services.Auth, services.ApiTokens, authmw.APICSRFGuard{
		BaseURL: cfg.BaseURL,
		Secret:  []byte(cfg.CookieSecret),
	}, cfg.TrustedProxies)(api)
	root.Handle("/api/v1/", http.StripPrefix("/api/v1", apiWithAuth))

	wsChain := authmw.Middleware(services.Auth, cfg.TrustedProxies)(authmw.RequireAuth(hub.ServeHTTP))
	root.Handle("/ws", wsChain)

	web := web.New(cfg, services, mail, mqttClient, ca)
	root.Handle("/", web)

	return &http.Server{
		Addr: cfg.HTTPAddr,
		// One wrap covers both frontends: browser security headers on every
		// web, API, and WS-upgrade response (see pkg/httpsec/headers.go).
		Handler:           httpsec.SecurityHeaders(root, cfg.TrustedProxies),
		ReadHeaderTimeout: 10 * time.Second,
	}
}

// bootstrapAdmin creates the configured admin user if it does not already
// exist, and if that user has no password hash yet, mints a one-shot reset
// link and logs it so the operator can set the initial password without
// waiting for SMTP to work. No-op if THESADA_ADMIN_EMAIL is empty.
// in: cfg, services bundle. out: none.
func bootstrapAdmin(cfg *config.Config, services *service.Services) {
	if cfg.AdminEmail == "" {
		return
	}
	u, err := services.Auth.EnsureAdminUser("default", cfg.AdminEmail)
	if err != nil {
		slog.Error("admin bootstrap failed", "email", cfg.AdminEmail, "err", err)
		return
	}
	// Flip an existing admin row to super-admin on every boot. Net-new bootstrap
	// users already get is_super_admin=true from EnsureAdminUser's INSERT; this
	// catches pre-0004 admin rows that predate the is_super_admin column.
	if !u.IsSuperAdmin {
		if err := services.Auth.PromoteSuperAdmin(u.ID); err != nil {
			slog.Warn("admin super-admin promote failed", "user_id", u.ID, "err", err)
		} else {
			u.IsSuperAdmin = true
		}
	}
	slog.Info("admin bootstrap ok", "email", u.Email, "user_id", u.ID, "super_admin", u.IsSuperAdmin)

	has, err := services.Auth.HasPassword(u.TenantID, u.ID)
	if err != nil {
		slog.Warn("admin has-password check failed", "err", err)
		return
	}
	if has {
		return
	}
	token, expires, err := services.Auth.CreateResetLink(u.ID)
	if err != nil {
		slog.Warn("admin one-shot reset link create failed", "err", err)
		return
	}
	slog.Warn("admin has no password - one-shot reset link",
		"email", u.Email,
		"url", cfg.BaseURL+"/reset-password?token="+token,
		"expires", expires.Format(time.RFC3339))
}

// runHTTPServer starts ListenAndServe in a goroutine and cancels the root
// context if the listener returns an error other than ErrServerClosed.
// in: server, root cancel. out: none.
func runHTTPServer(server *http.Server, cancel context.CancelFunc) {
	go func() {
		slog.Info("http listening", "addr", server.Addr)
		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("http server error", "err", err)
			cancel()
		}
	}()
}

// gracefulShutdown gives the HTTP server up to 10s to drain in-flight requests.
// in: server. out: none (errors are intentionally swallowed during shutdown).
func gracefulShutdown(server *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}
