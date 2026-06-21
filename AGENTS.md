# Project Overview

thesada-app is the web platform backend for the Thesada IoT product. Go + HTMX + Tailwind (standalone CLI, no node) + Postgres with TimescaleDB. Single static binary, embedded templates + static assets, migrations embedded under `migrations/`. AGPL-3.0-only.

## Repository Structure

- `cmd/thesada-app/` - program entry. Subcommands include `run`, `migrate`.
- `pkg/config/` - config loader (env + flags).
- `pkg/db/` - Postgres (pgx/v5) pool, queries, connection helpers.
- `pkg/service/` - domain services (tenants, devices, alerts, events).
- `pkg/web/` - HTTP handlers, HTML templates (embedded), static/ (tailwind + htmx + chart.js, embedded).
- `pkg/api/v1/` - JSON API surface.
- `pkg/ws/` - WebSocket handlers (live telemetry stream).
- `pkg/mqtt/` - MQTT client, tap filter, topic routing.
- `pkg/alerts/` - alert engine.
- `pkg/mailer/` - transactional email (magic link, alerts).
- `pkg/authmw/` - auth middleware (sessions, magic link, CSRF-friendly).
- `pkg/csrf/` - CSRF token handling.
- `pkg/ratelimit/` - per-IP + per-user rate limiting.
- `pkg/pki/` - CA + client cert issuance for device mTLS.
- `migrations/` - numbered SQL migrations + embedded runner (`migrate.go`).
- `tools/` - pinned toolchain binaries (Tailwind standalone CLI pulled on demand).
- `assets/` - source Tailwind input.
- `.github/workflows/` - CI (lint, tests, security scanners) + release (image + binary).
- `deploy/` - self-host artifacts (Docker Compose + bootstrap script).

## Build & Development Commands

```sh
# One-time: fetch pinned Tailwind standalone CLI (no node required)
make tailwind-cli

# Build CSS once (minified)
make css

# Build CSS in watch mode for local dev
make css-watch

# Build the Go binary (bin/thesada-app) - runs css first
make build

# Run tests
make test

# Tidy go.mod / go.sum
make tidy

# Clean build output
make clean

# Run locally
./bin/thesada-app run

# Run database migrations
./bin/thesada-app migrate
```

Database: Postgres + TimescaleDB extension. Connection via `THESADA_DATABASE_URL` env var. See `deploy/` for a Docker Compose quickstart and `pkg/config/` for the authoritative env var list.

## Code Style & Conventions

- Go 1.25+. Modules rooted at `thesada.app/app`.
- Package names short and lowercase. One domain concept per package.
- No em dashes anywhere. Hyphens only.
- Import order: stdlib, third-party, local (enforced by `goimports`).
- Error handling: wrap with `fmt.Errorf("do x: %w", err)`. No naked `return err` when context matters.
- Templates in `pkg/web/templates/` follow Go html/template, embedded via `//go:embed`.
- Static assets in `pkg/web/static/` (htmx, chart.js, compiled Tailwind). Vendored; refreshed periodically.
- SQL: pgx parameterised queries only. No string concatenation.

## Architecture Notes

```
    Browser (HTMX + chart.js)
         |
         v
   +-----+------+      WebSocket  +---------+
   |  HTTP API  |<--------------->|   ws/   |---+
   | (pkg/web,  |                 +---------+   |
   |  pkg/api)  |                               |
   +-----+------+                               |
         |                                      |
         v                                      v
   +-----+------+    +------------+    +--------+--------+
   | authmw /   |    | service/   |    | alerts/         |
   | csrf /     |--->| tenants,   |--->| rules + fanout  |
   | ratelimit  |    | devices,   |    +-----------------+
   +-----+------+    | events,    |           |
         |            | mailer     |           v
         v            +-----+------+    +------+-------+
   +-----+------+           |           |   mqtt/      |
   |  pkg/db    |<----------+           |  tap + route |
   |  pgx/v5    |                       +------+-------+
   |  Timescale |                              |
   +------------+                              v
                                      Mosquitto (TLS / mTLS)
                                              |
                                              v
                                      ESP32 fleet
```

Inbound: HTMX form POSTs or WebSocket. Outbound: server-rendered HTML fragments (HTMX friendly) + JSON for charts.

## Testing Strategy

- Unit tests co-located (`pkg/foo/foo_test.go`). Run with `make test`.
- Integration tests hit a real Postgres + Timescale (no DB mocks), spun via testcontainers under the `integration` build tag. Run with `make test-integration` (needs Docker).

## Security

- **License:** AGPL-3.0-only. `LICENSE` at repo root.
- **Secrets:** env vars only; never committed.
- **Auth:** session cookies + magic link (passwordless). CSRF protection on all state-changing routes.
- **Rate limiting:** per-IP + per-user. See `pkg/ratelimit/`.
- **Device mTLS:** client certs issued by `pkg/pki/`. Paired to device on provisioning. Mosquitto enforces on the TLS listener.
- **Dependency scanning:** govulncheck + gosec, run on every PR via `.github/workflows/ci.yml`. See `docs/security.md`.

## Agent Guardrails

- **`main` is protected - PRs required.** Work on `dev`, open a PR to `main`.
- **No breaking schema changes without a migration.** Add a new numbered file under `migrations/`.
- **No mocked DB in tests.** Real Postgres + Timescale.
- **No em dashes** in source, templates, commits, or email copy.
- **CSRF middleware is mandatory** on state-changing HTTP routes. Do not bypass.
- **Check the invariants ledger.** `docs/invariants.md` holds the load-bearing rules the codebase must uphold. Any security/correctness commit that establishes or relies on an invariant updates the ledger in the same commit. The `pools-app-guard` CI lint enforces one slice (no new `pools.App.{Query,Exec}` callers outside `pkg/db/`).
- **Find the bug's siblings.** When fixing a bug, grep for the same pattern before declaring it fixed.
- **Reject silent fallbacks.** A swallowed error, a default that hides a misconfiguration, a `tenant_id IS NULL` check that no-ops on a per-tenant row: justify it loudly in a comment or refactor it to fail loudly.

## Extensibility Hooks

- **Config:** new env vars wired in `pkg/config/`. Prefix `THESADA_`.
- **Routes:** register in `pkg/web/` or `pkg/api/v1/` via the router builder. Always go through `authmw` + `csrf` + `ratelimit` as appropriate.
- **Alert rules:** extend `pkg/alerts/` with a new rule type; tests alongside.
- **Migrations:** next numbered SQL file under `migrations/`. Run `./bin/thesada-app migrate`.
- **MQTT topic routing:** add handler in `pkg/mqtt/`. Tap filter config via env.

## Further Reading

- `README.md` - quickstart + deploy notes.
- `CONTRIBUTING.md` - contribution workflow.
- `CODE-GUIDELINES.md` - habit rules + ledger discipline.
- `Makefile` - canonical build targets.
- `docs/` - invariants, security, architecture, and operational docs.
