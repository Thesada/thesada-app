# thesada-app

Self-hosted device management platform for rural and farm property monitoring. Single Go binary. HTMX + Tailwind dashboard, versioned JSON API, WebSocket live updates, MQTT bridge to nodes, Postgres for state.

## Architecture

Dual frontend, single backend, one versioned API. Both frontends call into the same service layer.

```
                          +-------------------+
   nodes  --->  MQTT  --> |                   |
                          |   pkg/service     |  <--- pkg/web    (HTMX dashboard)
   psql   <--- db    <--- |  (business logic) |  <--- pkg/api/v1 (JSON, Flutter app)
                          |                   |
                          +---------+---------+
                                    |
                                    v
                              pkg/ws  (WebSocket hub: live sensor + alert events)
```

## Layout

```
cmd/thesada-app/       main.go entry point, wires everything
pkg/config/            env loader (THESADA_* vars)
pkg/db/                pgxpool wrapper
pkg/service/           business logic, only layer that touches the db
pkg/service/auth.go    users, sessions, magic links, password (bcrypt)
pkg/web/               HTMX page handlers, calls services in-process
pkg/web/templates/     html/template files embedded via embed.FS
pkg/api/v1/            JSON REST handlers under /api/v1/
pkg/ws/                WebSocket hub at /ws (live events)
pkg/mqtt/              MQTT subscriber, writes via services, publishes to ws hub
pkg/alerts/            email + telegram alert fan-out
pkg/mailer/            plain SMTP + STARTTLS wrapper
pkg/authmw/            session cookie middleware + RequireAuth helper

migrations/            plain SQL files, applied with psql
assets/css/app.css         Tailwind v4 source (CSS-first config)
pkg/web/static/css/app.css Tailwind output, generated, gitignored
tools/tailwindcss          standalone CLI binary, gitignored
```

One Go binary. Goroutines for HTTP, MQTT subscriber, background workers. No microservice split.

## Requirements

- Go 1.25+ (matches the `go 1.25.11` directive in `go.mod`)
- Postgres 14+
- The Tailwind v4 standalone binary, downloaded into `tools/tailwindcss`:

  ```
  curl -fsSL -o tools/tailwindcss https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-linux-x64
  chmod +x tools/tailwindcss
  ```

## Build

```
make build      # go binary into bin/thesada-app
make css        # tailwind build into pkg/web/static/css/app.css (minified)
make css-watch  # rebuild CSS on template/go changes
make run        # build + css + run with .env loaded
```

## Run (local dev)

Option A - bootstrap your own Postgres:

```
createdb thesada_app
```

Then copy `.env.example` to `.env` and fill in values (see below). Apply the
embedded migrations with the `migrate` subcommand - it runs every migration,
not just `0001` - then start the server:

```
make build
./bin/thesada-app migrate   # needs THESADA_DATABASE_URL set
make run
```

Health check: `curl http://localhost:8080/api/v1/healthz`.

## Environment variables

Required:

- `THESADA_DATABASE_URL` - `postgresql://user:pass@host:5432/thesada_app?sslmode=disable`
- `THESADA_COOKIE_SECRET` - 32+ bytes, signs session cookies

Optional (but recommended):

- `THESADA_ADMIN_EMAIL` - on startup, creates this user with is_admin=true and
  is_super_admin=true and no password. First login is magic-link only. Leave
  unset and bootstrap manually.
- `THESADA_BASE_URL` - public base URL used for magic link emails. Default
  `http://localhost:8080`. Set to the real URL clients can reach.
- `THESADA_HTTP_ADDR` - default `:8080`
- `THESADA_MQTT_URL` / `_USER` / `_PASS` / `_CLIENT_ID` / `_TOPIC_ROOT` - MQTT
  subscriber. If `THESADA_MQTT_URL` is empty, the subscriber is disabled.
- `THESADA_SMTP_HOST` / `_PORT` / `_USER` / `_PASS` / `_FROM` - magic link email
  send. If `THESADA_SMTP_HOST` is empty, the mailer logs a warning and drops
  the message (useful for local dev; paste the link from the log instead).
- `THESADA_TELEGRAM_BOT_TOKEN` - for alert fan-out via Telegram (not yet wired).

## Auth flow

- Visit `/login`, submit email.
- If password field is set, the server calls `bcrypt.CompareHashAndPassword`
  and starts a 30-day session.
- If password is empty, a 32-byte magic link token is generated, its sha256
  hash stored in `magic_link_tokens`, and a plain-text email is sent with
  `THESADA_BASE_URL + /login/verify?token=...`. The link is valid for 15
  minutes and one use. Session lifetime is 24 hours.
- On success, a cookie `thesada_session` is set (HttpOnly, SameSite=Lax,
  Secure when `BASE_URL` starts with https).
- `/devices`, `/devices/{id}`, `/alerts` are wrapped in `authmw.RequireAuth`
  and 302 to `/login` for anonymous requests.
- `POST /logout` revokes the session row and clears the cookie.

Admin bootstrap: if `THESADA_ADMIN_EMAIL` is set, startup calls
`AuthService.EnsureAdminUser("default", <email>)` which creates the user with
`is_admin=true` and `is_super_admin=true` and no password if missing. First
login is magic-link only.

## Architecture notes

- **Single transport**: MQTT over TLS for everything except firmware OTA.
- **Multi-tenant from day 1** with default tenant `default` for v1.
- **Topic shape**: `thesada/<tenant>/<device>/{status,alert,sensor/<name>}`.
- **Auth**: email-password and magic link, both day one.
- **Registration**: gated by `settings.invite_only_mode` (waitlist until flipped).
- **Module path**: `thesada.app/app` (vanity import).
- **API versioning**: `/api/v1/` from day one. Web dashboard and Flutter app share the same contract.
- **Service layer is the seam**: `pkg/web` and `pkg/api/v1` both call `pkg/service` directly. Business logic lives in exactly one place.

## License

AGPL-3.0-only. The firmware (thesada-fw) is GPL-3.0-only; this companion app is AGPL-3.0 because it is intended to be run as a network service. AGPL section 13 obligates network operators to share modifications with users who interact with the running service.
