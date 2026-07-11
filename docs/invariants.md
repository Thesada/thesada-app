# thesada-app invariants

The load-bearing rules this application relies on. Every PR that
touches a listed area must keep these true. Violations require this
file to be updated with a justification, not silent landing.

Dated 2026-07-10 (alert delivery lifecycle: retry with backoff,
dead-letter budget, startup + periodic redispatch sweep, bounded
insert retry. Same day, earlier: alert Dispatch tenant-scoped through
`db.WithTenant` so RLS returns rows; pools-app guard limitation
noted).
Previously 2026-07-01 (device-config secrets complete: provision-at-pair via
`secret.set`, write-only UI, root-KEK rotation, existing-device backfill,
field keys aligned to the firmware keymap - phases 5-7). Previously
2026-06-30 (device-config secrets phases 2-4: per-tenant DEK envelope
encryption, write-only contract, crypto-shred on tenant delete, RLS on
the two new stores, malformed-KEK boot failure, config-field blanking).
Previously 2026-06-22 (auth-layer hardening: password-login rate limiting,
constant-time login, super-admin guard on impersonation, service-layer
password floor, signed-double-submit CSRF, cookie-secret length hard-fail).
Previously 2026-06-16 (CI lint guard for the pools.App tenancy contract,
session token rotation, CA key encryption at rest, MQTT topic / cert
pairing tenant gate, RLS ungated as the steady-state default). Bump the
date on every edit.

Entries marked **WIP** describe target state that is not yet enforced
end-to-end. They live here so the audit surface is visible.

---

## Tenant isolation

### Every read against `pools.App` is tenant-scoped through `db.WithTenant` or explicitly bypassed through `db.WithAdminAudit` **(enforced)**

Shipped. RLS is the steady-state default: `0016_rls_policies.sql`
applies RLS policies to every tenant-scoped table on every deploy. The
`THESADA_APPLY_RLS_POLICIES` env gate was removed once the consumer code
landed - `gatedMigrations` in `migrate.go` is now empty. The
application-layer `WHERE tenant_id = $1` filters remain as the first
line; RLS is the second line of defence.

The refactor wraps every tenant-scoped read in `db.WithTenant`, which
opens a pgx transaction with `SET LOCAL app.tenant_id = $1`. Postgres
RLS policies on every tenant-scoped table then scope rows
automatically. Cross-tenant admin reads (`GetByIDAny`,
`ListAcrossTenants`) go through `db.WithAdminAudit` against
`pools.Admin` (the `BYPASSRLS` role) which writes an audit log row.

How enforced: `scripts/check-pools-app.sh` (wired into
`.github/workflows/ci.yml` as the `pools-app-guard` job) fails any
PR that introduces a new `pools.App.{Query,QueryRow,Exec,Begin,
SendBatch,CopyFrom,BeginTx}` caller outside the grandfathered set in
`scripts/pools-app-allowlist.txt`.

Guard limitation, learned 2026-07-10: the check is textual on
`pools.App.`, so a component that receives the App pool under another
name evades it - `pkg/alerts` queried through its `n.db` field with no
tenant GUC and RLS silently returned zero rows (alert delivery dead -
the silent-drop bug). When handing the App pool to a component, the receiver
either takes tenant IDs and wraps every query in `db.WithTenant`
(what `pkg/alerts` does now, verified by
`pkg/alerts/alerts_integration_test.go`), or it belongs on the
allowlist with a justification.

Phase 2 is complete: every `pkg/service/*.go` file converted to
`db.WithTenant` / `db.WithAdminAudit`. Every `pkg/service` file is now
converted: the last grandfathered entry (`config_snapshot.go`, dead
code) was deleted in phase 3 (migration `0021`), so the allowlist
holds only the structural `pkg/db/` prefix - the helpers themselves wrap
the pool. Phase 3 fixed two bugs in `0016` (the `magic_link_tokens`
policy referenced a non-existent `tenant_id` column; the
`deleted_device_tombstones` table had no policy at all) and added the
acceptance test.

How verified: `pkg/db/rls_integration_test.go` (build tag
`integration`) seeds two tenants and asserts the App and MQTT pools
see only their own rows while the Admin pool sees all. It is not in
the default `make test` lane - run it against a disposable
TimescaleDB with `THESADA_TEST_DATABASE_URL` set; see the file header.

Service-layer tenant scoping is additionally covered by
`pkg/service/*_integration_test.go` (e.g. `DeviceService` cross-tenant
`GetByID` / `ListByTenant` / tombstone isolation), which spin a throwaway
TimescaleDB via `pkg/service/servicetest` and run under `make
test-integration`.

The acceptance test passes and the `THESADA_APPLY_RLS_POLICIES` gate was
removed; `0016` now applies on every deploy (`gatedMigrations` is empty),
making RLS the steady-state default.

Source: `pkg/db/tenant.go` (helpers), `pkg/db/pools.go`,
`migrations/0001_init.sql`, `scripts/check-pools-app.sh`,
`scripts/pools-app-allowlist.txt`, `pkg/db/rls_integration_test.go`.

### Cross-tenant getters are named `*Any` and live behind `RequireSuperAdmin`

Naming convention: every service method that reads outside the
caller's tenant ends in `Any` (e.g. `GetByIDAny`, `ListDevicesAny`).
Every call site is wrapped in `RequireSuperAdmin` middleware. The
naming makes audit-by-grep practical; the middleware enforces.

How enforced: reviewers grep for new `*Any` methods at PR time, check
call site is wrapped. Comments on the service method state the
super-admin requirement.

How verified: `pkg/authmw/authmw_test.go` proves the gate redirects
anonymous callers and 404s non-super users; `pkg/web/routes_test.go`
audits that every gated route (`RequireAuth` + `RequireSuperAdmin`)
actually rejects an anonymous request, catching a handler registered
without its wrapper. The JSON `/api/v1` gates
(`RequireAuthJSON` / `RequireSuperAdminJSON`) return 401/403 instead of a
redirect/404 and are covered by `pkg/authmw/apiauth_test.go`.

Source: `pkg/authmw/` middleware, service files.

### MQTT cross-tenant read default OFF for new tenants

Setting `mqtt_cross_tenant_read` is ON only for the `default` tenant
(homelab legacy layout). Every other tenant defaults OFF - paired
devices get `thesada/<tenant>/#` subscribe scope, never `thesada/#`.

When the admin UI for this setting ships, it must require a second
confirmation, write an audit log entry, and re-pair every device in
the tenant (revoke + reissue dynsec roles) on toggle. Today the
setting is only flippable via direct DB write; the runtime effect is
real on every pair operation.

Source: `pkg/web/admin_pair.go::dynsecSettingCrossTenantRead`,
`pkg/web/admin_pair.go::dynsecDeviceACLs`.

### MQTT topic tenant must match the device's active pairing tenant

Every inbound MQTT message goes through a cross-tenant pairing gate
in `Client.onMessage` before any handler runs: if the
firmware-claimed `device_id` already has a paired (non-revoked)
certificate under a different tenant, the message is dropped without
side effects. Broker ACL drift therefore cannot trick the app into
auto-creating a duplicate device row in the wrong tenant.

A device with no active pairing (never paired, or its last pairing
was revoked) falls through; the topic tenant is treated as
authoritative until a pairing locks the device into a specific
tenant. Re-pairing into a different tenant goes through the admin
"Reassign tenant" flow which revokes the old cert before issuing
the new one, so the check switches over atomically.

How verified: `pkg/service/certificate_integration_test.go` -
`FindActivePairingTenant` discovers the paired tenant cross-tenant for a
device with an active cert, and falls open (`"", false`) once the cert is
revoked, which is exactly the gate `onMessage` relies on.

Source: `pkg/mqtt/mqtt.go::Client.onMessage`,
`pkg/service/certificate.go::FindActivePairingTenant`.

---

## Authentication and sessions

### Session tokens are stored as SHA256, never plaintext

Raw session token returned to the browser in a cookie; only the
sha256 hash is persisted. Lookup is by hash, never by string compare
on the raw token, so a leaked DB does not expose live sessions and
timing on the lookup leaks nothing usable.

Source: `pkg/service/auth.go::CreateSession`, `ValidateSession`.

### API bearer tokens are stored as SHA256, never plaintext

The JSON `/api/v1` surface accepts a bearer token
(`Authorization: Bearer`) alongside the session cookie. Like session
tokens, the raw token is returned once at issue time and only its
sha256 hash is persisted in `api_tokens`; lookup is by hash. A token is
user-bound (no scopes); a revoked (`revoked_at` set) or expired token is
rejected. `APIMiddleware` resolves a bearer token first, then falls back
to the session cookie, and stores the same `*service.Session` in the
request context so the gates and `EffectiveTenantID` work unchanged.
`api_tokens` carries the same transitive RLS policy as `user_sessions`
(`user_id -> users.tenant_id`).

How verified: `pkg/service/api_token_integration_test.go` - issue then
validate returns the owning user, revoke and expire are rejected, and a
cross-tenant `ListTokens` returns nothing (RLS).

Source: `pkg/service/api_token.go`,
`pkg/authmw/apiauth.go::APIMiddleware`,
`migrations/0001_init.sql`.

### The JSON `/api/v1/auth` endpoints do not enumerate users

`POST /auth/login` matches an email across all tenants
(`VerifyPasswordAnyTenant`) and returns the same 401 for an unknown email
as for a wrong password; only on success does it set the session cookie
and mint the bearer token. `POST /auth/signup` always answers 200 whether
or not the email is already on the waitlist. Neither response reveals
whether an account exists - the same posture as the web login/signup.

How verified: `pkg/api/v1/auth_integration_test.go` - an unknown email and
a wrong password both return 401 (indistinguishable), and signup returns
200 + lands a waitlist row.

Source: `pkg/api/v1/auth.go::handleAuthLogin`, `handleAuthSignup`.

### Password verification is constant-time across account existence

`VerifyPassword` and `VerifyPasswordAnyTenant` run a bcrypt comparison even
when no user (or no stored hash) is found, against a fixed decoy hash
(`dummyPasswordHash`, generated once at `DefaultCost`). Without it the
no-user path returns before any bcrypt call and the timing gap enumerates
valid emails despite the identical 401/error. The any-tenant lookup also
bounds work: it orders candidates by `created_at` and checks at most
`maxLoginCandidates` rows, so a reused email is deterministic (oldest
account wins) and cannot turn one login into an unbounded bcrypt run.

How enforced: reviewers reject a new early `return ErrBadCredentials` on a
no-user/no-hash branch that skips the bcrypt step.

Source: `pkg/service/auth_users.go::VerifyPassword`,
`VerifyPasswordAnyTenant`, `equaliseLoginTiming`, `dummyPasswordHash`.

### `/api/v1` reads are tenant-scoped and redact device secrets

Every `/api/v1/devices*` read resolves the tenant via
`authmw.EffectiveTenantID` and goes through the tenant-scoped service
methods (`GetByID`, `ListByTenant`, telemetry/alerts by device pk), so a
caller only sees their own tenant's rows - a foreign device id returns
404, never 403, so existence does not leak. The device JSON shape
(`deviceResponse`) omits the pairing key, owner id, and mqtt topic prefix.

How verified: `pkg/api/v1/devices_integration_test.go` - a device in
another tenant 404s under the caller's bearer token, and the list
response carries no `pairing_key`.

Source: `pkg/api/v1/devices.go`.

### `/api/v1` alert-subscription writes are scoped to the calling user

`POST /alert-subscriptions` ties the row to the authenticated user
(`u.ID` + `u.TenantID`) and 404s a `device_pk` outside the user's tenant.
`DELETE /alert-subscriptions/{id}` removes by id AND user_id, so a user
cannot delete another user's subscription - a foreign id is a silent
no-op. channel and min_severity are validated to the schema's allowed
values (400), not left to surface as a DB constraint 500.

How verified: `pkg/api/v1/alerts_integration_test.go` - bad channel and
bad severity return 400, a foreign device_pk 404s, and the create -> list
-> delete lifecycle round-trips.

Source: `pkg/api/v1/alerts.go`.

### Magic-link and password-reset consumption is atomic single-winner

`consumeLinkToken` and `MarkResetConsumed` use `UPDATE ... RETURNING`
with `WHERE consumed_at IS NULL`. Concurrent consumes of the same
token have at most one winner; the loser gets `ErrNotFound`.

How enforced: reviewers grep for new SELECT-then-UPDATE patterns on
magic_link_tokens / password_reset_tokens. New token-consume paths
follow the same pattern.

How verified: `pkg/service/auth_integration_test.go` - login token
consumed twice returns `ErrNotFound` on the second call, an 8-way
concurrent consume of one token yields exactly one winner, and reset
`MarkResetConsumed` is single-winner.

Source: `pkg/service/auth.go::consumeLinkToken`, `MarkResetConsumed`.

### Session tokens rotate every 4 hours of validation activity

A session token value is valid for at most `sessionRotationInterval`
(4 h) before `ValidateSession` mints a fresh 32-byte token, swaps
`token_hash` atomically, parks the old hash in `previous_token_hash`
for `sessionRotationGrace` (60 s), and pushes a new `Set-Cookie` via
the auth middleware. A stolen cookie therefore has a bounded
effective lifetime: at most one rotation interval after the next
legitimate browser hit, the attacker's copy stops validating.

Concurrency: the rotation `UPDATE` carries `WHERE token_hash = $old`
so only one of N concurrent rotations lands; the losers continue
with the old token and do not set a fresh cookie. The 60 s previous-
hash grace window keeps a parallel in-flight request (XHRs racing
the page load that triggered the rotation) from 401-ing on the
already-replaced token.

How verified: `pkg/service/auth_integration_test.go` - aging
`rotated_at` past the interval makes the next `ValidateSession` mint a
fresh token (`NewToken` set) while the previous hash still validates
within the grace window.

Source: `pkg/service/auth.go::ValidateSession`,
`AuthService::rotateSession`, `pkg/authmw/authmw.go::Middleware`,
`migrations/0001_init.sql`.

### Super-admin rows cannot be deleted through the admin UI

`AuthService.DeleteUser` issues a single predicated `DELETE ... WHERE NOT
is_super_admin`, so a super-admin target is refused atomically with no
separate check a concurrent promote could race; zero rows affected
disambiguates `ErrNotFound` from `ErrSuperAdminProtected`. The guard lives
at the service layer so every caller is covered, not just the admin handler
(which separately blocks deleting your own account). Super rows are
platform-critical.

How verified: `pkg/service/auth_users_integration_test.go` -
`DeleteUser_refuses_superadmin` promotes a user, asserts the delete returns
`ErrSuperAdminProtected`, and confirms the row survives.

Source: `pkg/service/auth_users.go::DeleteUser`, `pkg/web/admin.go`.

### Tenant impersonation requires super-admin, enforced at the service layer

`SetImpersonation` crosses tenant boundaries (it points a session's queries
at another tenant), so a single guarded `UPDATE ... FROM users WHERE
is_super_admin` gates the write on the session owner being a super-admin -
no separate check, so nothing can race a concurrent demote. Zero rows
affected means no such session (`ErrNotFound`) or a non-super one
(`ErrNotSuperAdmin`), disambiguated by an existence probe in the same tx.
The `RequireSuperAdmin` middleware on `/admin/impersonate` is the first
gate; this service guard is the backstop so a future route that forgets the
wrapper cannot grant cross-tenant view.

How verified: `pkg/service/auth_sessions_integration_test.go` -
`impersonation_refused_for_non_superadmin` asserts `ErrNotSuperAdmin` and
that the session's tenant view is unchanged;
`impersonation_unknown_session_not_found` asserts `ErrNotFound`.

Source: `pkg/service/auth_sessions.go::SetImpersonation`,
`pkg/web/admin.go::handleAdminImpersonate`.

---

## Cryptographic material at rest

### CA private key is encrypted on disk when `THESADA_CA_KEY_PASSPHRASE` is set

The internal CA signs every per-device mTLS client certificate, so its
private key is the foundation of multi-tenant device identity. With
`THESADA_CA_KEY_PASSPHRASE` set, the on-disk `ca.key` is a
`THESADA-CAKEY-V1` envelope: AES-256-GCM over a PKCS#8-marshaled
private key, under a scrypt-derived KEK (N=32768, r=8, p=1, 16-byte
salt). The passphrase itself is never persisted by the app - it is
consumed at boot from env and held only in memory.

Plaintext PEM on disk is still supported for back-compat with existing
deployments. When loaded that way, `Bootstrap` returns a
`*PlaintextKey` warning that surfaces as a `slog.Warn` at startup
naming the exposed file path and pointing the operator at the
`thesada-app ca-encrypt` migration subcommand.

This defends against backup-leak / sidecar-volume / cold-disk-theft
threat models. It does NOT defend against a live-process compromise -
the decrypted key sits in memory after boot. The KMS path (server
never sees the private key, signing happens at a remote authenticator)
is the year-two follow-up scoped in `docs/security.md`.

Source: `pkg/pki/ca.go::Bootstrap`, `pkg/pki/encrypt.go`,
`pkg/pki/encrypt_test.go`, `cmd/thesada-app/main.go` (warning surface
+ `ca-encrypt` subcommand).

### Device-config secrets are envelope-encrypted under a per-tenant DEK; the operator never reads them back

The 5 sensitive device-config fields (`wifi.password`, `mqtt.password`,
`telegram.bot_token`, `web.password`, `wifi.ap_password`) are stored in a
separate encrypted store (`device_config_secrets`), never in
`device_files` and never as plaintext columns. Envelope encryption
(`pkg/secrets`, AES-256-GCM throughout): the deployment root KEK
(`THESADA_DEVICE_CONFIG_KEK`, 32 bytes, env-sourced, never in the DB)
wraps a per-tenant random DEK (`tenant_dek`); the DEK encrypts each
value. Every ciphertext is AAD-bound - the DEK to its `tenant_id`, each
value to `tenant/device/field` - so a DB-write attacker cannot relocate
one row's ciphertext onto another tenant, device, or field and have it
decrypt.

Write-only contract: `SetSecret` writes, `Status` returns set/unset
booleans only, and there is no operator-facing read-back path. The
server CAN decrypt (`SecretService.Reveal`) to provision a device at
pair or rotate keys, but that method is server-side only and must never
be wired to an operator-facing route - the whole contract depends on it
staying off the request surface.

Config hygiene: the write path never persists plaintext secrets in
`device_files` / `device_file_history` (legacy pre-backfill
`device_file_history` rows may still hold plaintext - see Residual).
`DeviceFilesService.Upsert` is the single
chokepoint every ingest + app-write path funnels through; for
`config.json` it blanks the sensitive leaves (`blankConfigSecrets`:
the `SecretFields` allowlist plus a `sensitiveConfigKeyRE` backstop)
before the row is written. The device-reported `sha256` is kept as-is
as the drift fingerprint - blanking changes only the stored content, so
a sanitized snapshot never reads as drift against the device. Clean
configs (already-blank, e.g. app-managed devices) pass through
byte-identical.

Tenant delete crypto-shreds: the `tenant_dek` row cascades away on
`tenants` delete, rendering that tenant's ciphertext permanently
unrecoverable regardless of what backups still hold the `device_config_secrets`
rows. Root-KEK rotation re-wraps DEKs (phase 7), never re-encrypts values.

Both new tables are RLS `FORCE`d: `tenant_dek` scopes directly on
`tenant_id = app_tenant_id()`; `device_config_secrets` scopes reads on
its denormalized `tenant_id` and its write `WITH CHECK` additionally
binds `device_pk` to the calling tenant (an `EXISTS` against `devices`),
so a cross-tenant `device_pk` is rejected at write - the AAD binding is
the second line, RLS the first.

Feature gate: an empty `THESADA_DEVICE_CONFIG_KEK` leaves the feature
off (devices keep plaintext config); a non-empty but malformed KEK is a
hard boot failure (`NewSecretService` -> `service.New` error ->
`os.Exit`), never a silent fallback to off. The root KEK must never be
rendered: the `/admin/debug` redactor masks by trailing token, so KEK
config fields are named to END in `KEK` and `sensitiveKeyRE` includes
`kek` (a field named `...KEKNew` would print in cleartext - a bug caught
in review). Rotation is idempotent + re-runnable (`RotateRootKEK` retries
each DEK under the new key and skips already-rotated rows) so the operator
can re-run until `rotated=0` and no swap-window DEK is orphaned.

Provisioning + field keys: `SecretFields` are the firmware `secret.set`
keys (the firmware keymap) so a paired device is provisioned by
`handleAdminDevicePairIssue` pushing `secret.set <field>\n<value>` to
NVS (mirror of `cert.set`, before the restart, feature-gated). Four map
1:1; `wifi.password` is per-SSID on the firmware, so it is provisioned as
`wifi.password:<ssid>` (`FirmwareSecretField`), resolving the SSID from
the device's stored config. Root-KEK rotation (`rotate-kek` /
`RotateRootKEK`) re-wraps every DEK under a new KEK in one admin tx and
never touches value ciphertext. Existing devices migrate via
`backfill-secrets` (`BackfillDeviceSecrets`): extract plaintext from the
stored config, `SetSecret`, re-blank. KEK-in-env is v1; KMS is the later
follow-up. Residual: backfill does not purge plaintext from older
`device_file_history` rows.

How verified: `pkg/secrets/secrets_test.go` (crypto core: round-trip,
tamper / wrong-key / wrong-AAD reject, nonce freshness),
`pkg/service/secret_integration_test.go` (DB round-trip, overwrite,
write-only Status, cross-tenant RLS isolation, feature-off gate,
malformed-KEK boot failure), `pkg/service/tenant_integration_test.go`
(`Create_provisions_tenant_DEK`, `Delete_crypto_shreds_secrets`),
`pkg/service/config_secrets_blank_test.go` (allowlist + backstop + clean
passthrough + extract inverse), `pkg/service/device_files_integration_test.go`
(`config_json_secrets_blanked_sha_preserved`),
`pkg/service/secret_phase7_integration_test.go` (rotation: old-key-fails /
new-key-works / kek_version bump; backfill: extract -> encrypt -> re-blank,
idempotent), `pkg/service/secret_fields_test.go` (`FirmwareSecretField`
mapping), `pkg/web/provision_test.go` (pair-time provision loop:
ordering, skip-unset, no-SSID skip, reveal-error + push-fail abort),
`pkg/web/admin_secrets_integration_test.go` (write-only POST stores +
round-trips, rejects empty/unknown), and the web auth-gate + bad-UUID
audits for the two secrets routes (`routes_test.go`,
`handler_input_test.go`). Residual: the thin handler-to-MQTT adapter in
`handleAdminDevicePairIssue` (the closures wiring Reveal/pushSecret into
the tested loop) has no end-to-end pairing test - it needs an MQTT device
sim.

Source: `pkg/secrets/secrets.go`, `pkg/service/secret.go`
(`SecretFields`, `FirmwareSecretField`, `Reveal`, `RotateRootKEK`),
`pkg/service/tenant.go` (`Create` DEK provisioning),
`pkg/service/config_secrets_blank.go`, `pkg/service/secret_backfill.go`,
`pkg/service/device_files.go` (`Upsert` blanking chokepoint),
`pkg/web/admin_pair.go` (`pushSecret` provisioning),
`pkg/web/admin_secrets.go` (write-only UI),
`migrations/0023_device_config_secrets.sql`, `pkg/config/config.go`
(`DeviceConfigKEK` + `_NEW`), `cmd/thesada-app/main.go`
(`service.New` error surface, `backfill-secrets` + `rotate-kek`),
`docs/security.md` (operator runbook).

### Passwords use bcrypt at default cost (10)

`bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)`. No
SHA256-then-bcrypt, no length cap workaround, no custom KDF.

Source: `pkg/service/auth.go::SetPassword`.

### The password floor lives in `SetPassword`, not just the handlers

`SetPassword` rejects anything under `MinPasswordLen` (10) with
`ErrPasswordTooShort` before hashing, so the floor holds for any caller -
the settings form, the reset flow, and any future path. The two handlers
keep a friendlier inline message but reuse the same `service.MinPasswordLen`
constant rather than a literal, so the floor has one source of truth.

How verified: `pkg/service/auth_users_integration_test.go` -
`SetPassword_rejects_below_floor` asserts a 9-char password returns
`ErrPasswordTooShort`, nothing is stored, and a 10-char password is accepted.

Source: `pkg/service/auth_users.go::SetPassword`,
`pkg/service/auth.go::MinPasswordLen`, `pkg/web/web_settings.go`,
`pkg/web/web_auth.go`.

---

## CSRF

### Every state-changing HTTP endpoint requires CSRF verification

Signed double-submit cookie pattern: server sets a non-HttpOnly cookie
`thesada_csrf` whose value is a random token plus an HMAC-SHA256 signature
under the app's cookie secret (`<body>.<sig>`); the client reflects the
exact value via header `X-CSRF-Token` or hidden form field. Middleware
verifies unsafe methods (`{POST, PUT, PATCH, DELETE}`) echo the cookie,
constant-time. The signature is what lifts this above plain double-submit:
a sibling subdomain (or anything that can plant a cookie but does not hold
the secret) cannot forge a value that passes the signature check, so
`ensureCookie` discards the planted cookie and mints a fresh one - the
attacker's submitted value then no longer matches and the request 403s.

How enforced: middleware `pkg/csrf` runs on every router group that
isn't explicitly read-only (wired with `cfg.CookieSecret` in
`pkg/web/web.go`). Reviewers check new mutating endpoints sit behind it.

Deploy note: an old unsigned cookie fails the signature check, so a form
loaded before this shipped and submitted after will 403 once; `ensureCookie`
replaces the cookie on that same response and a refresh recovers.

How verified: `pkg/csrf/csrf_test.go` -
`TestMiddleware_RejectsPlantedCookie` (an unsigned planted cookie is
refused), `TestValidToken_AcceptsMintedRejectsForged` (only secret-signed
values validate), plus the missing/mismatched-token 403 paths.

Source: `pkg/csrf/csrf.go`, `pkg/web/web.go`.

---

## OAuth

### OAuth flow uses PKCE S256 + nonce + state, single-use state via DELETE-RETURNING

Every authorize request generates a PKCE code verifier (S256
challenge), a nonce, and a state value persisted to
`oauth_auth_requests`. On callback, the row is deleted with
`RETURNING` so reuse fails atomically. PKCE is required by Kanidm
1.x for confidential clients - non-negotiable.

Source: `pkg/service/oauth.go`, `pkg/web/oauth.go`.

### Every OAuth redirect target passes through `IsSafeReturnTo`

Open-redirect prevention. `return_to` query parameters and stored
post-login redirects are checked for same-origin + path-only before
issuing a 302. Centralised so any new redirect site picks up the
check by default.

How verified: `pkg/web/oauth_test.go::TestSafeReturn` - pass-through
for vetted relative paths, fallback for absolute / scheme-relative
(`//`) / non-slash input.

Source: `pkg/oauth/oauth.go::IsSafeReturnTo`, wrapped by
`pkg/web/oauth.go::safeReturn`.

### OIDC callback loads the provider by stored id, never re-resolves by slug

`/start` records the chosen provider's id in the auth request
(`pending.ProviderID`). The callback MUST load that exact provider via
`LoadProviderByID`, not `LoadProviderBySlug`. Re-resolving by slug with an
empty tenant hint returns `ORDER BY id LIMIT 1` - the lowest-id tenant's
provider - so any session on a different tenant gets a provider mismatch and a
400. Loading by stored id keeps `/start` and `/callback` symmetric per tenant.

Source: `pkg/web/oauth.go::handleOIDCCallback`, `pkg/service/oauth.go::LoadProviderByID`.

### Email auto-link is scoped to the provider's tenant

When the callback finds no existing (provider, subject) link but the id_token
carries a verified email, it may auto-link to a local user - but
`FindUserByEmail` matches only within the provider's own tenant. Email is
unique per `(tenant_id, email)`, so an unscoped match could bind the session to
the wrong tenant's user when the same address exists in several tenants. A
global provider (`tenant_id` NULL) has no tenant to scope to and therefore never
auto-links by email; those users link manually from settings. Successful
auto-links log `oauth.identity.state_change` (trigger `email_match`).

Source: `pkg/service/oauth.go::FindUserByEmail`, `pkg/web/oauth.go::handleOIDCCallback`.

---

## SQL and templating

### All SQL is parameterized

No `fmt.Sprintf` into a SQL string anywhere. pgx parameter binding
only. Reviewers grep for `fmt.Sprintf` near `Query` / `Exec` /
`QueryRow` at PR time.

### HTML rendered via `html/template`, plain text via `text/template`

`html/template` auto-escapes by default; `text/template` does not.
The two are not interchangeable - using `text/template` for HTML
output is an XSS vector. Email bodies are the only `text/template`
consumers, and even there only for plain-text MIME parts (HTML mail
templates use `html/template`).

Source: `pkg/web/templates/`, `pkg/service/mailer.go`.

### Migrations are forward-only and idempotent

`migrations.Apply` runs every `*.sql` newer than the highest version in
`schema_migrations`, each in its own transaction, recording the version
on success. There are no down migrations - rollback is a new
forward migration. Re-running `Apply` on an up-to-date database is a
clean no-op; a migration that is not safely re-runnable (e.g. a `CREATE`
missing `IF NOT EXISTS`) is the failure this guards against.

How verified: `migrations/migrate_integration_test.go` (build tag
`integration`) applies all migrations to a fresh TimescaleDB container,
then applies again and asserts `schema_migrations` is unchanged.
Run with `make test-integration`.

Source: `migrations/migrate.go::Apply`.

---

## Cookies

### Session + CSRF cookies: SameSite=Lax + Secure-when-HTTPS

Session cookie set via `authmw.SetSessionCookie` (login in
`pkg/web/web.go::startSession` and rotation in `pkg/authmw`); CSRF cookie in
`pkg/csrf`. All decide the Secure flag through the one shared
`httpsec.RequestIsSecure(r)` - true when `r.TLS != nil` OR the proxy set
`X-Forwarded-Proto: https`. So the flag is correct behind HAProxy (TLS to
the browser, plain HTTP to the app) and dev (plain HTTP) still works without
config drift. The session cookie is HttpOnly; the CSRF cookie is not (below).

### CSRF cookie: non-HttpOnly (intentional)

The CSRF token cookie must be readable by JS to participate in the
double-submit pattern; the session cookie stays HttpOnly. Same SameSite=Lax
+ the shared Secure decision above.

Source: `pkg/csrf/csrf.go`, `pkg/web/web.go`, `pkg/authmw`, `pkg/httpsec`.

### The cookie secret must be >= 32 bytes; short secrets hard-fail at boot

`THESADA_COOKIE_SECRET` signs both the session cookies and (now) the CSRF
tokens, so a weak secret undermines both. `config.validate` aborts startup
when it is under `minCookieSecretLen` (32) unless `THESADA_ALLOW_WEAK_SECRET`
is set truthy - safe by default, with an explicit, logged escape hatch for
an existing sub-32-byte deployment to boot across a restart while it rotates.
The error names the override so an operator hitting it knows the way out.

How verified: `pkg/config/config_test.go::TestValidate_CookieSecretFloor`
(empty/weak/weak+override/strong matrix) and
`TestValidate_WeakSecretErrorIsActionable`.

Source: `pkg/config/config.go::validate`, `minCookieSecretLen`, `envBool`.

---

## WebSocket origin

### Upgrades validate Origin against BaseURL

Both the device-event hub (`pkg/ws`) and the admin MQTT shell
(`pkg/web/admin_mqtt.go`) reject a cross-origin WebSocket upgrade: a present
Origin header must match `cfg.BaseURL` on scheme + host exactly, not a
substring. A missing Origin (non-browser client) is allowed. This closes
cross-site WebSocket hijacking, where a hostile page would otherwise ride
the browser's SameSite=Lax session cookie to open a socket. Rejections log
`ws.origin_rejected`.

Source: `pkg/httpsec.OriginAllowed`, `pkg/ws/ws.go`, `pkg/web/admin_mqtt.go`.

---

## PKI and mTLS

### Device certs are ECDSA P-256 with PKCS#8 private key envelope

P-256 keeps the cert + key small (cellular modem internal FS has a
~4 kB ceiling per file). PKCS#8 (not the older OpenSSL "EC PRIVATE
KEY" envelope) is required by SIM7080G firmware 1951B17; the
provisioner uses PKCS#8.

Source: `pkg/pki/ca.go`, `pkg/pki/sign.go`.

### Internal CA private key: KMS migration **(WIP)**

Mitigated by passphrase encryption (see the CA-private-key-encrypted-on-disk
invariant above). Long-term: move signing to a KMS (AWS KMS / GCP KMS /
Vault transit engine) so the server never sees the private key.

Source: `pkg/pki/ca.go::generate`.

### Device-CN topic-tenant cross-check on auto-create **(WIP)**

Today device auto-creation from MQTT trusts the topic-claimed tenant.
The FK constraint on `tenant_id` rejects non-existent tenants, but a
misconfigured ACL plus an existing tenant can land a `devices` row
in the wrong tenant. Target state: for paired devices, parse the
cert CN and reject the upsert if the topic tenant disagrees.

Source: `pkg/mqtt/mqtt.go::parseTopic`,
`pkg/service/device.go::upsertCore`.

---

## MQTT broker integration

### Devices authenticate via mTLS dynsec with cert-only clients (no password)

Dynsec client per paired device with empty password; auth resolves
to the cert CN on the mTLS broker listener (port 8884).
Non-paired / non-mTLS clients use password auth on the legacy
listener (port 8883). The split keeps mTLS optional during the
multi-tenant rollout but mandatory for any device that has a cert.

Source: `pkg/web/admin_pair.go`, `pkg/mqtt/dynsec.go`.

### CLI requests serialize per device + correlate by req_id

`CLIRequest` / `CLIRequestRaw` hold `cliLockFor(topicPrefix)` for the
full publish-then-await cycle. Two concurrent callers targeting the
same device queue on that mutex; the second goroutine does not
register a tap or publish until the first has consumed its response
or timed out. Without the mutex both taps fire on every cli/response
message and the loser captures the winner's reply.

Outgoing payloads (text path only) are wrapped as `{"req_id":<uuid>,
"args":<original>}`. Firmware v1.4.5+ echoes req_id back on every
cli/response; the receiver tap filters by req_id when present. Older
firmware that ignores the envelope still works - the mutex alone
makes the response unambiguous, and the tap accepts responses with
no req_id field.

Binary protocols (`fs.write`, `fs.append`, `cert.set` raw payloads)
go through `CLIRequestRaw` which does not wrap - firmware binary
handlers read raw bytes, not JSON. The mutex still serializes.

Multi-page consumption: firmware v1.4.6+ splits oversized command
output across multiple `cli/response` messages, each carrying a
0-indexed `page` and a `more` flag (final page `more:false`). Both
`CLIRequest` and `CLIRequestRaw` await the assembled result via
`awaitPagedCLIResponse`, which keys page output by index (arrival
order does not matter) and returns once the final page plus every
lower-indexed page has arrived. The returned `CLIResponse` has
`Page`/`More` cleared and `Output` holding the concatenation. The tap
channel is buffered (cap 64) so the non-blocking sink send never
drops an intermediate page. Pre-1.4.6 firmware omits `page`/`more`
entirely - its single message is treated as the final page and
returns immediately, so the path is mixed-fleet safe.

How enforced: every CLI caller goes through `Client.CLIRequest` or
`Client.CLIRequestRaw`. Reviewers reject direct `c.PublishRaw` calls
to `*/cli/<cmd>` topics from outside `pkg/mqtt`.

Source: `pkg/mqtt/mqtt.go::CLIRequest`, `CLIRequestRaw`,
`awaitPagedCLIResponse`, `cliLockFor`. Pairs with the thesada-fw
`docs/invariants.md` invariant "cli/response paginates oversized
command output".

### `/info` drift detection runs on every retained delivery

The MQTT subscriber subscribes to `<root>/#` at QoS 1, so retained
`<prefix>/info` payloads arrive on every reconnect. `handleInfo`
compares the device-reported `config_hash` / `scripts_main_hash` /
`scripts_rules_hash` against the latest stored snapshots; mismatch
launches `pullAndSnapshot` via the new per-device-serialized CLI
path. The pull writes a `source="drift"` row into device_files.

Path is retained-replay safe: the broker delivers the latest /info
on every subscribe, so app restarts re-trigger drift checks for any
device with a content delta accumulated while the app was offline.

Source: `pkg/mqtt/mqtt.go::handleInfo`, `pullAndSnapshot`.

---

## Alert delivery

### Every alert row reaches a terminal delivery state; pending rows are always swept

`device_alerts.delivery_status` is the lifecycle: `pending` ->
`delivered` / `none` (no matching subscription) / `dead` (attempt
budget spent, `THESADA_ALERT_MAX_ATTEMPTS`, default 5). A failed send
leaves the row `pending` with a backed-off `next_attempt_at`; the
redispatch sweeper (`Notifier.StartRedispatcher`, one pass at startup
+ one per `THESADA_ALERT_REDISPATCH_INTERVAL`) re-runs `Dispatch` for
every pending-and-due row. A process death between insert and dispatch
is therefore recovered at next boot, and all-channels-fail is surfaced
as an `alert.delivery.state_change` to `dead` at error level - never
silently dropped.

The sweep scan is the one sanctioned cross-tenant read in the alert
path: it runs on `pools.Admin` via `db.WithAdminAudit` and reads only
`(tenant_id, alert id)` pairs; each re-dispatch then runs tenant-scoped
via `db.WithTenant` like the inline path. Per-channel `delivered_*`
flags guarantee a retry never re-sends a channel that already
succeeded; channel success is per-alert, not per-recipient (partial
recipient failure within a channel is not retried). The in-process
`inflight` claim assumes a single app instance - running more than one
needs `FOR UPDATE SKIP LOCKED` claims first.

How verified: `pkg/alerts/alerts_integration_test.go` (retry
scheduling, dead-letter budget, cross-tenant sweep, startup-shaped
redispatch, no-double-send on partial channel failure).

Source: `pkg/alerts/alerts.go::Dispatch`, `pkg/alerts/redispatch.go`,
migration `0025_alert_delivery_retry.sql`.

### A failed alert insert retries bounded, then dead-letters to the log

`handleAlert` retries a failed `device_alerts` insert in the background
(3 attempts, 5s/15s/45s, capped at 64 concurrent retry goroutines) and
on exhaustion emits `alert.ingest.dead_letter` at error level with the
full payload, so the alert is reconstructable from logs. Until the
insert lands the alert exists only in process memory - MQTT QoS 1
redelivery on reconnect is the transport-level backstop.

Source: `pkg/mqtt/mqtt_ingest.go::retryAlertInsert`.

---

## Rate limiting

### Magic-link and reset endpoints are rate-limited per IP + per email

Window-based limiter (`pkg/ratelimit`). When either bucket (per-email
or per-IP) is full the request is dropped silently: the endpoint still
renders the same "check your email" confirmation, leaking neither which
addresses exist nor whether a request was throttled. This is deliberate
anti-enumeration (see the `allowMagicLink` header) - there is no 429.
Map sweep removes empty entries on the window cadence so the map does
not grow unbounded over the lifetime of the systemd unit.

Source: `pkg/ratelimit/ratelimit.go`, `pkg/web/web.go::allowMagicLink`
(consumed by the magic-link login handler + `handleForgotSubmit`).

### Password login is rate-limited per email + per IP and answers 429

The same window limiter brakes online password guessing, but here at the
service layer (`AuthService.allowLogin`, checked inside
`VerifyPasswordAnyTenant`) so the web form and `/api/v1/auth/login` are
covered by one gate rather than each handler. Per-email and per-IP buckets
(`loginMaxPerEmail` / `loginMaxPerIP` over `loginWindow`); over the cap
returns `ErrLoginRateLimited`, which the handlers surface as **429** (web
re-renders "too many attempts", API returns a 429 JSON body).

Unlike magic-link, login answers 429 rather than silent-dropping: login
already has a visible failure mode (wrong password), and the limiter keys
on (email, IP) independently of whether the account exists, so a throttle
response leaks no user enumeration - it only confirms the caller has been
hammering, which the caller already knows.

The per-IP key is the real client IP via `httpsec.ClientIP`, which honours
`X-Forwarded-For` only from a peer in `THESADA_TRUSTED_PROXIES` (walked
right-to-left, so a client-spoofed prefix is ignored). Without that env the
key is `RemoteAddr`; behind the TLS proxy every request shares the proxy IP,
so the proxy MUST be in the trusted set for the per-IP cap to be per-client
rather than a global bucket.

How verified: `pkg/service/auth_throttle_test.go` (per-email cap, per-IP
cap, empty-IP isolation, case-insensitive email key) and
`pkg/service/auth_users_integration_test.go::VerifyPasswordAnyTenant_rate_limited_per_email`
(the gate trips end-to-end and refuses even the correct password while full).

Source: `pkg/service/auth.go::allowLogin`,
`pkg/service/auth_users.go::VerifyPasswordAnyTenant`,
`pkg/web/web_auth.go::handleLoginSubmit`,
`pkg/api/v1/auth.go::handleAuthLogin`.

---

## Audit trail

### Every cross-tenant admin read writes an audit log entry **(WIP)**

Target state once `db.WithAdminAudit` wires the audit table.
Currently the helper exists and writes a log line; the audit table
schema is scaffolded but not consumed by any handler yet. Cross-
tenant admin operations today rely on the `*Any` naming + the
`RequireSuperAdmin` middleware as the only enforcement layer.

Source: `pkg/db/tenant.go::WithAdminAudit`.

### Security state transitions emit `<subsystem>.state_change`

Auditable state edges log a structured transition (`from`/`to` + ids) so the
trail is greppable. Wired so far:

- `auth.session.state_change` - login (anonymous -> authenticated, with method)
  and logout (authenticated -> anonymous). Source: `pkg/web/web.go::startSession`,
  `handleLogout`.
- `oauth.identity.state_change` - an external identity bound to a local user
  (unlinked -> linked), `trigger` is `settings_link` or `email_match`. Sign-in
  itself rides `auth.session.state_change` (method `oidc`).
  Source: `pkg/web/oauth.go::handleOIDCCallback`.
- `device.pair.state_change` - a device's pairing cert issued (unpaired ->
  paired) or revoked (paired -> revoked) via pair issue, admin revoke, or single
  / bulk device delete; `reason` names the trigger. Revoke/delete only log when
  the device was actually paired. Source: `pkg/web/admin_pair.go::logPairStateChange`.
- `alert.delivery.state_change` - an alert notification delivered (pending ->
  delivered) once at least one channel (email/telegram) succeeds and the
  device_alerts row is marked. Source: `pkg/alerts/alerts.go::Dispatch`.

Device OTA is intentionally absent: the app fire-and-forgets a `cli/ota.check`
command and the device owns the update lifecycle, so there is no app-side
`state_change` to emit for it.

---

## Error handling

### `recover()` only on goroutines fed by external input

Standard handlers return appropriate HTTP codes for every error path; nil
derefs are guarded at boundaries (request parse, DB scan, external service
call), so most goroutines need no recover. The exception is a goroutine
reachable by external input: `pkg/mqtt` dispatches every inbound broker
message on its own paho goroutine, so `onMessage` recovers at entry
(`mqtt.callback_panic`) - one malformed message must not crash the process.

New code that adds a goroutine MUST guard its entry against panic if the
goroutine can be triggered by user input. Reviewers grep for new `go func()`
at PR time + check for `defer recover` only where the goroutine processes
external input.

---

## What this list is not

- Not a feature spec.
- Not a coverage map.
- Not a roadmap.

It is the list of properties this app must keep true to remain
defensible. Reviewers consult it on every PR that touches the named
files. Update it before merging anything that violates an entry, or
the entry is wrong.

Related: [`../CODE-GUIDELINES.md`](../CODE-GUIDELINES.md),
[`security.md`](security.md) (Go security scanner gating).
