# thesada-app threat model

The per-asset, per-attacker view of what this application defends, how, and
what it explicitly does not. The one-paragraph summary lives in
[`../SECURITY.md`](../SECURITY.md); this is the scannable detail behind it, and
the honest residual column is the point - a control with an empty residual is
either perfect or under-examined.

Dated 2026-07-11. Bump on every edit; revisit when the architecture changes.
Load-bearing enforcement rules are in [`invariants.md`](invariants.md); the
at-rest crypto detail is in [`security.md`](security.md); failure-and-recovery
paths are in [`failure-modes/`](failure-modes/).

---

## Assets

- **Tenant data** - sensor history, device inventory, contact + alert config.
- **Internal CA private key** - mints every device certificate, so the
  highest-value secret in the system.
- **Device identity + broker credentials** - per-device mTLS certs and the
  per-tenant MQTT topic scoping they authorize.
- **OTA channel integrity** - a bad push reaches devices the operator does not
  physically control.
- **Auth material** - sessions, API bearer tokens, OAuth tokens, magic-link /
  reset tokens, passwords.
- **Device-config secrets** - per-device WiFi / MQTT / Telegram credentials,
  envelope-encrypted at rest.
- **Alert delivery integrity** - for a monitoring product a silently dropped
  alert is a core-value failure.
- **Operator power** - super-admin cross-tenant reach: impersonation, CA cert,
  device-secret push, fleet OTA.

## Trust boundaries

`internet -> app`, `app -> database`, `app -> MQTT broker`, `app -> device`
(via the broker), and the load-bearing one: **`tenant -> tenant`**.

## Assumed-trusted

The app server host, the database, the broker host, the operator's laptop, and
the CA chain rooted at the internal CA. Everything at rest on the host is
protected only as far as the envelope-encryption controls below reach; the host
itself is not defended (see non-goals).

## Assumed-hostile

- **Unauthenticated internet** - anyone who can reach the public endpoint.
- **Hostile tenant** - an authenticated tenant reaching for another tenant's
  data.
- **Stolen session / token** - a replayed cookie or bearer token.
- **Network MITM** - anyone on the wire between two trusted points.
- **Malicious / compromised device** - a device (or a broker-ACL drift) trying
  to write or read across the tenant boundary.

---

## What we defend against (per asset)

Attacker abbreviations: **net** = unauthenticated internet, **tenant** =
hostile authenticated tenant, **stolen** = stolen session/token, **MITM** =
network MITM, **device** = malicious/compromised device.

### Tenant data

| Attacker | Vector | Control | Known residual |
|---|---|---|---|
| tenant | IDOR / forged IDs coax a service method cross-tenant | App-layer `WHERE tenant_id` **plus** Postgres RLS `ENABLE`+`FORCE` on every tenant table, GUC set per-tx by `db.WithTenant`; three DB roles (app `NOBYPASSRLS`, admin `BYPASSRLS`, mqtt narrow-grant) | The `pools-app-guard` CI check is textual on `pools.App.`; a pool passed under another field name evades it (this is exactly how alert delivery silently died once). Review-caught only. |
| tenant | Cross-tenant read of the `device_telemetry` hypertable / continuous aggregates | Tenant-scoped `DeviceService.GetByID` resolves `device_pk` before the `WHERE device_pk` query | **Sensor history is single-layer**: `device_telemetry` and its aggregates carry no RLS policy - the app filter is the only isolation. (A docstring claiming transitive RLS here is stale; correction tracked separately.) |
| stolen | Super-admin cookie points `EffectiveTenantID` at any tenant | `RequireSuperAdmin` 404-cloaks `/admin`; service-layer `SetImpersonation` guarded `UPDATE ... WHERE is_super_admin` | Impersonation start/stop emits no durable audit of actor+target; a stolen super-admin cookie holds cross-tenant reach until expiry. |

### Internal CA private key

| Attacker | Vector | Control | Known residual |
|---|---|---|---|
| trusted-host compromise | Read `ca.key` from disk / backup / cold disk | `THESADA_CA_KEY_PASSPHRASE` -> AES-256-GCM + scrypt envelope (`THESADA-CAKEY-V1`), key `0600` / dir `0700`, wrong passphrase fails loud, never falls back to plaintext | Passphrase-unset default is **plaintext PEM on disk** (boot warning only, non-fatal). Even encrypted, the decrypted key sits in process memory after boot. KMS/HSM signer is roadmap, not built. |

### Device identity + broker credentials

| Attacker | Vector | Control | Known residual |
|---|---|---|---|
| device | Publish onto another tenant's `thesada/<other>/#` | `dynsecDeviceACLs` pins each device's publish scope to its own prefix; ingest re-checks `FindActivePairingTenant` in `onMessage` | A never-paired `device_id` is trusted on the topic-claimed tenant (cert-CN cross-check on auto-create is WIP). The shared `homeassistant/#` discovery tree is publish+retain for every device in every tenant. |
| device | Keep using a revoked cert (365-day validity) | `Revoke` flips `revoked=true` and deletes the dynsec client so the broker refuses the CN | No CRL/OCSP - enforcement rests on a **best-effort, warn-only** dynsec `deleteClient`; a failed delete silently leaves the cert working. |
| net | Mint a cert via `POST /admin/devices/{id}/pair/issue` | `RequireSuperAdmin` + CSRF on all pair routes; unauthorized access 404s | Stolen super-admin session passes outright (no step-up). Duplicate Issue accumulates multiple active certs (no revoke-prior guard). |

### OTA channel integrity

| Attacker | Vector | Control | Known residual |
|---|---|---|---|
| stolen | Stolen super-admin drives fleet `ota.check --force` | `RequireSuperAdmin` + CSRF; device-side SHA256 verify + abort-on-mismatch means a bad download never flashes | The app-side fan-out has **no audit trail / state_change** - nothing durably records who triggered a fleet push. Publish is QoS-0 fire-and-forget. |
| MITM | Serve a bad manifest/image between device and release origin | None in-app - authenticity is fully delegated to firmware (SHA256 + TLS-to-origin + no-CA refusal) | The app neither signs nor pins the manifest; a compromised release artifact is out of app scope (accepted delegation). |

### Auth material

| Attacker | Vector | Control | Known residual |
|---|---|---|---|
| trusted-host compromise | DB dump recovers replayable credentials | All token families stored **SHA256-only**; passwords bcrypt (cost 10, 10-char floor at the service layer) | `oauth_providers.client_secret` is the one plaintext auth secret at rest (PKCE + fixed redirect bound the blast radius; IdP rotation required on leak). |
| stolen | Replay an exfiltrated cookie/token | 4h session rotation (CAS single-winner + 60s grace), HttpOnly+SameSite=Lax+Secure, SHA256 storage; API tokens 90-day + revoke | **No revoke-all lever** - password reset does not invalidate existing sessions (thief survives reset up to 30d); API tokens never rotate. |
| net | Credential stuffing on `/login`, `/api/v1/auth/login` | Service-layer per-email + per-IP rate limit (429), shared web+API; constant-time login (decoy bcrypt); enumeration-resistant responses | No MFA of any kind. If `THESADA_TRUSTED_PROXIES` is unset behind the proxy, the per-IP limiter collapses to one global bucket. |
| MITM / stolen | Harvest a magic-link/reset token, or CSRF the magic-link GET | Single-use atomic consumption (`UPDATE ... RETURNING WHERE consumed_at IS NULL`), 32-byte tokens, purpose-separated TTLs; signed double-submit CSRF over the whole mux | The raw token rides a **GET query string** (browser history + proxy logs for its TTL). `GET /login/verify` mutates state outside the unsafe-method CSRF gate -> a magic-link login-CSRF can sign a victim into the attacker's tenant. |

### Device-config secrets

| Attacker | Vector | Control | Known residual |
|---|---|---|---|
| tenant / backup-leak | Read or relocate another tenant's secret ciphertext | RLS `FORCE` on `device_config_secrets` + per-tenant DEK; AAD binds every value to tenant/device/field so a relocated blob fails GCM open; tenant delete crypto-shreds the DEK | Root KEK sits in process memory after boot. Legacy pre-backfill `device_file_history` rows may still hold plaintext (backfill does not purge them). |
| stolen | Read back a stored secret value | **Write-only contract**: no read-back route; `Reveal` decrypts server-side only for pair/provision and is unwired from any handler | Enforced by convention + review, not a compile-time guard; a future handler returning `Reveal` output breaks it silently. A super-admin can still push secrets to device NVS cross-tenant. |

### Alert delivery integrity

| Attacker | Vector | Control | Known residual |
|---|---|---|---|
| MITM / misconfig | Channel down or SMTP unconfigured -> silent drop | Lifecycle `pending -> delivered/none/dead` with backed-off retry + dead-letter; unconfigured SMTP now **fails loud** instead of a silent no-op; startup redispatch recovers process-death mid-alert | `dead` is operator-visible only (no end-user UI). Channel success is per-alert not per-recipient. The redispatch claim is in-process - a second instance double-sends. |
| device | Spoofed / duplicate / flooded alerts | Severity validated against the DB CHECK; cross-tenant pairing gate; bounded insert-retry then dead-letter | No dedup key (retained `/alert` re-ingests and re-notifies on every reconnect); no ingest-rate limit, so a compromised device can spam its own tenant. The Telegram bot token can leak into an error log on a send failure (URL-path token; correction tracked separately). |

### Operator power (cross-tenant accountability)

| Attacker | Vector | Control | Known residual |
|---|---|---|---|
| stolen / insider | Quiet cross-tenant browsing via the legitimate admin UI with a super-admin credential | Every `BYPASSRLS` access routes through `db.WithAdminAudit` (~38 call sites, one chokepoint) | **Audit is log-only** and marked WIP: the line carries a reason string, no actor / target / row identity, and the durable audit table is scaffolded but unconsumed. Routine per-request calls flow through the same wrapper, drowning genuine cross-tenant reads. (This is the gap the authorization-layer + audit-trail work closes.) |

---

## Explicit non-goals

- **Nation-state / APT** adversaries.
- **Physical extraction** of key material, and HSM-grade protection of keys in
  use - the CA key and root KEK live in process memory after boot; KMS/HSM
  signing is roadmap.
- **Root on the app or broker host** - a live-process or host compromise reads
  decrypted keys and env secrets; envelope encryption defends backup-leak and
  cold-disk theft, not a live root.
- **The self-hosted perimeter** - host OS, Postgres, the MQTT broker host, and
  the reverse proxy are the operator's to harden. The shipped quickstart
  broker/compose is explicitly not hardened; production needs TLS + per-device
  mTLS + ACLs on the broker and `THESADA_TRUSTED_PROXIES` set to the proxy.
- **Upstream dependency vulnerabilities** - report to their maintainers; CI
  gates (govulncheck, gosec, coverage on the security packages) reduce but do
  not own this.
- **Backup confidentiality** - backup encryption and storage are the operator's;
  the app crypto-shreds a deleted tenant's DEK but does not encrypt backups.
