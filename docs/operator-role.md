# Operator role

What a platform operator can and cannot do, and how. Written for a stranger on call: assume the reader has admin access and a running incident, and knows nothing else.

Each capability lists where it lives. Each **gap** is an operation an operator would reasonably need but that has **no tool** today - those are the load-bearing items to build, not just document.

---

## Access model

- **Super-admin gate.** Everything under `/admin/*` requires `is_super_admin`. A non-super-admin gets a **404** (not 403), so the admin tree is undiscoverable. There is no intermediate "tenant-admin" web surface: `is_admin` only flips *inside* a tenant.
- **Effective tenant.** A super-admin can set an impersonated tenant on their session ("view-as"); the effective tenant is then that tenant. Otherwise it is the operator's own tenant.
- **Two DB paths.** Normal requests run row-level-security-scoped (`SET app.tenant_id`). Cross-tenant reads run on a separate BYPASSRLS "admin" pool and are **logged** (`rls.admin_audit`). Cross-tenant *writes* are executed scoped to the target tenant the operator picks.

> Correction to the old assumption "operator can read but not write across tenants": not true. A super-admin reads **and writes** across tenants (create/delete tenants and users, reassign devices, issue/revoke certs, set secrets, publish MQTT). Reads are audited; writes are tenant-scoped per action but the operator chooses the target.

---

## What the operator can do (admin UI)

| Area | Capability | Where |
|------|-----------|-------|
| Tenants | Create / delete a tenant (delete guards the default tenant + an active impersonation target) | `/admin/tenants`, `/admin/tenants/{slug}/delete` |
| Users | List / create / edit / delete a user in **any** tenant; toggle a user's admin flag | `/admin/tenants/{slug}/users/...` |
| Users | Send a password-reset link | `/admin/tenants/{slug}/users/{id}/send-reset` |
| Waitlist | Convert a waitlist entry into a user (into an existing tenant, emails a reset link); delete an entry | `/admin/waitlist/{id}/convert`, `/delete` |
| View-as | Impersonate a **tenant** (switch effective tenant); clear it | `/admin/impersonate/{slug}` |
| Devices | List all devices cross-tenant; reassign a device to another tenant (single + bulk) | `/admin/devices`, `/admin/devices/{id}/reassign` |
| Devices | Delete a device (revokes cert + tears down dynsec + clears retained topics + DB cascade) | `/admin/devices/{id}/delete` |
| Certs | **Issue / re-issue** a device cert (signs, pushes cert+key+secrets over MQTT, creates dynsec role+client, marks paired) | `/admin/devices/{id}/pair/issue` |
| Certs | **Revoke** a device cert (DB revoke + dynsec delete + push device into password-recovery mode) | `/admin/devices/{id}/pair/revoke` |
| Certs | Download the CA cert (PEM) | `/admin/ca.crt` |
| MQTT | Live subscribe tap + publish (publish restricted to `root/<tenant>/`, rate-limited) | `/admin/mqtt` |
| Device shell | Run arbitrary firmware CLI, read/write device config, snapshot, history over MQTT | `/admin/devices/{id}/...` (config/cmd, config/write, fs.write) |
| Secrets | Set (write-only, no read-back) + provision a device-config secret to device NVS | `/admin/devices/{id}/secrets/set`, `/provision` |
| Fleet | Bulk OTA check (`cli/ota.check --force`) to selected devices | `/admin/devices/bulk` (action=ota) |
| Debug | Build info + **redacted** live config dump (sensitive keys masked) | `/admin/debug` |

## Platform-owner operations (CLI / host shell, not the UI)

These need shell access to the host and, for some, an env var. An operator who only has the admin UI **cannot** do these.

| Capability | Command |
|-----------|---------|
| Run DB migrations | `thesada-app migrate` |
| Encrypt the CA private key at rest | `thesada-app ca-encrypt` (needs `THESADA_CA_KEY_PASSPHRASE`) |
| Backfill device secrets into the encrypted store | `thesada-app backfill-secrets` |
| Rotate the device-config root KEK (re-wrap every tenant DEK) | `thesada-app rotate-kek` (needs `THESADA_DEVICE_CONFIG_KEK_NEW`) |

---

## What the operator CANNOT do (gaps)

These are operations an on-call operator would reach for and find no tool. Each is a build target.

1. **Rotate a tenant's / device's broker-side MQTT credential.** No endpoint, no CLI. The dynsec client is written once at pair time as a cert-auth (empty-password) client, and the dynsec driver has no `setClientPassword`/`modifyClient`. Only workarounds: revoke + re-pair the device (new cert identity), or set the per-device `mqtt.password` secret and re-provision.
2. **Toggle tenant runtime settings from the UI** (`mqtt_cross_tenant_read`, `multi_tenant_mode`). The templates *show* these flags and the code comments claim they are flippable at runtime, but no route calls `SettingsService.SetBool` - changing them today needs a **direct DB write**. (This both is a gap and breaks the "no direct DB access" goal.)
3. **Per-user impersonation ("become user X").** Only tenant-level view-as exists; the acting identity stays the super-admin. No way to reproduce a specific end user's session for support.
4. **Convert a waitlist entry straight into a new tenant.** Convert only creates a user in an *existing* tenant; tenant creation is a separate manual step. No single "onboard new customer" flow.
5. **Reassigning a device does not re-key the on-device topic prefix.** Reassign updates only the app-side row; the device's `mqtt.topic_prefix` must be changed out of band. No tool pushes the new prefix.
6. **KEK rotation + CA-key encryption are CLI-only** - not doable by a UI-only operator.
7. **Revocation is not broker-enforced (no CRL/OCSP).** Revoke flips the DB row and deletes the dynsec client; a still-valid cert is kept out by the dynsec delete, not by CRL/OCSP. Flagged for "is a revoked cert actually rejected."

---

Related: [`security-review-checklist.md`](security-review-checklist.md), [`../SECURITY.md`](../SECURITY.md), [`security.md`](security.md).
