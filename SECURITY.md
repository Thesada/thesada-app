# Security Policy

## Reporting a Vulnerability

Report security issues privately - please do not open a public issue.

**Preferred:** GitHub private vulnerability reporting. Open the **Security** tab of this repository and click **"Report a vulnerability"** (Security -> Advisories -> Report a vulnerability). The report stays private and threaded with the maintainer.

**Alternative:** email **info@hit-con.ca** with a description, steps to reproduce, and relevant version information.

Response target: acknowledgement within 5 business days.

## Coordinated Disclosure

This project follows a **90-day coordinated disclosure** policy. After reporting:

1. I will confirm receipt and assess severity.
2. We agree on a fix timeline (typically within 90 days).
3. A fix is released before public disclosure.

If a fix cannot land within 90 days I will communicate the reason and negotiate a reasonable extension.

## Scope

**In scope:**

- Application code in this repository (server, web, API, background workers)
- Authentication and authorization: sessions, OAuth/OIDC, magic-link, the admin/operator roles
- Tenant isolation - any path that reads or writes across tenants
- MQTT broker integration (dynamic-security provisioning, per-tenant credential scoping)
- Device pairing, certificate minting, and the OTA distribution channel
- Handling of the internal CA private key and device-config secrets

**Out of scope:**

- Vulnerabilities in upstream libraries (Go modules, JS packages) - report these to their maintainers
- The self-hosted deployment (Postgres, the MQTT broker host, reverse proxy, host OS) - infrastructure concerns, not this repo
- Physical access to the server host

## Threat Model (honest summary)

thesada-app is the **multi-tenant** control plane for self-hosted property monitoring: it onboards tenants, provisions device identities, brokers MQTT credentials, ships OTA firmware, and delivers alerts. Where the firmware (thesada-fw) is single-owner on a private network, the app assumes **mutually distrustful tenants** sharing one deployment, plus unauthenticated internet traffic.

This section is the summary; the per-asset, per-attacker matrix (controls and honest residual gaps) lives in [`docs/threat-model.md`](docs/threat-model.md).

**Assets:**

- Tenant data (sensor history, device inventory, contact + alert config)
- The internal **CA private key** - it mints every device certificate, so it is the highest-value secret
- Device identities and broker credentials (per-tenant MQTT dynsec scoping)
- OTA channel integrity (a bad push reaches devices the operator does not physically control)
- Auth material: sessions, OAuth tokens, magic-link tokens
- Alert delivery integrity

**Trust boundaries:** internet -> app, app -> database, app -> MQTT broker, app -> device (via broker), and the load-bearing one: **tenant -> tenant**.

**Assumed-trusted:** the app server host, the database, the broker host, the operator's laptop, and the CA chain rooted at the internal CA.

**Assumed-hostile:** any unauthenticated user; any authenticated tenant reaching for another tenant's data; anyone holding a stolen session or token; the network between any two trusted points.

The primary realistic risks:

- **Cross-tenant access** via a query that forgets its tenant scope - the load-bearing control, see the tenant-isolation note below
- Auth compromise: magic-link or OAuth/OIDC misconfiguration, session fixation, token replay
- **CSRF** on state-changing admin routes, including `X-Forwarded-Proto` spoofing when the proxy header is trusted from an untrusted peer
- A privileged admin action (impersonation, credential rotation, MQTT publish) taken without a durable **audit trail**
- **CA private-key exposure** - compromise mints trusted device certs fleet-wide
- Broker credential leakage or a dynsec misconfiguration letting one tenant's device publish into another's topics

### Tenant isolation (load-bearing)

Every tenant-scoped query must filter on the request's **effective tenant**, never a raw user tenant field or an unscoped table. Cross-tenant reads exist only for super-admin auditing and are logged. A single unscoped query is a data-leak boundary, so new data-access paths run through the [security review checklist](docs/security-review-checklist.md) before merge.

### CA private-key protection

The internal CA key is the highest-value secret in the system; its at-rest protection, rotation, and the long-term HSM/KMS plan are documented in [`docs/security.md`](docs/security.md).

## Supported Versions

Only the latest release on the `main` branch is supported. No backport patches are planned.
