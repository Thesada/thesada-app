# Pre-launch checklist

Run before opening a new endpoint / module / MQTT cmd / board to traffic.

---

## Checklist

| # | Check | Why |
|---|-------|-----|
| 1 | [ ] Threat model updated? | New attack surface changes the threat model. Write down what you are exposing, who can reach it, and what the worst-case abuse looks like before anyone else can. |
| 2 | [ ] Failure modes documented? | Silent failures in app code produce bad DB state, dangling device pairing, or leaked credentials. List what breaks, how loudly. |
| 3 | [ ] Observability hooks in place (logs + metrics)? | If you cannot see it in `slog` output or a Prometheus counter at 3am, you cannot debug it at 3am. Every new subsystem emits at least one structured log on state change. |
| 4 | [ ] Tests for the contract, not just the bug? | Regression tests catch the bug that was fixed. Contract tests catch the next bug. Cover the invariant (`pkg/service/*_integration_test.go`), not the incident. |
| 5 | [ ] Adversarial pass done? | Spend 15 minutes pretending to be an attacker. Send malformed input, skip auth steps in sequence, try cross-tenant IDs, replay tokens. File findings before merging. |

---

## Scope

This checklist applies to:

- A new HTTP handler (route in `pkg/web/`)
- A new MQTT topic subscription or command handler (`pkg/mqtt/`)
- A new service method that touches tenant data (`pkg/service/`)
- A new admin or super-admin endpoint
- A new auth flow, token type, or session path

It does NOT apply to internal refactors, doc-only changes, or test-only commits.

---

## Minimum bar per item

### 1. Threat model updated

Answer these before opening the PR:

- What is exposed? (route, MQTT topic, service method)
- Who can reach it? (anonymous, any authed user, tenant admin, super-admin only)
- Is tenant isolation enforced? (`db.WithTenant`, `RequireSuperAdmin`, or explicit bypass in `db.WithAdminAudit`)
- What is the blast radius of a successful exploit?

Add or update the relevant section in `docs/invariants.md`.

### 2. Failure modes

For every new handler or service method, answer:

- What happens on malformed input? (4xx + log, or panic?)
- What happens on partial write or constraint violation? (rollback? orphaned row?)
- What happens if the downstream dependency (DB, MQTT broker, PKI) is unavailable?
- Does failure leak internal details (stack trace, SQL error, cert path) to the caller?

Errors returned to HTTP callers must not include raw DB errors, stack traces, or internal file paths.

### 3. Observability

Minimum per new subsystem:

- `slog.Info` on successful init and key state transitions
- `slog.Error` or `slog.Warn` on every error path that an operator needs to act on
- At least one Prometheus counter or gauge if the path is in the hot loop (MQTT `onMessage`, `handleInfo`, drift detection)

See `docs/invariants.md` - auth, session, and MQTT handlers each have their own observability requirements.

### 4. Contract tests

Unit tests that only verify the happy path are insufficient. For service-layer changes, write or extend `pkg/service/*_integration_test.go`. Minimum coverage:

- Cross-tenant isolation (another tenant's ID returns `ErrNotFound`, not the row)
- Rejected inputs (empty string, zero UUID, malformed payload)
- Concurrent access (token consume race, session rotation race - see existing patterns)
- The post-condition that must hold after a successful call

Run integration tests with `make test-integration` against a throwaway TimescaleDB.

### 5. Adversarial pass

Walk through the new surface manually. Minimum actions for an HTTP endpoint:

- Send an unauthenticated request - expect 401 or redirect, never 200
- Send a request with another tenant's resource ID - expect 403 or 404, never the resource
- Send a request with a super-admin-only resource as a regular authed user - expect 403
- Replay a consumed token (magic-link, reset, OAuth state) - expect `ErrNotFound`
- Send a CSRF-bypass attempt (missing header / cookie) on any mutating endpoint - expect 403
- Plant an unsigned `thesada_csrf` cookie and submit it as the form token - expect 403 (signed double-submit rejects it)
- Hammer `/login` (and `/api/v1/auth/login`) past the per-email cap - expect 429, not an endless 401 stream
- Boot with a sub-32-byte `THESADA_COOKIE_SECRET` and no override - expect startup to abort; confirm `THESADA_ALLOW_WEAK_SECRET=1` lets it boot with a warning
- Fuzz payload size and field types

For MQTT:

- Publish to another device's `cli/` topic (if the broker ACL permits) and verify the app does not process it for the wrong tenant
- Send an oversized payload to a new command topic and verify no panic or deadlock

Document what you tried and what happened. "Did adversarial pass - no issues found" is an acceptable entry if you actually did it.

---

Related: [`invariants.md`](invariants.md), [`security.md`](security.md), [`../CODE-GUIDELINES.md`](../CODE-GUIDELINES.md).
