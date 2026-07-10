# Security review checklist

Run at PR time when a change adds or widens **attack surface**: a new HTTP endpoint, a new admin action, a new MQTT publish path, or anything crossing the tenant boundary. Paste the table into the PR description and answer every row. "N/A" is a valid answer if you can say why.

This is the security-specific pass. The broader readiness gate is [`pre-launch-checklist.md`](pre-launch-checklist.md); the two overlap on "threat model" and "adversarial pass" by design.

---

## Checklist

| # | Check | What good looks like |
|---|-------|----------------------|
| 1 | [ ] Authenticated? How? | Names the mechanism: session, OAuth, magic-link, admin role. Public endpoints are stated as intentionally public. |
| 2 | [ ] Tenant-scoped? Via what mechanism? | Every query filters on `EffectiveTenantID`, never a raw `u.TenantID` or unscoped table (see #519). Cross-tenant read is super-admin-audit only and logged. |
| 3 | [ ] Input validated? | Type, length, range checked server-side before use. Client validation does not count. |
| 4 | [ ] Path traversal / SSRF possible? | File and URL inputs are canonicalised and allow-listed. No caller-supplied path or host reaches the FS or an outbound request unchecked. |
| 5 | [ ] Injection vectors? Parameterized? | All SQL parameterized. No string-built queries, topics, or shell args. |
| 6 | [ ] Rate limited? Should it be? | Auth, magic-link, and enumeration-prone endpoints are throttled or have a stated reason they are not. |
| 7 | [ ] Logged? Level + context? | Dotted structured event on state change, with a `state_change` marker on security edges. No PII (no raw email) in the payload (see #520). |
| 8 | [ ] Audit trail for privileged actions? | MQTT publish, waitlist convert, impersonation, credential rotation leave a searchable trail (the #79 audit layer). |
| 9 | [ ] CSRF protection on state-changing routes? | Token present and validated; `RequestIsSecure` trusts `X-Forwarded-Proto` only from the known proxy, not any peer (see #517). |
| 10 | [ ] Error messages leak info? | No stack traces, internal IDs, or tenant existence oracles returned to unauthenticated callers. |
| 11 | [ ] Failure mode designed? | Documented what happens on DB lag, broker down, mail outage - multi-step admin flows are retry-safe / transactional (#79). |

---

## Scope

Applies to: a new HTTP endpoint, a new admin surface, a new MQTT publish path, a new OAuth/provider integration, anything reading or writing across tenants.

Does NOT apply to: internal refactors, doc-only changes, test-only commits.

---

Related: [`pre-launch-checklist.md`](pre-launch-checklist.md), [`invariants.md`](invariants.md), [`security.md`](security.md).
