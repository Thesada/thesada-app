# thesada-app code guidelines

How to write code in this repo. Reference material for PR review.
Sibling to [docs/invariants.md](docs/invariants.md) (the load-bearing
rules).

Dated 2026-06-22. Bump on every edit.

---

## Comments

### Default: no comment

Names do the talking. `userTenant := authmw.EffectiveTenantID(r)` does
not need a comment.

### Comment only WHY, not WHAT

The code already shows what. Comments cover hidden constraints, subtle
invariants, workarounds for specific bugs, or behaviour that would
surprise a reader. If removing the comment would not confuse the next
reader, do not write it.

Good:
```go
// SIM7080G fw 1951B17 silently drops empty-payload +SMSUB URCs.
// Substitute "{}" so the device receives the SMSUB even for zero-arg
// commands.
payload := "{}"
```

Bad:
```go
// Set payload to "{}"
payload := "{}"
```

### Function header comments

Every exported function (and large unexported functions) gets a short
header: a one-line what, then `in:` / `out:`. Keep it to 1-3 lines.

```go
// CreateSession stores a session token's sha256 hash and returns the raw
// token for the cookie (hash-only storage so a leaked DB exposes no live sessions).
// in: user id, auth method. out: raw token, db row id, error.
func (s *AuthService) CreateSession(userID uuid.UUID, method AuthMethod) (string, uuid.UUID, error) {
```

Headers are not the place for essays. One subtle WHY clause is fine; full
rationale (alternatives considered, history, tuning math) goes in the commit
body or a session doc, never the header. If a header runs past ~3 lines, the
extra lines are rationale that belongs elsewhere.

Big functions get split into helpers. Three similar lines is better
than a premature abstraction; thirty lines of nested branching is not.

### Do NOT comment

- WHAT the code does (names do that).
- The current task / fix / callers ("used by X", "added for the Y
  flow") - those rot as the codebase evolves and belong in the commit
  body.
- TODOs without an owner.

---

## Logging

### Structured key=value, never interpolated

Every `slog.Info` / `Warn` / `Error` call uses structured fields, not
`fmt.Sprintf` into the message.

Good:
```go
slog.Info("magic.link.sent", "user_id", u.ID, "expires_at", expiresAt)
```

Bad:
```go
slog.Info(fmt.Sprintf("magic link sent for user %s, expires %s", u.ID, expiresAt))
```

Reason: logs are queryable, not just human-readable. At 3am, someone
greps `magic.link.sent` and filters by `user_id=...`. The interpolated
form is grep-hostile.

### Event names are dotted subsystem.action on security and state edges

Security-sensitive and state-transition logs use a stable, queryable
`subsystem.action` (or `subsystem.subaction.detail`) name. These are the
lines you grep and alert on in prod, so the taxonomy earns its keep here.
Examples:

- `auth.session.created`
- `oauth.callback.state_mismatch`
- `mqtt.dynsec.role_created`
- `device.pair.cert_issued`

Operational and debug breadcrumbs (a failed upgrade, a retry, a dropped
frame) may stay prose - they are already structured slog key=value and a
forced taxonomy is churn with no query payoff. Rule of thumb: if you would
alert or audit on it, dot it; if you only read it while debugging, prose is
fine.

### State machine transitions emit `<subsystem>.state_change`

The security/state edges - pairing flow, OAuth flow, OTA progress, alert
delivery, auth - emit a transition log on every edge. Operational paths do
not need one.

```go
slog.Info("auth.session.state_change",
  "from", "anonymous", "to", "authenticated",
  "user_id", u.ID, "method", method)
```

### Level discipline

- `slog.Debug` - tracing during development, opt-in via env var.
- `slog.Info` - normal lifecycle events, audit trail.
- `slog.Warn` - the system continues but a human should know.
- `slog.Error` - something failed; include error in fields.

Do not log raw passwords, raw tokens, cookie values, or PKCS#8 key
material at any level.

---

## Silent fallbacks: reject them

Every `if err != nil { return nil }`, every default value, every
"this probably never happens" branch: ask "is this hiding a real
condition?"

### Prefer loud failure with a clear error

```go
if err != nil {
  return nil, fmt.Errorf("auth: load user %s: %w", userID, err)
}
```

### Document any fallback you keep

If a fallback is the right choice, write the comment that says why.
Otherwise the next reader will think it is sloppy and "improve" it
into a bug.

```go
// Telegram chat_id is optional - users without a configured chat
// silently skip the channel rather than failing the whole alert.
// Email + on-page notifications still fire.
if u.TelegramChatID == nil { return nil }
```

---

## Test naming

### Tests are documentation of the contract

Test names are the guarantee, not the procedure. Read the test name
in isolation - it should describe what the system promises.

Good:
```go
TestCSRF_RejectsPostWithoutToken
TestAuthService_MagicLinkSingleUse_UnderConcurrentRequests
TestLimiter_SweepDeletesEmptyKeys
TestOAuth_StateReplay_ReturnsError
```

Bad:
```go
TestCSRF1
TestThing
TestMagicLinkWorks
```

### Security-sensitive code: write the contract test even when nothing is broken

If a function is part of the auth / CSRF / OAuth / pkg-pki / tenant-
scoping path, the contract test exists. The test describes what must
remain true. It runs in CI on every PR.

The `coverage` job in ci.yml enforces 80 %+ statement coverage on
`pkg/csrf`, `pkg/oauth`, `pkg/pki`, and `pkg/authmw` via
`scripts/check-coverage.sh` (run it locally with `make cover`).
`pkg/service/auth.go` is exercised by the integration lane, not this
gate.

---

## When you find a bug, find its siblings

Before fixing one occurrence, grep for the same pattern across the
codebase.

Example: a path-traversal review on a sibling firmware project found
the same pattern was only checked at one of three transports. Fixing
only one would have left the other two wide open. The fix was to
centralise the policy + apply at every transport in one PR.

Process:
1. Find the bug.
2. Read the surrounding code for the pattern that allowed it.
3. Grep the rest of the codebase for the same pattern.
4. Fix all instances in one PR (or document why some are different).
5. Add the pattern to [docs/invariants.md](docs/invariants.md) if it
   is not already there.

---

## SQL discipline

### Always parameterised

Never `fmt.Sprintf` a *value* into a SQL string. pgx parameter binding only.

```go
// Good
rows, err := pool.Query(ctx, "SELECT id FROM devices WHERE tenant_id = $1", tenantID)

// Bad - SQL injection risk + grep-hostile
rows, err := pool.Query(ctx, fmt.Sprintf("SELECT id FROM devices WHERE tenant_id = '%s'", tenantID))
```

Exception: building a `$N` placeholder *index* for an optional filter is
fine, as long as every value still goes through the args slice. What gets
interpolated is the bind index, never user data.

```go
// OK - Sprintf builds "$3"; the value lives in args
if severity != "" {
    args = append(args, severity)
    query += fmt.Sprintf(" AND severity = $%d", len(args))
}
```

### Tenant-scoped reads go through `db.WithTenant`

Target state. A CI lint will fail any new caller of
`pools.App.{Query,QueryRow,Exec}` outside `pkg/db/tenant.go`.

```go
return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
  return tx.QueryRow(ctx, sql, args...).Scan(&x)
})
```

Cross-tenant admin reads use `db.WithAdminAudit` against
`s.pools.Admin`. Method names end in `Any`.

### Migrations are forward-only after merge

`migrations/NNNN_description.sql` plus a doc-comment header explaining
the WHY and any rollback caveat. No `DROP TABLE` without an explicit
operator runbook reference. Migrations shipped ahead of their consumer
code can be gated on prod readiness via the `gatedMigrations` map in
`migrate.go` (currently empty - `THESADA_APPLY_RLS_POLICIES` gated
`0016_rls_policies` until RLS became the steady-state default).

---

## HTML and templating

### `html/template` for HTML, `text/template` only for plain text

`html/template` auto-escapes by default. `text/template` does not.
Mixing them is an XSS vector.

```go
import (
  "html/template"
  texttemplate "text/template"
)
```

Plain-text email bodies are the only legitimate `text/template`
consumers, and even those use `html/template` for the HTML MIME part.

---

## Error handling

### Wrap errors with context

`fmt.Errorf("subsystem: doing-thing for %s: %w", key, err)`. The
subsystem prefix lets the reader trace which layer raised the error
without unwrapping. `%w` preserves the chain for `errors.Is` /
`errors.As`.

### `recover()` is not the default

This codebase is panic-free under reasonable input. Adding
`defer recover()` is a code smell unless the goroutine processes
external input that could trigger a panic (eg JSON parse, regex
compile from user data).

---

## Goroutines

### Every goroutine has a clear lifecycle

- Started where? (`web.New`, `mustStartMQTT`, `cmd/main.go`).
- Stopped how? (context cancel, channel close, sentinel value).
- What happens if it panics? (recover? crash the binary? log + exit?).

If a goroutine can be triggered by user input (eg HTTP handler spawns
work), guard the entry against panic so a malformed request cannot
crash the binary.

### Context everywhere

Every long-running goroutine takes a `context.Context` parameter and
exits cleanly on `ctx.Done()`. Singletons started at app boot can use
`context.Background()` - they live for the binary's lifetime. Add a
comment explaining the choice.

---

## Stop-doings

These are mistakes we have made before. Don't repeat them.

### Stop treating "I know this works" as documentation

The implicit knowledge in your head is the single biggest gap between
"this codebase is OK" and "this codebase is defensible." Every time
you catch yourself thinking "I know why this is here," that is a
comment that is missing.

### Stop deferring small fixes when you're already in the file

Every low-priority polish item (10-30 minutes each) is on the list
because nobody fixed it while they were in the file for some other
reason. When you touch a file, fix any open polish item that lives in
it. Leaves the codebase cleaner than you found it.

### Stop letting test coverage drift on security paths

New auth code without tests = doesn't merge. New tenant-scoping code
without tests = doesn't merge. Hard rule, not aspiration: the ci.yml
`coverage` job blocks any security package that drops below 80 %.

### Stop writing prose where a checklist would do

Operational docs (runbook, security review) live by being scanned at
3am, not read. Convert prose-heavy operational docs to numbered
checklists + decision trees. Save the prose for blog posts.

### Stop committing without running tests

`go build ./... && go test ./...` is the bare minimum before
`git commit`. Pre-commit hook should enforce. CI is a backstop, not
a substitute.

---

## What this list is not

- Not a style guide (gofmt + golangci-lint cover style).
- Not architecture documentation
  ([docs/invariants.md](docs/invariants.md) covers load-bearing
  rules).
- Not a tutorial.

It is the set of habits that distinguish "this code works" from
"this code stays defensible." Read it on the way into a new file.

Related: [docs/invariants.md](docs/invariants.md),
[docs/security.md](docs/security.md) (security scanner gating).
