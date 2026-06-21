# Contributing to thesada-app

Short version: read `docs/invariants.md` first. The rules in that file
are load-bearing - every PR has to keep them true.

## Local development

```
make dev           # build + run with local config
make test          # go test ./...
make test-integration  # DB-backed tests behind the integration build tag
make lint          # golangci-lint run --build-tags integration ./...
```

Integration tests are fenced behind the `integration` build tag and are
not in `make test` or the default CI lane - they need a live database.
Run them against a disposable TimescaleDB:

```
THESADA_TEST_DATABASE_URL='postgres://postgres:pw@127.0.0.1:5432/thesada_app?sslmode=disable' \
    go test -tags integration ./...
```

See `pkg/db/rls_integration_test.go` for the RLS acceptance test and its
database preconditions.

## CI gates

Every PR has to pass four gates before merge.

| Workflow | Job | What it checks |
|---|---|---|
| `lint.yml` | `golangci-lint` | The curated linter set in `.golangci.yml` (errcheck, staticcheck, govet, ineffassign, unused, bodyclose, errorlint, misspell, prealloc, unconvert). |
| `lint.yml` | `pools-app-guard` | No new `pools.App.{Query,Exec,...}` callers outside the grandfathered allowlist. See **Tenant isolation guard** below. |
| `security.yml` | `govulncheck` | Reachable-symbol vuln scan (`golang.org/x/vuln`). |
| `security.yml` | `gosec` | HIGH-severity static security findings; full report uploaded as a workflow artifact. |

## Tenant isolation guard

Every read against the application database has to be tenant-scoped.
The contract lives in `pkg/db/tenant.go`:

- `db.WithTenant(ctx, pool, tenantID, fn)` opens a pgx transaction,
  runs `SET LOCAL app.tenant_id = $1`, and hands the tx to `fn`.
  Postgres RLS policies (migration `0016_rls_policies.sql`) read
  `app.tenant_id` and scope rows automatically.
- `db.WithAdminAudit(ctx, pool, ...)` is the explicit cross-tenant
  bypass. Use `pools.Admin` (the `BYPASSRLS` role); every call writes
  an audit row.

Direct `pools.App.{Query,QueryRow,Exec,Begin,SendBatch,CopyFrom,
BeginTx}` calls are forbidden in any file not listed in
`scripts/pools-app-allowlist.txt`. The CI guard
(`scripts/check-pools-app.sh`) is what enforces this.

### Migrating a file off the allowlist

The systematic RLS rollout converts the grandfathered
`pkg/service/*.go` files. The workflow per file:

1. Rewrite each `pools.App.{Query,Exec}` call to flow through
   `db.WithTenant` (or `db.WithAdminAudit` for super-admin-only paths
   - those should already be named `*Any`).
2. Run `make test` - the tx-per-call shape sometimes surfaces missing
   ctx threading or rollback expectations.
3. Delete the file's line from `scripts/pools-app-allowlist.txt`.
4. Re-run `bash scripts/check-pools-app.sh` locally - should still
   pass for the migrated file and fail loudly if you missed a call.

The allowlist is a TODO list, not a permanent exception list.

### Adding a deliberate exception

If a new file genuinely needs the direct pool (a health check, a
migration helper, internal `pkg/db` machinery), add it to
`scripts/pools-app-allowlist.txt` with a comment explaining the
exception in the same PR. The reviewer's job is to push back if the
exception is dodging the contract instead of carving out a
narrow-scope escape hatch.

## Commit messages

- Subject line under ~72 chars, imperative voice.
- Body explains *why*, not *what* - the diff shows the what.
