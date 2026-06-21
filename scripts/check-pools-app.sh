#!/usr/bin/env bash
# check-pools-app.sh - guard against new tenant-unscoped DB callers.
#
# Locks in the "every read against pools.App is tenant-scoped through
# db.WithTenant" target state (docs/invariants.md "Tenant isolation").
#
# Rule: any *.go file (non-test) that calls pools.App.{Query, QueryRow,
# Exec, Begin, SendBatch, CopyFrom, BeginTx} must be in the allowlist at
# scripts/pools-app-allowlist.txt. Each line of the allowlist is a file
# path relative to the repo root, or a path glob ending in / (treated as
# a prefix). Comments (# ...) and blank lines ignored.
#
# To migrate a file off the allowlist: replace direct pools.App.* calls
# with db.WithTenant or db.WithAdminAudit, then delete the line from
# scripts/pools-app-allowlist.txt. CI will then catch any regression.
#
# Usage:
#   scripts/check-pools-app.sh
# Exit code 0 = pass, 1 = new violation, 2 = config error.

set -euo pipefail

cd "$(dirname "$0")/.."

ALLOWLIST="scripts/pools-app-allowlist.txt"
if [ ! -f "$ALLOWLIST" ]; then
  echo "check-pools-app.sh: missing $ALLOWLIST" >&2
  exit 2
fi

pattern='pools\.App\.(Query|QueryRow|Exec|Begin|SendBatch|CopyFrom|BeginTx)'

# Files containing the pattern, excluding *_test.go and vendor/.
mapfile -t HITS < <(
  grep -REln "$pattern" --include='*.go' . \
    | sed 's|^\./||' \
    | grep -Ev '(^|/)vendor/' \
    | grep -Ev '_test\.go$' \
    | sort -u
)

# Parse allowlist: exact paths or directory prefixes (lines ending in /).
mapfile -t EXACT < <(grep -Ev '^\s*(#|$)' "$ALLOWLIST" | grep -v '/$' || true)
mapfile -t PREFIX < <(grep -Ev '^\s*(#|$)' "$ALLOWLIST" | grep '/$' || true)

is_allowed() {
  local f="$1"
  local e p
  for e in "${EXACT[@]:-}"; do
    [ "$f" = "$e" ] && return 0
  done
  for p in "${PREFIX[@]:-}"; do
    case "$f" in
      "$p"*) return 0;;
    esac
  done
  return 1
}

violations=0
for f in "${HITS[@]:-}"; do
  [ -z "$f" ] && continue
  if ! is_allowed "$f"; then
    if [ "$violations" -eq 0 ]; then
      echo "check-pools-app.sh: new tenant-unscoped DB callers detected" >&2
      echo "" >&2
      echo "These files call pools.App.{Query,QueryRow,Exec,Begin,...}" >&2
      echo "directly but are NOT in $ALLOWLIST:" >&2
      echo "" >&2
    fi
    echo "  $f" >&2
    grep -nE "$pattern" "$f" | sed 's/^/    /' >&2
    echo "" >&2
    violations=$((violations + 1))
  fi
done

if [ "$violations" -gt 0 ]; then
  cat >&2 <<'EOF'
Fix: route the query through pkg/db helpers instead of touching the
pool directly. Tenant-scoped reads use db.WithTenant; cross-tenant
admin reads use db.WithAdminAudit on pools.Admin. See pkg/db/tenant.go
and docs/invariants.md "Tenant isolation".

If the new caller is intentionally outside that contract (health
check, migration helper, pkg/db internals), add the file path to
scripts/pools-app-allowlist.txt with a comment explaining why.
EOF
  exit 1
fi

echo "check-pools-app.sh: ok (${#HITS[@]} grandfathered files unchanged)"
