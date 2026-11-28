#!/usr/bin/env bash
# check-coverage.sh - gate statement coverage on the security packages.
# allow-long-comment
#
# Locks in the CODE-GUIDELINES rule ("Stop letting test coverage drift on
# security paths"): every package on the auth / CSRF / OAuth / pkg-pki
# path stays at or above the threshold. It reads the profile that
# `make test-integration` writes (-tags integration, -covermode=set), so
# oauth's DB-backed Start/LookupState count against a real Postgres and the
# integration tests run once for both the pass/fail and the coverage gate.
# go test -cover instruments each package for its own tests only, so a
# package is measured against its own statements, as -coverpkg did before.
# pkg/service (auth.go) is deliberately absent: large surface, gated separately.
#
# Usage:
#   make coverage                                   # runs test-integration, then this
#   PROFILE=coverage-integration.out scripts/check-coverage.sh
#   THRESHOLD=85 PROFILE=... scripts/check-coverage.sh
# Exit code 0 = all packages pass, 1 = at least one below threshold or no profile.

set -euo pipefail

cd "$(dirname "$0")/.."

THRESHOLD="${THRESHOLD:-80}"
PROFILE="${PROFILE:-coverage-integration.out}"
PKGS=(csrf oauth pki authmw)

# allow-long-comment
# FILES gates one file at a time, for packages too broad to gate whole (#281):
# pkg/service sits around 84% over a wide surface, so gating the package would
# block unrelated PRs; auth.go is the part that carries the security contract.
FILES=(
  "pkg/service/auth.go"
)

if [ ! -s "$PROFILE" ] || [ "$(head -n 1 "$PROFILE")" != "mode: set" ]; then
  printf 'FAIL  no set-mode coverage profile at %s (run make coverage)\n' "$PROFILE" >&2
  exit 1
fi

module="$(awk '$1 == "module" { print $2; exit }' go.mod)"
status=0

# allow-long-comment
# Statement coverage off the profile lines "<import path>/<file>:<span>
# <numStmt> <count>". kind=pkg takes every file under the package dir (what
# -coverpkg=./pkg/x/... measured), kind=file one file. Blocks are merged by
# span taking the max count first: a block can appear more than once, and
# summing raw lines reads as a coverage change that never happened.
pct() {
  awk -v kind="$1" -v want="${module}/$2" '
    NR == 1 { next }
    {
      split($1, parts, ":"); path = parts[1]
      if (kind == "file") { if (path != want) next }
      else if (index(path, want "/") != 1) next
      stmts[$1] = $2
      if ($3 > 0 && $3 > hit[$1]) hit[$1] = $3
    }
    END {
      for (b in stmts) {
        total += stmts[b]
        if (hit[b] > 0) covered += stmts[b]
      }
      if (total == 0) { print "none"; exit }
      printf "%.1f", (covered / total) * 100
    }' "$PROFILE"
}

gate() {
  local label="$1" got="$2"
  if [ "$got" = "none" ]; then
    printf 'FAIL  %-24s no statements found in profile (renamed or deleted?)\n' "$label" >&2
    status=1
  elif awk -v got="$got" -v want="$THRESHOLD" 'BEGIN { exit !((got + 0) >= (want + 0)) }'; then
    printf 'PASS  %-24s %5s%% (>= %s%%)\n' "$label" "$got" "$THRESHOLD"
  else
    printf 'FAIL  %-24s %5s%% (<  %s%%)\n' "$label" "$got" "$THRESHOLD" >&2
    status=1
  fi
}

for p in "${PKGS[@]}"; do
  gate "pkg/${p}" "$(pct pkg "pkg/${p}")"
done

for file in "${FILES[@]}"; do
  gate "$file" "$(pct file "$file")"
done

if [ "$status" -ne 0 ]; then
  echo "" >&2
  echo "check-coverage.sh: a security target dropped below ${THRESHOLD}% coverage." >&2
  echo "Add the missing contract tests (see CODE-GUIDELINES.md) before merging." >&2
  exit 1
fi

echo "check-coverage.sh: ok (all security targets >= ${THRESHOLD}%)"
