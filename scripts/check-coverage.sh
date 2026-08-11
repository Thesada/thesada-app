#!/usr/bin/env bash
# check-coverage.sh - gate statement coverage on the security packages.
# allow-long-comment
#
# Locks in the CODE-GUIDELINES rule ("Stop letting test coverage drift on
# security paths"): every package on the auth / CSRF / OAuth / pkg-pki
# path stays at or above the threshold. Each package is measured against
# its own statements via -coverpkg + -coverprofile; the run fails if any
# falls below THRESHOLD. Runs with -tags integration so oauth's DB-backed
# Start/LookupState count (real Postgres via testcontainers - needs Docker).
# pkg/service (auth.go) is deliberately absent: large surface, gated separately.
#
# Usage:
#   scripts/check-coverage.sh            # gate at the default threshold
#   THRESHOLD=85 scripts/check-coverage.sh
# Exit code 0 = all packages pass, 1 = at least one below threshold.

set -euo pipefail

cd "$(dirname "$0")/.."

THRESHOLD="${THRESHOLD:-80}"
PKGS=(csrf oauth pki authmw)

# allow-long-comment
# FILES gates one file at a time, for packages too broad to gate whole (#281):
# pkg/service sits around 84% over a wide surface, so gating the package would
# block unrelated PRs; auth.go is the part that carries the security contract.
# Format: <file>:<package whose tests exercise it>.
FILES=(
  "pkg/service/auth.go:pkg/service"
)

status=0
profile="$(mktemp)"
trap 'rm -f "$profile"' EXIT

for p in "${PKGS[@]}"; do
  go test -tags integration -covermode=set -timeout 300s \
    -coverpkg="./pkg/${p}/..." \
    -coverprofile="$profile" \
    "./pkg/${p}/..." >/dev/null

  pct="$(go tool cover -func="$profile" | awk '/^total:/ {sub(/%/,"",$3); print $3}')"

  if awk -v got="$pct" -v want="$THRESHOLD" 'BEGIN { exit !((got + 0) >= (want + 0)) }'; then
    printf 'PASS  pkg/%-8s %5s%% (>= %s%%)\n' "$p" "$pct" "$THRESHOLD"
  else
    printf 'FAIL  pkg/%-8s %5s%% (<  %s%%)\n' "$p" "$pct" "$THRESHOLD" >&2
    status=1
  fi
done

for entry in "${FILES[@]}"; do
  file="${entry%%:*}"
  pkg="${entry##*:}"

  go test -tags integration -covermode=set -timeout 300s \
    -coverpkg="./${pkg}/..." \
    -coverprofile="$profile" \
    "./${pkg}/..." >/dev/null

  # allow-long-comment
  # Statement coverage for one file, off the profile lines
  # "<import path>/<file>:<span> <numStmt> <count>". Every test binary in the
  # package emits its own copy of each block, so blocks are merged by span
  # taking the max count first - summing raw lines counts each one twice and
  # reads as a coverage drop that never happened.
  pct="$(awk -v want="$file" '
    NR == 1 { next }
    { split($1, parts, ":"); path = parts[1] }
    index(path, want) == length(path) - length(want) + 1 {
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
    }' "$profile")"

  if [ "$pct" = "none" ]; then
    printf 'FAIL  %-24s no statements found in profile (renamed or deleted?)\n' "$file" >&2
    status=1
  elif awk -v got="$pct" -v want="$THRESHOLD" 'BEGIN { exit !((got + 0) >= (want + 0)) }'; then
    printf 'PASS  %-24s %5s%% (>= %s%%)\n' "$file" "$pct" "$THRESHOLD"
  else
    printf 'FAIL  %-24s %5s%% (<  %s%%)\n' "$file" "$pct" "$THRESHOLD" >&2
    status=1
  fi
done

if [ "$status" -ne 0 ]; then
  echo "" >&2
  echo "check-coverage.sh: a security target dropped below ${THRESHOLD}% coverage." >&2
  echo "Add the missing contract tests (see CODE-GUIDELINES.md) before merging." >&2
  exit 1
fi

echo "check-coverage.sh: ok (all security targets >= ${THRESHOLD}%)"
