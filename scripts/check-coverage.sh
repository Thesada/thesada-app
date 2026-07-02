#!/usr/bin/env bash
# check-coverage.sh - gate statement coverage on the security packages.
# allow-long-comment
#
# Locks in the CODE-GUIDELINES rule ("Stop letting test coverage drift on
# security paths"): every package on the auth / CSRF / OAuth / pkg-pki
# path stays at or above the threshold. Each package is measured against
# its own statements via -coverpkg + -coverprofile; the run fails if any
# falls below THRESHOLD. pkg/service (auth.go) is deliberately absent: it
# is covered by the integration lane (testcontainers), not this lane.
#
# Usage:
#   scripts/check-coverage.sh            # gate at the default threshold
#   THRESHOLD=85 scripts/check-coverage.sh
# Exit code 0 = all packages pass, 1 = at least one below threshold.

set -euo pipefail

cd "$(dirname "$0")/.."

THRESHOLD="${THRESHOLD:-80}"
PKGS=(csrf oauth pki authmw)

status=0
profile="$(mktemp)"
trap 'rm -f "$profile"' EXIT

for p in "${PKGS[@]}"; do
  go test -covermode=set \
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

if [ "$status" -ne 0 ]; then
  echo "" >&2
  echo "check-coverage.sh: a security package dropped below ${THRESHOLD}% coverage." >&2
  echo "Add the missing contract tests (see CODE-GUIDELINES.md) before merging." >&2
  exit 1
fi

echo "check-coverage.sh: ok (all security packages >= ${THRESHOLD}%)"
