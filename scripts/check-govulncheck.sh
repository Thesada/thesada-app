#!/usr/bin/env bash
# check-govulncheck.sh - govulncheck reachability gate with a reviewed allowlist.
#
# Runs govulncheck ./... and fails on any reachable (symbol level) advisory
# not in scripts/govulncheck-allowlist.txt. A listed id that is no longer
# reported fails too, so a fixed advisory forces its line out.
# Exit code 0 = pass, 1 = unlisted or stale advisory, 2 = scan or parse error.

set -euo pipefail

cd "$(dirname "$0")/.."

ALLOWLIST="scripts/govulncheck-allowlist.txt"
[ -f "$ALLOWLIST" ] || { echo "check-govulncheck.sh: missing $ALLOWLIST" >&2; exit 2; }

out="$(mktemp)"
trap 'rm -f "$out"' EXIT

rc=0
"${GOVULNCHECK:-govulncheck}" ./... >"$out" 2>&1 || rc=$?
cat "$out"
case "$rc" in
  0 | 3) ;;
  *) echo "check-govulncheck.sh: govulncheck exited $rc" >&2; exit 2 ;;
esac

found="$(awk '/^=== Symbol Results ===/{s=1; next} /^=== /{s=0} s && /^Vulnerability #[0-9]+: GO-/{print $3}' "$out" | sort -u)"
allowed="$(grep -oE '^GO-[0-9]{4}-[0-9]+' "$ALLOWLIST" | sort -u || true)"

if [ "$rc" = 3 ] && [ -z "$found" ]; then
  echo "check-govulncheck.sh: govulncheck reported findings but none parsed" >&2
  exit 2
fi

status=0
for id in $(comm -23 <(printf '%s\n' "$found" | sed '/^$/d') <(printf '%s\n' "$allowed" | sed '/^$/d')); do
  echo "FAIL  $id is reachable and not in $ALLOWLIST" >&2
  status=1
done
for id in $(comm -13 <(printf '%s\n' "$found" | sed '/^$/d') <(printf '%s\n' "$allowed" | sed '/^$/d')); do
  echo "FAIL  $id is listed in $ALLOWLIST but no longer reported, remove it" >&2
  status=1
done
for id in $(comm -12 <(printf '%s\n' "$found" | sed '/^$/d') <(printf '%s\n' "$allowed" | sed '/^$/d')); do
  echo "ALLOW $id (see $ALLOWLIST)"
done
exit "$status"
