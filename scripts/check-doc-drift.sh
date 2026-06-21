#!/bin/sh
# Doc-drift gate (thesada-app).
#
# thesada-app documentation lives in-repo under docs/, so this check can
# ENFORCE: it refuses a commit that touches application source without a
# matching docs/ update. Catches the drift where a handler, package, or
# database migration ships and docs/invariants.md / docs/security.md go
# stale.
#
# Shared entry point for scripts/hooks/pre-commit. The file list arrives
# on stdin, one path per line.
#
# Usage:
#   git diff --cached --name-only | scripts/check-doc-drift.sh
#
# Bypass: set DOC_OK=1 in the environment when a change is genuinely
# doc-neutral. The bypass leaves a trail in the shell history rather
# than being silent.

set -eu

# Source trees whose changes should be reflected in docs/. Build tooling
# (scripts/, tools/, Makefile) is intentionally excluded.
SOURCE_REGEX='^(cmd/|pkg/|migrations/)'
DOC_REGEX='^docs/'

files="$(cat)"
touched_src="$(printf '%s\n' "$files" | grep -E "$SOURCE_REGEX" || true)"
touched_doc="$(printf '%s\n' "$files" | grep -E "$DOC_REGEX" || true)"

if [ -n "$touched_src" ] && [ -z "$touched_doc" ]; then
  if [ "${DOC_OK:-}" = "1" ]; then
    echo "doc-drift check: DOC_OK=1 set, skipping." >&2
    exit 0
  fi
  cat >&2 <<EOF

doc-drift check: thesada-app source changed without a docs/ update.

Source files in this change:
$(printf '%s\n' "$touched_src" | sed 's/^/  /')

Update the matching docs/ page (invariants.md, security.md, ...) in the
same commit, or bypass with:

    DOC_OK=1 git commit ...

if this change genuinely does not affect any documentation.
EOF
  exit 1
fi

exit 0
