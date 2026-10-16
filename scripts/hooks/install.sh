#!/bin/sh
# Symlink scripts/hooks/pre-commit and pre-push into .git/hooks.

set -eu

repo_root="$(git rev-parse --show-toplevel)"
hooks_src="$repo_root/scripts/hooks"
hooks_dst="$repo_root/.git/hooks"

if [ ! -d "$hooks_dst" ]; then
  echo "install.sh: $hooks_dst missing - is this a git working tree?" >&2
  exit 1
fi

for hook in pre-commit pre-push; do
  src="$hooks_src/$hook"
  dst="$hooks_dst/$hook"
  if [ ! -x "$src" ]; then
    chmod +x "$src"
  fi
  ln -sfn "$src" "$dst"
  echo "linked $hook -> $src"
done
