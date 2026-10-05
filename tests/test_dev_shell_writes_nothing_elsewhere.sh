#!/usr/bin/env bash
# Entering this repository's dev shell from ANOTHER git repository writes
# nothing into that repository.
#
# The owning dev shell installs canonical native hooks under `.git/hooks`.
# Its ownership guard must prevent aiming them at
# `git rev-parse --show-toplevel` of the CURRENT DIRECTORY, so without a guard
# `nix develop /path/to/this-repo` run from a sibling checkout plants this
# repository's hooks there: an untracked file that blocks that repository's
# pre-push gate, and foreign checks on its commits. flake.nix runs the hook only
# when the enclosing repository is this one.
#
# Asserted, from a scratch git repository and from a subdirectory of it: no
# file or directory appears, no hook is
# installed and `core.hooksPath` is untouched. As the positive control, entered
# from inside this repository the tracked regular configuration is preserved
# and the genuine native local hooks precede matching managed dispatch.
#
#   bash tests/test_dev_shell_writes_nothing_elsewhere.sh
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

git -C "$SCRATCH" init -q
git -C "$SCRATCH" -c user.name=t -c user.email=t@t commit -q --allow-empty -m init
mkdir -p "$SCRATCH/sub"
hooks_before="$(ls "$SCRATCH/.git/hooks")"

for dir in "$SCRATCH" "$SCRATCH/sub"; do
  ( cd "$dir" && nix develop "$REPO" --no-write-lock-file -c true ) >/dev/null 2>&1 \
    || fail "the dev shell did not start from $dir"
  [ -z "$(git -C "$SCRATCH" status --porcelain --ignored)" ] \
    || fail "entered from $dir: files were written into the other repository: $(git -C "$SCRATCH" status --porcelain --ignored | tr '\n' ' ')"
  # git status does not list empty directories.
  extra="$(cd "$SCRATCH" && find . -mindepth 1 -path ./.git -prune -o ! -path ./sub -print)"
  [ -z "$extra" ] || fail "entered from $dir: entries were created in the other repository: $(echo $extra)"
  [ "$(ls "$SCRATCH/.git/hooks")" = "$hooks_before" ] \
    || fail "entered from $dir: git hooks were installed into the other repository"
  [ -z "$(git -C "$SCRATCH" config --local --get core.hooksPath || true)" ] \
    || fail "entered from $dir: the other repository's core.hooksPath was changed"
done

# Positive control: preserve the committed regular rules and install the owned chain.
[ -f "$REPO/.pre-commit-config.yaml" ] && [ ! -L "$REPO/.pre-commit-config.yaml" ] \
  || fail "control: owning portable configuration is not a regular file"
git -C "$REPO" ls-files --error-unmatch .pre-commit-config.yaml >/dev/null \
  || fail "control: owning portable configuration is not tracked"
config_before="$(git -C "$REPO" hash-object .pre-commit-config.yaml)"
( cd "$REPO" && nix develop "$REPO" --no-write-lock-file -c true ) >/dev/null 2>&1 \
  || fail "the dev shell did not start from this repository"
[ -f "$REPO/.pre-commit-config.yaml" ] && [ ! -L "$REPO/.pre-commit-config.yaml" ] \
  || fail "control: owning portable configuration changed type"
[ "$(git -C "$REPO" hash-object .pre-commit-config.yaml)" = "$config_before" ] \
  || fail "control: owning portable configuration changed bytes"
hooks="$(git -C "$REPO" rev-parse --path-format=absolute --git-path hooks)"
for hook in pre-commit pre-push; do
  [ -f "$hooks/$hook" ] && [ ! -L "$hooks/$hook" ] && [ -x "$hooks/$hook" ] \
    || fail "control: missing regular executable owned dispatcher $hook"
  [ -f "$hooks/$hook.repro-local" ] && [ ! -L "$hooks/$hook.repro-local" ] && [ -x "$hooks/$hook.repro-local" ] \
    || fail "control: missing regular executable native local $hook"
  [ -f "$hooks/$hook.repro-managed" ] && [ ! -L "$hooks/$hook.repro-managed" ] && [ -x "$hooks/$hook.repro-managed" ] \
    || fail "control: missing regular executable matching managed $hook"
  grep -qx 'export PREK_NO_FAST_PATH=1' "$hooks/$hook.repro-local" \
    || fail "control: native $hook does not persist canonical upstream execution"
  grep -q 'reprobuild hook dispatcher protocol=2' "$hooks/$hook" \
    || fail "control: $hook does not dispatch the owned local/managed chain"
done

echo "PASS: foreign shell entry writes nothing; owning entry preserves tracked rules and installs canonical native/managed hooks"
