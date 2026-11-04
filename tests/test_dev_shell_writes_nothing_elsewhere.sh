#!/usr/bin/env bash
# Entering this repository's dev shell from ANOTHER git repository writes
# nothing into that repository.
#
# The dev shell's hook installs git hooks (hooks under `.git/hooks`,
# `core.hooksPath`). Its installer aims them at
# `git rev-parse --show-toplevel` of the CURRENT DIRECTORY, so without a guard
# `nix develop /path/to/this-repo` run from a sibling checkout plants this
# repository's hooks there: an untracked file that blocks that repository's
# pre-push gate, and foreign checks on its commits. flake.nix runs the hook only
# when the enclosing repository is this one.
#
# Asserted, from a scratch git repository and from a subdirectory of it: no
# file or directory appears, no hook is
# installed and `core.hooksPath` is untouched. As the positive control, entered
# from inside this repository the hook still installs the pre-commit hook
# (running the committed, tracked `.pre-commit-config.yaml`, which it leaves
# byte-identical), and every Reprobuild hook dispatcher that held a slot before
# entry still holds it afterwards, with its `.repro-managed` body beside it.
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

# Positive control: the guard must not stop the hook in this repository.
[ -f "$REPO/.pre-commit-config.yaml" ] && [ ! -L "$REPO/.pre-commit-config.yaml" ] \
  || fail "control: the committed .pre-commit-config.yaml is not a regular file"
git -C "$REPO" ls-files --error-unmatch .pre-commit-config.yaml >/dev/null \
  || fail "control: .pre-commit-config.yaml is not tracked"
config_before="$(git -C "$REPO" hash-object .pre-commit-config.yaml)"
hooks_dir="$(git -C "$REPO" rev-parse --path-format=absolute --git-path hooks)"
dispatched=()
for hook in pre-commit pre-push; do
  if [ -f "$hooks_dir/$hook" ] && grep -q 'reprobuild hook dispatcher protocol=2' "$hooks_dir/$hook"; then
    dispatched+=("$hook")
  fi
done
( cd "$REPO" && nix develop "$REPO" --no-write-lock-file -c true ) >/dev/null 2>&1 \
  || fail "the dev shell did not start from this repository"
[ -f "$REPO/.pre-commit-config.yaml" ] && [ ! -L "$REPO/.pre-commit-config.yaml" ] \
  && [ "$(git -C "$REPO" hash-object .pre-commit-config.yaml)" = "$config_before" ] \
  || fail "control: the committed .pre-commit-config.yaml was replaced or changed"
grep -qs -- '--config .pre-commit-config.yaml' "$hooks_dir/pre-commit" "$hooks_dir/pre-commit.repro-local" \
  || fail "control: entered from this repository, no pre-commit hook runs the committed config"
# Entering the shell must leave Reprobuild's dispatchers in their slots: the
# pre-push one is the publication gate.
for hook in "${dispatched[@]}"; do
  [ -f "$hooks_dir/$hook" ] && [ ! -L "$hooks_dir/$hook" ] && [ -x "$hooks_dir/$hook" ] \
    && grep -q 'reprobuild hook dispatcher protocol=2' "$hooks_dir/$hook" \
    || fail "control: the Reprobuild dispatcher in $hook was displaced"
  [ -f "$hooks_dir/$hook.repro-managed" ] && [ ! -L "$hooks_dir/$hook.repro-managed" ] \
    && [ -x "$hooks_dir/$hook.repro-managed" ] \
    || fail "control: missing regular executable managed $hook.repro-managed"
  [ ! -e "$hooks_dir/$hook.legacy" ] \
    || fail "control: a displaced $hook.legacy was left behind"
done
if [[ " ${dispatched[*]} " == *" pre-commit "* ]]; then
  [ -f "$hooks_dir/pre-commit.repro-local" ] && [ ! -L "$hooks_dir/pre-commit.repro-local" ] \
    && [ -x "$hooks_dir/pre-commit.repro-local" ] \
    && grep -q -- '--config .pre-commit-config.yaml' "$hooks_dir/pre-commit.repro-local" \
    || fail "control: under the dispatcher, pre-commit.repro-local does not run the committed config"
fi

echo "PASS: entered from another repository the dev shell writes nothing there; from this one it installs its hooks and keeps the Reprobuild dispatchers in place"
