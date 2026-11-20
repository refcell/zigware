#!/usr/bin/env bash
# Publishes committed work to main without push races between lanes on one machine.
#   etc/scripts/push.sh            full suite and tidy first, then a locked rebase and push
#   etc/scripts/push.sh --no-test  skip the unlocked full suite (it already passed)
#
# The full suite runs outside the lock. Inside a machine-wide lock (flock) the script fetches,
# rebases, compiles everything (`zig build check`), and pushes, so no other lane can move main
# between this lane's rebase and its push. CI runs the full suite on every push.
#
# The locked check runs in one shared checkout ($check_dir) with its own cache: consecutive
# pushes differ by one lane's commits, so only the packages they touch recompile.
#
# The body is one function so bash parses the whole script before it runs: a rebase inside
# the lock may rewrite this file.
set -euo pipefail

main() {
  cd "$(git rev-parse --show-toplevel)"
  local lock=${ZIGWARE_PUSH_LOCK:-$HOME/.cache/zigware/push.lock}
  local check_dir=${ZIGWARE_CHECK_DIR:-$HOME/.cache/zigware/push-check}
  mkdir -p "$(dirname "$lock")"

  if [ "${1:-}" != "--no-test" ]; then
    git fetch -q origin main
    git rebase -q origin/main
    # A hung test fails with its name instead of blocking the push (macOS CI uses the same limit).
    zig build test --test-timeout 10m
  fi
  just tidy >/dev/null

  exec 9>"$lock"
  echo "push: waiting for the push lock"
  flock 9
  echo "push: holding the lock"
  [ -d "$check_dir/.git" ] || git clone -q --no-checkout "$PWD" "$check_dir"
  # Rule 10: the shared check cache stays under about 50 GB.
  if [ "$(du -sm "$check_dir/.zig-cache" 2>/dev/null | cut -f1)" -gt 50000 ] 2>/dev/null; then
    rm -rf "$check_dir/.zig-cache"
  fi
  # Retries cover pushes from outside the lock (another machine, or a lane not using it yet).
  local attempt
  for attempt in 1 2 3 4 5; do
    git fetch -q origin main
    git rebase -q origin/main
    git -C "$check_dir" fetch -q "$PWD" HEAD
    git -C "$check_dir" checkout -q --force --detach FETCH_HEAD
    (cd "$check_dir" && zig build check)
    just tidy >/dev/null
    if git push -q origin HEAD:main; then
      echo "push: pushed $(git rev-parse --short HEAD) on attempt $attempt"
      exit 0
    fi
  done
  echo "push: rejected 5 times; rerun once main settles" >&2
  exit 1
}

main "$@"
