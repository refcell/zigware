#!/usr/bin/env bash
# Publishes committed work to main without push races between lanes on one machine.
#   etc/scripts/push.sh            full suite and tidy first, then a locked rebase and push
#   etc/scripts/push.sh --no-test  skip the unlocked full suite (it already passed)
#
# The full suite runs outside the lock. Inside a machine-wide lock (flock) the script fetches,
# rebases, compiles everything (`zig build check`), and pushes, so no other lane can move main
# between this lane's rebase and its push. CI runs the full suite on every push.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

lock=${ZIGWARE_PUSH_LOCK:-$HOME/.cache/zigware/push.lock}
mkdir -p "$(dirname "$lock")"

if [ "${1:-}" != "--no-test" ]; then
  git fetch -q origin main
  git rebase -q origin/main
  zig build test
fi
just tidy >/dev/null

exec 9>"$lock"
echo "push: waiting for the push lock"
flock 9
echo "push: holding the lock"
# Retries cover pushes from outside the lock (another machine, or a lane not using it yet).
for attempt in 1 2 3 4 5; do
  git fetch -q origin main
  git rebase -q origin/main
  zig build check
  just tidy >/dev/null
  if git push -q origin HEAD:main; then
    echo "push: pushed $(git rev-parse --short HEAD) on attempt $attempt"
    exit 0
  fi
done
echo "push: rejected 5 times; rerun once main settles" >&2
exit 1
