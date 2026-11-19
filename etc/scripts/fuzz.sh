#!/usr/bin/env bash
# Coverage-guided fuzzing that fails on a failure: `zig build test --fuzz` exits 0 even when a
# fuzz test panics or returns an error, and without an iteration limit it keeps running after
# one, so this watches its output and stops it at the first failed test.
#
#   etc/scripts/fuzz.sh [step] [zig build args...]
#
# The step defaults to `test`; `--fuzz` (no limit: it runs until stopped) and
# `-Doptimize=ReleaseSafe` are added unless given. On a failure it copies each saved input
# (`.zig-cache/f/crash`) into a fresh directory under FUZZ_CRASH_DIR (default
# .cache/fuzz-crashes, relative to the repository root), next to the run's log, and exits 1.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
export LC_ALL=C

step=test
if [ $# -gt 0 ] && [[ "$1" != -* ]]; then
  step=$1
  shift
fi
extra=()
case " $* " in *" --fuzz "* | *" --fuzz="*) ;; *) extra+=(--fuzz) ;; esac
case " $* " in *" -Doptimize="*) ;; *) extra+=(-Doptimize=ReleaseSafe) ;; esac
set -- "$step" "${extra[@]}" "$@" # Before any `--`, which passes the rest to the step.

run_dir="${FUZZ_CRASH_DIR:-.cache/fuzz-crashes}/$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$run_dir"
log="$run_dir/fuzz.log"
: > "$log"
# The runner prints exactly this for a fuzz test that panics or returns an error.
pattern="^error: test '.*' (terminated with signal|exited with code)|input saved to '"

pid=""
tail_pid=""
stop=""
# Stops zig's process group (TERM, then KILL after 5 s) and the log follower.
stop_zig() {
  if [ -n "$pid" ]; then
    kill -TERM -- -"$pid" 2>/dev/null || true
    for _ in $(seq 1 50); do
      kill -0 -- -"$pid" 2>/dev/null || break
      sleep 0.1 || true
    done
    kill -KILL -- -"$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    pid=""
  fi
  [ -z "$tail_pid" ] || { kill "$tail_pid" 2>/dev/null || true; tail_pid=""; }
}
trap stop_zig EXIT
trap 'stop=signal' INT TERM HUP

set -m # zig gets its own process group, so it can be stopped as a whole.
zig build "$@" < /dev/null > "$log" 2>&1 &
pid=$!
set +m
tail -n +1 -f --pid="$pid" "$log" &
tail_pid=$!

status=0
while [ -z "$stop" ] && kill -0 "$pid" 2>/dev/null; do
  if grep -a -E -q "$pattern" "$log"; then
    stop=failure
    sleep 1 || true # Let the runner finish writing the failure.
    break
  fi
  sleep 1 || true
done
if [ -n "$stop" ]; then
  stop_zig
  status=130
else
  wait "$pid" || status=$? # The EXIT trap still stops zig if a signal cut this short.
  wait "$tail_pid" 2>/dev/null || true
fi
trap - INT TERM HUP

if grep -a -E -q "$pattern" "$log"; then
  echo "fuzz: a fuzz test failed:" >&2
  grep -a -E "$pattern" "$log" >&2
  count=0
  while IFS= read -r saved; do
    count=$((count + 1))
    if [ -f "$saved" ]; then
      cp -- "$saved" "$run_dir/$count-$(basename -- "$saved")"
    else
      echo "fuzz: saved input $saved is missing" >&2
    fi
  done < <(sed -n -E "s/.*input saved to '([^']+)'.*/\1/p" "$log")
  echo "fuzz: $count saved input(s) and the log are in $run_dir" >&2
  exit 1
fi
[ "$status" -ne 0 ] || rm -rf -- "$run_dir"
exit "$status"
