#!/usr/bin/env bash
# End-to-end smoke test of the full-system examples on this machine: builds them, runs a
# small local network of each for a bounded time, and fails unless every node finalizes at
# least E2E_HEIGHTS heights that agree with every other node of its network.
#
#   dkg     setup with 4 peers, the epoch-0 bootstrap, then 4 validators; every validator
#           must log `finalized block` for heights 1..E2E_HEIGHTS with one digest per height.
#   bridge  examples/bridge/local.sh: an indexer and two networks of 4 validators; every
#           validator must finalize E2E_HEIGHTS views its whole network finalized, with one
#           payload per view, and each network must propose a block carrying the other's
#           finalization.
#   log     4 validators in tmux (etc/scripts/interop_log.py with zigware on every seat) must
#           finalize E2E_HEIGHTS views with one digest per view across all 4.
#   chat    2 friends in pseudo-terminals (etc/scripts/interop_chat.py, zigware on both sides)
#           must each show the other's message.
#   flood   examples/flood/local.sh and demo.sh run 4 peers for 6 s; every peer must report
#           received messages and a nonzero rate on its last sample, and log no error.
#
#   etc/scripts/e2e.sh [dkg|bridge|log|chat|flood]...   (default: all five)
#
# Environment: E2E_HEIGHTS (default 20), E2E_TIMEOUT (seconds per example, default 120),
# E2E_PORT (base port, default 24500: dkg uses it, log +100, chat +120; bridge uses local.sh's
# 3000-3008 and flood its fixed 4545 and 9090 on 127.0.0.1-4), E2E_DIR (work directory,
# default a fresh temporary one, kept on failure).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

heights=${E2E_HEIGHTS:-20}
timeout_s=${E2E_TIMEOUT:-120}
port=${E2E_PORT:-24500}
work=${E2E_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/zigware-e2e.XXXXXX")}
examples=("$@")
[ ${#examples[@]} -gt 0 ] || examples=(dkg bridge log chat flood)
mkdir -p "$work"
export NO_COLOR=1

pids=()
stop_all() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  pids=()
}
trap stop_all EXIT

# Fails with the tail of each log in $1.
fail() {
  local dir=$1
  shift
  echo "e2e: FAIL: $*" >&2
  for log in "$dir"/*.log; do
    echo "--- $log" >&2
    tail -n 5 "$log" | cut -c1-200 >&2
  done
  echo "e2e: logs kept in $dir" >&2
  exit 1
}

# Waits until `$2` succeeds, up to $timeout_s seconds; fails with $3 otherwise.
wait_for() {
  local dir=$1 check=$2 what=$3 deadline=$((SECONDS + timeout_s))
  until eval "$check"; do
    [ $SECONDS -lt $deadline ] || fail "$dir" "timed out after ${timeout_s}s waiting for $what"
    for pid in "${pids[@]}"; do
      kill -0 "$pid" 2>/dev/null || fail "$dir" "a node exited while waiting for $what"
    done
    sleep 1
  done
}

# Heights 1..$heights finalized by every log given, with one digest per height across them:
# prints the number of agreeing heights, or "conflict <height>" on a fork.
dkg_agreed() {
  awk -v want="$heights" '
    / finalized block / {
      match($0, /height=[0-9]+/); h = substr($0, RSTART + 7, RLENGTH - 7) + 0
      match($0, /digest=[0-9a-f]+/); d = substr($0, RSTART + 7, RLENGTH - 7)
      if (h < 1 || h > want || seen[FILENAME, h]++) next
      if ((h in digest) && digest[h] != d) { forked = h; exit }
      digest[h] = d; count[h]++
    }
    END {
      if (forked) { print "conflict " forked; exit }
      n = 0; for (h = 1; h <= want; h++) if (count[h] == ARGC - 1) n++; print n
    }
  ' "$@" 2>/dev/null
}

run_dkg() {
  local dir=$work/dkg bin=$PWD/zig-out/bin/dkg
  mkdir -p "$dir"
  "$bin" setup --node-dir "$dir/data" --peers 4 --committee-size 4 --base-port "$port" \
    >"$dir/setup.log" 2>&1 || fail "$dir" "setup failed"
  for i in 0 1 2 3; do
    "$bin" bootstrap --node-dir "$dir/data/validator-$i" >"$dir/bootstrap-$i.log" 2>&1 &
    pids+=($!)
  done
  wait_for "$dir" '[ "$(cat "$dir"/bootstrap-*.log | grep -c "bootstrap complete")" = 4 ]' \
    "the epoch-0 bootstrap"
  stop_all
  # Let the bootstraps' ports close before the validators bind them.
  local closing=$((SECONDS + 30))
  while ss -ltn 2>/dev/null | grep -qE ":($port|$((port + 1))|$((port + 2))|$((port + 3))) "; do
    [ $SECONDS -lt $closing ] || fail "$dir" "bootstrap ports stayed bound"
    sleep 0.2
  done
  for i in 0 1 2 3; do
    "$bin" validator --node-dir "$dir/data/validator-$i" >"$dir/validator-$i.log" 2>&1 &
    pids+=($!)
  done
  local logs=("$dir"/validator-{0,1,2,3}.log)
  agreed() {
    local result
    result=$(dkg_agreed "${logs[@]}")
    case $result in conflict*) fail "$dir" "validators forked: $result" ;; esac
    [ "$result" = "$heights" ]
  }
  wait_for "$dir" agreed "$heights agreeing heights on 4 validators"
  stop_all
  echo "e2e: dkg: 4 validators finalized heights 1-$heights with identical digests"
}

# Views finalized by every log given (one network) with one payload each: prints how many,
# or "conflict <view>" on a fork.
bridge_agreed() {
  awk '
    /actor: finalized view=/ {
      match($0, /view=[0-9]+/); v = substr($0, RSTART + 5, RLENGTH - 5) + 0
      match($0, /payload=[0-9a-f]+/); p = substr($0, RSTART + 8, RLENGTH - 8)
      if (seen[FILENAME, v]++) next
      if ((v in payload) && payload[v] != p) { forked = v; exit }
      payload[v] = p; count[v]++
    }
    END {
      if (forked) { print "conflict " forked; exit }
      n = 0; for (v in count) if (count[v] == ARGC - 1) n++; print n
    }
  ' "$@" 2>/dev/null
}

run_bridge() {
  local dir=$work/bridge
  examples/bridge/local.sh "$dir" >"$work/bridge-local.log" 2>&1 &
  pids+=($!)
  local one=("$dir"/validator-{1,2,3,4}.log) two=("$dir"/validator-{5,6,7,8}.log)
  enough() {
    local a b
    a=$(bridge_agreed "${one[@]}")
    b=$(bridge_agreed "${two[@]}")
    case "$a $b" in *conflict*) fail "$dir" "a network forked: $a / $b" ;; esac
    [ "$a" -ge "$heights" ] && [ "$b" -ge "$heights" ]
  }
  sleep 2
  wait_for "$dir" 'enough && grep -qs "proposed block=Bridge" "${one[@]}" &&
    grep -qs "proposed block=Bridge" "${two[@]}"' \
    "$heights agreeing views on both networks and a bridged block on each"
  stop_all
  echo "e2e: bridge: both networks of 4 finalized $heights identical views and bridged blocks"
}

run_log() {
  local dir=$work/log
  mkdir -p "$dir"
  INTEROP_LOG_MIX=zzzz INTEROP_LOG_RESTART=0 python3 -I etc/scripts/interop_log.py \
    zig-out/bin/log zig-out/bin/log $((port + 100)) "$timeout_s" "$heights" \
    >"$dir/driver.log" 2>&1 || fail "$dir" "log validators did not agree"
  echo "e2e: log: 4 validators finalized $(grep -o '[0-9]* views ([0-9.]*)' "$dir/driver.log")" \
    "with identical digests"
}

run_chat() {
  local dir=$work/chat
  mkdir -p "$dir"
  python3 -I etc/scripts/interop_chat.py zig-out/bin/chat zig-out/bin/chat $((port + 120)) \
    "$timeout_s" >"$dir/driver.log" 2>&1 || fail "$dir" "chat messages did not cross"
  echo "e2e: chat: both friends showed the other's message"
}

run_flood() {
  local dir=$work/flood
  mkdir -p "$dir"
  examples/flood/local.sh 4 "$dir/deployment" >"$dir/setup.log" 2>&1 ||
    fail "$dir" "local.sh failed"
  examples/flood/demo.sh "$dir/deployment" 6 2>&1 | sed 's/\x1b\[[0-9;]*m//g' >"$dir/peers.log" ||
    fail "$dir" "demo.sh failed"
  # Every line a peer printed is a JSON event below ERROR; anything else is a crash or error.
  if grep '^\[peer' "$dir/peers.log" | grep -vE '^\[peer [0-9]+\] \{' | grep -q . ||
    grep -q '"level":"ERROR"' "$dir/peers.log"; then
    fail "$dir" "a flood peer logged an error"
  fi
  # The last sample: one row per peer with received messages and a nonzero rate.
  local last
  last=$(awk '/received +messages/ { rows = "" } /^peer [0-9]+ / { rows = rows $0 "\n" }
    END { printf "%s", rows }' "$dir/peers.log")
  [ "$(grep -c . <<<"$last")" = 4 ] || fail "$dir" "flood reported fewer than 4 peers"
  if awk '$3 !~ /^[1-9][0-9]*$/ || $4 !~ /^[1-9][0-9]*$/ { bad = 1 } END { exit !bad }' \
    <<<"$last"; then
    fail "$dir" "a flood peer received nothing: $(tr '\n' ';' <<<"$last")"
  fi
  local slowest
  slowest=$(awk '{ print $4 }' <<<"$last" | sort -n | head -1)
  echo "e2e: flood: 4 peers each received at least $slowest messages/s with no errors"
}

echo "e2e: building (ReleaseFast)"
zig build -Doptimize=ReleaseFast
for example in "${examples[@]}"; do
  case $example in
    dkg) run_dkg ;;
    bridge) run_bridge ;;
    log) run_log ;;
    chat) run_chat ;;
    flood) run_flood ;;
    *) echo "usage: e2e.sh [dkg|bridge|log|chat|flood]..." >&2; exit 2 ;;
  esac
done
[ -n "${E2E_DIR:-}" ] || rm -rf "$work"
echo "e2e: ok"
