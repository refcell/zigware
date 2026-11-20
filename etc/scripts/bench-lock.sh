#!/usr/bin/env bash
# The machine-wide bench queue: first come, first served, into one of two CPU slots.
#   etc/scripts/bench-lock.sh cmd [args...]   run one command holding a slot, pinned to it
#   source etc/scripts/bench-lock.sh          then bench_lock_acquire / bench_lock_release
#
# A waiter takes a ticket under a short flock and is served in ticket order, so no lane
# starves. Each slot is one of the CPU's two CCDs (8 cores, 16 threads, its own L3), and the
# holder runs pinned to it with taskset. rayon and std.Thread.getCpuCount both read the
# affinity mask, so each side's pool sizes itself to the slot. Hold one slot for both sides of a
# pair, so the two always run on the same CCD. BENCH_WHOLE=1 waits for both slots and runs on
# every CPU, for rows with more than 16 threads.
#
# Tickets whose process has died are dropped, and a slot is a flock, so a crashed holder
# frees it. Scripts that still flock ~/.cache/zigware/bench.lock directly bypass the queue.

bench_lock_dir=${BENCH_LOCK_DIR:-$HOME/.cache/zigware/bench-lock}
bench_lock_cpus=("0-7,16-23" "8-15,24-31")

# Waits for this process's turn and a free slot, then sets BENCH_CPUS (a taskset list).
bench_lock_acquire() {
  mkdir -p "$bench_lock_dir"
  local queue ticket head path slot fd pid
  exec {queue}> "$bench_lock_dir/queue.lock"
  flock "$queue"
  ticket=$(($(cat "$bench_lock_dir/counter" 2> /dev/null || echo 0) + 1))
  echo "$ticket" > "$bench_lock_dir/counter"
  ticket=$(printf '%s/ticket.%012d' "$bench_lock_dir" "$ticket")
  echo "$BASHPID" > "$ticket"
  flock -u "$queue"
  bench_lock_fds=()
  while :; do
    flock "$queue"
    head=""
    for path in "$bench_lock_dir"/ticket.*; do # Zero-padded, so the glob is ticket order.
      [ -e "$path" ] || continue
      pid=$(cat "$path" 2> /dev/null || true) # Under set -e, a vanished ticket must not exit.
      if [ -n "$pid" ] && kill -0 "$pid" 2> /dev/null; then head=$path; break; fi
      rm -f "$path"
    done
    if [ "$head" = "$ticket" ]; then
      for slot in 0 1; do
        exec {fd}> "$bench_lock_dir/slot.$slot"
        if flock -n "$fd"; then
          bench_lock_fds+=("$fd")
          BENCH_CPUS=${bench_lock_cpus[$slot]}
          [ "${BENCH_WHOLE:-0}" = 1 ] || break
        else
          exec {fd}>&-
        fi
      done
      if [ "${BENCH_WHOLE:-0}" = 1 ] && [ "${#bench_lock_fds[@]}" -eq 2 ]; then
        BENCH_CPUS=0-31
      elif [ "${BENCH_WHOLE:-0}" = 1 ]; then
        for fd in "${bench_lock_fds[@]}"; do exec {fd}>&-; done
        bench_lock_fds=()
      fi
      if [ "${#bench_lock_fds[@]}" -gt 0 ]; then
        rm -f "$ticket"
        flock -u "$queue"
        exec {queue}>&-
        export BENCH_CPUS
        return 0
      fi
    fi
    flock -u "$queue"
    sleep 0.2
  done
}

bench_lock_release() {
  local fd
  for fd in "${bench_lock_fds[@]}"; do exec {fd}>&-; done
  bench_lock_fds=()
  unset BENCH_CPUS
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  set -euo pipefail
  [ $# -gt 0 ] || { echo "usage: bench-lock.sh cmd [args...]" >&2; exit 2; }
  bench_lock_acquire
  taskset -c "$BENCH_CPUS" "$@"
fi
