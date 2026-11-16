#!/usr/bin/env bash
# Runs every peer of a local flood deployment (examples/flood/local.sh) on this machine,
# interleaving their logs, and prints what each peer received every two seconds. (Its sent
# counter also counts sends made before any peer connected, as commonware's does.)
#   examples/flood/demo.sh <directory> [seconds]
set -euo pipefail

dir=${1:?usage: demo.sh <directory> [seconds]}
seconds=${2:-10}
flood=${FLOOD:-zig-out/bin/flood}
flood=$(realpath "$flood")

colors=(36 33 35 32 34 31)
pids=()
stop() { for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done; wait 2>/dev/null || true; }
trap stop EXIT

index=0
# Peers in hosts.yaml order, so peer i is 127.0.0.<i>.
for key in $(awk '$1 == "-" && $2 == "name:" { print $3 }' "$dir/hosts.yaml"); do
  config=$dir/$key.yaml
  color=${colors[index % ${#colors[@]}]}
  label=$(printf '\033[%sm[peer %d]\033[0m' "$color" $((index + 1)))
  (cd "$dir" && exec "$flood" --hosts hosts.yaml --config "$(basename "$config")") 2>&1 |
    sed -u "s/^/$label /" &
  pids+=($!)
  index=$((index + 1))
done
peers=$index

metric() { awk -v name="$2" '$1 == name { print $2 }' <<<"$1"; }

declare -a last
for ((i = 1; i <= peers; i++)); do last[i]=0; done
sleep 1
for ((elapsed = 2; elapsed <= seconds; elapsed += 2)); do
  sleep 2
  printf '\n\033[1m%-8s %10s %12s %14s   after %ds\033[0m\n' peer received messages/s \
    mean_latency "$elapsed"
  for ((i = 1; i <= peers; i++)); do
    page=$(curl -s --max-time 1 "http://127.0.0.$i:9090/metrics" || true)
    received=$(metric "$page" flood_receiver_latency_count)
    sum=$(metric "$page" flood_receiver_latency_sum)
    rate=$(((${received:-0} - last[i]) / 2))
    last[i]=${received:-0}
    mean=$(awk -v s="${sum:-0}" -v n="${received:-0}" \
      'BEGIN { if (n > 0) printf "%.3f ms", 1000 * s / n; else print "-" }')
    printf '%-8s %10s %12s %14s\n' "peer $i" "${received:--}" "$rate" "$mean"
  done
done
