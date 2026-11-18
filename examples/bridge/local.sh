#!/usr/bin/env bash
# Runs the bridge on this machine: an indexer on 127.0.0.1:3000 and two networks of 4
# validators (1-4 on ports 3001-3004, 5-8 on 3005-3008), each network's secret dealt by
# bridge-dealer. Logs go to <dir>/<indexer|validator-N>.log; stops everything on exit.
#   zig build -Doptimize=ReleaseFast && examples/bridge/local.sh /tmp/zigware-bridge
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
dir=${1:?usage: local.sh <dir>}
bin=zig-out/bin
rm -rf "$dir"
mkdir -p "$dir"

# Network n's dealing: seed n, participants 1-4 or 5-8.
deal() { "$bin/bridge-dealer" --seed "$1" --participants "$2"; }
deal 1 1,2,3,4 >"$dir/network-1.txt"
deal 2 5,6,7,8 >"$dir/network-2.txt"
field() { awk -v key="$2" '$1 == key { print $NF }' "$dir/network-$1.txt"; }
share() { grep "validator=$2)" "$dir/network-$1.txt" | awk '{ print $NF }'; }

pids=()
trap 'kill "${pids[@]}" 2>/dev/null || true; wait 2>/dev/null || true' EXIT
"$bin/bridge-indexer" --me 0@3000 --participants 1,2,3,4,5,6,7,8 \
  --networks "$(field 1 public:),$(field 2 public:)" >"$dir/indexer.log" 2>&1 &
pids+=($!)
sleep 1
for v in 1 2 3 4 5 6 7 8; do
  if [ "$v" -le 4 ]; then net=1 other=2 first=1 parts=1,2,3,4; else
    net=2 other=1 first=5 parts=5,6,7,8
  fi
  boot=()
  [ "$v" != "$first" ] && boot=(--bootstrappers "$first@127.0.0.1:300$first")
  "$bin/bridge-validator" --me "$v@300$v" "${boot[@]}" --participants "$parts" \
    --storage-dir "$dir/storage-$v" --indexer 0@127.0.0.1:3000 \
    --identity "$(field $net polynomial:)" --share "$(share $net $v)" \
    --other-public "$(field $other public:)" >"$dir/validator-$v.log" 2>&1 &
  pids+=($!)
done
wait
