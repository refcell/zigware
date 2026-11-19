#!/usr/bin/env bash
# Head-to-head benchmarks: commonware's criterion benches against zigware's counterparts of the
# same name (and so the same parameters), on this machine. docs/BENCHMARKS.md has the results.
#
#   etc/scripts/bench-compare.sh [runs]     best of `runs` (default 3) medians per side
#
# COMMONWARE_REF names the commonware checkout (default ~/.cache/zigware/commonware-ref).
# BENCH_DIR is where both sides' storage benches keep their files (default ${TMPDIR:-/tmp}):
# commonware's tokio runner uses `env::temp_dir()` and zigware's benches `./.zig-cache/tmp`,
# so commonware runs with TMPDIR and zigware with its working directory under it.
# BENCH_FILTER keeps only the benches whose name contains it.
# Each run alternates the two sides so both see the same machine load. The table goes to
# stdout; the raw medians to .cache/bench-compare/raw.tsv.
set -euo pipefail

runs=${1:-3}
ref=${COMMONWARE_REF:-$HOME/.cache/zigware/commonware-ref}
root=$(cd "$(dirname "$0")/../.." && pwd)
out="$root/.cache/bench-compare"
mkdir -p "$out"
scratch=$(mktemp -d "${BENCH_DIR:-${TMPDIR:-/tmp}}/bench-compare.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
# The same criterion settings on both sides.
cw_args=(--bench --noplot --warm-up-time 1 --measurement-time 3 --sample-size 50)
zw_args=(--bench --warm-up-ms 1000 --measurement-ms 3000 --samples 50)

# commonware bench target | zigware package | the bench name both print.
benches=(
  "codec|codec|codec::lazy::get/source=shared txs=100000 conc=1"
  "sha256|cryptography|sha256::hash_message/msg_len=4096"
  "sha256|cryptography|sha256::hash_message/msg_len=1048576"
  "ed25519|cryptography|ed25519::signature_verification/ns_len=9 msg_len=32"
  "ed25519|cryptography|ed25519::batch_verify_same_message/pks=100 conc=1"
  "bls12381|cryptography|bls12381::signature_verification/ns_len=9 msg_len=32"
  "bls12381|cryptography|bls12381::aggregate_verify_same_message/pks=1000"
  "journal|storage|journal::fixed_append/items=10000 size=32"
  "journal|storage|journal::append_sync/journal=fixed mode=sync"
  "journal|storage|journal::fixed_replay/items=100000 buffer=65536 size=32 read_options=cache"
  "qmdb|storage|qmdb::apply_batch/case=direct variant=any::unordered::fixed::mmb chunk=32 \
updates=16384"
  "buffer_paged|runtime|buffer_paged::append/backend=tokio chunk=4096"
  # storage-merkle's merkle, bmt, rmap, and variable-journal read benches.
  "merkle|storage|merkle::append/n=100000 family=mmr"
  "merkle|storage|merkle::append/n=100000 family=mmb"
  "merkle|storage|merkle::add_many/items=65536 workers=1 family=mmr"
  "merkle|storage|merkle::add_many/items=65536 workers=8 family=mmb"
  "merkle|storage|merkle::update/updates=100000 leaves=100000 strategy=BatchedSerial family=mmr"
  "merkle|storage|merkle::flush/n=100000 family=mmr"
  "merkle|storage|merkle::position_to_location/n=1000000 family=mmb"
  "merkle|storage|merkle::proof/n=100000 samples=100 family=mmr"
  "merkle|storage|merkle::proof/n=100000 samples=100 family=mmb"
  "merkle|storage|merkle::multi_proof/n=100000 items=100 family=mmr"
  "merkle|storage|merkle::range_proof/n=100000 range=100 samples=100 family=mmb"
  "merkle|storage|merkle::verify_single_element/n=100000 samples=100 family=mmr"
  "merkle|storage|merkle::verify_single_element/n=100000 samples=100 family=mmb"
  "merkle|storage|merkle::verify_multi/n=100000 items=100 family=mmr"
  "merkle|storage|merkle::verify_many_elements/n=100000 range=100 samples=100 family=mmr"
  "bmt|storage|bmt::build/n=100000"
  "bmt|storage|bmt::proof/n=100000"
  "bmt|storage|bmt::multi_proof/n=100000 items=100"
  "bmt|storage|bmt::range_proof/n=100000 items=100"
  "bmt|storage|bmt::verify_single/n=100000 items=100"
  "bmt|storage|bmt::verify_multi/n=100000 items=100"
  "bmt|storage|bmt::verify_range/n=100000 items=100"
  "rmap|storage|rmap::insert/items=100000"
  "journal|storage|journal::read_cached/journal=variable size=32"
  "journal|storage|journal::variable_read_random/mode=serial items=10000 size=32"
  "journal|storage|journal::variable_read_random/mode=read_many items=10000 size=32"
  "journal|storage|journal::variable_read_compressed/mode=read_many items=10000 size=1024 \
random=true"
  "journal|storage|journal::variable_read_compressed/mode=read_many_uncached items=10000 \
size=1024 random=true"
  "journal|storage|journal::variable_replay/items=100000 buffer=65536 size=32 \
read_options=cache"
  # p2p's hot paths (stream's cipher and handshake); p2p and stream have no benches of their own.
  "chacha20_poly1305|cryptography|chacha20_poly1305::seal_open/n=4096"
  "chacha20_poly1305|cryptography|chacha20_poly1305::seal_open/n=65536"
  "chacha20_poly1305|cryptography|chacha20_poly1305::seal_open/n=1048576"
  "sake|cryptography|sake::sake"
)

echo "building commonware benches (cargo bench --no-run, release)" >&2
(cd "$ref" && cargo bench --no-run --message-format=json \
  -p commonware-codec -p commonware-cryptography -p commonware-storage -p commonware-runtime \
  --features commonware-storage/test-traits \
  --bench codec --bench sha256 --bench ed25519 --bench bls12381 \
  --bench journal --bench qmdb --bench merkle --bench bmt --bench rmap --bench buffer_paged \
  --bench chacha20_poly1305 --bench sake \
  2> "$out/cargo.log") |
  python3 -I -c '
import json, sys
for line in sys.stdin:
    try:
        message = json.loads(line)
    except ValueError:
        continue
    if message.get("reason") == "compiler-artifact" and message.get("executable"):
        if "bench" in message["target"]["kind"]:
            print(message["target"]["name"] + " " + message["executable"])
' > "$out/cargo-bins"
echo "building zigware benches (zig build bench-install, ReleaseFast)" >&2
(cd "$root" && zig build bench-install)

cw_bin() { awk -v n="$1" '$1 == n { print $2 }' "$out/cargo-bins"; }

# The median (ns) of the block named exactly `$1` in criterion-style output on stdin. It reads
# all of stdin: zigware's filters match substrings, so later benches may follow, and closing
# the pipe early would fail their writes.
median_ns() {
  python3 -I -c '
import re, sys
want = sys.argv[1]
scale = {"ps": 1e-3, "ns": 1, "µs": 1e3, "us": 1e3, "ms": 1e6, "s": 1e9}
previous = ""
found = None
for raw in sys.stdin:
    line = raw.rstrip("\n").split("\r")[-1]
    match = re.search(r"time:\s+\[(\S+) (\S+) (\S+) (\S+) (\S+) (\S+)\]", line)
    if match:
        name = line[: line.index("time:")].strip() or previous
        if name == want and found is None:
            found = float(match.group(3)) * scale[match.group(4)]
    elif line.strip():
        previous = line.strip()
if found is not None:
    print(found)
' "$1"
}

: > "$out/raw.tsv"
: > "$out/bench.log"
for run in $(seq 1 "$runs"); do
  for entry in "${benches[@]}"; do
    IFS='|' read -r target package name <<< "$entry"
    [[ "$name" == *"${BENCH_FILTER:-}"* ]] || continue
    load=$(cut -d' ' -f1 /proc/loadavg 2> /dev/null || uptime | sed 's/.*average[s]*: //')
    # A failed run records nan (its stderr is in bench.log) instead of ending the comparison.
    log="$out/bench.log"
    cw=$(cd "$ref" && TMPDIR="$scratch" "$(cw_bin "$target")" "${cw_args[@]}" --exact "$name" \
      2>> "$log" | median_ns "$name") || cw=nan
    zw=$(cd "$scratch" && "$root/zig-out/bench/bench-$package" "${zw_args[@]}" -- "$name" \
      2>> "$log" | median_ns "$name") || zw=nan
    printf '%s\t%s\t%s\t%s\t%s\n' "$run" "$name" "${cw:-nan}" "${zw:-nan}" "$load" |
      tee -a "$out/raw.tsv" >&2
  done
done

fstype=$(findmnt -no FSTYPE --target "$scratch" 2> /dev/null || echo unknown)
python3 -I - "$out/raw.tsv" "$fstype" << 'EOF'
import math, sys
best = {}
loads = []
order = []
for line in open(sys.argv[1]):
    run, name, cw, zw, load = line.rstrip("\n").split("\t")
    loads.append(float(load))
    if name not in best:
        order.append(name)
        best[name] = [math.inf, math.inf]
    for side, value in enumerate((cw, zw)):
        value = float(value)
        if not math.isnan(value):
            best[name][side] = min(best[name][side], value)

def show(ns):
    if math.isinf(ns):
        return "n/a"
    for unit, size in (("s", 1e9), ("ms", 1e6), ("µs", 1e3)):
        if ns >= size:
            return f"{ns / size:.3g} {unit}"
    return f"{ns:.3g} ns"

print("| bench | parameters | commonware | zigware | zigware / commonware |")
print("|---|---|---|---|---|")
for name in order:
    group, _, params = name.partition("/")
    cw, zw = best[name]
    ratio = "n/a" if math.isinf(cw) or math.isinf(zw) else f"{zw / cw:.2f}×"
    print(f"| `{group}` | `{params}` | {show(cw)} | {show(zw)} | {ratio} |")
print(f"\nLoad average (1 min) during the runs: {min(loads):.1f} to {max(loads):.1f}.")
print(f"Storage benches ran on: {sys.argv[2]}.")
EOF
