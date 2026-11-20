#!/usr/bin/env bash
# Head-to-head benchmarks: commonware's criterion benches against zigware's counterparts of the
# same name (and so the same parameters), on this machine. docs/BENCHMARKS.md has the results.
#
#   etc/scripts/bench-compare.sh [runs]     `runs` rounds (default 4), in ABBA order
#
# COMMONWARE_REF names the commonware checkout (default ~/.cache/zigware/commonware-ref).
# BENCH_DIR is where both sides' storage benches keep their files (default ${TMPDIR:-/tmp}):
# commonware's tokio runner uses `env::temp_dir()` and zigware's benches `./.zig-cache/tmp`,
# so commonware runs with TMPDIR and zigware with its working directory under it.
# BENCH_FILTER keeps only the benches whose name contains it.
# BENCH_SET=all compares every bench a zigware harness lists that a commonware criterion bench
# also lists under the same name, instead of the hand-picked rows below; BENCH_SET=<package>
# (such as formatting or storage) does the same for one zigware package. The rows come from
# both sides' `--bench --list`, and the set's commonware crates build in one cargo call.
# Rounds run in ABBA order: odd rounds run commonware then zigware, even rounds zigware then
# commonware, so drift within a round cancels. The ratio is the median of the per-round
# (paired) zigware / commonware ratios; BENCH_STAT=best reports the best of each side instead.
# A row is "faster" only when the median is below 0.95 and at most n/8 of its n rounds
# (rounded down: none of 4, one of 8) reach 1, "slower" mirrored, and "tie" otherwise (noise
# counts as not yet faster); raise `runs` on noisy rows. Each round's pair holds one slot of
# the machine-wide bench queue (etc/scripts/bench-lock.sh: first come, first served, one CCD
# per slot), and both sides run pinned to it, so lanes' benches never share cores.
# BENCH_WHOLE=1 takes both slots for rows above 16 threads. commonware builds with
# RUSTFLAGS="-C target-cpu=native" in its
# own target directory (target-native), as zigware builds for the native CPU; CW_NATIVE=0
# builds it for baseline x86-64 instead. The table goes to stdout; the raw medians to
# .cache/bench-compare/raw.tsv (a previous one moves to raw.<UTC time>.tsv), in the format
# docs/bench/<lane>.tsv takes: `# key: value`
# header lines (date, zigware, commonware, method), then one row per bench and round of
# round, zigware package, bench name, commonware ns, zigware ns, and 1-minute load (tab
# separated; a failed side is nan).
set -euo pipefail

runs=${1:-4}
ref=${COMMONWARE_REF:-$HOME/.cache/zigware/commonware-ref}
root=$(cd "$(dirname "$0")/../.." && pwd)
source "$root/etc/scripts/bench-lock.sh"
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
  # One case per qmdb group and family; the other qmdb names match commonware's too.
  "qmdb|storage|qmdb::apply_batch/case=direct variant=immutable::fixed::mmb chunk=32 updates=16384"
  "qmdb|storage|qmdb::apply_batch/case=direct variant=any::ordered::p256::fixed::mmb chunk=32 \
updates=16384"
  "qmdb|storage|qmdb::apply_batch/case=uncomm_ancestor variant=any::unordered::fixed::mmb chunk=32 \
updates=16384"
  "qmdb|storage|qmdb::chained_growth/variant=current::unordered::fixed::mmb chunk=32 batches=100"
  "qmdb|storage|qmdb::generate/variant=any::unordered::fixed::mmb elements=1000 operations=10000"
  "qmdb|storage|qmdb::generate/variant=any::ordered::variable::mmb elements=1000 operations=10000"
  "qmdb|storage|qmdb::generate/variant=current::unordered::fixed::mmb elements=1000 \
operations=10000"
  "qmdb|storage|qmdb::generate/variant=keyless::mmb operations=10000"
  "qmdb|storage|qmdb::generate/variant=store::variable elements=1000 operations=10000"
  "qmdb|storage|qmdb::init/variant=any::unordered::fixed::mmb cache=0 elements=100000"
  "qmdb|storage|qmdb::init/variant=current::ordered::fixed::mmb cache=262144 elements=100000"
  "qmdb|storage|qmdb::init/variant=store::variable cache=0 elements=100000"
  "qmdb|storage|qmdb::merkleize/v=any::unordered::fixed::mmb k=10000 ch=false s=false cc=false"
  "qmdb|storage|qmdb::merkleize/v=any::ordered::variable::mmr k=10000 ch=true s=false cc=false"
  "qmdb|storage|qmdb::merkleize/v=current::unordered::fixed::mmb chunk=32 k=10000 ch=false s=false \
cc=false"
  "qmdb|storage|qmdb::merkleize/variant=any::unordered::fixed::mmb keys=10000 churn=50 \
cache_pages=32"
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
  "secp256r1|cryptography|secp256r1::signature_generation/variant=standard ns_len=9 msg_len=32"
  "secp256r1|cryptography|secp256r1::signature_generation/variant=recoverable ns_len=9 \
msg_len=32"
  "secp256r1|cryptography|secp256r1::signature_verification/variant=standard ns_len=9 msg_len=32"
  "secp256r1|cryptography|secp256r1::signature_verification/variant=recoverable ns_len=9 \
msg_len=32"
  # actor's mailbox, every case.
  "mailbox|actor|mailbox::mailbox::enqueue_ready/capacity=1024"
  "mailbox|actor|mailbox::mailbox::try_recv_ready/capacity=1024"
  "mailbox|actor|mailbox::mailbox::try_recv_overflow/capacity=1024 overflow=1024"
  "mailbox|actor|mailbox::mailbox::round_trip_ready/capacity=1024"
  "mailbox|actor|mailbox::mailbox::recv_waiting/capacity=1"
  "mailbox|actor|mailbox::mailbox::overflow_drop/capacity=1"
  "mailbox|actor|mailbox::mailbox::overflow_spill/capacity=1"
  "mailbox|actor|mailbox::mailbox::overflow_replace/capacity=1024 position=newest"
  "mailbox|actor|mailbox::mailbox::overflow_replace/capacity=1024 position=oldest"
  "mailbox|actor|mailbox::mailbox::concurrent_enqueue/producers=4 capacity=65536"
  # bulletproofs ipa, every case; conc=8 runs on an adaptive Policy on both sides.
  "bulletproofs|cryptography|bulletproofs::ipa::prove/n=8 conc=1"
  "bulletproofs|cryptography|bulletproofs::ipa::prove/n=8 conc=8"
  "bulletproofs|cryptography|bulletproofs::ipa::prove/n=16 conc=1"
  "bulletproofs|cryptography|bulletproofs::ipa::prove/n=16 conc=8"
  "bulletproofs|cryptography|bulletproofs::ipa::prove/n=32 conc=1"
  "bulletproofs|cryptography|bulletproofs::ipa::prove/n=32 conc=8"
  "bulletproofs|cryptography|bulletproofs::ipa::prove/n=64 conc=1"
  "bulletproofs|cryptography|bulletproofs::ipa::prove/n=64 conc=8"
  "bulletproofs|cryptography|bulletproofs::ipa::prove/n=128 conc=1"
  "bulletproofs|cryptography|bulletproofs::ipa::prove/n=128 conc=8"
  "bulletproofs|cryptography|bulletproofs::ipa::verify/n=8 conc=1"
  "bulletproofs|cryptography|bulletproofs::ipa::verify/n=8 conc=8"
  "bulletproofs|cryptography|bulletproofs::ipa::verify/n=16 conc=1"
  "bulletproofs|cryptography|bulletproofs::ipa::verify/n=16 conc=8"
  "bulletproofs|cryptography|bulletproofs::ipa::verify/n=32 conc=1"
  "bulletproofs|cryptography|bulletproofs::ipa::verify/n=32 conc=8"
  "bulletproofs|cryptography|bulletproofs::ipa::verify/n=64 conc=1"
  "bulletproofs|cryptography|bulletproofs::ipa::verify/n=64 conc=8"
  "bulletproofs|cryptography|bulletproofs::ipa::verify/n=128 conc=1"
  "bulletproofs|cryptography|bulletproofs::ipa::verify/n=128 conc=8"
)

cw_env=()
if [[ "${CW_NATIVE:-1}" == 1 ]]; then
  cw_env=(RUSTFLAGS="-C target-cpu=native" CARGO_TARGET_DIR="$ref/target-native")
fi
bench_set=${BENCH_SET:-}
cargo_args=(
  -p commonware-codec -p commonware-cryptography -p commonware-storage -p commonware-runtime
  -p commonware-actor
  --features commonware-storage/test-traits
  --bench codec --bench sha256 --bench ed25519 --bench bls12381
  --bench journal --bench qmdb --bench merkle --bench bmt --bench rmap --bench buffer_paged
  --bench chacha20_poly1305 --bench sake
  --bench secp256r1 --bench mailbox --bench bulletproofs
)
if [[ -n "$bench_set" ]]; then
  # Every commonware crate with bench targets (all), or the one named after the package:
  # commonware-<package>, or commonware-*-<package> (curve25519).
  mapfile -t crates < <(cd "$ref" && cargo metadata --no-deps --format-version 1 |
    python3 -I -c '
import json, sys
want = sys.argv[1]
for package in json.load(sys.stdin)["packages"]:
    if not any("bench" in target["kind"] for target in package["targets"]):
        continue
    name = package["name"]
    if want == "all" or name == "commonware-" + want or name.endswith("-" + want):
        print(name)
' "$bench_set")
  if ((${#crates[@]} == 0)); then
    echo "BENCH_SET=$bench_set: no commonware crate with benches matches" >&2
    exit 1
  fi
  cargo_args=(--benches)
  for crate in "${crates[@]}"; do
    cargo_args+=(-p "$crate")
    [[ "$crate" == commonware-storage ]] && cargo_args+=(--features commonware-storage/test-traits)
  done
fi
echo "building commonware benches (cargo bench --no-run, release, ${cw_env[*]:-baseline})" >&2
(cd "$ref" && env "${cw_env[@]}" cargo bench --no-run --message-format=json \
  "${cargo_args[@]}" 2> "$out/cargo.log") |
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

# The names a criterion-style `--bench --list` prints (`<name>: benchmark`), one per line.
list_names() { sed -n 's/: benchmark$//p'; }

if [[ -n "$bench_set" ]]; then
  # Pair every name a zigware harness lists with the commonware target listing the same name.
  # A harness whose listing fails (stderr in list.log) contributes no rows.
  : > "$out/zigware-names" && : > "$out/commonware-names" && : > "$out/list.log"
  for harness in "$root"/zig-out/bench/bench-*; do
    package=${harness##*/bench-}
    [[ "$bench_set" == all || "$bench_set" == "$package" ]] || continue
    (cd "$scratch" && "$harness" --bench --list 2>> "$out/list.log") | list_names |
      sed "s|^|$package\t|" >> "$out/zigware-names" || true
  done
  while read -r target executable; do
    (cd "$ref" && TMPDIR="$scratch" "$executable" --bench --list 2>> "$out/list.log") |
      list_names | sed "s|^|$target\t|" >> "$out/commonware-names" || true
  done < "$out/cargo-bins"
  mapfile -t benches < <(python3 -I - "$out/zigware-names" "$out/commonware-names" << 'EOF'
import collections, sys
targets = {}
for line in open(sys.argv[2]):
    target, name = line.rstrip("\n").split("\t", 1)
    targets.setdefault(name, target)
seen = set()
counts = collections.Counter()
listed = collections.Counter()
for line in open(sys.argv[1]):
    package, name = line.rstrip("\n").split("\t", 1)
    listed[package] += 1
    if name in targets and name not in seen:
        seen.add(name)
        counts[package] += 1
        print(f"{targets[name]}|{package}|{name}")
for package in sorted(listed):
    print(f"{package}: {counts[package]} of {listed[package]} zigware benches have a commonware "
          "counterpart", file=sys.stderr)
print(f"{len(seen)} rows; {len(targets) - len(seen)} commonware benches without a zigware one",
      file=sys.stderr)
EOF
  )
fi

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

cw_cpu=baseline
[[ "${CW_NATIVE:-1}" == 1 ]] && cw_cpu=native
method="ABBA rounds=$runs, ${cw_args[*]} | ${zw_args[*]}, commonware target-cpu=$cw_cpu"
# A restart keeps the previous run's rows: raw.tsv moves to raw.<UTC time>.tsv first.
[ -s "$out/raw.tsv" ] && mv "$out/raw.tsv" "$out/raw.$(date -u +%Y%m%dT%H%M%S).tsv"
{
  echo "# date: $(date -u +%F)"
  echo "# zigware: $(git -C "$root" rev-parse --short HEAD)"
  echo "# commonware: $(git -C "$ref" rev-parse --short HEAD)"
  echo "# method: $method"
} > "$out/raw.tsv"
: > "$out/bench.log"
for run in $(seq 1 "$runs"); do
  for entry in "${benches[@]}"; do
    IFS='|' read -r target package name <<< "$entry"
    [[ "$name" == *"${BENCH_FILTER:-}"* ]] || continue
    load=$(cut -d' ' -f1 /proc/loadavg 2> /dev/null || uptime | sed 's/.*average[s]*: //')
    # A failed run records nan (its stderr is in bench.log) instead of ending the comparison.
    log="$out/bench.log"
    run_cw() {
      cw=$(cd "$ref" && TMPDIR="$scratch" taskset -c "$BENCH_CPUS" "$(cw_bin "$target")" \
        "${cw_args[@]}" --exact \
        "$name" 2>> "$log" | median_ns "$name") || cw=nan
    }
    run_zw() {
      zw=$(cd "$scratch" && taskset -c "$BENCH_CPUS" "$root/zig-out/bench/bench-$package" \
        "${zw_args[@]}" -- "$name" \
        2>> "$log" | median_ns "$name") || zw=nan
    }
    bench_lock_acquire
    if ((run % 2 == 1)); then run_cw; run_zw; else run_zw; run_cw; fi
    bench_lock_release
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$run" "$package" "$name" "${cw:-nan}" "${zw:-nan}" \
      "$load" |
      tee -a "$out/raw.tsv" >&2
  done
done

fstype=$(findmnt -no FSTYPE --target "$scratch" 2> /dev/null || echo unknown)
python3 -I - "$out/raw.tsv" "$fstype" "${BENCH_STAT:-median}" << 'EOF'
import math, statistics, sys
best = {}
values = {}
ratios = {}
loads = []
order = []
for line in open(sys.argv[1]):
    if line.startswith("#"):
        continue
    run, _package, name, cw, zw, load = line.rstrip("\n").split("\t")
    loads.append(float(load))
    if name not in best:
        order.append(name)
        best[name] = [math.inf, math.inf]
        values[name] = [[], []]
        ratios[name] = []
    for side, value in enumerate((cw, zw)):
        value = float(value)
        if not math.isnan(value):
            best[name][side] = min(best[name][side], value)
            values[name][side].append(value)
    if not math.isnan(float(cw)) and not math.isnan(float(zw)):
        ratios[name].append(float(zw) / float(cw))
median = sys.argv[3] == "median"

def show(ns):
    if math.isinf(ns):
        return "n/a"
    for unit, size in (("s", 1e9), ("ms", 1e6), ("µs", 1e3)):
        if ns >= size:
            return f"{ns / size:.3g} {unit}"
    return f"{ns:.3g} ns"

print("| bench | parameters | commonware | zigware | zigware / commonware | rounds | verdict |")
print("|---|---|---|---|---|---|---|")
counts = {"faster": 0, "tie": 0, "slower": 0}
for name in order:
    group, _, params = name.partition("/")
    cw, zw = best[name]
    ratio = "n/a" if math.isinf(cw) or math.isinf(zw) else f"{zw / cw:.2f}×"
    if median:
        cw, zw = (statistics.median(v) if v else math.inf for v in values[name])
        ratio = f"{statistics.median(ratios[name]):.2f}×" if ratios[name] else "n/a"
    paired = ratios[name]
    spread = f"{min(paired):.2f}–{max(paired):.2f}× ({len(paired)})" if paired else "n/a"
    verdict = "n/a"
    if paired:
        mid = statistics.median(paired)
        verdict = "tie"
        allowed = len(paired) // 8
        if mid < 0.95 and sum(r >= 1 for r in paired) <= allowed:
            verdict = "faster"
        elif mid > 1.05 and sum(r <= 1 for r in paired) <= allowed:
            verdict = "slower"
        counts[verdict] += 1
    print(f"| `{group}` | `{params}` | {show(cw)} | {show(zw)} | {ratio} | {spread} | {verdict} |")
print(f"\nfaster {counts['faster']}, tie {counts['tie']}, slower {counts['slower']}.")
if median:
    print("Medians over the rounds; the ratio is the median of each round's paired ratio.")
print(f"\nLoad average (1 min) during the runs: {min(loads):.1f} to {max(loads):.1f}.")
print(f"Storage benches ran on: {sys.argv[2]}.")
EOF
