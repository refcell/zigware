# Benchmarks: zigware against commonware

Twelve of commonware's criterion benchmarks, each run against the zigware benchmark of the same
name, so both sides use the same parameters and inputs. Both sides ran on the same machine, one
after the other for each bench, and each number is the best of three criterion medians. Lower is
better. A ratio below 1 means zigware is faster.

| bench | parameters | commonware | zigware | zigware / commonware |
|---|---|---|---|---|
| `codec::lazy::get` | `source=shared txs=100000 conc=1` | 3.57 ms | 590 µs | 0.17× |
| `sha256::hash_message` | `msg_len=4096` | 1.87 µs | 2.08 µs | 1.11× |
| `sha256::hash_message` | `msg_len=1048576` | 480 µs | 538 µs | 1.12× |
| `ed25519::signature_verification` | `ns_len=9 msg_len=32` | 26.7 µs | 43.3 µs | 1.62× (fixed, see below) |
| `ed25519::batch_verify_same_message` | `pks=100 conc=1` | 1.52 ms | 789 µs | 0.52× (re-run, see below) |
| `bls12381::signature_verification` | `ns_len=9 msg_len=32` | 1.51 ms | 1.20 ms | 0.79× (re-run, see below) |
| `bls12381::aggregate_verify_same_message` | `pks=1000` | 3.19 ms | 3.13 ms | 0.98× (re-run, see below) |
| `journal::fixed_append` | `items=10000 size=32` | 2.23 ms | 533 µs | 0.24× (paired median, see below) |
| `journal::append_sync` | `journal=fixed mode=sync` | 14.6 µs | 1.55 µs | 0.11× |
| `journal::fixed_replay` | `items=100000 buffer=65536 size=32 read_options=cache` | 415 µs | 316 µs | 0.76× (re-run, see below) |
| `qmdb::apply_batch` | `case=direct variant=any::unordered::fixed::mmb chunk=32 updates=16384` | 1.79 ms | 1.74 ms | 0.97× (paired median, see below) |
| `buffer_paged::append` | `backend=tokio chunk=4096` | 66.1 ms | 28.2 ms | 0.43× |

Measured 2026-11-19. The 1-minute load average was 28.9 to 83.3 during the runs (see Caveats).
Both sides' storage benches ran on tmpfs.

## Setup

- CPU: AMD Ryzen AI MAX+ 395, 16 cores and 32 threads, 64 MiB L3, `performance` governor,
  125 GiB RAM. Linux 7.2.8.
- commonware: `a9ffc25f3` (2026-11-19), rustc and cargo 1.100.0 (LLVM 23.1.5), built with
  `cargo bench`. That uses the workspace's `bench` profile: release with `overflow-checks = true`,
  the same as commonware's `release` profile.
- zigware: main at `d83f96f`, Zig 0.17.1, harnesses built in ReleaseFast
  (`zig build bench-install`).
- Criterion settings, the same on both sides: 1 s warm-up, 3 s measurement, 50 samples.

## Re-running

```sh
etc/scripts/bench-compare.sh [runs]   # default 3; COMMONWARE_REF=path to the checkout
```

The script builds commonware's bench targets (`cargo bench --no-run -p commonware-codec
-p commonware-cryptography -p commonware-storage -p commonware-runtime --features
commonware-storage/test-traits`) and zigware's measured harnesses (`zig build bench-install`,
which puts them in `zig-out/bench/`). Then it runs each pair `runs` times, alternating sides, as:

```sh
<commonware bench binary> --bench --noplot --warm-up-time 1 --measurement-time 3 \
  --sample-size 50 --exact '<name>'
zig-out/bench/bench-<package> --bench --warm-up-ms 1000 --measurement-ms 3000 --samples 50 \
  -- '<name>'
```

`BENCH_SET=all` compares every bench a zigware harness lists (`--bench --list`) that a
commonware criterion bench also lists under the same name, building all of commonware's bench
crates in one cargo call; `BENCH_SET=<package>` (such as `formatting`) does the same for one
zigware package and the commonware crate of that name.

It prints the table above and writes the raw medians and the load average for each run to
`.cache/bench-compare/raw.tsv`, in docs/bench/<lane>.tsv's format: `# date:`, `# zigware:`,
`# commonware:`, and `# method:` lines, then tab-separated round, zigware package, bench,
commonware ns, zigware ns, and load. Both sides keep their storage benches' files in a scratch
directory under `BENCH_DIR` (default `$TMPDIR` or `/tmp`). commonware gets it through `TMPDIR`
(its tokio runner uses `env::temp_dir()`), and zigware runs from it (its benches use
`./.zig-cache/tmp`).

## Caveats

- **Method from 2026-11-20 on.** `bench-compare.sh` runs rounds in ABBA order (default 4),
  reports the median of per-round ratios, builds commonware with
  `RUSTFLAGS="-C target-cpu=native"` (zigware also builds for the native CPU), and gives each
  row a verdict: "faster" when the median is below 0.95 and at most n/8 of its n rounds reach
  1, "slower" mirrored, "tie" otherwise. Each round's pair waits its turn in a first-come, first-served
  queue (etc/scripts/bench-lock.sh) for one of two slots, one CCD each (8 cores and its own
  L3), and both sides run pinned to that slot, so two lanes' benches never share cores; rows
  above 16 threads take both slots with BENCH_WHOLE=1. Rows measured
  before then alternated with commonware first, often reported best-of-3 per side, and ran
  commonware built for baseline x86-64, which favored zigware wherever commonware relies on
  compiler auto-vectorization.
- **The machine was not quiet.** Other lanes were running test suites on the same desktop, so
  the 1-minute load average on 32 threads ranged from 29 to 83. Best-of-three filters some of
  the noise, but every number here can move by tens of percent. Ratios near 1 (sha256,
  bls12381, journal replay) don't show either side winning. Re-run at a quiet moment before
  quoting exact figures.
- **Storage is on tmpfs, so fsync costs almost nothing.** The journal and buffer numbers
  measure the code's overhead, not the disk. In a first run commonware used tmpfs and zigware
  used btrfs (`.zig-cache/tmp`), and zigware looked 5.6× slower on `fixed_append` and 97×
  slower on `append_sync`. That gap came from the filesystem, not from zigware.
  `bench-compare.sh` now puts both sides on the same directory. A comparison on a real disk is
  still to do.
- Every commonware bench binary installs mimalloc (`Config::DEFAULT`) as its global
  allocator. Since the commit "perf(bench): run measured benches on allocator.Heap"
  (2026-11-19), zigware's measured (ReleaseFast) harnesses run on `allocator.Heap` with
  `Config.default`, the port of that allocator and config; Debug and ReleaseSafe smoke runs keep
  the leak-checking `init.gpa`. Rows measured before that commit ran on `smp_allocator`, which
  maps any allocation in its 64 KiB class fresh and faults it in again on every call.
- commonware's `bls12381` harness builds every case's inputs at startup even when filtered, so
  one run of it takes minutes. Only the measured iterations count toward the numbers.
- No sampling profiler works on this machine: `perf` isn't installed, `ptrace_scope` is 1, and
  gdb hung when it ran the bench as a child. The perf-bug causes below come from reading the
  hot paths. They are hypotheses until someone profiles them.

## Fixed perf bugs

- **`ed25519::batch_verify_same_message`, 2.13× to 1.35× (then 0.52× on IFMA, below).** `verify_shard` summed every
  shard with `core.MultiScalar`, whose 8-point flushes each ran their own 256-doubling chain.
  Shards of 44 or more signatures now go through the bucket MSM in
  `src/cryptography/ed25519/msm.zig` (moved from curve25519's `batch.zig`, which shares it),
  with one `A` term per distinct key, as commonware coalesces. The row above is a separate
  re-run of this pair only (`etc/scripts/bench-compare.sh`'s settings, best of three
  alternating runs, load average 34 to 62). An interleaved A/B of the old and new zigware code
  at a load average of about 67 measured 3.02 ms against 1.90 ms. A component profile of both
  sides (same 100 signatures, ReleaseFast and `--release`, under load) puts the rest of the gap
  in the MSM's field arithmetic: decompressing 100 `R` takes 349 µs against dalek's 406 µs,
  the challenges 30 µs against 37 µs, and the bucket MSM over 200 terms 0.94 to 1.27 ms against
  0.82 to 0.89 ms. Forced to its serial backend (`curve25519_dalek_backend="serial"`), dalek's
  MSM takes 1.55 to 1.77 ms, so its lead is its AVX2 backend. The MSM's width (6), chunking, and
  coalescing match dalek's for this size; the basepoint term now shares the MSM's doubling
  chain instead of a separate 28 µs `mulPublic`.

## Perf bugs (zigware more than 1.5× slower)

- None in the crypto lane's groups since 2026-11-20: `ed25519::signature_verification` (was
  1.62×) is 0.80× commonware; see "cryptography: hashes, ed25519, lthash" below.

## Updates since the table

- **ed25519, 2026-11-19.** The table above predates two fixes. 3907c86 (actor-stream) sums
  batch shards with the bucket MSM. be8adb1 ports commonware curve25519's single-signature
  check (`ed25519/verify_msm.zig`): `half_size` splits `k` so every scalar is below 2^128,
  and one Straus doubling chain of at most 129 steps runs in projective and completed
  coordinates, with width-8 NAF tables of `B` and `2^128 B` built at compile time. The
  re-run of both benches came at a 1-minute load average of 100 to 127, where commonware's
  own medians were 2 to 3 times the table's, so the wall-clock figures are not quotable:
  best medians were 74.8 µs against 57.9 µs for `signature_verification` (1.29×) and
  3.58 ms against 3.81 ms for `batch_verify_same_message` (0.94×). By thread CPU time in
  one process, which the load moves less, the new single verify takes 38 to 40 µs where
  std's `mulDoubleBasePublic` path took 51 to 54 µs. The rest of the gap is std's
  radix-2^51 field arithmetic (commonware selects an AVX-512 or NEON backend) and
  `half_size`, about 4.6 µs here as a 256-bit shift-and-subtract Euclid. A vectorized field
  and a Lehmer-style `half_size` are the next steps.
- **ed25519 on AVX-512 IFMA, 2026-11-19.** `ed25519/verify_ifma.zig` ports commonware's
  packed single-point backend (`curve/avx512/single.rs`): a point's four coordinates share
  one 256-bit vector per limb, so each multiplication level of an addition or doubling is
  one lane-wise IFMA product. It compiles only for targets with AVX-512F, VL, and IFMA (this
  machine has them; CI runners without them keep the scalar Straus, and a test compares the
  two wherever IFMA is present). Best of 3 at a load average of 63 to 73, where commonware's
  `signature_verification` medians ran 37.7 to 54.8 µs: zigware 20.9 µs against commonware
  37.7 µs, about 0.55×. `batch_verify_same_message` (pks=100) does not use the backend yet;
  its best medians were 2.01 ms against 1.70 ms (1.18×), and its bucket MSM is the next user
  of the packed point type.
- **`journal::fixed_replay`, 2026-11-19.** The 1.19× was the bench's consumer, not the replay.
  By thread CPU time per 100k-item replay, the journal's fill (blob reads, CRC-32C at 24 GB/s,
  page copy) took 310 to 450 µs and decoding 110 µs, but the drain loop took 600 µs:
  `std.mem.doNotOptimizeAway(item)` on a `[32]u8` emits one barrier per byte, 32 per item,
  where commonware's `black_box(item)` is one opaque use. The drain now consumes a copy of
  each item through one barrier (`doNotOptimizeAway(&item)`), as `black_box` does; it also
  serves `variable_replay`. Best of 3 at a load average of 74 to 82: zigware 481 µs (was
  1.08 ms at a similar load), commonware 1.78 ms. commonware's multi-threaded runtime slows
  far more under this load than zigware's replay, so the fair comparison is with its quiet
  table figure: 481 µs against 690 µs, about 0.70× while loaded. The table row is a later
  re-run with bench-compare.sh's own method (`BENCH_FILTER=journal::fixed_replay
  etc/scripts/bench-compare.sh 5`: five alternating runs per side on tmpfs, load average 38.6
  to 44.2, on fa6525fd): commonware 415 µs, zigware 316 µs, 0.76×, and zigware was faster in
  all five pairs (315 to 341 µs against 415 to 472 µs). The 1.19× (690 µs against 817 µs)
  was measured before the drain fix. Commonware's replay also keeps three reads in flight
  ahead of the decoder (`Blob::start_read_many`). zigware ports that behind storage
  `Config.read_ahead`, off by default: on `std.Io.Threaded` each read starts on another task,
  and on tmpfs that made fixed replay about 4× slower (1.3 to 2.1 ms against 0.38 to 0.47 ms
  inline), while `variable_replay` was neutral.
- **ed25519 batch MSM on AVX2, 2026-11-19.** `ed25519/verify_avx2.zig` ports
  curve25519-dalek 5.0.0's `backend/vector/avx2` (four radix-2^25.5 field elements per
  `u32x8` lane set, and its parallel extended-point add and double), the backend commonware's
  batch MSM runs on x86-64. The bucket MSM in `ed25519/msm.zig` runs on it wherever the target
  has AVX2 and on std's scalar arithmetic otherwise. Head-to-head for
  `batch_verify_same_message` `pks=100 conc=1`, four alternating runs at a load average of 53
  to 57, best medians: commonware 1.43 ms, zigware on AVX2 1.07 ms (0.75×), zigware on the
  scalar backend 1.95 ms.
- **ed25519 batch MSM on IFMA, 2026-11-19.** The bucket MSM picks `verify_ifma.zig`'s packed
  point first where the target has AVX-512 IFMA (this machine), then AVX2, then std's scalar
  arithmetic. Four alternating runs at a load average of 66 to 74, best medians: commonware
  1.52 ms, zigware on IFMA 789 µs (0.52×), on AVX2 1.16 ms (0.76×). That is the table's row.
- **bls12381, 2026-11-19 (simplex lane).** 67308018, 6e50645b, and 73cb985e sped up the
  pairing, hash-to-curve, and subgroup checks under single verify. The two bls12381 rows
  above are a re-run of this pair only at zigware 3181c058 (`etc/scripts/bench-compare.sh`'s
  settings, best of three alternating runs), at a 1-minute load average of 59 to 111.
  commonware's best medians came out 1.2 to 1.4 times the earlier table's (1.23 ms and
  2.27 ms), so the load inflates both sides and the wall-clock figures are not quotable.
  Single verify had zigware ahead in every run (per-run ratios 0.73×, 0.86×, 0.79×; it was
  1.30×). The aggregate's per-run ratios swung from 0.53× to 1.43×, so its 0.98× shows no
  winner. Per-phase timing counters before the fixes put zigware's single verify at about
  1.17× blst's assembly, so re-run at a quiet moment before quoting the single-verify lead.
- **`qmdb::apply_batch`, 2026-11-19 (row re-measured).** Was 2.72 ms against 1.12 ms
  (2.43×). Timing counters split zigware's apply into the index update (about 2.75 ms) and the
  log append (about 0.7 ms); commonware's Sequential build spends about 1.27 ms and 0.37 ms.
  Two of commonware's apply steps were missing: ffaef15a/eb8466cd probes the index 64 keys
  ahead of each applied chunk (`PROBE_CHUNK`), which halves the index time, and d28ed752 runs
  the index apply as a strategy job alongside the log append, with the bench's databases on
  commonware's 8-thread pool. Allocation is not a factor (no page faults while encoding), so
  no allocator change. Back to back at a load average of 36 to 45, best of three:
  commonware 1.13 ms (runs 1.13 to 1.69), zigware 1.21 ms (1.21 to 1.29). What remains is
  the fixed journal append, about 3× commonware's: a per-op stack-copy encode and a second
  copy through the paged tip. The profile and a patch are with the storage-journal and
  runtime lanes; the in-place encode landed as 55202ede.
  Paired re-run with 55202ede (`bench-compare.sh 5`, each round commonware then zigware back
  to back; load sampled at each round's start): 1.62/1.26 ms (0.78×, load 34.4), 1.19/1.55
  (1.30×, 25.6), 1.66/1.71 (1.03×, 62.7), 1.58/1.93 (1.22×, 49.2), 1.65/1.84 (1.11×, 58.5).
  The median of the per-round ratios is 1.11×, inside the row's noise. Load rose to about 80
  inside round 2, so the start-of-round samples understate it.
- **`journal::fixed_append` and `qmdb::apply_batch` on `allocator.Heap`, 2026-11-20 (rows
  re-measured at d3264bb2, after 0ea389fd).** No journal or bench change. Five paired rounds
  each (`bench-compare.sh 5`), commonware/zigware with the load at the round's start;
  each row shows its median round. `fixed_append`: 2.26/0.550 ms (0.24×, load 86.3),
  2.21/0.538 (0.24×, 83.2), 2.32/0.542 (0.23×, 78.3), 2.23/0.533 (0.24×, 74.3), 2.34/0.534
  (0.23×, 70.2); median 0.24×. `apply_batch`: 1.91/1.71 ms (0.89×, 75.8), 1.66/1.64 (0.99×,
  81.0), 1.54/1.62 (1.05×, 61.6), 1.79/1.74 (0.97×, 52.4), 1.86/1.65 (0.88×, 106.2); median
  0.97× (was 1.11×). The append's remaining cost was first-touch faults on each fresh db's
  2 MB tip buffer: `smp_allocator` unmaps it on free, so every iteration re-faulted it
  (`getrusage` minor faults around the tip copy: 109 to 384 per applied batch before). Same
  tree, counters around the whole apply: `smp_allocator` 177 faults per batch, all in the tip
  copy; `allocator.Heap` 0 in two runs, as it keeps the freed block mapped.

## utils handles.Table on packed slots (2026-11-20, utils lane)

`handles.Table` keeps each slot's metadata and handle together again, as commonware's packed
`Slot` does, so an insert into a large cold table touches one cache line instead of the
metadata and handle lines of 32a9db92's split arrays. Inserts and removes shift a run inside one
64-byte span of packed slots with masks and one store; lookups walk one slot at a time with
98687b0e's single-compare stop. The Clock2Q+ cache sizes its indexes for twice its capacity,
as commonware's `HashTable::with_capacity(2 * capacity)` does, so most runs end at their home
slot. `bench-compare.sh` against commonware built with `target-cpu=native`, on the
CCD-pinned queue. Raw rounds of the cache rows: docs/bench/utils-handles.tsv.

| bench | parameters | commonware | zigware | zigware / commonware | rounds | verdict |
|---|---|---|---|---|---|---|
| `qmdb::apply_batch` | `case=direct variant=immutable::fixed::mmb chunk=32 updates=16384` | 440 µs | 337 µs | 0.76× | 0.37–0.80× (8) | faster (was 3.50×) |
| `transfers::plan` | `transfers=16 accounts=128 effects=none conc=1` | 353 ns | 280 ns | 0.80× | 0.78–0.81× (6) | faster |
| `transfers::plan` | `transfers=16 accounts=4096 effects=none conc=1` | 343 ns | 289 ns | 0.84× | 0.81–0.85× (6) | faster |
| `transfers::plan` | `transfers=16 accounts=1000000 effects=none conc=1` | 346 ns | 265 ns | 0.76× | 0.74–0.78× (6) | faster |
| `transfers::plan` | `transfers=16 accounts=4096 effects=nonce conc=1` | 469 ns | 521 ns | 1.12× | 1.08–1.21× (6) | slower |
| `transfers::plan` | `transfers=16 accounts=1000000 effects=nonce conc=1` | 462 ns | 497 ns | 1.08× | 1.04–1.09× (6) | slower |
| `cache::get` | `capacity=1024` | 2.17 µs | 1.37 µs | 0.63× | 0.61–0.63× (6) | faster |
| `cache::insert` | `capacity=1024` | 48 µs | 29.9 µs | 0.62× | 0.58–0.70× (6) | faster |
| `cache::mixed` | `capacity=1024` | 137 µs | 107 µs | 0.78× | 0.77–0.80× (6) | faster |
| `cache::refill` | `capacity=1024` | 4.66 µs | 5.36 µs | 1.15× | 1.15–1.16× (6) | slower |
| `cache::get` | `capacity=16384` | 2.67 µs | 1.57 µs | 0.59× | 0.58–0.60× (6) | faster |
| `cache::insert` | `capacity=16384` | 63.3 µs | 33.7 µs | 0.53× | 0.51–0.60× (6) | faster |
| `cache::mixed` | `capacity=16384` | 89.5 µs | 78.1 µs | 0.86× | 0.85–0.95× (6) | faster |
| `cache::refill` | `capacity=16384` | 90 µs | 96.5 µs | 1.08× | 1.06–1.09× (6) | slower |
| `cache::get` | `capacity=262144` | 2.77 µs | 1.61 µs | 0.59× | 0.57–0.59× (6) | faster |
| `cache::insert` | `capacity=262144` | 54.6 µs | 109 µs | 1.27× | 0.78–2.66× (6) | tie |
| `cache::mixed` | `capacity=262144` | 126 µs | 151 µs | 1.02× | 0.83–1.52× (6) | tie |
| `cache::refill` | `capacity=262144` | 3.88 ms | 4.24 ms | 1.21× | 0.85–1.57× (6) | tie |

The qmdb row's 1.02× tie after the packed table alone (4 rounds, 438 µs against 443 µs) became
0.76× with two follow-ups. The immutable index reserves its key ring once per batch: the ring
grows by half from a near-empty open, so it ended the 65,536-key seed just past full and the
measured apply regrew and copied it (Rust's `VecDeque` doubles, so commonware keeps headroom).
And `Table.prefetch` warms both cache lines of the 64-byte span from the home slot, which an
insert reads (one line before). Same-binary A/B: about 440 → 370 → 338 µs. Five of the eight
rounds ran at load 5.8 to 6.3 (0.76–0.80×); three under compiles at load 9.9 read 0.37–0.61×.
Raw rounds: docs/bench/storage-qmdb-immutable.tsv.

Load 2.6 to 17.3. The glue rows at conc=8 follow conc=1 (none 0.69–0.74× faster, nonce
0.99–1.04× ties); the nonce rows' remaining gap is in plan's own path (see the glue settle
section below), not the table. Against the split-array table on the same binary harness,
cache::refill stayed at 1.02–1.05×, so refill's gap predates this change. The capacity-262144
rows swing with the queue's load (single rounds from 0.78× to 2.66×) and need a quieter run.

## qmdb: every bench group, pinned ABBA (2026-11-20, storage-qmdb lane)

One row per qmdb group and family, `BENCH_FILTER=qmdb:: BENCH_WARMUP_MS=300
BENCH_MEASURE_MS=1000 BENCH_SAMPLES=10 bench-compare.sh 8` (commonware's own `sample_size(10)`
for these groups), on the CCD-pinned bench queue, at ad4d3ac0 (main c7935b0c, same code), after
the runner plans its samples from wall time as criterion does. Load 0.8 to 78.3. Raw rounds:
docs/bench/storage-qmdb.tsv. Verdicts: 5 faster, 4 tie, 8 slower.

| bench | parameters | commonware | zigware | zigware / commonware | rounds | verdict |
|---|---|---|---|---|---|---|
| `qmdb::apply_batch` | `case=direct variant=any::unordered::fixed::mmb chunk=32 updates=16384` | 610 µs | 705 µs | 1.05× | 0.50–1.28× (8) | slower |
| `qmdb::apply_batch` | `case=direct variant=immutable::fixed::mmb chunk=32 updates=16384` | 423 µs | 1.51 ms | 3.50× | 1.60–3.78× (8) | slower (0.76× faster since; see the utils handles.Table section) |
| `qmdb::apply_batch` | `case=direct variant=any::ordered::p256::fixed::mmb chunk=32 updates=16384` | 1.07 ms | 1.02 ms | 0.91× | 0.64–1.21× (8) | tie |
| `qmdb::apply_batch` | `case=uncomm_ancestor variant=any::unordered::fixed::mmb chunk=32 updates=16384` | 1.63 ms | 1.73 ms | 1.06× | 1.03–1.13× (8) | slower |
| `qmdb::chained_growth` | `variant=current::unordered::fixed::mmb chunk=32 batches=100` | 1.35 ms | 965 µs | 0.71× | 0.68–0.76× (8) | faster |
| `qmdb::generate` | `variant=any::unordered::fixed::mmb elements=1000 operations=10000` | 7.9 ms | 7.91 ms | 1.00× | 0.98–1.05× (8) | tie |
| `qmdb::generate` | `variant=any::ordered::variable::mmb elements=1000 operations=10000` | 12.4 ms | 12.4 ms | 1.01× | 0.99–1.03× (8) | tie |
| `qmdb::generate` | `variant=current::unordered::fixed::mmb elements=1000 operations=10000` | 8.74 ms | 8.29 ms | 0.96× | 0.93–1.07× (8) | tie |
| `qmdb::generate` | `variant=keyless::mmb operations=10000` | 5.7 ms | 2.9 ms | 0.51× | 0.50–0.54× (8) | faster |
| `qmdb::generate` | `variant=store::variable elements=1000 operations=10000` | 6.35 ms | 3.98 ms | 0.63× | 0.62–0.64× (8) | faster |
| `qmdb::init` | `variant=any::unordered::fixed::mmb cache=0 elements=100000` | 25.1 ms | 11.6 ms | 0.46× | 0.44–0.49× (8) | faster |
| `qmdb::init` | `variant=current::ordered::fixed::mmb cache=262144 elements=100000` | 15.1 ms | 17.3 ms | 1.15× | 1.08–1.24× (8) | slower |
| `qmdb::init` | `variant=store::variable cache=0 elements=100000` | 51.2 ms | 27.4 ms | 0.52× | 0.49–0.55× (8) | faster |
| `qmdb::merkleize` | `v=any::unordered::fixed::mmb k=10000 ch=false s=false cc=false` | 313 µs | 707 µs | 2.27× | 2.21–2.37× (8) | slower |
| `qmdb::merkleize` | `v=any::ordered::variable::mmr k=10000 ch=true s=false cc=false` | 479 µs | 1.08 ms | 2.22× | 2.18–2.27× (8) | slower |
| `qmdb::merkleize` | `v=current::unordered::fixed::mmb chunk=32 k=10000 ch=false s=false cc=false` | 369 µs | 736 µs | 1.98× | 1.93–2.15× (8) | slower |
| `qmdb::merkleize` | `variant=any::unordered::fixed::mmb keys=10000 churn=50 cache_pages=32` | 536 µs | 1.08 ms | 2.01× | 1.92–2.07× (8) | slower |

The four `merkleize` rows are now faster (0.78–0.93×); see "qmdb merkleize, pinned ABBA" below.

The immutable `apply_batch` row replaces the 0.67× recorded earlier the same day (8 unpinned
rounds at load 44 to 120, under the old planner). That run's commonware side read 0.97 to 1.52
ms, against 0.42 to 0.63 ms here at low load, so its ratio measured commonware under load, not
zigware's speed. Pinning does not explain the gap: the same binaries on one CCD and on all 32
CPUs read commonware 0.63/0.63 and 0.60/0.58 ms, zigware 1.65/1.48 and 1.54/1.60 ms (load
about 10). b3528252's prefetch still halves zigware's table-insert cycles; the rest of the gap is
open.

## qmdb merkleize, pinned ABBA (2026-11-20, qmdb merkleize thread)

The four `qmdb::merkleize` rows above (1.98–2.27×), re-run on d996f123 with the same settings
(`BENCH_FILTER=qmdb::merkleize BENCH_WARMUP_MS=300 BENCH_MEASURE_MS=1000 BENCH_SAMPLES=10
bench-compare.sh 8`). Load 5.8 to 7.4. Raw rounds: docs/bench/storage-qmdb_merkleize.tsv.
Verdicts: 4 faster.

| bench | parameters | commonware | zigware | zigware / commonware | rounds | verdict |
|---|---|---|---|---|---|---|
| `qmdb::merkleize` | `v=any::unordered::fixed::mmb k=10000 ch=false s=false cc=false` | 327 µs | 272 µs | 0.82× | 0.81–0.87× (8) | faster |
| `qmdb::merkleize` | `v=any::ordered::variable::mmr k=10000 ch=true s=false cc=false` | 498 µs | 467 µs | 0.93× | 0.91–0.96× (8) | faster |
| `qmdb::merkleize` | `v=current::unordered::fixed::mmb chunk=32 k=10000 ch=false s=false cc=false` | 379 µs | 298 µs | 0.78× | 0.76–0.81× (8) | faster |
| `qmdb::merkleize` | `variant=any::unordered::fixed::mmb keys=10000 churn=50 cache_pages=32` | 561 µs | 454 µs | 0.81× | 0.78–0.84× (8) | faster |

What changed (ec2650ed, 03f3ab28, 0290140c, 3ac948ab, d996f123): the bench opens its databases
on an 8-thread pool as commonware's does (`THREADS = 8`); writes, diffs, and locations sort by
an LSD radix pass on each key's first 8 bytes instead of a stable byte-compare merge sort, and
lookups take a branchless prefix search; the fixed journal and the page cache probe a batch of
reads under one cache lock per 64 instead of one per item; ordered emits use advancing cursors;
the snapshot probes are prefetched 8 keys ahead; and the floor walk under `Proportional` moves
values without copying them. Phase times per iteration on one CCD slot (rdtsc in zigware,
`Instant` in commonware, scratch builds), any fixed row: building the batch's 1,000 writes 87
µs vs 132 µs, gathering snapshot locations 15 vs 6, reading them 26 vs 17, emitting 17 vs 31,
the floor walk 49 vs 62, finishing (journal hash and root) 69 vs 67.

## bls12381: the remaining benches (2026-11-19, bls-math lane)

The bls12381 benches the table above left out, at `bench-compare.sh`'s settings (1 s warm-up,
3 s measurement, 50 samples), one `conc=1` case per bench. Each side's number is its best
median of two alternating rounds, at a 1-minute load average of 81 (round 1) and 41
(round 2). Rows marked "re-run" are a later paired re-run of that row alone (two
alternating rounds, best medians, load 28 to 84), after the fixes below and parallel's
batched timing (5c5d48cd); it confirmed `signature_generation` and
`aggregate_verify_same_signer` and showed the other two near-1.3× rows were noise. The
golden DKG rows use 10 samples (commonware's own sample size for them).

| bench | parameters | commonware | zigware | zigware / commonware |
|---|---|---|---|---|
| `bls12381::signature_generation` | `ns_len=9 msg_len=32` | 270 µs | 368 µs | 1.36× (re-run, open) |
| `bls12381::hash_to_curve` | `n=100 conc=1` | 4.33 ms | 7.37 ms | 1.70× (now 1.22×, see below) |
| `bls12381::tle_encrypt` | | 1.29 ms | 1.04 ms | 0.80× |
| `bls12381::tle_decrypt` | | 704 µs | 901 µs | 1.28× |
| `bls12381::combine_public_keys` | `pks=1000` | 1.27 ms | 1.22 ms | 0.96× |
| `bls12381::combine_signatures` | `sigs=1000` | 598 µs | 617 µs | 1.03× (re-run) |
| `bls12381::batch_to_affine` | `group=g1 n=100` | 31.9 µs | 18.9 µs | 0.59× |
| `bls12381::batch_to_affine` | `group=g2 n=100` | 85.8 µs | 62.7 µs | 0.73× |
| `bls12381::attestation_eq` | `bytes=equal` | 35.1 ns | 9.9 ns | 0.28× (re-run, fixed) |
| `bls12381::msm` | `group=g1 n=1000 conc=1` | 14.0 ms | 17.2 ms | 1.22× |
| `bls12381::msm` | `group=g2 n=1000 conc=1` | 40.1 ms | 49.6 ms | 1.23× |
| `bls12381::evaluate_point` | `n=50 t=34 conc=1` | 899 µs | 954 µs | 1.06× |
| `bls12381::batch_verify_same_signer` | `conc=1 msgs=100` | 9.36 ms | 9.29 ms | 0.99× (re-run) |
| `bls12381::aggregate_verify_same_signer` | `conc=1 msgs=100` | 5.90 ms | 7.91 ms | 1.34× (re-run, open) |
| `bls12381::scheme_batch_verify_same_message` | `pks=100 conc=1` | 37.3 ms | 38.8 ms | 1.04× |
| `bls12381::scheme_batch_verify_same_signer` | `msgs=100 conc=1` | 33.3 ms | 37.4 ms | 1.12× |
| `bls12381::threshold_recover` | `mode=NonZeroCounter n=100 t=67` | 954 µs | 959 µs | 1.01× |
| `bls12381::threshold_batch_verify_same_message` | `n=10 t=7 invalid=0 conc=1 mode=NonZeroCounter` | 7.83 ms | 2.20 ms | 0.28× |
| `bls12381::threshold_batch_verify_same_message_pre` | `n=10 t=7 invalid=0 conc=1 mode=NonZeroCounter` | 1.48 ms | 1.71 ms | 1.16× |
| `bls12381::threshold_batch_verify_same_signer` | `n=10 t=7 msgs=100 conc=1 mode=NonZeroCounter` | 9.22 ms | 8.53 ms | 0.93× |
| `bls12381::threshold_optimistic_assemble` | `variant=MinPk mode=NonZeroCounter n=100 case=valid` | 7.00 ms | 7.95 ms | 1.14× (fixed, was 2.54×) |
| `bls12381::multisig_optimistic_assemble` | `variant=MinPk n=100 case=valid` | 1.48 ms | 1.35 ms | 0.91× (re-run, fixed, was 6.51×) |
| `bls12381::dkg::feldman_desmedt_recovery` | `n=20 t=14 conc=1` | 24.1 ms | 12.8 ms | 0.53× |
| `bls12381::dkg::feldman_desmedt_reshare_recovery` | `n=20 t=14 conc=1` | 45.6 ms | 22.4 ms | 0.49× |
| `bls12381::dkg::golden::deal` | `n=5` | 9.16 s | 8.07 s | 0.88× (re-run) |
| `bls12381::dkg::golden::verify` | `n=5` | 849 ms | 411 ms | 0.48× (re-run, fixed, was 3.45×) |

- **Optimistic assembly (fixed, f72c0613).** `certificate.Deferred.get()` decoded the
  signature on every call: for MinPk a G2 decompression and subgroup check, about 105 µs in
  ReleaseFast under load, and an assembly reads 67 of them. commonware's `Lazy` caches the
  decoded value in a `OnceLock`. `Deferred` now keeps the value from `init(value)`, decodes
  read bytes once through `decode()`, and compares like `Lazy`'s `PartialEq` (equal bytes,
  else equal decoded values, two failures equal).
- **`attestation_eq` (fixed, beaf4df5).** Not the harness after all: with 5c5d48cd it still
  read 111 ns. On this AVX-512 machine's native target `std.mem.eql` of 96 bytes costs about
  120 ns (its 64-byte chunk compare reduces a `bool` vector, which lowers slowly), against
  4 to 14 ns built for `x86_64_v3`. `Deferred.eql` now XOR-ORs 32-byte vectors, about 2 ns.
  Any hot `std.mem.eql` over more than 32 bytes pays the same on native AVX-512 builds.
- **`hash_to_curve` (open, simplex lane).** The bench hashes to G1 (MinSig messages): 74 µs
  against 43 µs per hash. 024c35d4 shares the two maps' inversions (56.0 to 50.7 µs by thread
  CPU time); the square roots and cofactor clearing are next. `signature_generation` and
  `aggregate_verify_same_signer` (1.3× to 1.4×) run the same hash and pairing code.
- **`dkg::golden::verify` (fixed).** A per-phase split of one verify (2.04 s) found three
  costs. (1) `Synthetic` merged free terms with a scan and insert per term, quadratic in the
  generator count: bulletproofs verify took 780 ms; one sorted merge, as commonware's
  `BTreeMap` does, takes 24 ms (52d0b401). (2) The eVRF circuit build canonicalized every
  window multiple through `from_x` (three Fermat inversions, a Legendre symbol, a square root:
  48 µs each); a valid point's canonical twin is its affine point negated to a positive `y`,
  so `G.canonical_affine_batch` does a window with one inversion and identical constants, and
  the build drops from about 935 to 33 ms (d80992c3). (3) The final MSM summed 256-point
  chunks with narrow windows; past one chunk the sequential path now runs one tiled
  Pippenger (3d7a069c), about 930 to 555 ms. The MSM is now most of what is left.
  commonware's best here (849 ms, load 53 to 66) is above its quieter 577 ms; against that,
  zigware's 411 ms is 0.71×. Deal shares the circuit build, so it also gained.

## Storage: index, archive, freezer (2026-11-19, clearing lane)

commonware's clearing crate has no benches (`[lib] bench = false`), so this head-to-head covers
the storage benches the clearing lane ported (`index`, `archive`, `freezer`). Same method as
the table above: `bench-compare.sh`'s criterion settings, best of three alternating runs,
both sides on tmpfs, commonware `a9ffc25f3` against zigware `7f0df2c` (ReleaseFast). The
1-minute load average was 28 to 84, so treat ratios near 1 as a tie.

| bench | parameters | commonware | zigware | zigware / commonware |
|---|---|---|---|---|
| `index::insert` | `variant=unordered items=10000` | 267 µs | 200 µs | 0.75× |
| `index::insert` | `variant=ordered items=10000` | 954 µs | 1.15 ms | 1.20× |
| `index::insert` | `variant=partitioned_unordered_1 items=10000` | 356 µs | 308 µs | 0.87× |
| `index::grinding` | `op=lookup dist=uniform items=10000` | 144 µs | 847 µs | 5.89× |
| `index::hashmap_insert` | `n=100000 k=8` | 7.81 ms | 6.39 ms | 0.82× |
| `archive::put` | `variant=prunable items=10000 comp=off` | 484 ms | 970 ms | 2.00× |
| `archive::put` | `variant=immutable items=10000 comp=off` | 697 ms | 1.17 s | 1.68× |
| `archive::get` | `variant=prunable mode=serial pattern=key comp=off items=10000 reads=1000` | 24.1 ms | 47.3 ms | 1.97× |
| `archive::restart` | `variant=prunable items=10000 comp=off` | 4.36 ms | 2.99 ms | 0.69× |
| `freezer::put` | `items=10000` | 134 ms | 9.99 ms | 0.07× |
| `freezer::get` | `pattern=random mode=serial items=10000 reads=1000` | 15.7 ms | 468 µs | 0.03× |
| `freezer::restart` | `items=10000` | 13.5 ms | 6.34 ms | 0.47× |

Slower by more than 1.5×, unprofiled (no sampling profiler works here, see Caveats):
- **`index::grinding` lookup (5.89×).** 10,000 `get`s on a partitioned ordered index
  (`Cap<6>`, two-byte prefix). zigware keeps every run in one treap over
  `(partition, sub-key)`; commonware keeps a sorted array per partition, so its lookups are a
  short binary search over contiguous memory. Guess: pointer chasing in the treap.
- **`archive::put` (2.00× prunable, 1.68× immutable) and `archive::get` serial by key
  (1.97×).** 64 KiB values: guess, extra copies of each value through the paged write buffer
  and on read (commonware hands out `IoBuf`s without copying).
- **`freezer::put` (0.07×) and `freezer::get` random (0.03×)** are far ahead of commonware,
  which this comparison does not explain; check that both sides do the same work (resizes,
  the final sync, the key cache) before quoting them. Checked below.

### Partitioned ordered index: per-partition arrays (2026-11-19, clearing lane)

`partitioned.ordered.Index` now stores each partition as commonware does: sorted parallel
arrays that spill to a tree at 512 entries. Before is zigware `7f0df2c` (one treap), after is
this change; commonware `a9ffc25f3`. Best of two alternating runs, load 52 to 60.

| bench | parameters | commonware | before | after | after / commonware |
|---|---|---|---|---|---|
| `index::grinding` | `op=lookup dist=uniform items=10000` | 169 µs | 847 µs | 143 µs | 0.85× |
| `index::grinding` | `op=lookup dist=grinding items=10000` | 590 µs | | 484 µs | 0.82× |
| `index::grinding` | `op=insert dist=uniform items=10000` | 386 µs | | 473 µs | 1.23× |
| `index::grinding` | `op=insert dist=grinding items=10000` | 904 µs | | 1.29 ms | 1.43× |
| `index::insert` | `variant=partitioned_ordered_2 items=10000` | 409 µs | | 576 µs | 1.41× |

The lookup gap is closed. The partition array is now allocated outside the timed region, as
commonware's `new` allocates it; ordered inserts are still about 1.2 to 1.4× slower
(unprofiled).

### Archive: RNG fill and the glob read buffer (2026-11-19, clearing lane)

Before is zigware `7f0df2c`; after adds two changes. `utils.ChaChaRng.fill_bytes` (cff3e83d)
streams whole buffers straight into the destination instead of copying one word at a time:
filling the put bench's 10,000 64 KiB values took 609 ms of zigware's 970 ms, and now takes
167 ms, byte-identical. Glob `get` reads into the journal's retained scratch buffer: a fresh
64 KiB buffer per get was an mmap, a munmap, and 16 page faults, because `smp_allocator` maps
every allocation over 32 KiB directly (31.5 µs for a fresh 64 KiB alloc and copy against
1.8 µs reused, measured in isolation). Best of two alternating runs, load 43 to 72.

| bench | parameters | commonware | before | after | after / commonware |
|---|---|---|---|---|---|
| `archive::put` | `variant=prunable items=10000 comp=off` | 517 ms | 970 ms | 410 ms | 0.79× |
| `archive::put` | `variant=immutable items=10000 comp=off` | 670 ms | 1.17 s | 424 ms | 0.63× |
| `archive::get` | `variant=prunable mode=serial pattern=key comp=off items=10000 reads=1000` | 24.5 ms | 47.3 ms | 31.0 ms | 1.26× |

The rest of the get gap is the returned value: decoding still allocates its 64 KiB, which
`smp_allocator` maps directly, where commonware's malloc reuses heap memory. The values'
copies are not the cost: CRC32C over 10,000 64 KiB values takes 25 ms and a memcpy 12 ms.

Then the returned value: the archives, the freezer, and the glob gained `get_with(identifier,
value_gpa)`, which decodes the value's memory from the caller's allocator (decompression
scratch still comes from the journal's own). The bench now decodes every read into one reused
64 KiB buffer, as a caller that drops each value does under commonware's malloc. After the
machine's reboot, load 79 to 102:

| bench | parameters | commonware | zigware | zigware / commonware |
|---|---|---|---|---|
| `archive::get` | `variant=prunable mode=serial pattern=key comp=off items=10000 reads=1000` | 16.8 ms | 11.2 ms | 0.67× |
| `archive::get` | `variant=immutable mode=serial pattern=key comp=off items=10000 reads=1000` | 24.2 ms | 13.2 ms | 0.55× |

### Freezer: same work, different I/O dispatch (2026-11-19, clearing lane)

Both benches use the same configuration (1 MiB key and value write buffers, a 65,536-entry
table, 64-byte keys, 128-byte values, a 10,000-page cache, one sync after the loads) and run on
tmpfs. Sampling each process's `/proc/pid/io` over a whole bench run gives the syscalls per
operation (rate × time per iteration):

| bench | side | read or write syscalls/s | time per iteration | syscalls per op |
|---|---|---|---|---|
| `freezer::get` random serial, 1,000 reads | commonware | 229K reads/s | 8.1 ms | 1.9 |
| | zigware | 3.9M reads/s | 0.51 ms | 2.0 |
| `freezer::put`, 10,000 items | commonware | 100K writes/s | 94 ms | 0.94 |
| | zigware | 730K writes/s | 9.2 ms | 0.67 |

So both sides issue about the same reads per `get` (the table entry, then the key and value
reads), and the same order of writes per `put`. The gap is the cost per syscall: about 4 µs on
commonware, whose tokio blob runs each `read_at`/`write_at` on a `spawn_blocking` thread, against
about 0.25 µs on zigware, which calls the kernel inline. The ratio measures the runtimes'
blob dispatch, not the freezer, so quote it as that. The write counts differ by about 30%
(unverified: the samples also cover the untimed setup).

### Ordered index: B-tree heads (2026-11-20, clearing lane)

The flat ordered index kept its translated keys in a `std.Treap`, one key per node and a cache
miss per level. It now keeps them in a B-tree of Rust's `BTreeMap` order (B = 6, 5 to 11 keys
a node), as commonware's `BTreeMap`, with pooled nodes; integer keys (the `IntCap`
translators) search a node by counting the smaller keys without a branch. bench-compare.sh, 8
ABBA rounds on c7935b0c (wall-time iteration planning), commonware target-cpu=native:

| bench | parameters | step | commonware | zigware | rounds | median | verdict |
|---|---|---|---|---|---|---|---|
| `index::insert` | `variant=ordered items=10000` | treap (e76ac91f, 2 rounds) | 744 µs | 939 µs | 1.19–1.33× | 1.26× | slower |
| | | B-tree, linear node search | 491 µs | 487 µs | 0.97–1.21× | 0.99× | tie |
| | | B-tree, branchless search | 645 µs | 586 µs | 0.78–0.95× | 0.87× | faster |

The treap rounds predate the planning fix and were cut short when the bench queue changed, so
read that step as provisional. Load: 1.4 to 61 for the linear search, 26 to 68 for the
branchless one.

## p2p: stream's cipher and handshake (2026-11-19, p2p lane)

commonware's p2p and stream crates have no Criterion benches of their own. Their hot paths
are benched in cryptography: `chacha20_poly1305::seal_open` is stream's per-frame cipher,
and `sake::sake` is one full handshake (two ed25519 keys, two ephemeral X25519 keys, the
exchanges, and the signatures). `bench-compare.sh` now runs these four rows too
(`BENCH_FILTER=` narrows a run to the names containing it). Same method as the table above:
best of three alternating runs, commonware `a9ffc25f3`. "Before" is main at `f1b64446`,
"after" adds `0d25f30c` (the cipher) and `d4996e72` (fixed-base multiplication). The 1-minute
load average was 60 to 83, and commonware's own medians moved by up to 25% between runs, so
each row shows that run's commonware figure.

| bench | parameters | commonware | zigware before | commonware | zigware after | after / commonware |
|---|---|---|---|---|---|---|
| `chacha20_poly1305::seal_open` | `n=4096` | 3.6 µs | 9.67 µs (2.69×) | 3.64 µs | 3.63 µs | 1.00× |
| `chacha20_poly1305::seal_open` | `n=65536` | 55.6 µs | 152 µs (2.74×) | 76 µs | 50.4 µs | 0.66× |
| `chacha20_poly1305::seal_open` | `n=1048576` | 791 µs | 2.57 ms (3.25×) | 935 µs | 824 µs | 0.88× |
| `sake::sake` | | 316 µs | 421 µs (1.33×) | 392 µs | 217 µs | 0.55× |

There is no sampling profiler on this machine (see Caveats), so the components were timed
by thread CPU time in scratch harnesses, best of ten:
- **seal_open.** std's ChaCha20 picks a 4-way `ChaChaVecImpl` on AVX-512, and on this Zen 5
  LLVM lowers it to about 6 ms/MiB, against 2 ms/MiB for std's own AVX2 path. commonware
  runs aws-lc's assembly. zigware's keystream now runs one u32 vector lane per block (16
  blocks per step on AVX-512), so the rounds have no shuffles, and a butterfly of
  `@shuffle`s transposes the lanes back into blocks: 0.14 ms/MiB. Poly1305 (std's, about
  0.23 ms/MiB) is now the larger half. A first try that cast `[64]u8` to a vector with
  `@bitCast` compiled to thousands of scalar moves, at 4.8 ms/MiB; an unaligned vector
  pointer fixed it.
- **sake.** Fixed-base multiplications made up nearly all of the gap. std's
  `basePoint.mul` takes about 43 µs (ed25519 keygen and each signature's `R`), and
  `X25519.recoverPublicKey` is a full ladder at about 34 µs. dalek reads an
  `EdwardsBasepointTable` for both. `ed25519/base_mul.zig` ports that: 64 signed radix-16
  digits over 32 comptime tables, read in constant time. It takes 12.7 µs, and the X25519
  public key 14 µs. The two Diffie-Hellman ladders (about 44 µs each, std's) and the two
  verifications are unchanged.

## End to end: flood, 4 peers (2026-11-19, p2p lane)

`etc/scripts/flood-compare.py` runs four flood peers on this machine with commonware's binary,
then the same four with zigware's (ReleaseFast). Both read one `examples/flood/local.sh`
deployment, so they share the keys, 1024-byte messages, the rate, 2 worker threads, and a
16384-entry mailbox. Every peer floods `p2p.authenticated.discovery` (SAKE and CUPS) over
loopback TCP to the other three. After a warm-up (8 s), it reads each peer's metrics twice
and reports the messages received per second and their mean latency. Each run is 15 or
20 s, alternating sides, commonware `a9ffc25f3` against zigware `08b4d763`, at a load
average of 30 to 100.

The rate is flood's per-peer `Quota`, so each peer can receive at most 3 times the rate. The
ranges cover the four peers over 2 or 3 rounds.

| rate (msg/s per peer) | commonware received/s per peer | latency | zigware received/s per peer | latency |
|---|---|---|---|---|
| 200 (local.sh default) | 600 (cap) | 0.08–1.9 ms | 600 (cap) | 0.07–0.33 ms |
| 16384 (commonware's README) | 49,152 (cap) | 0.6–72 ms | 49,152 (cap) | 0.08–0.34 ms |
| 65536 | 196,600 (cap) | 2.8–3.5 ms | 196,600 (cap) | 0.18–0.21 ms |
| 131072 | 392,000 (cap) | 6.7–10 ms | 393,300 (cap) | 1.0–1.3 ms |
| 262144 | 212,000–266,000 (saturated) | 194–294 ms | 673,000–772,000 (saturated) | 23–80 ms |

zigware reaches the cap at every rate up to 131072. At 262144, where commonware saturates,
zigware delivers about 3 times as many messages at about a fifth of the latency. Below
saturation, its mean latency is 5 to 10 times lower. No row is slower, so nothing was
profiled.

commonware's flood needed two local patches to run here (kept outside the repository):
- **Binding.** It listens on `0.0.0.0:4545` and serves metrics on `0.0.0.0:9090`, so a
  second peer on one machine cannot bind. As zigware's flood does, a peer whose host IP is
  loopback binds that IP.
- **A starved sender (an upstream bug).** `flood_sender` loops on
  `check(Recipients::All)` and `send` without awaiting whenever the check passes. When no
  send is accepted, for example before discovery has connected anyone, the loop spins on
  its tokio worker. The network tasks it wakes sit in that worker's LIFO slot, which other
  workers cannot steal, so no peer ever sends its greeting. After the handshakes, only about
  140 bytes cross each connection, and every peer receives nothing (also with 8 worker
  threads, or with 2 peers). One `commonware_runtime::reschedule().await` when a send is not
  accepted fixes it. The same loop also starves at rates the quota never limits (1,000,000
  msg/s: commonware receives 0, while zigware receives 450,000 to 740,000 per peer), so the
  table stops at 262144. zigware's port has the same loop, but its sender runs on its own
  `std.Io.Threaded` thread, so the spin starves nothing.

Re-run: build commonware's `flood` with those two changes, then `zig build install
-Doptimize=ReleaseFast`, `examples/flood/local.sh 4 <dir> 1024 <rate>`, and
`etc/scripts/flood-compare.py <commonware-flood> zig-out/bin/flood <dir> 20 3 8`.

## End to end: consensus, 4 log validators (2026-11-20, p2p lane)

`etc/scripts/consensus-compare.py` runs four validators of commonware's `log` example
(`a9ffc25f3`, built with `RUSTFLAGS="-C target-cpu=native"`), then four of zigware's
(ReleaseFast, main at `167c52cd`), on loopback in ABBA order, each run 20 s of warm-up and a
60 s window. It counts the views each validator shows finalized and nullified, from the
examples' Activity panes, and reports medians over the validators. The ratio is the median of
the per-round ratios, oriented so that below 1 means zigware is better; "faster" needs that
median below 0.95 and every round below 1.

| run | load (1 min) | metric | commonware | zigware | ratio | verdict |
|---|---|---|---|---|---|---|
| 1 | 85 to 100 | finalized views/s | 1.93 | 3.23 | 0.61× | faster |
| 1 | 85 to 100 | nullified per finalized | 0.282 | 0.229 | 0.81× | faster |
| 2 | 100 to 119 | finalized views/s | 3.64 | 2.95 | 1.28× | not yet faster |
| 2 | 100 to 119 | nullified per finalized | 0.236 | 0.228 | 0.96× | not yet faster |

(Run 1 measured nullified views per second; its row here is recomputed per finalized view from
the same raw counts, so it shows what the script now prints.)

The two runs disagree: each side was ahead in every round of one run, and commonware's rate
nearly doubled between them while zigware's stayed near 3. At a load average of about 100 on
32 cores, a view needs several scheduler hops across four processes, so this row measures CPU
contention more than either engine, and it gets no verdict until a quiet run. What holds in
both: neither side is quota-bound (at 3 to 4 views/s a connection carries about 6 to 8 of the
10 messages per second each channel allows), and both nullify about one view in four to five.

Propose-to-finalize latency is not measured. Both examples print timestamps to the second and
serve no metrics, so simplex's `finalization_latency` histogram (which both register with the
same 36 buckets) cannot be read from outside, and on loopback nearly every view finalizes
within the second it was proposed. Measuring it, or the engines' speed without the example's
quota, needs the same local patch to both examples, as flood's comparison does.

## Storage: partitioned ordered index inserts, mimalloc against smp_allocator (2026-11-19, clearing lane)

`index::insert/variant=partitioned_ordered_2` stays 1.2 to 1.4× commonware's, and the reason
is the allocator, not the index. Both benches time only the inserts (the partition array is
allocated untimed), and each new key in an empty partition allocates its keys and values
arrays on both sides. Commonware's index benches install mimalloc as the global allocator
(`storage/src/index/benches/bench.rs`); zigware's run on `smp_allocator`. In an isolated
harness the same 10,000 inserts take about 25 to 30% less time with their arrays in an arena,
which is roughly the gap. Neither side is changed: the index matches commonware's structure,
and its allocator is the caller's.

## Clearing: model checking (2026-11-19, clearing lane)

commonware's clearing has no benches, so this compares its stateright model checks
(`tests/bajillion/model.rs`, `cargo test --release`, `threads(available_parallelism)`) with
zigware's port (`-Dslow-tests -Doptimize=ReleaseSafe`, one worker per core) on the same six
workloads. Both sides reach the same unique and generated state counts, which zigware's
tests assert. Commonware's times are its reporter's whole seconds; 32 cores, the two runs
back to back.

| workload | unique states | commonware | zigware before | zigware after | after / commonware |
|---|---|---|---|---|---|
| admits one payment | 232 | 0 s | 0.05 s | 0.006 s | |
| retries payments | 196,690 | 6 s | 29.4 s | 2.3 s | 0.38× |
| halts and claims | 78,862 | 2 s | 7.1 s | 0.38 s | 0.19× |
| rebuilds on the posted row | 257,586 | 3 s | 29.9 s | 2.1 s | 0.71× |
| replays a dropped request | 3,151 | 0 s | 0.46 s | 0.03 s | |
| recovers funds after a halt | 3,284,669 | 19 s | 355 s | 18.6 s | 0.98× |

Before ran at load 80 to 100 against commonware's 21 s for the largest at load 100. Two
changes, found by timing each stage of a transition per thread:
- The model cloned each world from `std.testing.allocator`, a `SafeAllocator` behind one lock
  that every worker shared; cloning took 50 µs of each 105 µs transition. Slow-test builds
  now use `smp_allocator` (the default run keeps the testing allocator's leak checks).
- The checker then spent about a quarter of its time waiting on its one mutex, taken three or
  four times per transition. Each worker now explores on a stack of its own and shares half
  of it while another waits, and the visited set is 64 shards by fingerprint, as
  Stateright's job market and sharded map do.

## Bench harness on allocator.Heap (2026-11-19, storage-merkle lane)

The measured harnesses moved from `smp_allocator` to `allocator.Heap` (`Config.default`), as
commonware's 36 bench binaries all set `mimalloc::MiMalloc` with `Config::DEFAULT` (the only
other global allocators in its tree are test fixtures). Rows above this section, and any row
dated before this commit, ran on `smp_allocator`. Before and after, same tree, the two
harnesses alternating per row; best of three medians (seven for `add_many` mmb, four for the
other parallel rows, three for glue's plan rows), at a 1-minute load of 26 to 101:

| bench | smp_allocator | allocator.Heap | change |
|---|---|---|---|
| `merkle::multi_proof/n=100000 items=100 family=mmr` | 13.8 µs | 8.54 µs | −38% |
| `merkle::add_many/items=65536 workers=8 family=mmb` | 3.78 ms | 3.94 ms | +4% (medians 5.22 → 5.02 ms) |
| `merkle::add_many/items=65536 workers=8 family=mmr` | 4.45 ms | 3.51 ms | −21% |
| `merkle::update/... strategy=BatchedParallel family=mmr` | 40.9 ms | 33.7 ms | −18% |
| `index::insert/variant=ordered items=10000` | 1.15 ms | 1.12 ms | −3% |
| `index::insert/variant=partitioned_ordered_2 items=10000` | 550 µs | 473 µs | −14% |
| `sha256::hash_message/msg_len=4096` | 1.99 µs | 1.92 µs | −3% |
| `codec::lazy::get/source=shared txs=100000 conc=1` | 883 µs | 791 µs | −10% |
| `mailbox::mailbox::enqueue_ready/capacity=1024` | 13.4 µs | 12.7 µs | −6% |
| `reed_solomon::encode/msg_len=1048576 chunks=10 conc=1` | 1.28 ms | 1.30 ms | +1% |
| `transfers::plan/transfers=1024 accounts=128 effects=none conc=1` | 49.1 µs | 27.9 µs | −43% |
| `transfers::plan/transfers=1024 accounts=4096 effects=none conc=1` | 59.3 µs | 32.6 µs | −45% |
| `transfers::plan/transfers=32768 accounts=4096 effects=none conc=1` | 1.68 ms | 1.43 ms | −15% |
| `transfers::plan/transfers=16 accounts=128 effects=none conc=1` | 637 ns | 775 ns | +22% (each of 7 rounds +14% to +26%) |

- The heap keeps freed large blocks (purged after 4 s, as mimalloc), so buffers that
  `smp_allocator` unmapped and re-faulted every iteration are reused: `multi_proof`'s 38 KB
  digests, glue's plan buffers (commonware: 21 µs at `transfers=1024`), and the index arrays
  (clearing's finding above).
- One lock guards a `Heap`. The parallel rows did not suffer measurably: `add_many` mmb's
  seven rounds spread 3.8 to 6.6 ms on both sides (round 1 alone read +51%), but every small allocation pays a
  mutex through the Io vtable and a page lookup by address, where mimalloc and `smp_allocator`
  pop a thread-local free list. That fixed cost is the +22% on the 16-transfer plan, a few
  hundred nanoseconds with a handful of allocations. The thread-local fast path below
  removes it.

## allocator.Heap thread caches (2026-11-19, storage-merkle lane)

`allocator.Heap` now gives each thread a cache, as mimalloc's per-thread heaps: the owning
thread allocates from and frees into its own small pages without the heap's lock, a block
freed by another thread goes onto its page's lock-free deferred list for the owner to drain,
and a size class keeps its last emptied pages for a few refills (mimalloc's
`_mi_page_retire`, `MI_RETIRE_CYCLES`) instead of releasing and re-taking a page every time
it empties. A single-thread loop allocating and freeing eight size classes went from 46.6 to
4.5 ns per pair (26.8 to 6.4 ns when the pages never empty). Before is the harness at
0ea389fd (one lock), after is this commit, alternating per row, best of three medians (five
for the rows marked), at a 1-minute load of 56 to 89 with another lane benchmarking:

| bench | one lock | thread caches | change |
|---|---|---|---|
| `transfers::plan/transfers=16 accounts=128 effects=none conc=1` | 801 ns | 625 ns | −22% (three passes: −23%, −8%, −23%) |
| `transfers::plan/transfers=1024 accounts=128 effects=none conc=1` | 33.1 µs | 34.1 µs | +3% |
| `transfers::plan/transfers=1024 accounts=4096 effects=none conc=1` | 35.7 µs | 36.5 µs | +2% |
| `transfers::plan/transfers=32768 accounts=4096 effects=none conc=1` | 1.64 ms | 1.42 ms | −13% |
| `merkle::multi_proof/n=100000 items=100 family=mmr` | 7.94 µs | 8.08 µs | +2% |
| `merkle::add_many/items=65536 workers=8 family=mmb` (5) | 4.45 ms | 4.68 ms | +5% (medians 4.45–6.19 against 4.68–8.56 ms) |
| `merkle::add_many/items=65536 workers=8 family=mmr` (5) | 3.20 ms | 3.54 ms | +10% (medians 3.20–5.79 against 3.54–5.54 ms) |
| `merkle::update/... strategy=BatchedParallel family=mmr` | 31.5 ms | 31.6 ms | 0% |
| `index::insert/variant=ordered items=10000` | 1.02 ms | 905 µs | −11% |
| `index::insert/variant=partitioned_ordered_2 items=10000` | 526 µs | 482 µs | −8% |
| `sha256::hash_message/msg_len=4096` | 1.98 µs | 2.02 µs | +2% |
| `codec::lazy::get/source=shared txs=100000 conc=1` (5) | 750 µs | 762 µs | +2% |
| `mailbox::mailbox::enqueue_ready/capacity=1024` (5) | 11.9 µs | 13.1 µs | +10% (other medians 13.5 against 13.4 µs) |
| `reed_solomon::encode/msg_len=1048576 chunks=10 conc=1` (5) | 1.24 ms | 1.27 ms | +3% |

- The 16-transfer plan is back under `smp_allocator`'s 637 ns: it makes about six
  allocations per iteration, each now a pop from the thread's page.
- The +10% rows time no allocations (the pool's workers in `add_many` and the timed
  `enqueue_ready` allocate nothing), and their rounds overlap; treat them as noise.
- A first build without cold hints on the heap's slow paths read
  `partitioned_ordered_2` at +40% in every round while the same code with probe counters
  read even: a code-layout effect. Marking `refill`, `attach`, `alloc_locked`, and
  `retire_owned` cold took the pair cost from 14.3 to 4.5 ns and the row to −8%.
- A thread's cache outlives the thread (there is no `mi_thread_done`): its slot and pages
  stay until a thread with the same id reuses them, and past 64 distinct threads later
  threads take the lock. Bench threads come from `std.Io.Threaded`, which keeps its workers
  for the whole run, so a harness reaches neither; only the bench harnesses use a `Heap`.

## Storage: merkle, bmt, rmap, variable journal, native ABBA (2026-11-20, storage-merkle lane)

31 rows, 4 rounds of etc/scripts/bench-compare.sh's method (ABBA order, commonware built with
`-C target-cpu=native`, each pair on one CCD slot of etc/scripts/bench-lock.sh), zigware
65b32e52, which includes the wall-time iteration planning of c7935b0c, so these replace the
provisional rows below. The ratio is the median of the per-round zigware / commonware ratios;
the times are each side's median. Load averaged 2.2 in rounds 2 to 4 and 48 in round 1, whose
ratios agree with the others. Raw rounds: [bench/storage-merkle.tsv](bench/storage-merkle.tsv).
Verdicts: 20 faster, 8 tie, 3 slower.

| Bench | commonware | zigware | ratio | verdict |
|---|---|---|---|---|
| `merkle::append/n=100000 family=mmr` | 9.77 ms | 7.25 ms | 0.74× | faster |
| `merkle::append/n=100000 family=mmb` | 10.1 ms | 7.35 ms | 0.73× | faster |
| `merkle::add_many/items=65536 workers=1 family=mmr` | 6.83 ms | 6.99 ms | 1.02× | tie |
| `merkle::add_many/items=65536 workers=8 family=mmb` | 1.06 ms | 1.2 ms | 1.13× | slower |
| `merkle::update/updates=100000 leaves=100000 strategy=BatchedSerial family=mmr` | 18 ms | 19.3 ms | 1.05× | slower |
| `merkle::flush/n=100000 family=mmr` | 1.62 ms | 1.65 ms | 1.00× | tie |
| `merkle::position_to_location/n=1000000 family=mmb` | 5.11 µs | 2.86 µs | 0.58× | faster |
| `merkle::proof/n=100000 samples=100 family=mmr` | 34.5 µs | 23.3 µs | 0.65× | faster |
| `merkle::proof/n=100000 samples=100 family=mmb` | 43.4 µs | 31.7 µs | 0.73× | faster |
| `merkle::multi_proof/n=100000 items=100 family=mmr` | 8.31 µs | 4.03 µs | 0.49× | faster |
| `merkle::range_proof/n=100000 range=100 samples=100 family=mmb` | 49.9 µs | 34.1 µs | 0.69× | faster |
| `merkle::verify_single_element/n=100000 samples=100 family=mmr` | 172 µs | 150 µs | 0.88× | faster |
| `merkle::verify_single_element/n=100000 samples=100 family=mmb` | 247 µs | 212 µs | 0.88× | faster |
| `merkle::verify_multi/n=100000 items=100 family=mmr` | 80.4 µs | 71.4 µs | 0.89× | faster |
| `merkle::verify_many_elements/n=100000 range=100 samples=100 family=mmr` | 1.03 ms | 701 µs | 0.68× | faster |
| `bmt::build/n=100000` | 4.79 ms | 4.93 ms | 1.03× | tie |
| `bmt::proof/n=100000` | 20.5 ns | 20.5 ns | 1.01× | tie |
| `bmt::multi_proof/n=100000 items=100` | 2.25 µs | 2.3 µs | 1.02× | tie |
| `bmt::range_proof/n=100000 items=100` | 31.6 ns | 24.4 ns | 0.77× | faster |
| `bmt::verify_single/n=100000 items=100` | 112 µs | 101 µs | 0.90× | faster |
| `bmt::verify_multi/n=100000 items=100` | 37.4 µs | 37.7 µs | 1.00× | tie |
| `bmt::verify_range/n=100000 items=100` | 6.31 µs | 6 µs | 0.95× | tie |
| `rmap::insert/items=100000` | 17.4 ms | 10.6 ms | 0.60× | faster |
| `journal::read_cached/journal=variable size=32` | 2.88 ms | 1.21 ms | 0.42× | faster |
| `journal::variable_read_random/mode=serial items=10000 size=32` | 49.5 ms | 10.6 ms | 0.21× | faster |
| `journal::variable_read_random/mode=read_many items=10000 size=32` | 10.8 ms | 12.2 ms | 1.13× | slower |
| `journal::variable_read_compressed/mode=read_many items=10000 size=1024 random=true` | 1.38 ms | 958 µs | 0.70× | faster |
| `journal::variable_read_compressed/mode=read_many_uncached items=10000 size=1024 random=true` | 3.96 ms | 2.15 ms | 0.54× | faster |
| `journal::variable_replay/items=100000 buffer=65536 size=32 read_options=cache` | 1.95 ms | 574 µs | 0.30× | faster |
| `journal::variable_prepare_append/items=1 size=1048576 compression=3 random=false` | 89.5 µs | 87.6 µs | 0.98× | tie |
| `journal::variable_prepare_append/items=32 size=1048576 compression=3 random=false` | 3.38 ms | 2.98 ms | 0.88× | faster |

## Storage: merkle, bmt, rmap, variable journal reads (2026-11-19, storage-merkle lane)

The rows bench-compare.sh now carries for storage-merkle's crates, with its settings (warm-up
1 s, measurement 3 s, 50 samples), sinks per AGENTS.md (pointers). Three alternating runs at
zigware 9dd371a3, which includes crypto's SHA-256 single and pair fast paths (f6518bb0) and
the harness fix that times a workload without `before_iter` as one batch (5c5d48cd); each
number is the best of three medians. The 1-minute load average was 41 to 85 and the storage
benches ran on tmpfs, so per-run ratios swing: `merkle::append` mmr ran 0.91×, 1.66×, and
0.96×, and `bmt::verify_multi` 1.11×, 1.33×, and 0.91×. Treat rows within 1.3× as even.

| bench | parameters | commonware | zigware | zigware / commonware |
|---|---|---|---|---|
| `merkle::append` | `n=100000 family=mmr` | 16.4 ms | 25.2 ms | 1.54× |
| `merkle::append` | `n=100000 family=mmb` | 16.6 ms | 17.9 ms | 1.07× |
| `merkle::add_many` | `items=65536 workers=1 family=mmr` | 8.91 ms | 11.4 ms | 1.28× |
| `merkle::add_many` | `items=65536 workers=8 family=mmb` | 4.85 ms | 4.05 ms | 0.83× |
| `merkle::update` | `updates=100000 leaves=100000 strategy=BatchedSerial family=mmr` | 43.3 ms | 37.2 ms | 0.86× |
| `merkle::flush` | `n=100000 family=mmr` | 2.88 ms | 2.95 ms | 1.02× |
| `merkle::position_to_location` | `n=1000000 family=mmb` | 9.15 µs | 4.94 µs | 0.54× |
| `merkle::proof` | `n=100000 samples=100 family=mmr` | 96.7 µs | 35.6 µs | 0.37× |
| `merkle::proof` | `n=100000 samples=100 family=mmb` | 118 µs | 51 µs | 0.43× |
| `merkle::multi_proof` | `n=100000 items=100 family=mmr` | 15 µs | 41.9 µs | 2.80× (fixed, see below) |
| `merkle::range_proof` | `n=100000 range=100 samples=100 family=mmb` | 146 µs | 55.3 µs | 0.38× |
| `merkle::verify_single_element` | `n=100000 samples=100 family=mmr` | 229 µs | 257 µs | 1.12× |
| `merkle::verify_single_element` | `n=100000 samples=100 family=mmb` | 352 µs | 348 µs | 0.99× |
| `merkle::verify_multi` | `n=100000 items=100 family=mmr` | 122 µs | 143 µs | 1.18× |
| `merkle::verify_many_elements` | `n=100000 range=100 samples=100 family=mmr` | 1.53 ms | 1.8 ms | 1.17× |
| `bmt::build` | `n=100000` | 6.66 ms | 12.5 ms | 1.87× (fixed, see below) |
| `bmt::proof` | `n=100000` | 41.9 ns | 41.2 ns | 0.98× |
| `bmt::multi_proof` | `n=100000 items=100` | 6.86 µs | 4.55 µs | 0.66× |
| `bmt::range_proof` | `n=100000 items=100` | 72 ns | 45.7 ns | 0.63× |
| `bmt::verify_single` | `n=100000 items=100` | 148 µs | 177 µs | 1.19× |
| `bmt::verify_multi` | `n=100000 items=100` | 61.9 µs | 82.1 µs | 1.33× |
| `bmt::verify_range` | `n=100000 items=100` | 10.9 µs | 12.4 µs | 1.14× |
| `rmap::insert` | `items=100000` | 26.6 ms | 14 ms | 0.53× (fixed, see below) |
| `journal::read_cached` | `journal=variable size=32` | 4.98 ms | 2.15 ms | 0.43× |
| `journal::variable_read_random` | `mode=serial items=10000 size=32` | 180 ms | 26.8 ms | 0.15× |
| `journal::variable_read_random` | `mode=read_many items=10000 size=32` | 31.7 ms | 20.8 ms | 0.65× |
| `journal::variable_read_compressed` | `mode=read_many items=10000 size=1024 random=true` | 4.38 ms | 4.3 ms | 0.98× |
| `journal::variable_read_compressed` | `mode=read_many_uncached items=10000 size=1024 random=true` | 8.5 ms | 4.93 ms | 0.58× |
| `journal::variable_replay` | `items=100000 buffer=65536 size=32 read_options=cache` | 4.25 ms | 1.58 ms | 0.37× |

- **`rmap::insert`, fixed (9c60febd).** Was 70–76 ms against 19–21 ms (3.7×). One sorted
  array of ranges is quadratic under random inserts: 100,000 shuffled values moved 8 GB.
  Ranges now live in chunks of at most 256, binary-searched by first start, so an insert moves
  at most one chunk. 76.5 ms → 14.5 ms in an alternating A/B; 0.53× above.
- **`merkle::multi_proof`, fixed (this section's commit).** zigware held at 42–45 µs in every
  run (commonware 15–44 µs). Timed in parts with smp_allocator: the positions took 37.6 µs
  of 49.2 µs. The explicit-stack walk emitted siblings before their subtrees, so an MMR's
  1,194 positions needed a real sort; it now unrolls commonware's recursion in postorder
  (sorted for an MMR, so the sort is skipped) and reserves the positions once instead of
  growing them about ten times. Positions 37.6 → 6.6 µs, the whole proof 49.2 → 18.6 µs.
  Of what remains, about 9 µs is the 38 KB digest buffer: smp_allocator maps anything in its
  64 KiB class fresh and faults each page in on every call, where commonware's mimalloc
  reuses pages. That is the harness's allocator (`src/bench`), not the proof code.
- **`bmt::build` (1.87×) and the verify rows** are SHA-256 bound: 100,000 two-part 36-byte
  leaf hashes and 50,000 `hash_pair`s. crypto's own rows still put `hash_parts` at 1.4–1.85×
  and `hash_pair` near 1.3× commonware's hand-scheduled assembly; the bmt code adds one 3 MB
  leaf copy (about 2%). The fix is in cryptography's sha256, not storage.
- **`bmt::build`, fixed (clearing lane, this row's commit).** The SHA-256 cost was assembling
  each message on the stack before compressing it. `sha256_blocks.digest_shape` ports
  commonware's `hash_36` (the 4+32 leaf's words built in registers, padding included) and the
  64-byte node kernels (two digests loaded straight into registers, then the padding block's
  constant W + K table, commonware's `FIXED_ROUNDS4`), singly and as interleaved pairs.
  Eleven alternating rounds of commonware, zigware before (356e1da9) and zigware after, with
  bench-compare.sh's settings at a load average of 75 to 104:

  | | commonware | before | after |
  | --- | --- | --- | --- |
  | best median | 7.34 ms | 10.6 ms | 8.10 ms |
  | median ratio to commonware, per round | | 1.21× | 0.88× |

  After/before is 0.72× (median per round). Best of each side puts it at 1.10×; at this load
  the per-round ratio to commonware ran 0.60× to 1.37×, so treat it as even.
- **Proof generation** (`merkle::proof`, `range_proof`, `bmt::proof`, `bmt::multi_proof`) is
  0.37× to 0.98×. Before 5c5d48cd, `bmt::proof` (about 40 ns) and `bmt::multi_proof` read
  1.8× and 2.9×: the clock read per iteration dominated.
- **`merkle::append` and `add_many`, re-run (2026-11-20).** On main at 10c383dd, after
  crypto's MMR shape kernels (569941c9: commonware's `hash_40`, `hash_72`, and their pairs)
  and the thread-cached `allocator.Heap` (9f4eeba4), bench-compare.sh, best of three, load
  40 to 79:

  | bench | parameters | commonware | zigware | zigware / commonware |
  |---|---|---|---|---|
  | `merkle::append` | `n=100000 family=mmr` | 20.8 ms | 14.5 ms | 0.70× (was 1.54×) |
  | `merkle::append` | `n=100000 family=mmb` | 14.6 ms | 9.82 ms | 0.67× (was 1.07×) |
  | `merkle::add_many` | `items=65536 workers=1 family=mmr` | 11.5 ms | 8.59 ms | 0.75× (was 1.28×) |
  | `merkle::add_many` | `items=65536 workers=8 family=mmb` | 6.23 ms | 4.47 ms | 0.72× (was 0.83×) |

  Commonware's medians ran higher than in the table above (append mmr 16.4 → 20.8 ms) at
  this load, so the ratios flatter zigware somewhat; both families are now ahead.

## secp256r1: signature verification (2026-11-20, p2p lane)

commonware verifies P-256 signatures with aws-lc, and zigware verified them with std's
`mulDoubleBasePublic`. Same method as above: best of three alternating runs, commonware
`a9ffc25f3`. "Before" is main at `91c3b6f4`; "after" adds `add57d98` (an aws-lc-shaped
verify), `2de33dbe` (`mulx`/`adx` field multiplication), and `bdedcab4` (products in registers,
u256 addition). The 1-minute load average was 60 to 73 before and 70 to 80 after, and
commonware's own best moved from 47 to 69 µs between runs; at commonware's best seen in any
run (47 µs), the after row is 1.24×.

| bench | parameters | commonware | zigware before | commonware | zigware after | after / commonware |
|---|---|---|---|---|---|---|
| `secp256r1::signature_verification` | `variant=standard` | 68.6 µs | 192 µs (2.80×) | 57.8 µs | 58.5 µs | 1.01× |
| `secp256r1::signature_verification` | `variant=recoverable` | 270 µs | 213 µs (0.79×) | 221 µs | 178 µs | 0.80× |

Components by thread CPU time in scratch harnesses, best of ten (load about 60):
- **Before.** One verify was about 155 µs of thread CPU: `mulDoubleBasePublic` 125 to 130 µs
  (256 doublings and about 128 additions, all complete projective formulas), the scalar
  inverse 15 µs (std's constant-time divsteps), and `affineCoordinates` 14 µs. Decompressing
  the key (19 µs) happens once, in `PublicKey.from_bytes`.
- **verify.zig** (`add57d98`) does what aws-lc does: one shared chain of a = -3 Jacobian
  doublings; `G` from a width-8 wNAF over a comptime table of 64 affine odd multiples (mixed
  additions), `Q` from a width-5 wNAF over 8 Jacobian multiples; `x(R) = r` checked as
  `X = r Z^2` (and `(r + n) Z^2`), with no inversion. Public keys keep affine coordinates. 84 µs.
- **field.zig** (`2de33dbe`, `bdedcab4`): std's fiat-crypto multiplication is portable code
  (15.6 ns per dependent multiply). On x86_64 with BMI2 and ADX the multiply is aws-lc's
  `mulx` with `adcx`/`adox` chains and shift reductions, returning limbs in registers: 10.5 ns.
  Addition and subtraction are u256 arithmetic, about half std's time. A dedicated squaring
  (aws-lc's `sqr_mont`) measured slower, so squaring is a multiply. The scalar inverse is a
  variable-time binary extended GCD (2 µs; `s` is public). 39 to 41 µs per verify, against
  110 to 120 µs for std's path in the same run.

Every routine returns std's limbs exactly (tests check edges and random inputs against std,
and a fuzz checks verify against std's `mulDoubleBasePublic`); signatures, encodings, and the
conformance hashes are unchanged. Recoverable verification still recovers the key through
std's `mulDoubleBasePublic`; it is already 0.80×, so it was left alone.

## Actor: mailbox (2026-11-19, actor-stream lane)

All ten cases of commonware's `mailbox` bench, with bench-compare.sh's settings (warm-up 1 s,
measurement 3 s, 50 samples). The two sides alternated per case over three runs, and each
number is the best of the three medians. The 1-minute load average was 63 to 78.

| bench | parameters | commonware | zigware | zigware / commonware |
|---|---|---|---|---|
| `enqueue_ready` | `capacity=1024` | 24.7 µs | 12.9 µs | 0.52× |
| `try_recv_ready` | `capacity=1024` | 8.85 µs | 6.30 µs | 0.71× (fixed, see below) |
| `try_recv_overflow` | `capacity=1024 overflow=1024` | 63.1 µs | 44.4 µs | 0.70× |
| `round_trip_ready` | `capacity=1024` | 26.7 µs | 19.2 µs | 0.72× |
| `recv_waiting` | `capacity=1` | 77.5 µs | 156 µs | 2.01× (runtime, see below) |
| `overflow_drop` | `capacity=1` | 49.3 µs | 29.3 µs | 0.59× |
| `overflow_spill` | `capacity=1` | 39.9 µs | 38.9 µs | 0.98× |
| `overflow_replace` | `capacity=1024 position=newest` | 44.9 µs | 38.8 µs | 0.87× |
| `overflow_replace` | `capacity=1024 position=oldest` | 416 µs | 272 µs | 0.65× (fixed, see below) |
| `concurrent_enqueue` | `producers=4 capacity=65536` | 3.74 ms | 1.66 ms | 0.45× |

Fixed in d2b6c4f0:

- **`try_recv_ready`, before 1.49× (10.8 µs against 7.25 µs at load 34 to 50).** Every pop
  locked and unlocked one `std.Io.Mutex` that guarded ready and overflow. With the lock
  stubbed out, the case fell to about 3 µs, so the lock was the whole gap. The mailbox now
  uses commonware's design: a port of crossbeam's `ArrayQueue` for ready, the overflow
  activity word, and a futex word in place of `AtomicWaker`.
- **`overflow_replace position=oldest`, before 2.2× (675 µs against 302 µs).** The bench's
  policy scanned the overflow deque backward with `atPtr`, a wrap branch per element. It now
  scans the deque's two contiguous halves from the back, 4 bytes per step, as Rust's slice
  `rfind` does behind commonware's `iter_mut().rev().find`.

Not fixed: **`recv_waiting`, 2.01×.** zigware runs it on the deterministic runtime, and each
message costs one `io.sleep` scheduler cycle, a park, and a wake. commonware polls the future
by hand with `block_on`. The same loop with the mailbox swapped for a bare `futexWait` and
`futexWake` handoff took 223 to 258 µs, against 247 to 294 µs with the mailbox in the same
alternating runs, so about 90% of the time is the runtime's scheduler, not the mailbox.

**Re-run after 1fe045bf (runtime's scheduler bookkeeping cut), load 35 to 55.** The other
eight cases stayed within 0.51× to 0.98×.

- **`recv_waiting`: 81.6 µs against 158 µs, 1.94× (from 2.01×).** The rest of each cycle is
  spread over the task body and fiber switches (about 120 cycles), the audit event (about
  55), and the shuffle (about 20), which the replay hashes depend on. It is the deterministic
  runtime's per-message scheduler cycle, not the mailbox, so the item is closed at 1.94×.
- **`concurrent_enqueue`: load-sensitive, no regression.** Four producer threads on a loaded
  machine gave commonware medians of 5.6 to 14.8 ms and zigware 12.6 to 14.7 ms in this
  re-run. Alternating the d2b6c4f0 bench binary with this build at load 43 gave the same
  fastest sample (1.33 ms and 1.36 ms) and medians of 1.7 to 6.2 ms on both, so the
  0.45× above stands as the quieter-machine number.

## Bulletproofs: inner product argument (2026-11-19, actor-stream lane)

All twenty cases of commonware's `bulletproofs::ipa` bench, with bench-compare.sh's settings.
The two sides alternated per case over three runs, and each number is the best of the three
medians. Before is main at 91c3b6f4 (load 42 to 58). After is 8ff7bb34, measured on its tree
before the rebase onto 356e1da9 (load 59 to 108). Every row is now at most 1.14×.

| bench | parameters | commonware | zigware before | zigware after | after / commonware |
|---|---|---|---|---|---|
| `prove` | `n=8 conc=1` | 5.53 ms | 5.37 ms | 4.53 ms | 0.82× |
| `prove` | `n=8 conc=8` | 6.11 ms | 5.22 ms | 4.37 ms | 0.72× |
| `prove` | `n=16 conc=1` | 11.2 ms | 10.6 ms | 8.63 ms | 0.77× |
| `prove` | `n=16 conc=8` | 10.2 ms | 10.1 ms | 8.51 ms | 0.83× |
| `prove` | `n=32 conc=1` | 21.3 ms | 20.0 ms | 17.7 ms | 0.83× |
| `prove` | `n=32 conc=8` | 20.9 ms | 17.9 ms | 13.6 ms | 0.65× |
| `prove` | `n=64 conc=1` | 34.7 ms | 35.6 ms | 30.9 ms | 0.89× |
| `prove` | `n=64 conc=8` | 21.5 ms | 31.8 ms | 22.3 ms | 1.04× |
| `prove` | `n=128 conc=1` | 61.3 ms | 66.0 ms | 56.8 ms | 0.93× |
| `prove` | `n=128 conc=8` | 35.5 ms | 40.5 ms | 35.7 ms | 1.00× |
| `verify` | `n=8 conc=1` | 799 µs | 807 µs | 814 µs | 1.02× |
| `verify` | `n=8 conc=8` | 911 µs | 1.05 ms | 409 µs | 0.45× |
| `verify` | `n=16 conc=1` | 1.29 ms | 1.52 ms | 1.24 ms | 0.96× |
| `verify` | `n=16 conc=8` | 1.43 ms | 1.36 ms | 619 µs | 0.43× |
| `verify` | `n=32 conc=1` | 2.35 ms | 2.22 ms | 2.45 ms | 1.04× |
| `verify` | `n=32 conc=8` | 1.77 ms | 2.37 ms | 1.15 ms | 0.65× |
| `verify` | `n=64 conc=1` | 3.36 ms | 3.94 ms | 3.81 ms | 1.14× |
| `verify` | `n=64 conc=8` | 2.89 ms | 4.07 ms | 1.57 ms | 0.54× |
| `verify` | `n=128 conc=1` | 5.90 ms | 6.87 ms | 6.26 ms | 1.06× |
| `verify` | `n=128 conc=8` | 4.37 ms | 6.87 ms | 1.85 ms | 0.42× |

The commonware column and the last column are from the after run. Against the before run's
own commonware medians, the rows over 1.3× were `verify` n=64 (1.32× and 1.43×) and `verify`
n=128 conc=8 (2.28×, against 3.02 ms). Proofs and transcripts are unchanged: the ipa tests and conformance
vectors pass, and every change below computes the same group elements.

- **`verify` at conc=8: `Setup.eval` ignored the strategy.** commonware's `eval` takes one
  for the final multi-scalar multiplication, and zigware's always summed sequentially, so
  its conc=8 rows timed the conc=1 work. `eval` now takes the strategy, through
  `Synthetic.eval_strategy`.
- **Small MSMs: Straus instead of narrow-window Pippenger.** 2 to 32 points (16 in G2) used
  Pippenger with 2- and 3-bit windows, about 1.7 times the point additions of per-point
  tables. They now share one doubling chain over per-point tables of P to 8P, as blst does
  below 32 points. zigware's own `bls12381::msm/group=g1 n=10 conc=1` went from 652 to
  387 µs and `group=g2 n=10` from 1.60 ms to 834 µs, with `group=g1 n=50` (still Pippenger)
  at 1.92 and 1.71 ms as the control. This speeds up the prove rows' small round MSMs.
- Landed beside these on main, from another lane: 52d0b401 merges synthetic free terms in
  one pass, and 3d7a069c sums a sequential MSM of more than 256 points in one Pippenger,
  which covers `verify` n=128's 272-point MSM at conc=1.

## Actor mailbox and bulletproofs ipa, ABBA rounds (2026-11-20, actor-stream lane)

fe6c92bc's bench-compare.sh, 4 ABBA rounds, commonware built for the native CPU, at load 53
to 143 (mailbox) and 77 to 143 (ipa), so rows whose rounds straddle 1 are noise-bound ties.

- **Mailbox: faster 5, tie 5, slower 0.** `recv_waiting` is 0.25× (190 against 47.4 µs),
  from 1.94×. commonware's bench is one task under `block_on`: it polls `recv()` once to
  register its waker, enqueues, then awaits the ready future. zigware's ran a consumer task
  and a sleeping producer, so it timed the deterministic scheduler's handoff. a1ccb817 adds
  `Receiver.poll_recv` (a pending poll parks the receiver until the next receive) and runs
  commonware's sequence in one task. Its test checks the waker word after each step, and
  catches a poll that does not park and a receive that leaves the receiver parked. The
  other rows: `enqueue_ready` 0.44×, `round_trip_ready` 0.43×, `overflow_replace` oldest
  0.35×, `concurrent_enqueue` 0.39× (faster); `try_recv_ready` 0.57×, `try_recv_overflow`
  0.72×, `overflow_drop` 1.28×, `overflow_spill` 0.71×, `overflow_replace` newest 0.44×
  (ties, with rounds from 0.2× to 2×).
- **ipa: faster 14, tie 6, slower 0.** The bench's pool now carries an adaptive
  `parallel.Policy`, as commonware's `Rayon::new` does (577e8383); the conc=8 rows above were
  measured on an always-split pool. Ties: `prove` n=16 conc=1 0.56×, n=32 conc=1 1.19×, n=64
  conc=1 0.80×; `verify` n=32 conc=1 1.51×, n=64 conc=1 0.68×, n=128 conc=1 0.78×. Every
  conc=8 row is faster (0.39× to 0.81×).

## formatting, codec, bls12381 hash and signing (2026-11-19, consensus-simplex lane)

commonware's whole `formatting` and `codec` bench binaries against zigware's benches of the
same names, at `bench-compare.sh`'s settings (1 s warm-up, 3 s measurement, 50 samples). The
two sides alternated per crate in three rounds at a 1-minute load of 32 to 72. Each round's
zigware/commonware ratio is one sample. The table gives the median of the three ratios and
their range, next to each side's median time. These ran on `smp_allocator`, before 0ea389fd;
none of the rows allocates in its timed loop.

| bench | parameters | commonware | zigware | zigware / commonware | per-round range |
|---|---|---|---|---|---|
| `formatting::encode` | `size=16` | 16.1 ns | 17.3 ns | 1.08× | 1.07–2.62× (3) |
| `formatting::encode` | `size=32` | 16.6 ns | 20.2 ns | 1.33× | 0.86–5.25× (3) |
| `formatting::encode` | `size=64` | 17.9 ns | 16.6 ns | 0.93× | 0.51–1.14× (3) |
| `formatting::encode` | `size=256` | 21.5 ns | 24.2 ns | 1.25× | 0.74–2.21× (3) |
| `formatting::encode` | `size=1024` | 66.2 ns | 30.7 ns | 0.51× | 0.38–1.04× (3) |
| `formatting::encode` | `size=16384` | 587 ns | 319 ns | 0.58× | 0.35–0.63× (3) |
| `formatting::decode` | `input=pristine size=16` | 43.9 ns | 20.5 ns | 0.36× | 0.32–0.49× (3) |
| `formatting::decode` | `input=ugly size=16` | 82.8 ns | 51.7 ns | 0.59× | 0.42–0.64× (3) |
| `formatting::decode` | `input=pristine size=32` | 67.3 ns | 25.5 ns | 0.42× | 0.26–1.75× (3) |
| `formatting::decode` | `input=ugly size=32` | 182 ns | 88.3 ns | 0.70× | 0.49–3.84× (3) |
| `formatting::decode` | `input=pristine size=64` | 101 ns | 38.1 ns | 0.26× | 0.25–0.39× (3) |
| `formatting::decode` | `input=ugly size=64` | 199 ns | 83.3 ns | 0.47× | 0.42–0.48× (3) |
| `formatting::decode` | `input=pristine size=256` | 319 ns | 75.8 ns | 0.29× | 0.24–0.38× (3) |
| `formatting::decode` | `input=ugly size=256` | 692 ns | 251 ns | 0.38× | 0.36–0.52× (3) |
| `formatting::decode` | `input=pristine size=1024` | 1.22 µs | 262 ns | 0.20× | 0.20–0.22× (3) |
| `formatting::decode` | `input=ugly size=1024` | 2.34 µs | 1.65 µs | 0.70× | 0.41–0.76× (3) |
| `formatting::decode` | `input=pristine size=16384` | 28.5 µs | 5.17 µs | 0.22× | 0.14–0.37× (3) |
| `formatting::decode` | `input=ugly size=16384` | 63.4 µs | 37.9 µs | 0.56× | 0.36–0.74× (3) |
| `formatting::display` | `size=16` | 21.1 ns | 6.82 ns | 0.32× | 0.18–0.38× (3) |
| `formatting::display` | `size=32` | 19 ns | 9.05 ns | 0.50× | 0.41–1.02× (3) |
| `formatting::display` | `size=64` | 20.2 ns | 5.2 ns | 0.27× | 0.26–0.65× (3) |
| `formatting::display` | `size=256` | 58.5 ns | 19.6 ns | 0.34× | 0.32–0.65× (3) |
| `formatting::display` | `size=1024` | 216 ns | 122 ns | 0.46× | 0.15–0.57× (3) |
| `formatting::display` | `size=16384` | 4.5 µs | 1.63 µs | 0.33× | 0.28–0.59× (3) |
| `codec::lazy::get` | `source=shared txs=100000 conc=1` | 4.78 ms | 760 µs | 0.18× | 0.14–0.27× (3) |
| `codec::lazy::get` | `source=private txs=100000 conc=1` | 4.77 ms | 1.99 ms | 0.40× | 0.30–0.48× (3) |
| `codec::lazy::get` | `source=borrowed txs=100000 conc=1` | 918 µs | 234 µs | 0.26× | 0.19–0.28× (3) |
| `codec::lazy::get` | `source=shared txs=100000 conc=8` | 1.04 ms | 443 µs | 0.28× | 0.22–0.45× (3) |
| `codec::lazy::get` | `source=private txs=100000 conc=8` | 1.92 ms | 1.08 ms | 0.62× | 0.56–0.83× (3) |
| `codec::lazy::get` | `source=borrowed txs=100000 conc=8` | 698 µs | 217 µs | 0.23× | 0.10–1.44× (3) |
| `codec::lazy::get` | `value=memo_tx source=shared txs=100000 conc=1` | 4.85 ms | 1.2 ms | 0.24× | 0.19–0.29× (3) |
| `codec::lazy::get` | `value=memo_tx source=shared txs=100000 conc=8` | 3.95 ms | 556 µs | 0.14× | 0.09–0.32× (3) |
| `codec::lazy::get` | `value=key33 source=shared txs=100000 conc=1` | 2.18 ms | 123 µs | 0.04× | 0.04–0.09× (3) |
| `codec::lazy::get` | `value=key33 source=shared txs=100000 conc=8` | 548 µs | 186 µs | 0.15× | 0.08–0.51× (3) |

- **Hex (c8c682b0, 732258c1).** Decode and display are vectorized, and encode runs at the
  target's widest vector width. `encode size=32`'s median of 1.33× comes from rounds of
  0.86×, 1.33×, and 5.25×, which is noise around 3 ns of difference.
- **Timing harness (5c5d48cd, parallel lane).** These rows were measured after
  `bench.criterion` began timing a hook-less workload's iterations as one batch. Before that,
  every row under about 50 ns measured the clock instead of the code.

The bls12381 rows bls-math left open were re-run on main after 024c35d4 and 0ea389fd, with
three alternating rounds at a load of 50 to 69:

| bench | parameters | commonware | zigware | zigware / commonware | per-round range |
|---|---|---|---|---|---|
| `bls12381::hash_to_curve` | `n=100 conc=1` | 5.92 ms | 7 ms | 1.22× | 0.88–1.40× (3) |
| `bls12381::hash_to_curve` | `n=100 conc=8` | 3.31 ms | 1.96 ms | 0.59× | 0.32–0.90× (3) |
| `bls12381::signature_generation` | `ns_len=9 msg_len=32` | 571 µs | 383 µs | 0.71× | 0.67–0.79× (3) |
| `bls12381::aggregate_verify_same_signer` | `conc=1 msgs=100` | 6.99 ms | 8.23 ms | 1.18× | 0.77–1.21× (3) |
| `bls12381::aggregate_verify_same_signer` | `conc=8 msgs=100` | 6.09 ms | 4.11 ms | 0.61× | 0.52–0.85× (3) |

- **G1 `hash_to_curve` (024c35d4), 1.70× before.** Its two SSWU inversions and two isogeny
  inversions now share one inversion each (Montgomery's trick), and the sum before cofactor
  clearing stays projective. By thread CPU time one hash costs 57 µs: two (p+1)/4 square-root
  exponentiations (about 12 µs each) and cofactor clearing (18 µs), the rest polynomials and
  SHA-256. All of these are Fp multiplies at 27 ns, against blst's hand-written
  `mulx_mont_384`.
- **Rejected: an assembly Fp multiply.** A mulx/adcx/adox CIOS in one inline-assembly block
  measured 23 to 31 ns standalone against 37 ns for the same portable code. In the tree it
  measured 32 to 35 ns against the portable 27 ns: the block reads its operands through
  pointers, so it needs a memory clobber, and Zig's `"m"` operands pass an address rather
  than the value. The branch was dropped. A dedicated Montgomery square (a 21-product wide
  square, then `reduce_wide`) was no faster than `mul` either (39 against 38 ns).

## glue: transfers::settle with nonces, provisional (2026-11-20, consensus-simplex lane)

`transfers::settle/transfers=32768 accounts=4096 effects=nonce` read 1.9× commonware on
`smp_allocator`. Thread CPU timing put the cause in the allocator, not the settle loop. Of
settle's 38–50 µs, the effects loop took 14 µs. Allocating and memsetting the 4096 × 24-byte
slot array took 21 µs, because `smp_allocator` unmaps and remaps a block that size on every
call. The bench harness's `allocator.Heap` (0ea389fd) reuses that block in 615 ns with no
page faults, and 9f4eeba4's thread caches remove its per-allocation mutex. Commonware's
settle does the same work (`vec![Slot::Keep; len]`, then `try_run_batches`), so no settle
code changed.

One pair per row, binaries built after 9f4eeba4, run under the old bench lock at a 1-minute
load of about 70. It is a single round, not yet ABBA, so these are not verdicts:

| bench | parameters | commonware | zigware | zigware / commonware |
|---|---|---|---|---|
| `transfers::settle` | `transfers=32768 accounts=4096 effects=nonce conc=1` | 27.7 µs | 21.7 µs | 0.78× |
| `transfers::settle` | `transfers=32768 accounts=4096 effects=nonce conc=8` | 31.9 µs | 20.4 µs | 0.64× |
| `transfers::settle` | `transfers=32768 accounts=4096 effects=none conc=1` | 13.1 µs | 8.06 µs | 0.62× |
| `transfers::settle` | `transfers=32768 accounts=4096 effects=none conc=8` | 9.63 µs | 6.77 µs | 0.70× |

The ABBA rounds for every glue `transfers` row follow once the bls12381 runs finish.

The allocator explains settle's nonce row only. `transfers::plan` at n=16 is not
allocator-bound (runtime lane, 2026-11-20). After 9f4eeba4, `Heap` costs 5.8–13 ns per
alloc+free against `smp_allocator`'s 12–18 ns, with no mutex on the small path. The same glue
bench binary built on each allocator read a median Heap/smp ratio of about 1.01 over seven
A/B pairs. The plan rows' 1.27–1.49× (native ABBA, 8 rounds, conc=1, accounts=128 and 4096)
come from plan's own code path, which the broadcast-resolver lane holds for now.

## Coding: Reed-Solomon scheme and engines (2026-11-20, coding lane)

commonware's `coding_scheme_times` (`reed_solomon::encode`, `reed_solomon::decode`) and
cryptography's `reed_solomon` benches against zigware's `bench-coding` and
`bench-cryptography`, with `bench-compare.sh`'s criterion settings. Three rounds alternate
the two sides per bench group. Each ratio is the median over rounds of that round's
zigware / commonware ratio, and the times are the medians of the per-round medians.
commonware `a9ffc25f3` against zigware `c5b9d9f0` (ReleaseFast, AVX-512 GFNI engine). The
1-minute load average was 42 to 97, so ratios within about 1.3× of 1 are noise here: single
rows swung by 2× between rounds.

The `engine_mul` rows were re-measured on `95742da3`, after `5c5d48cd` timed a workload with
no `before_iter` as one batch. Before it, each iteration paid about 20 ns for two clock reads,
so avx2 read 2.34× (60 ns against 47 ns) and avx512 34 ns against 13 ns. Those rows are now
even. The other engine groups' avx512 rows were not in this run; zigware has had all five
since `c5b9d9f0`.

| group | rows | median ratio | fastest row | slowest row | rows over 1.3× |
|---|---:|---:|---:|---:|---:|
| `reed_solomon::encode` | 30 | 0.96× | 0.53× | 1.78× | 5 |
| `reed_solomon::decode` | 130 | 1.26× | 0.44× | 2.88× | 61 |
| `reed_solomon::encoder` | 23 | 0.74× | 0.35× | 0.91× | 0 |
| `reed_solomon::decoder` | 46 | 0.75× | 0.50× | 1.19× | 0 |
| `reed_solomon::high_rate_encoder` | 9 | 0.86× | 0.60× | 0.95× | 0 |
| `reed_solomon::low_rate_encoder` | 9 | 0.87× | 0.53× | 1.14× | 0 |
| `reed_solomon::high_rate_decoder` | 9 | 0.84× | 0.60× | 1.15× | 0 |
| `reed_solomon::low_rate_decoder` | 9 | 0.62× | 0.37× | 0.85× | 0 |
| `reed_solomon::engine_eval_poly` | 6 | 0.82× | 0.64× | 1.09× | 0 |
| `reed_solomon::engine_fft` | 3 | 0.89× | 0.88× | 0.89× | 0 |
| `reed_solomon::engine_ifft` | 3 | 0.88× | 0.80× | 0.89× | 0 |
| `reed_solomon::engine_mul` | 4 | 1.02× | 0.94× | 1.11× | 0 |

Engine rows:

| bench | parameters | commonware | zigware | zigware / commonware |
|---|---|---|---|---|
| `reed_solomon::engine_eval_poly` | `engine=naive elems=65536` | 1.18 ms | 831 µs | 0.70× |
| `reed_solomon::engine_eval_poly` | `engine=naive elems=8192 mode=truncated` | 812 µs | 513 µs | 0.64× |
| `reed_solomon::engine_eval_poly` | `engine=scalar elems=65536` | 1.02 ms | 928 µs | 0.86× |
| `reed_solomon::engine_eval_poly` | `engine=scalar elems=8192 mode=truncated` | 646 µs | 520 µs | 0.79× |
| `reed_solomon::engine_eval_poly` | `engine=avx2 elems=65536` | 813 µs | 792 µs | 0.97× |
| `reed_solomon::engine_eval_poly` | `engine=avx2 elems=8192 mode=truncated` | 469 µs | 516 µs | 1.09× |
| `reed_solomon::engine_fft` | `engine=naive shards=128` | 488 µs | 453 µs | 0.88× |
| `reed_solomon::engine_fft` | `engine=scalar shards=128` | 318 µs | 272 µs | 0.89× |
| `reed_solomon::engine_fft` | `engine=avx2 shards=128` | 16.8 µs | 15 µs | 0.89× |
| `reed_solomon::engine_ifft` | `engine=naive shards=128` | 488 µs | 430 µs | 0.88× |
| `reed_solomon::engine_ifft` | `engine=scalar shards=128` | 327 µs | 262 µs | 0.80× |
| `reed_solomon::engine_ifft` | `engine=avx2 shards=128` | 17.3 µs | 15.8 µs | 0.89× |
| `reed_solomon::engine_mul` | `engine=naive shard_bytes=1024` | 1.29 µs | 1.03 µs | 1.05× |
| `reed_solomon::engine_mul` | `engine=scalar shard_bytes=1024` | 599 ns | 593 ns | 0.99× |
| `reed_solomon::engine_mul` | `engine=avx2 shard_bytes=1024` | 33 ns | 33 ns | 1.11× |
| `reed_solomon::engine_mul` | `engine=avx512 shard_bytes=1024` | 13.3 ns | 12.7 ns | 0.94× |

Decode is the only group with many rows over 1.3×, and it is worst with a thread pool:

| decode `conc` | `shard_selection` | rows | median ratio | rows over 1.3× |
|---|---|---:|---:|---:|
| 1 | best | 15 | 1.33× | 8 |
| 1 | exception | 15 | 1.16× | 4 |
| 1 | interleaved | 18 | 1.09× | 7 |
| 1 | worst | 15 | 1.05× | 3 |
| 4 | best | 1 | 2.85× | 1 |
| 4 | interleaved | 5 | 1.46× | 4 |
| 4 | worst | 1 | 2.51× | 1 |
| 8 | best | 15 | 1.72× | 12 |
| 8 | exception | 15 | 1.31× | 8 |
| 8 | interleaved | 15 | 1.26× | 6 |
| 8 | worst | 15 | 1.30× | 7 |

Rows over 2×:

| bench | parameters | commonware | zigware | zigware / commonware |
|---|---|---|---|---|
| `reed_solomon::decode` | `msg_len=1048576 chunks=25 min_shards=9 conc=8 shard_selection=best` | 602 µs | 1.73 ms | 2.88× |
| `reed_solomon::decode` | `msg_len=1048576 chunks=20 min_shards=7 conc=4 shard_selection=best` | 766 µs | 2.18 ms | 2.85× |
| `reed_solomon::decode` | `msg_len=4194304 chunks=25 min_shards=9 conc=8 shard_selection=exception` | 4.23 ms | 8.03 ms | 2.67× |
| `reed_solomon::decode` | `msg_len=1048576 chunks=20 min_shards=7 conc=4 shard_selection=worst` | 1.11 ms | 2.69 ms | 2.51× |
| `reed_solomon::decode` | `msg_len=1048576 chunks=100 min_shards=34 conc=8 shard_selection=best` | 883 µs | 2.06 ms | 2.43× |
| `reed_solomon::decode` | `msg_len=4194304 chunks=100 min_shards=34 conc=8 shard_selection=worst` | 6.14 ms | 11 ms | 2.39× |
| `reed_solomon::decode` | `msg_len=1048576 chunks=20 min_shards=7 conc=4 shard_selection=interleaved` | 1.28 ms | 3.01 ms | 2.35× |
| `reed_solomon::decode` | `msg_len=1048576 chunks=25 min_shards=9 conc=8 shard_selection=exception` | 845 µs | 1.82 ms | 2.23× |
| `reed_solomon::decode` | `msg_len=1048576 chunks=250 min_shards=84 conc=1 shard_selection=best` | 800 µs | 2.06 ms | 2.23× |
| `reed_solomon::decode` | `msg_len=4194304 chunks=25 min_shards=9 conc=8 shard_selection=best` | 2.55 ms | 5.78 ms | 2.21× |
| `reed_solomon::decode` | `msg_len=4194304 chunks=25 min_shards=9 conc=8 shard_selection=interleaved` | 5.45 ms | 8.26 ms | 2.14× |
| `reed_solomon::decode` | `msg_len=1048576 chunks=25 min_shards=9 conc=8 shard_selection=worst` | 909 µs | 1.71 ms | 2.12× |
| `reed_solomon::decode` | `msg_len=1048576 chunks=250 min_shards=84 conc=8 shard_selection=best` | 772 µs | 1.71 ms | 2.10× |
| `reed_solomon::decode` | `msg_len=4194304 chunks=10 min_shards=4 conc=8 shard_selection=worst` | 2.52 ms | 5.82 ms | 2.08× |
| `reed_solomon::decode` | `msg_len=4194304 chunks=50 min_shards=17 conc=8 shard_selection=best` | 4.38 ms | 6.58 ms | 2.02× |


Unprofiled. A spot check of `decode/msg_len=4194304 chunks=100 min_shards=34
shard_selection=best` at load 63 had zigware ahead at both `conc=1` (5.88 ms against 6.99 ms)
and `conc=8` (4.87 ms against 5.35 ms), where this run gives 1.40× and 1.65×. So part of the
decode gap is load, which the rerun below confirms.

### Decode with a pool, re-measured (2026-11-20, coding lane)

The rows over 2× above do not reproduce. Three alternating rounds of the six worst rows on
`95742da3` (benches on `allocator.Heap`), load 75 to 105 on 32 cores, median of per-round
ratios:

| bench | parameters | first run | rerun | rerun, adaptive policy |
|---|---|---:|---:|---:|
| `reed_solomon::decode` | `msg_len=1048576 chunks=25 min_shards=9 conc=8 shard_selection=best` | 2.88× | 0.99× | 1.27× |
| `reed_solomon::decode` | `msg_len=1048576 chunks=20 min_shards=7 conc=4 shard_selection=best` | 2.85× | 1.08× | 0.97× |
| `reed_solomon::decode` | `msg_len=4194304 chunks=25 min_shards=9 conc=8 shard_selection=exception` | 2.67× | 0.93× | 0.92× |
| `reed_solomon::decode` | `msg_len=4194304 chunks=100 min_shards=34 conc=8 shard_selection=worst` | 2.39× | 0.89× | 1.02× |
| `reed_solomon::encode` | `msg_len=1048576 chunks=25 conc=8` | 1.78× | 0.74× | 0.65× |
| `reed_solomon::decode` | `msg_len=8388608 chunks=50 min_shards=17 conc=8 shard_selection=worst` | 2.08× | 0.77× | 0.73× |

So the pool rows' gap was the load (about three runnable threads per core), not the code.
zigware's fastest samples run 1.5 to 2× under commonware's (`decode` 1 MiB chunks=25 best:
352 µs against 629 µs) but its slowest run well over them: its spread under load is wider.
The coding benches now run their pool through `Rayon.with_policy`, the adaptive strategy
commonware's `Rayon::new` builds. That made no difference beyond noise here.

## Journal: zstd level 3 compression, native ABBA (2026-11-20, storage-journal lane)

Every compressed `journal::variable_prepare_append` row against commonware built with
`target-cpu=native`, 8 ABBA rounds through the bench queue (load 6 to 9). "before" is main at
94e3da52 (8 rounds, load 4 to 17), random rows only; "after" is d5a0ab1a. Times are the median
per-round medians. All 24 rows are faster; no random row has a round at or above 1 (the closest,
a single random 1 KiB item, reads 0.90 to 0.98 per round).

| parameters | commonware | zigware | before | after | verdict |
|---|---|---|---|---|---|
| `items=1 size=64 compression=3 random=false` | 655 ns | 482 ns | — | 0.75× | faster |
| `items=32 size=64 compression=3 random=false` | 19.9 µs | 14.3 µs | — | 0.72× | faster |
| `items=256 size=64 compression=3 random=false` | 159 µs | 115 µs | — | 0.72× | faster |
| `items=1024 size=64 compression=3 random=false` | 633 µs | 459 µs | — | 0.73× | faster |
| `items=32768 size=64 compression=3 random=false` | 20.1 ms | 14.7 ms | — | 0.73× | faster |
| `items=1 size=64 compression=3 random=true` | 381 ns | 210 ns | 0.64× | 0.55× | faster |
| `items=32 size=64 compression=3 random=true` | 11.7 µs | 6.19 µs | 0.51× | 0.53× | faster |
| `items=256 size=64 compression=3 random=true` | 93.3 µs | 52.4 µs | 0.51× | 0.56× | faster |
| `items=1024 size=64 compression=3 random=true` | 363 µs | 218 µs | 1.17× | 0.60× | faster |
| `items=32768 size=64 compression=3 random=true` | 11.8 ms | 8.91 ms | 1.25× | 0.75× | faster |
| `items=1 size=1024 compression=3 random=false` | 706 ns | 524 ns | — | 0.72× | faster |
| `items=32 size=1024 compression=3 random=false` | 22.1 µs | 15 µs | — | 0.68× | faster |
| `items=256 size=1024 compression=3 random=false` | 177 µs | 120 µs | — | 0.68× | faster |
| `items=1024 size=1024 compression=3 random=false` | 714 µs | 491 µs | — | 0.68× | faster |
| `items=32768 size=1024 compression=3 random=false` | 24.9 ms | 15.5 ms | — | 0.62× | faster |
| `items=1 size=1024 compression=3 random=true` | 1.25 µs | 1.2 µs | 0.87× | 0.94× | faster |
| `items=32 size=1024 compression=3 random=true` | 45.3 µs | 39.6 µs | 0.89× | 0.88× | faster |
| `items=256 size=1024 compression=3 random=true` | 366 µs | 325 µs | 1.74× | 0.89× | faster |
| `items=1024 size=1024 compression=3 random=true` | 1.44 ms | 1.31 ms | 1.78× | 0.90× | faster |
| `items=32768 size=1024 compression=3 random=true` | 52.3 ms | 43.1 ms | 1.63× | 0.83× | faster |
| `items=1 size=1048576 compression=3 random=false` | 92.7 µs | 51.3 µs | — | 0.55× | faster |
| `items=32 size=1048576 compression=3 random=false` | 3.47 ms | 2.04 ms | — | 0.58× | faster |
| `items=1 size=1048576 compression=3 random=true` | 102 µs | 61.4 µs | 1.17× | 0.60× | faster |
| `items=32 size=1048576 compression=3 random=true` | 5.9 ms | 3.78 ms | 1.41× | 0.63× | faster |

What moved them, in the encoder (all frames stay byte-identical to libzstd 1.5.7's; new
`alphabet` fixtures cover matchless blocks whose literals Huffman still shrinks):
- a769320e, 01ce7df3, 06099fb2: the double-fast search selects candidates with a conditional
  move (`ZSTD_selectAddr`) instead of branching on the window check, runs on window indexes
  with one 8-byte read per position, and is specialized on min_match, on whether a repeat
  offset is set, and on level 3's table logs, which keeps its state in registers.
- ef300078, fbf91279: a block without matches whose sampled literals stay raw is stored raw
  without gathering and copying its literals twice, and Huffman literals are not written when
  the new table's estimate already rules them out.
- becdb025, bbe63e26: one encoder per journal, whose window indexes continue from frame to
  frame (`ZSTDirp_continue`) instead of clearing 768 KB of tables per 1 MiB frame.

On identical bytes, a random 1 MiB frame now takes 185k TSC ticks against libzstd's 241k,
and random 1 KiB and 64 B items 3.57k and 0.56k against 3.72k and 0.68k. The rest is the
batch: c2766157 reserves a batch of fixed-size items once (a 32 MiB random batch grew from
empty, copying about twice its size), and d5a0ab1a passes items to the encoder by
pointer: a `[1048576]u8` item was copied twice per frame, which held the single random 1 MiB
row at 0.96× (96.7 to 61.4 µs, against commonware's 102 µs). Tried and
dropped: a four-table histogram (`HIST_count_parallel`, slower on this Zen 5 than one table)
and prefetching the next positions' table entries (slower at every size).

## Journal: every bench group, paired rounds (2026-11-19, storage-journal lane)

All 161 of commonware's `journal` benches (12 groups) against zigware's of the same names,
on tmpfs with bench-compare.sh's criterion settings. Each round runs a whole group on both
sides back to back, alternating which goes first, and a row's ratio is the median of its
per-round ratios (zigware / commonware), not a ratio of bests. "before" is main at 3d7a069c
(3 rounds, load 33 to 116). "after" re-ran the five groups that had rows over 1.3× (3
rounds, load 50 to 112), `variable_prepare_append` on 3075f3a9 (load 77 to 112); a dash
means the group was not re-run and its times are the before run's. The load moves both sides
by tens of percent, so read ratios between 0.8 and 1.3 as even.

Fixes, each with a planted bug its tests catch:
- 269da2cd: `paged.Replay` sized its read slots and data buffer to the requested buffer even
  for a blob of a few pages (1 MiB rows, 2.3 to 3.2×, now 0.3 to 1.0×); a read never spans
  more than the stored pages, so the cap leaves every read unchanged. The journal benches
  also run on `allocator.Heap` (commonware's harness installs mimalloc with
  `Config::DEFAULT`), so a buffer above smp_allocator's size classes is no longer a fresh
  `mmap` faulting on every page (`segmented_variable_append_buffered` size=256 1.46× to
  0.50×).
- 13008b07: a native zstd decoder (`zstd/decode.zig`). `std.compress.zstd` copied matches a
  byte at a time, 0.16 to 0.6 GB/s; the new decoder decodes the bench's 16 KiB records at
  tens of GB/s. Every `variable_read_compressed` row is now below 1× (it was up to 10.5×).
- 3075f3a9: uncompressed `prepare_append` sizes the batch and encodes into one exact buffer
  instead of growing a list and shrinking it (size=1024 items=32 9.3× to 1.0×).
- 501df260: the journals' recovery scans read whole pages up to the replay buffer per blob
  read (`recoverable_prefix_len_scan`), as commonware's do. Reopening 100k committed items
  above the watermark takes 56 mock reads instead of 785. Wall time is unchanged within the
  noise: 405 against 389 µs in memory, and 16.4 ms either way on tmpfs (3 alternating
  rounds). Replay does not scan, so replay rows don't move.

Still over 1.3× in this run, all `variable_prepare_append`: the single-item rows (8.3× at
size=64, 3.9× at size=1024), most compressed size=1024 rows (1.3 to 1.6×), and compressible
1 MiB items (3.3 to 5.5×). Every row of this table comes from binaries before c7935b0c
(criterion's wall-time iteration planning), so rows of benches with setup, teardown or
`before_iter` are provisional until the re-run lands.

Since then (2026-11-20):
- `allocator.Heap` is not behind these rows. The earlier note blaming its 35 to 45 ns small
  allocations predates 9f4eeba4's thread caches: Heap now takes 5.8 to 13 ns per alloc and
  free against smp_allocator's 12 to 18 ns. runtime's native ABBA, 8 rounds on main: items=1
  size=64 none 0.66× and size=1024 none 0.84× (faster), size=1024 level 3 0.82× (faster),
  size=1024 level 3 random 1.22× (slower, the zstd encoder on incompressible input).
- The zstd encoder moved to this lane. e96c83ca reuses one encoder per batch, a9cfb330
  compresses `[N]u8` items in place (the encoded temporary cost twice the compression of a
  compressible 1 MiB item), f78b7454 ports `PREPARED_SPARE_LIMIT` (the batch is no longer
  copied into an exact buffer), and 20d5e341 keeps dfast's search state in locals (5 to 9%
  fewer dfast cycles; its loop is no slower than libzstd 1.5.7's on the same core). With
  storage-merkle's 896d3bf2, compressible 1 MiB rows went from 3.3–5.5× to 0.84–0.98×
  (items=32 about 0.86×, items=1 about 0.96×, 6 of 8 rounds on c7935b0c). Random 1 MiB rows
  read 1.35× (items=1) and 1.69× (items=32) before f78b7454 and 20d5e341.

Fixed append waits for storage-qmdb's write-side findings: the paged write path does not run
inside its timed batch, and its tip copy is first-touch page faults of a fresh buffer, an
allocator effect.

| bench | parameters | commonware | zigware | before | after |
|---|---|---|---|---|---|
| `append_sync` | `journal=fixed mode=sync` | 21.6 µs | 1.75 µs | 0.08× | — |
| `append_sync` | `journal=fixed mode=start_sync` | 22.8 µs | 1.81 µs | 0.08× | — |
| `append_sync` | `journal=fixed mode=commit` | 18.2 µs | 1.27 µs | 0.07× | — |
| `append_sync` | `journal=variable mode=sync` | 42.9 µs | 3.35 µs | 0.08× | — |
| `append_sync` | `journal=variable mode=start_sync` | 45.2 µs | 3.46 µs | 0.08× | — |
| `append_sync` | `journal=variable mode=commit` | 16.9 µs | 2.46 µs | 0.15× | — |
| `fixed_append` | `items=1000 size=32` | 283 µs | 67.1 µs | 0.22× | — |
| `fixed_append` | `items=10000 size=32` | 2.37 ms | 653 µs | 0.28× | — |
| `fixed_append` | `items=100000 size=32` | 22.2 ms | 6.59 ms | 0.30× | — |
| `fixed_append` | `items=1000000 size=32` | 201 ms | 65.5 ms | 0.33× | — |
| `fixed_append` | `items=100000 size=32 items_per_blob=1000000` | 21 ms | 5.87 ms | 0.28× | — |
| `fixed_append` | `items=1000000 size=32 items_per_blob=1000000` | 199 ms | 55 ms | 0.27× | — |
| `fixed_append_buffered` | `items=10240 size=32 prepared=false` | 1.57 ms | 353 µs | 0.22× | — |
| `fixed_append_buffered` | `items=10240 size=32 prepared=true` | 1.84 ms | 683 µs | 0.37× | — |
| `fixed_append_buffered` | `items=1280 size=256 prepared=false` | 198 µs | 84.1 µs | 0.42× | — |
| `fixed_append_buffered` | `items=1280 size=256 prepared=true` | 247 µs | 130 µs | 0.52× | — |
| `fixed_read_random` | `mode=serial items=100 size=32` | 7.23 µs | 3.75 µs | 0.53× | — |
| `fixed_read_random` | `mode=serial items=1000 size=32` | 94.5 µs | 35.4 µs | 0.47× | — |
| `fixed_read_random` | `mode=serial items=10000 size=32` | 6.67 ms | 501 µs | 0.08× | — |
| `fixed_read_random` | `mode=serial items=100000 size=32` | 677 ms | 225 ms | 0.33× | — |
| `fixed_read_random` | `mode=concurrent items=100 size=32` | 20 µs | 4 µs | 0.20× | — |
| `fixed_read_random` | `mode=concurrent items=1000 size=32` | 256 µs | 41.9 µs | 0.16× | — |
| `fixed_read_random` | `mode=concurrent items=10000 size=32` | 21 ms | 547 µs | 0.02× | — |
| `fixed_read_random` | `mode=concurrent items=100000 size=32` | 683 ms | 153 ms | 0.25× | — |
| `fixed_read_random` | `mode=read_many items=100 size=32` | 28.5 µs | 5.42 µs | 0.19× | — |
| `fixed_read_random` | `mode=read_many items=1000 size=32` | 246 µs | 57.4 µs | 0.28× | — |
| `fixed_read_random` | `mode=read_many items=10000 size=32` | 1.83 ms | 797 µs | 0.47× | — |
| `fixed_read_random` | `mode=read_many items=100000 size=32` | 102 ms | 73.9 ms | 0.79× | — |
| `fixed_read_sequential` | `items=1000 size=32` | 68.2 µs | 33.6 µs | 0.52× | — |
| `fixed_read_sequential` | `items=10000 size=32` | 672 µs | 346 µs | 0.57× | — |
| `fixed_read_sequential` | `items=100000 size=32` | 6.72 ms | 3.34 ms | 0.50× | — |
| `fixed_read_sequential` | `items=500000 size=32` | 34.1 ms | 17.6 ms | 0.52× | — |
| `fixed_replay` | `items=1000 buffer=16384 size=32 read_options=dont_cache` | 48.7 µs | 4.91 µs | 0.10× | 0.11× |
| `fixed_replay` | `items=1000 buffer=65536 size=32 read_options=dont_cache` | 22.1 µs | 4.51 µs | 1.19× | 0.20× |
| `fixed_replay` | `items=1000 buffer=1048576 size=32 read_options=dont_cache` | 13.1 µs | 4.62 µs | 2.63× | 0.34× |
| `fixed_replay` | `items=1000 buffer=16384 size=32 read_options=cache` | 45.9 µs | 4.62 µs | 0.12× | 0.09× |
| `fixed_replay` | `items=1000 buffer=65536 size=32 read_options=cache` | 17.4 µs | 4.63 µs | 1.63× | 0.25× |
| `fixed_replay` | `items=1000 buffer=1048576 size=32 read_options=cache` | 11.1 µs | 4.47 µs | 3.17× | 0.38× |
| `fixed_replay` | `items=10000 buffer=16384 size=32 read_options=dont_cache` | 590 µs | 43.8 µs | 0.11× | 0.08× |
| `fixed_replay` | `items=10000 buffer=65536 size=32 read_options=dont_cache` | 174 µs | 42.9 µs | 0.58× | 0.25× |
| `fixed_replay` | `items=10000 buffer=1048576 size=32 read_options=dont_cache` | 97.8 µs | 45 µs | 2.33× | 0.47× |
| `fixed_replay` | `items=10000 buffer=16384 size=32 read_options=cache` | 433 µs | 43.2 µs | 0.09× | 0.10× |
| `fixed_replay` | `items=10000 buffer=65536 size=32 read_options=cache` | 164 µs | 43.3 µs | 0.79× | 0.26× |
| `fixed_replay` | `items=10000 buffer=1048576 size=32 read_options=cache` | 71.6 µs | 44.1 µs | 3.10× | 0.70× |
| `fixed_replay` | `items=100000 buffer=16384 size=32 read_options=dont_cache` | 6.76 ms | 593 µs | 0.07× | 0.09× |
| `fixed_replay` | `items=100000 buffer=65536 size=32 read_options=dont_cache` | 1.71 ms | 435 µs | 0.31× | 0.27× |
| `fixed_replay` | `items=100000 buffer=1048576 size=32 read_options=dont_cache` | 685 µs | 475 µs | 1.30× | 0.69× |
| `fixed_replay` | `items=100000 buffer=16384 size=32 read_options=cache` | 3.64 ms | 474 µs | 0.07× | 0.13× |
| `fixed_replay` | `items=100000 buffer=65536 size=32 read_options=cache` | 1.5 ms | 473 µs | 0.33× | 0.32× |
| `fixed_replay` | `items=100000 buffer=1048576 size=32 read_options=cache` | 621 µs | 471 µs | 1.60× | 0.75× |
| `fixed_replay` | `items=500000 buffer=16384 size=32 read_options=dont_cache` | 27.8 ms | 4.07 ms | 0.12× | 0.15× |
| `fixed_replay` | `items=500000 buffer=65536 size=32 read_options=dont_cache` | 10.1 ms | 3.79 ms | 0.41× | 0.39× |
| `fixed_replay` | `items=500000 buffer=1048576 size=32 read_options=dont_cache` | 4.65 ms | 4.1 ms | 1.44× | 0.88× |
| `fixed_replay` | `items=500000 buffer=16384 size=32 read_options=cache` | 20 ms | 4.24 ms | 0.25× | 0.19× |
| `fixed_replay` | `items=500000 buffer=65536 size=32 read_options=cache` | 7.6 ms | 4.08 ms | 0.37× | 0.55× |
| `fixed_replay` | `items=500000 buffer=1048576 size=32 read_options=cache` | 4.03 ms | 4.01 ms | 1.20× | 0.97× |
| `read_cached` | `journal=fixed size=8` | 1.45 ms | 672 µs | 0.46× | — |
| `read_cached` | `journal=fixed size=32` | 1.66 ms | 695 µs | 0.42× | — |
| `read_cached` | `journal=fixed size=64` | 1.8 ms | 706 µs | 0.36× | — |
| `read_cached` | `journal=fixed size=128` | 2.79 ms | 769 µs | 0.28× | — |
| `read_cached` | `journal=fixed size=129` | 5.26 ms | 823 µs | 0.16× | — |
| `read_cached` | `journal=fixed size=256` | 5.5 ms | 961 µs | 0.23× | — |
| `read_cached` | `journal=variable size=32` | 5.08 ms | 2.1 ms | 0.41× | — |
| `segmented_variable_append_buffered` | `items=10240 size=32` | 306 µs | 114 µs | 0.52× | 0.37× |
| `segmented_variable_append_buffered` | `items=1280 size=256` | 48.7 µs | 25.8 µs | 1.46× | 0.54× |
| `variable_prepare_append` | `items=1 size=64 compression=none random=false` | 37.9 ns | 384 ns | 2.25× | 8.29× |
| `variable_prepare_append` | `items=1 size=64 compression=3 random=false` | 1.35 µs | 1.42 µs | 0.85× | 1.05× |
| `variable_prepare_append` | `items=32 size=64 compression=none random=false` | 457 ns | 164 ns | 0.58× | 0.37× |
| `variable_prepare_append` | `items=32 size=64 compression=3 random=false` | 40.5 µs | 34 µs | 0.80× | 0.84× |
| `variable_prepare_append` | `items=256 size=64 compression=none random=false` | 2.16 µs | 632 ns | 0.73× | 0.29× |
| `variable_prepare_append` | `items=256 size=64 compression=3 random=false` | 316 µs | 279 µs | 0.81× | 0.88× |
| `variable_prepare_append` | `items=1024 size=64 compression=none random=false` | 7.71 µs | 1.91 µs | 2.51× | 0.25× |
| `variable_prepare_append` | `items=1024 size=64 compression=3 random=false` | 1.17 ms | 1.17 ms | 1.06× | 1.03× |
| `variable_prepare_append` | `items=32768 size=64 compression=none random=false` | 296 µs | 51.7 µs | 2.23× | 0.17× |
| `variable_prepare_append` | `items=32768 size=64 compression=3 random=false` | 37.2 ms | 38.2 ms | 0.81× | 1.05× |
| `variable_prepare_append` | `items=1 size=64 compression=3 random=true` | 824 ns | 920 ns | 0.78× | 1.12× |
| `variable_prepare_append` | `items=32 size=64 compression=3 random=true` | 20.8 µs | 19.4 µs | 0.69× | 0.93× |
| `variable_prepare_append` | `items=256 size=64 compression=3 random=true` | 176 µs | 170 µs | 0.76× | 0.87× |
| `variable_prepare_append` | `items=1024 size=64 compression=3 random=true` | 700 µs | 982 µs | 1.21× | 1.40× |
| `variable_prepare_append` | `items=32768 size=64 compression=3 random=true` | 23.6 ms | 30.9 ms | 1.09× | 1.31× |
| `variable_prepare_append` | `items=1 size=1024 compression=none random=false` | 57 ns | 224 ns | 1.74× | 3.86× |
| `variable_prepare_append` | `items=1 size=1024 compression=3 random=false` | 1.4 µs | 2.16 µs | 1.08× | 1.61× |
| `variable_prepare_append` | `items=32 size=1024 compression=none random=false` | 1.36 µs | 838 ns | 9.31× | 0.62× |
| `variable_prepare_append` | `items=32 size=1024 compression=3 random=false` | 43.2 µs | 62 µs | 1.14× | 1.49× |
| `variable_prepare_append` | `items=256 size=1024 compression=none random=false` | 9.86 µs | 5.7 µs | 5.28× | 0.53× |
| `variable_prepare_append` | `items=256 size=1024 compression=3 random=false` | 373 µs | 543 µs | 0.87× | 1.22× |
| `variable_prepare_append` | `items=1024 size=1024 compression=none random=false` | 52.7 µs | 25.3 µs | 3.39× | 0.48× |
| `variable_prepare_append` | `items=1024 size=1024 compression=3 random=false` | 1.47 ms | 1.99 ms | 0.74× | 1.27× |
| `variable_prepare_append` | `items=32768 size=1024 compression=none random=false` | 6.72 ms | 2.59 ms | 1.11× | 0.42× |
| `variable_prepare_append` | `items=32768 size=1024 compression=3 random=false` | 53.7 ms | 63.3 ms | 1.13× | 1.50× |
| `variable_prepare_append` | `items=1 size=1024 compression=3 random=true` | 2.73 µs | 2.93 µs | 0.80× | 1.09× |
| `variable_prepare_append` | `items=32 size=1024 compression=3 random=true` | 99.5 µs | 95 µs | 0.83× | 0.93× |
| `variable_prepare_append` | `items=256 size=1024 compression=3 random=true` | 918 µs | 1.27 ms | 1.22× | 1.39× |
| `variable_prepare_append` | `items=1024 size=1024 compression=3 random=true` | 3.53 ms | 4.73 ms | 1.29× | 1.33× |
| `variable_prepare_append` | `items=32768 size=1024 compression=3 random=true` | 116 ms | 159 ms | 1.20× | 1.37× |
| `variable_prepare_append` | `items=1 size=1048576 compression=none random=false` | 26.4 µs | 39.4 µs | 12.73× | 1.48× |
| `variable_prepare_append` | `items=1 size=1048576 compression=3 random=false` | 199 µs | 861 µs | 7.65× | 5.50× |
| `variable_prepare_append` | `items=32 size=1048576 compression=none random=false` | 7.32 ms | 3.08 ms | 1.51× | 0.42× |
| `variable_prepare_append` | `items=32 size=1048576 compression=3 random=false` | 8.36 ms | 28.8 ms | 6.14× | 3.32× |
| `variable_prepare_append` | `items=1 size=1048576 compression=3 random=true` | 200 µs | 208 µs | 4.24× | 1.06× |
| `variable_prepare_append` | `items=32 size=1048576 compression=3 random=true` | 10.5 ms | 14.6 ms | 2.16× | 1.56× |
| `variable_read_compressed` | `mode=read_many items=10000 size=64 random=false` | 2.36 ms | 1.74 ms | 2.06× | 0.75× |
| `variable_read_compressed` | `mode=read_many_uncached items=10000 size=64 random=false` | 2.56 ms | 1.34 ms | 1.64× | 0.53× |
| `variable_read_compressed` | `mode=read_uncached items=10000 size=64 random=false` | 97.2 ms | 10 ms | 0.13× | 0.14× |
| `variable_read_compressed` | `mode=replay items=10000 size=64 random=false` | 2.89 ms | 1.33 ms | 1.22× | 0.46× |
| `variable_read_compressed` | `mode=read_many items=10000 size=64 random=true` | 1.51 ms | 978 µs | 1.73× | 0.65× |
| `variable_read_compressed` | `mode=read_many_uncached items=10000 size=64 random=true` | 1.88 ms | 998 µs | 1.13× | 0.53× |
| `variable_read_compressed` | `mode=read_uncached items=10000 size=64 random=true` | 91.8 ms | 10.8 ms | 0.10× | 0.12× |
| `variable_read_compressed` | `mode=replay items=10000 size=64 random=true` | 2.33 ms | 606 µs | 1.10× | 0.26× |
| `variable_read_compressed` | `mode=read_many items=10000 size=1024 random=false` | 6.55 ms | 2.81 ms | 3.49× | 0.43× |
| `variable_read_compressed` | `mode=read_many_uncached items=10000 size=1024 random=false` | 7.26 ms | 2.08 ms | 2.08× | 0.29× |
| `variable_read_compressed` | `mode=read_uncached items=10000 size=1024 random=false` | 108 ms | 11.8 ms | 0.26× | 0.11× |
| `variable_read_compressed` | `mode=replay items=10000 size=1024 random=false` | 6.47 ms | 2.79 ms | 4.53× | 0.43× |
| `variable_read_compressed` | `mode=read_many items=10000 size=1024 random=true` | 5.25 ms | 3.29 ms | 0.87× | 0.62× |
| `variable_read_compressed` | `mode=read_many_uncached items=10000 size=1024 random=true` | 11.6 ms | 4.4 ms | 0.54× | 0.38× |
| `variable_read_compressed` | `mode=read_uncached items=10000 size=1024 random=true` | 129 ms | 18.2 ms | 0.12× | 0.15× |
| `variable_read_compressed` | `mode=replay items=10000 size=1024 random=true` | 6.73 ms | 3.84 ms | 1.15× | 0.57× |
| `variable_read_compressed` | `mode=read_many items=1024 size=16384 random=false` | 3.66 ms | 1.32 ms | 10.46× | 0.36× |
| `variable_read_compressed` | `mode=read_many_uncached items=1024 size=16384 random=false` | 4.85 ms | 620 µs | 4.66× | 0.12× |
| `variable_read_compressed` | `mode=read_uncached items=1024 size=16384 random=false` | 11.2 ms | 1.74 ms | 3.49× | 0.16× |
| `variable_read_compressed` | `mode=replay items=1024 size=16384 random=false` | 5.42 ms | 4.72 ms | 6.53× | 0.83× |
| `variable_read_compressed` | `mode=read_many items=1024 size=16384 random=true` | 7.02 ms | 2.97 ms | 0.46× | 0.42× |
| `variable_read_compressed` | `mode=read_many_uncached items=1024 size=16384 random=true` | 12.5 ms | 4.09 ms | 0.37× | 0.31× |
| `variable_read_compressed` | `mode=read_uncached items=1024 size=16384 random=true` | 45.4 ms | 6.89 ms | 0.14× | 0.15× |
| `variable_read_compressed` | `mode=replay items=1024 size=16384 random=true` | 10.2 ms | 4.81 ms | 0.58× | 0.48× |
| `variable_read_random` | `mode=serial items=100 size=32` | 23.8 µs | 10.4 µs | 0.44× | — |
| `variable_read_random` | `mode=serial items=1000 size=32` | 421 µs | 110 µs | 0.29× | — |
| `variable_read_random` | `mode=serial items=10000 size=32` | 162 ms | 31.5 ms | 0.19× | — |
| `variable_read_random` | `mode=serial items=100000 size=32` | 1.27 s | 356 ms | 0.29× | — |
| `variable_read_random` | `mode=concurrent items=100 size=32` | 45.4 µs | 11.7 µs | 0.26× | — |
| `variable_read_random` | `mode=concurrent items=1000 size=32` | 798 µs | 119 µs | 0.15× | — |
| `variable_read_random` | `mode=concurrent items=10000 size=32` | 176 ms | 24.1 ms | 0.15× | — |
| `variable_read_random` | `mode=concurrent items=100000 size=32` | 1.32 s | 392 ms | 0.30× | — |
| `variable_read_random` | `mode=read_many items=100 size=32` | 32.1 µs | 13.2 µs | 0.41× | — |
| `variable_read_random` | `mode=read_many items=1000 size=32` | 336 µs | 148 µs | 0.46× | — |
| `variable_read_random` | `mode=read_many items=10000 size=32` | 34.7 ms | 22.6 ms | 0.65× | — |
| `variable_read_random` | `mode=read_many items=100000 size=32` | 133 ms | 107 ms | 0.88× | — |
| `variable_replay` | `items=1000 buffer=16384 size=32 read_options=dont_cache` | 80.2 µs | 12.6 µs | 0.43× | 0.16× |
| `variable_replay` | `items=1000 buffer=65536 size=32 read_options=dont_cache` | 67.7 µs | 13.2 µs | 0.76× | 0.20× |
| `variable_replay` | `items=1000 buffer=1048576 size=32 read_options=dont_cache` | 48 µs | 12.9 µs | 1.03× | 0.27× |
| `variable_replay` | `items=1000 buffer=16384 size=32 read_options=cache` | 84.7 µs | 12.3 µs | 0.40× | 0.14× |
| `variable_replay` | `items=1000 buffer=65536 size=32 read_options=cache` | 57.9 µs | 12.8 µs | 0.81× | 0.23× |
| `variable_replay` | `items=1000 buffer=1048576 size=32 read_options=cache` | 44.7 µs | 12.9 µs | 1.01× | 0.29× |
| `variable_replay` | `items=10000 buffer=16384 size=32 read_options=dont_cache` | 738 µs | 106 µs | 0.30× | 0.15× |
| `variable_replay` | `items=10000 buffer=65536 size=32 read_options=dont_cache` | 468 µs | 111 µs | 0.49× | 0.24× |
| `variable_replay` | `items=10000 buffer=1048576 size=32 read_options=dont_cache` | 490 µs | 124 µs | 0.54× | 0.25× |
| `variable_replay` | `items=10000 buffer=16384 size=32 read_options=cache` | 575 µs | 110 µs | 0.37× | 0.21× |
| `variable_replay` | `items=10000 buffer=65536 size=32 read_options=cache` | 441 µs | 112 µs | 0.53× | 0.25× |
| `variable_replay` | `items=10000 buffer=1048576 size=32 read_options=cache` | 520 µs | 121 µs | 0.62× | 0.23× |
| `variable_replay` | `items=100000 buffer=16384 size=32 read_options=dont_cache` | 7.45 ms | 1.15 ms | 0.28× | 0.15× |
| `variable_replay` | `items=100000 buffer=65536 size=32 read_options=dont_cache` | 4.72 ms | 1.24 ms | 0.43× | 0.26× |
| `variable_replay` | `items=100000 buffer=1048576 size=32 read_options=dont_cache` | 4.16 ms | 1.42 ms | 0.92× | 0.32× |
| `variable_replay` | `items=100000 buffer=16384 size=32 read_options=cache` | 6.41 ms | 1.15 ms | 0.54× | 0.18× |
| `variable_replay` | `items=100000 buffer=65536 size=32 read_options=cache` | 4.33 ms | 1.28 ms | 0.49× | 0.30× |
| `variable_replay` | `items=100000 buffer=1048576 size=32 read_options=cache` | 3.95 ms | 1.55 ms | 0.48× | 0.36× |
| `variable_replay` | `items=500000 buffer=16384 size=32 read_options=dont_cache` | 34.9 ms | 7.53 ms | 0.22× | 0.22× |
| `variable_replay` | `items=500000 buffer=65536 size=32 read_options=dont_cache` | 22.9 ms | 7.42 ms | 0.35× | 0.32× |
| `variable_replay` | `items=500000 buffer=1048576 size=32 read_options=dont_cache` | 21.7 ms | 7.92 ms | 0.55× | 0.37× |
| `variable_replay` | `items=500000 buffer=16384 size=32 read_options=cache` | 31.2 ms | 7.01 ms | 0.33× | 0.22× |
| `variable_replay` | `items=500000 buffer=65536 size=32 read_options=cache` | 21.9 ms | 7.16 ms | 0.54× | 0.34× |
| `variable_replay` | `items=500000 buffer=1048576 size=32 read_options=cache` | 19.6 ms | 7.58 ms | 0.47× | 0.39× |

## cryptography: hashes, ed25519, lthash (2026-11-20, crypto lane)

ABBA rounds=8 through `etc/scripts/bench-lock.sh` (one CCD slot per pair), bench-compare.sh's
Criterion settings, commonware built with `-C target-cpu=native`; the ratio is the median of
per-round zigware/commonware ratios, and a verdict allows n/8 rounds past 1. Raw rounds are in
`docs/bench/crypto.tsv`. Load 1–7, except ed25519 (3–77). ed25519 and the sha256/blake3/bloom
rows ran on 655836a6, lthash and sha256 individual on c7935b0c (before_iter planning fixed).
Totals: 22 faster, 20 tie, 6 slower.

| bench | params | commonware | zigware | median | worst | verdict |
|---|---|---|---|---|---|---|
| `ed25519::signature_verification` | `ns_len=9 msg_len=32` | 16.1 µs | 13.8 µs | 0.80× | 0.96× | faster |
| `ed25519::signature_generation` | `ns_len=9 msg_len=32` | 14.9 µs | 13.9 µs | 0.79× | 1.18× | faster |
| `sha256::hash_message` | `msg_len=256` | 138 ns | 130 ns | 0.93× | 0.96× | faster |
| `sha256::hash_message` | 4 KiB to 16 MiB (5 rows) | | | 0.99–1.00× | ≤1.01× | tie |
| `sha256::hash_parts` | 4 shapes | 18.7–38.1 ns | 18.3–36.7 ns | 0.95–0.98× | ≤0.99× | tie |
| `sha256::hash_pair` | `shape=bmt`, `shape=mmr` | 60 ns | 62–63 ns | 1.04× | 1.05× | tie |
| `sha256::hash_many::individual` | `count=1/7 len=64/256` (4 rows) | | | 0.73–0.92× | | faster |
| `sha256::hash_many::individual` | `count=1/7 len≥4096` (8 rows) | | | 0.98–1.00× | ≤1.03× | tie |
| `sha512::hash_many::individual` | `count=1 len=96` | 136 ns | 148 ns | 1.09× | 1.10× | slower |
| `sha512::hash_many::individual` | `count=1 len=1 KiB to 256 KiB` (4 rows) | | | 1.29× | 1.31× | slower |
| `blake3::hash_message` | `msg_len=256 conc=1`, `conc=8` | 289 ns | 230 ns | 0.79× | 0.80× | faster |
| `bloomfilter::contains` | `hasher=blake3 item_size=32` (4 rows) | 89–100 ns | 81–93 ns | 0.89–0.93× | ≤0.96× | faster |
| `lthash::add` / `subtract` | 32 B to 1 KiB (6 rows) | | | 0.52–0.71× | ≤0.72× | faster |
| `lthash::add` | `bytes=4096` | 1.7 µs | 1.61 µs | 0.96× | 0.98× | tie |
| `lthash::combine` | | 95.7 ns | 21.3 ns | 0.22× | 0.32× | faster |
| `lthash::update` | `incremental`, `full` | | | 0.92×, 0.57× | ≤0.93× | faster |
| `lthash::checksum` | | 1.17 µs | 1.25 µs | 1.07× | 1.08× | slower |

- **ed25519** went from 1.62× to 0.80×: `half_size` runs Lehmer's algorithm (a1fdd462, 3.8 ->
  0.9 µs), and decompression's `pow2523` and sign's point encoding square with 64-bit
  coefficient products (2642cac4, 6e46b58f). The IFMA double-scalar sum was already on.
- **Long SHA-256 is at SHA-NI parity** (0.99–1.00×): both sides run the same instructions at
  the same rate. A hybrid of the x16 AVX-512 kernel with 2–4 interleaved SHA-NI streams was
  slower than x16 alone (3.0 against 3.1–3.3 µs a 16 KiB message), so it did not land.
- **sha512 individual** (1.29×) is the open gap: commonware's `sha2` crate runs its AVX2 message
  schedule; zigware's `sha512_blocks.zig` four-block schedule beats std by 15–20% but not it.
  Since flipped to 0.85–0.93× (see [Sweep](#sweep-the-rows-still-slower-2026-11-20-sweep)).

## cryptography: blake3 and bloomfilter (2026-11-20, parallel lane)

ABBA rounds through `etc/scripts/bench-lock.sh` (one CCD slot per pair), bench-compare.sh's
Criterion settings, commonware a9ffc25f3 built with `-C target-cpu=native`; the ratio is the
median of per-round zigware/commonware ratios. Raw rounds are in `docs/bench/parallel.tsv`.
blake3 ran 4 rounds on 9467df21 (load 1.4–8.6, one round 22); bloomfilter ran 2–3 rounds on
b55d750c (load 2–3), and its rounds are still being extended. blake3: 3 faster, 11 tie,
2 slower; bloomfilter: 16 faster, 11 tie, 9 slower.

| bench | params | commonware | zigware | median | rounds | verdict |
|---|---|---|---|---|---|---|
| `blake3::hash_message` | `msg_len=256`, conc=1 and 8 | 300 ns | 238 ns | 0.79× | 0.79–0.80 | faster |
| `blake3::hash_message` | `msg_len=4096`, conc=1 and 8 | 1.26 µs | 1.41 µs | 1.12× | 1.11–1.12 | not yet faster: at hardware floor |
| `blake3::hash_message` | 64 KiB to 16 MiB, conc=1 (5 rows) | | | 0.99–1.02× | ≤1.02 | tie |
| `blake3::hash_message` | 64 KiB to 512 KiB, conc=8 (4 rows) | | | 1.01–1.04× | 0.26–1.14 | tie |
| `blake3::hash_message` | `msg_len=1048576 conc=8` | 88.0 µs | 16.7 µs | 0.19× | 0.19–0.20 | faster |
| `blake3::hash_message` | `msg_len=16777216 conc=8` | 249 µs | 224 µs | 0.90× | 0.79–1.06 | tie |
| `bloomfilter::{insert,contains}` | `item_size=32`, both hashers (12 rows) | | | 0.81–0.93× | ≤0.95 | faster |
| `bloomfilter::{insert,contains}` | blake3, `item_size=2048/4096` (12 rows) | | | 1.02–1.11× | | not yet faster: at hardware floor |
| `bloomfilter::contains` | sha256, `item_size=2048/4096`, positive (4 rows) | | | 0.87–0.91× | ≤0.92 | faster |
| `bloomfilter::{insert,contains}` | sha256, 2048/4096, other (8 rows) | | | 0.95–0.99× | ≤1.02 | tie |

- **blake3 at 2–4 KiB is at the Zen 5 vector-latency floor.** On this core (Ryzen AI Max+
  395), every vector integer op has a 2-cycle dependent latency, against 1 cycle for scalar
  add/ror; a dependent-chain microbench gave about 0.42 ns per op for vpaddd, vpxor, vprold,
  vpshufb, vpshufd, vpshuflw, and vpternlogd, at xmm and zmm width alike. A chunk is a chain
  of 16 compressions × 168 dependent ops, so a vector chunk takes at least about 1144 ns
  however many lanes run. The crate already sits there: its row-form one-chunk hash takes
  1150 ns, and its 4-chunk `hash4` about 1172 ns. zigware's 4-lane chunk pass alone takes
  1236 ns, 0.94 of the crate's whole 4 KiB hash (1316 ns in-process), so even with a perfect
  parent tail the best case is about 0.97× at 2 KiB and 1.02–1.03× at 4 KiB. The bloomfilter
  blake3 2–4 KiB items hash the same way. A one-chunk message runs one scalar chain at
  1-cycle latency instead: 1 KiB takes 762 ns against the crate's 1150 ns.
- **Rejected at 2–4 KiB** (in-process, thread CPU time, pinned): padding a 2–4 chunk batch
  to 8 or 16 lanes; message words in a stack buffer as memory operands (no change); two
  interleaved scalar chains (1615 ns for 2 chunks, spill-bound at 855 movs per block); a
  row-form compress in Zig vectors (one parent 61 against 46 ns, a chunk 2.2–3.1 µs); an
  all-scalar 4 KiB parent tail (no change). A hand-written minimal 4-chunk path costs the
  same as `hash_serial`, so routing and plumbing are not the cost.
- **Rejected for the long rows:** a 17th chunk on the scalar ALUs beside each 16-lane zmm
  block. 16 chunks take 1255 ns; 16 plus one interleaved scalar chunk take 1900–1940 ns,
  about the sum of the two, so the scalar chain does not ride on idle pipes. A 32-lane
  kernel and a policy-free `hash_across` gave no gain either.

## Sweep: the rows still slower (2026-11-20, sweep)

The rows left slower or unverdicted when the lanes paused, measured with `bench-compare.sh`
(ABBA rounds through `bench-lock.sh`, commonware `-C target-cpu=native`, median of per-round
ratios). Raw rounds are in `docs/bench/sweep.tsv`. Load 5 to 15 on 32 threads.

| bench | params | commonware | zigware | median | rounds | verdict |
|---|---|---|---|---|---|---|
| `sha512::hash_many::individual` | `count=1 len=96` | 146 ns | 125 ns | 0.85× | 0.84–0.92 (8) | faster |
| `sha512::hash_many::individual` | `count=1 len=1024` | 1.05 µs | 966 ns | 0.92× | 0.89–0.94 (8) | faster |
| `sha512::hash_many::individual` | `count=1 len=16384` | 14.5 µs | 13.5 µs | 0.92× | 0.92–1.25 (8) | faster |
| `sha512::hash_many::individual` | `count=1 len=65536` | 57.7 µs | 53.5 µs | 0.93× | 0.81–0.93 (8) | faster |
| `sha512::hash_many::individual` | `count=1 len=262144` | 230 µs | 212 µs | 0.92× | 0.89–0.93 (8) | faster |
| `archive::get` | `variant=prunable mode=concurrent`, 4 rows | 7.8–8.9 ms | 2.7–2.9 ms | 0.32–0.35× | ≤0.38 (6) | faster |
| `lthash::checksum` | | 1.17 µs | 1.26 µs | 1.08× | 1.07–1.08 (6) | slower |
| `blake3::hash_message` | `msg_len=4096`, conc=1 and 8 | 1.35 µs | 1.50 µs | 1.11–1.12× | 1.10–1.14 (6) | slower |
| `journal::variable_read_random` | `mode=read_many items=10000 size=32` | 11.5 ms | 10.3 ms | 0.89× | 0.35–0.95 (6) | faster |
| `cache::insert` | `capacity=1024` | 48.0 µs | 30.3 µs | 0.63× | 0.61–0.70 (6) | faster |
| `cache::insert` | `capacity=16384` | 63.8 µs | 34.4 µs | 0.54× | 0.47–0.57 (6) | faster |
| `cache::insert` | `capacity=262144` | 67.5 µs | 50.6 µs | 0.77× | 0.57–0.88 (6) | faster |
| `merkle::update` | `updates=100000 leaves=100000 strategy=BatchedSerial family=mmr` | 18.2 ms | 17.6 ms | 0.97× | 0.93–0.99 (8) | tie |
| `merkle::add_many` | `items=65536 workers=8 family=mmb` | 1.05 ms | 1.08 ms | 1.03× | 1.02–1.04 (8) | tie |
| `bls12381::msm` | `group=g1 n=50 conc=1` | 944 µs | 924 µs | 0.98× | 0.97–1.01 (6) | tie |
| `bls12381::msm` | `group=g1 n=100 conc=1` | 1.60 ms | 1.60 ms | 1.00× | 0.97–1.29 (6) | tie |
| `bls12381::msm` | `group=g2 n=10 conc=1` | 724 µs | 694 µs | 0.95× | 0.94–0.97 (6) | tie |
| `bls12381::msm` | `group=g2 n=10 conc=8` | 409 µs | 241 µs | 0.58× | 0.21–1.75 (6) | tie |

- **sha512** was 1.10× at 1 KiB and a tie from 16 KiB on b9f83fde (4 rounds). Two changes
  flipped it, both in `sha512_blocks.zig`: blocks schedule eight at a time on AVX-512, where
  eight u64 lanes cost what four do (a0cd1ca0; 1 KiB then read 1.00×, longer messages 0.96×),
  and the looped rounds keep LLVM from chaining `Ch`, `h`, `W + K`, `Σ1`, and `d` one after
  another on `e` (ce4b9de7): empty-asm pins hold `d + h + W + K` and `h + W + K` off the chain,
  and majority adds as its disjoint terms `a & (b ^ c)` and `b & c`. The same pins on the
  unrolled lone block made 96 B slower (150 against 118 ns), so it keeps the old form, and a
  padding block routed through the loop after whole blocks cost 96 B the same. This is
  `sha2` crate code on commonware's side, not commonware's.
- **archive concurrent get** (prunable) was 1.10×; ec9b8ee5 (`get_many` reads values
  concurrently) made it 0.32–0.35×.
- **lthash checksum** hashes its 2 KiB state with BLAKE3: two chunks, which the transposed
  kernel compresses in 2-lane vectors. On this CPU a dependent vector add, xor, or rotate takes
  about twice a scalar add's latency (1.27 against 0.63 TSC ticks), so the kernel is bound by
  its round chain, not its op count (per 4-lane block: 336 `vpaddd`, 224 `vprold`, 232 xors,
  the minimum). It runs about 239 TSC ticks a compression against about 200 for the `blake3`
  crate's row-wise asm. A single chunk on scalar registers is 130 a compression, but two
  interleaved scalar chunks spill (32 state words) and a scalar chunk beside a vector one
  waits on the vector chain. Rotates as byte shuffles were rewritten back into `vprold` by
  LLVM, and forced `vpshufb` was slower. Not yet faster; the same kernel holds
  `blake3::hash_message/msg_len=4096` at 1.12×.
- **merkle** rows above ran on bcd218db (`add_many` hashes leaves in pairs through the SHA-NI
  pair kernel), 949b51e4 (overwrites keyed by a folded-multiply position hash) and 9757335d
  (merkleize reads a parent's children from the height just hashed below through a sorted
  cursor, not a map lookup each). `update` was 1.05× before them. 02f95ab0 then radix-sorts the
  updated leaf locations, which pdq sorted in hash order (11% of the row): standalone
  18.2 → 16.4 ms, to be re-measured. `add_many` w8 is 10% faster than before the pairing
  (1.19 → 1.06 ms standalone) and is bound by SHA-256 across its eight workers.
- **bls msm** rows above ran before five msm commits, which standalone take g1 n=50 conc=1
  from 965 to 775 µs, g1 n=100 from 1.61 to 1.30 ms, g2 n=50 from 2.27 to 1.82 ms, g2 n=200
  from 7.34 to 5.80 ms, and g1/g2 n=1000 conc=1 (1.12–1.13× in a 1-round screen) from
  14.1/33.2 to 9.4/24 ms: the tiled msm past 256 points splits scalars by GLV/GLS and
  accumulates batch-affine (dd3848b6), Straus splits its terms the same way (988b5a01), the
  split window is chosen for batch-affine costs (7b610f79), a point whose bucket is already in
  the batch waits for the next batch instead of a Jacobian side bucket (7c1b1dca), and as many
  windows as the buckets hold share one batch-affine pass and its inversions (0f4975ec).
  Verdicts follow. This is blst code on commonware's side, not commonware's.

## Appendix: bench coverage

Every Criterion bench in commonware a9ffc25f3 (`benches/` dirs with `criterion_main!`), listed
with `cargo bench --no-run` and each bench binary's `--list`, matched by exact name against
zigware's `--list` output in both standard and full mode (`COMMONWARE_BENCH_FULL=1`; zigware
keeps the largest inputs of some benches to full mode). Each package's benches run under
`zig build bench` (filter with `-Dbench-filter=`). Counts are bench cases (one Criterion name
each); a group is the name before the first `/`.

**2229 of 2262** commonware cases have a zigware bench of the same name. The 33 without one:

- 18 `impl=roaring-rs` rows of the roaring bitmap benches: they measure an external Rust crate.
- 15 `iobuf::iobuf::decode_fixed` cases: the `bytes` and `bytes_ref` modes measure the `bytes`
  crate, and `vec` is the same decode as `vec_slice` here (decided when the bench was ported).

Ported by this audit: utils' `bitmap`, `cache`, `rational`, and `sequence` benches (168
cases), storage's `ordinal` (13) and `rmap` (5), curve25519's batch verify at
commonware's concurrency levels 16 and 32, `sha256::hash_parts` (4), and the `conc=8` rows of
`blake3::hash_message` (8, after `Blake3.hash_across` learned to split a long message into
subtrees across the strategy, as commonware does) and of six bls12381 groups (100). Renamed to commonware's Criterion names:
`curve25519::batch_verify` to `batch_verify::verify_batch_bytes_bench`, and
`iobuf::decode_fixed` to `iobuf::iobuf::decode_fixed`.

Not Criterion benches, so not in the table: `qmdb_gungraun` (an instruction-count harness),
`coding_scheme_sizes` (a size report; zigware's `reed_solomon size (shard)` rows),
`index_scale`, runtime's `storage` workload binary (zigware's `runtime::storage::<workload>`),
and qmdb's `cold_read`, `scale`, and `constantinople` (zigware's `zig build qmdb-<name>`).
Crates with no Criterion benches in commonware, so no rows: `resolver`, `broadcast`,
`collector`, and `stream` (no `[[bench]]` target or `benches/` dir); zigware has none for them
either. stream's cipher and handshake are measured through p2p's rows above.
zigware-only groups, with no commonware counterpart: `clearing::*`, `curve25519::{sign,
verify, x25519}` (against `std.crypto`), `parallel::{fold, sort_by}`, `journal::zstd::encode`,
and runtime's I/O backend benches (`runtime::network::echo`, `runtime::storage`).

| Crate | Bench target | Group | commonware | zigware | Notes |
|---|---|---|---:|---:|---|
| actor | `mailbox` | `mailbox::mailbox::enqueue_ready` | 1 | 1 |  |
| actor | `mailbox` | `mailbox::mailbox::try_recv_ready` | 1 | 1 |  |
| actor | `mailbox` | `mailbox::mailbox::try_recv_overflow` | 1 | 1 |  |
| actor | `mailbox` | `mailbox::mailbox::round_trip_ready` | 1 | 1 |  |
| actor | `mailbox` | `mailbox::mailbox::recv_waiting` | 1 | 1 |  |
| actor | `mailbox` | `mailbox::mailbox::overflow_drop` | 1 | 1 |  |
| actor | `mailbox` | `mailbox::mailbox::overflow_spill` | 1 | 1 |  |
| actor | `mailbox` | `mailbox::mailbox::overflow_replace` | 2 | 2 |  |
| actor | `mailbox` | `mailbox::mailbox::concurrent_enqueue` | 1 | 1 |  |
| codec | `codec` | `codec::lazy::get` | 10 | 10 |  |
| coding | `coding_scheme_times` | `reed_solomon::encode` | 30 | 30 |  |
| coding | `coding_scheme_times` | `reed_solomon::decode` | 130 | 130 |  |
| cryptography | `blake3` | `blake3::hash_message` | 16 | 16 |  |
| cryptography | `bloomfilter` | `bloomfilter::insert` | 12 | 12 |  |
| cryptography | `bloomfilter` | `bloomfilter::contains` | 24 | 24 |  |
| cryptography | `bls12381` | `bls12381::batch_to_affine` | 8 | 8 |  |
| cryptography | `bls12381` | `bls12381::dkg::golden::deal` | 3 | 3 |  |
| cryptography | `bls12381` | `bls12381::dkg::golden::verify` | 3 | 3 |  |
| cryptography | `bls12381` | `bls12381::dkg::feldman_desmedt_recovery` | 4 | 4 |  |
| cryptography | `bls12381` | `bls12381::dkg::feldman_desmedt_reshare_recovery` | 4 | 4 |  |
| cryptography | `bls12381` | `bls12381::hash_to_curve` | 8 | 8 |  |
| cryptography | `bls12381` | `bls12381::attestation_eq` | 2 | 2 |  |
| cryptography | `bls12381` | `bls12381::threshold_recover` | 20 | 20 |  |
| cryptography | `bls12381` | `bls12381::threshold_optimistic_assemble` | 32 | 32 |  |
| cryptography | `bls12381` | `bls12381::combine_public_keys` | 4 | 4 |  |
| cryptography | `bls12381` | `bls12381::combine_signatures` | 4 | 4 |  |
| cryptography | `bls12381` | `bls12381::signature_generation` | 1 | 1 |  |
| cryptography | `bls12381` | `bls12381::signature_verification` | 1 | 1 |  |
| cryptography | `bls12381` | `bls12381::batch_verify_same_signer` | 10 | 10 |  |
| cryptography | `bls12381` | `bls12381::aggregate_verify_same_message` | 4 | 4 |  |
| cryptography | `bls12381` | `bls12381::aggregate_verify_same_signer` | 10 | 10 |  |
| cryptography | `bls12381` | `bls12381::scheme_batch_verify_same_signer` | 10 | 10 |  |
| cryptography | `bls12381` | `bls12381::scheme_batch_verify_same_message` | 10 | 10 |  |
| cryptography | `bls12381` | `bls12381::evaluate_point` | 14 | 14 |  |
| cryptography | `bls12381` | `bls12381::msm` | 24 | 24 |  |
| cryptography | `bls12381` | `bls12381::multisig_optimistic_assemble` | 16 | 16 |  |
| cryptography | `bls12381` | `bls12381::threshold_batch_verify_same_message` | 56 | 56 |  |
| cryptography | `bls12381` | `bls12381::threshold_batch_verify_same_message_pre` | 56 | 56 |  |
| cryptography | `bls12381` | `bls12381::threshold_batch_verify_same_signer` | 56 | 56 |  |
| cryptography | `bls12381` | `bls12381::tle_encrypt` | 1 | 1 |  |
| cryptography | `bls12381` | `bls12381::tle_decrypt` | 1 | 1 |  |
| cryptography | `bulletproofs` | `bulletproofs::ipa::prove` | 10 | 10 |  |
| cryptography | `bulletproofs` | `bulletproofs::ipa::verify` | 10 | 10 |  |
| cryptography | `chacha20_poly1305` | `chacha20_poly1305::seal_open` | 3 | 3 |  |
| cryptography | `ed25519` | `ed25519::signature_generation` | 1 | 1 |  |
| cryptography | `ed25519` | `ed25519::signature_verification` | 1 | 1 |  |
| cryptography | `ed25519` | `ed25519::batch_verify_same_message` | 10 | 10 |  |
| cryptography | `ed25519` | `ed25519::batch_verify_same_signer` | 10 | 10 |  |
| cryptography | `ed25519` | `ed25519::batch_verify` | 5 | 5 |  |
| cryptography | `lthash` | `lthash::add` | 4 | 4 |  |
| cryptography | `lthash` | `lthash::subtract` | 3 | 3 |  |
| cryptography | `lthash` | `lthash::combine` | 1 | 1 |  |
| cryptography | `lthash` | `lthash::checksum` | 1 | 1 |  |
| cryptography | `lthash` | `lthash::update` | 2 | 2 |  |
| cryptography | `reed_solomon` | `reed_solomon::encoder` | 23 | 23 |  |
| cryptography | `reed_solomon` | `reed_solomon::decoder` | 46 | 46 |  |
| cryptography | `reed_solomon` | `reed_solomon::high_rate_encoder` | 9 | 9 |  |
| cryptography | `reed_solomon` | `reed_solomon::low_rate_encoder` | 9 | 9 |  |
| cryptography | `reed_solomon` | `reed_solomon::high_rate_decoder` | 9 | 9 |  |
| cryptography | `reed_solomon` | `reed_solomon::low_rate_decoder` | 9 | 9 |  |
| cryptography | `reed_solomon` | `reed_solomon::engine_eval_poly` | 8 | 8 |  |
| cryptography | `reed_solomon` | `reed_solomon::engine_mul` | 4 | 4 |  |
| cryptography | `reed_solomon` | `reed_solomon::engine_fft` | 4 | 4 |  |
| cryptography | `reed_solomon` | `reed_solomon::engine_ifft` | 4 | 4 |  |
| cryptography | `sake` | `sake::sake` | 1 | 1 |  |
| cryptography | `secp256r1` | `secp256r1::signature_generation` | 2 | 2 |  |
| cryptography | `secp256r1` | `secp256r1::signature_verification` | 2 | 2 |  |
| cryptography | `sha256` | `sha256::hash_message` | 6 | 6 |  |
| cryptography | `sha256` | `sha256::hash_many::individual` | 54 | 54 |  |
| cryptography | `sha256` | `sha256::hash_many::batch` | 108 | 108 |  |
| cryptography | `sha256` | `sha256::hash_pair` | 2 | 2 |  |
| cryptography | `sha256` | `sha256::hash_parts` | 4 | 4 |  |
| cryptography | `sha256` | `sha256::digest_cmp` | 12 | 12 |  |
| cryptography | `sha512` | `sha512::hash_many::individual` | 40 | 40 |  |
| cryptography | `sha512` | `sha512::hash_many::batch` | 80 | 80 |  |
| curve25519 | `batch_verify` | `batch_verify::verify_batch_bytes_bench` | 24 | 24 | ported in full by this audit: renamed from `curve25519::batch_verify`, conc 16 and 32 added |
| formatting | `formatting` | `formatting::encode` | 6 | 6 |  |
| formatting | `formatting` | `formatting::decode` | 12 | 12 |  |
| formatting | `formatting` | `formatting::display` | 6 | 6 |  |
| glue | `transfers` | `transfers::plan` | 48 | 48 |  |
| glue | `transfers` | `transfers::settle` | 48 | 48 |  |
| glue | `transfers` | `transfers::select` | 48 | 48 |  |
| math | `interpolation` | `interpolation::interpolator_creation` | 11 | 11 |  |
| runtime | `buffer_paged` | `buffer_paged::append` | 8 | 8 |  |
| runtime | `buffer_paged` | `buffer_paged::read` | 8 | 8 |  |
| runtime | `buffer_paged` | `buffer_paged::sync` | 4 | 4 |  |
| runtime | `iobuf` | `iobuf::iobuf::decode_fixed` | 45 | 30 | `bytes`, `bytes_ref`, `vec` not ported: no counterpart to the `bytes` crate, and `vec` is `vec_slice`'s decode here; renamed from `iobuf::decode_fixed` to commonware's name |
| storage | `archive` | `archive::put` | 4 | 4 |  |
| storage | `archive` | `archive::get` | 16 | 16 |  |
| storage | `archive` | `archive::restart` | 4 | 4 |  |
| storage | `bmt` | `bmt::build` | 7 | 7 |  |
| storage | `bmt` | `bmt::proof` | 3 | 3 |  |
| storage | `bmt` | `bmt::multi_proof` | 3 | 3 |  |
| storage | `bmt` | `bmt::range_proof` | 3 | 3 |  |
| storage | `bmt` | `bmt::verify_single` | 7 | 7 |  |
| storage | `bmt` | `bmt::verify_multi` | 7 | 7 |  |
| storage | `bmt` | `bmt::verify_range` | 7 | 7 |  |
| storage | `freezer` | `freezer::get` | 4 | 4 |  |
| storage | `freezer` | `freezer::put` | 1 | 1 |  |
| storage | `freezer` | `freezer::restart` | 1 | 1 |  |
| storage | `index` | `index::grinding` | 8 | 8 |  |
| storage | `index` | `index::hashmap_iteration` | 4 | 4 |  |
| storage | `index` | `index::hashmap_insert_fixed` | 1 | 1 |  |
| storage | `index` | `index::hashmap_insert` | 4 | 4 |  |
| storage | `index` | `index::insert` | 18 | 18 |  |
| storage | `index` | `index::insert_and_retain` | 2 | 2 |  |
| storage | `index` | `index::lookup` | 12 | 12 |  |
| storage | `index` | `index::lookup_miss` | 6 | 6 |  |
| storage | `journal` | `journal::append_sync` | 6 | 6 |  |
| storage | `journal` | `journal::fixed_append` | 6 | 6 |  |
| storage | `journal` | `journal::fixed_append_buffered` | 4 | 4 |  |
| storage | `journal` | `journal::fixed_read_random` | 12 | 12 |  |
| storage | `journal` | `journal::fixed_read_sequential` | 4 | 4 |  |
| storage | `journal` | `journal::fixed_replay` | 24 | 24 |  |
| storage | `journal` | `journal::read_cached` | 7 | 7 |  |
| storage | `journal` | `journal::segmented_variable_append_buffered` | 2 | 2 |  |
| storage | `journal` | `journal::variable_prepare_append` | 36 | 36 |  |
| storage | `journal` | `journal::variable_read_compressed` | 24 | 24 |  |
| storage | `journal` | `journal::variable_read_random` | 12 | 12 |  |
| storage | `journal` | `journal::variable_replay` | 24 | 24 |  |
| storage | `merkle` | `merkle::add_many` | 28 | 28 |  |
| storage | `merkle` | `merkle::append` | 4 | 4 |  |
| storage | `merkle` | `merkle::append_additional` | 16 | 16 |  |
| storage | `merkle` | `merkle::flush` | 4 | 4 |  |
| storage | `merkle` | `merkle::multi_proof` | 4 | 4 |  |
| storage | `merkle` | `merkle::position_to_location` | 4 | 4 |  |
| storage | `merkle` | `merkle::proof` | 4 | 4 |  |
| storage | `merkle` | `merkle::range_proof` | 40 | 40 |  |
| storage | `merkle` | `merkle::verify_single_element` | 4 | 4 |  |
| storage | `merkle` | `merkle::verify_many_elements` | 40 | 40 |  |
| storage | `merkle` | `merkle::verify_multi` | 4 | 4 |  |
| storage | `merkle` | `merkle::update` | 8 | 8 |  |
| storage | `metadata` | `metadata::sync` | 21 | 21 |  |
| storage | `metadata` | `metadata::overwrite` | 12 | 12 |  |
| storage | `metadata` | `metadata::restart` | 4 | 4 |  |
| storage | `ordinal` | `ordinal::get` | 6 | 6 | ported by this audit; `mode=concurrent` keeps its name but reads serially (the store is not shared between tasks), as the freezer's does |
| storage | `ordinal` | `ordinal::put` | 3 | 3 | ported by this audit |
| storage | `ordinal` | `ordinal::restart` | 4 | 4 | ported by this audit |
| storage | `qmdb` | `qmdb::apply_batch` | 8 | 8 |  |
| storage | `qmdb` | `qmdb::chained_growth` | 4 | 4 |  |
| storage | `qmdb` | `qmdb::generate` | 29 | 29 |  |
| storage | `qmdb` | `qmdb::init` | 50 | 50 |  |
| storage | `qmdb` | `qmdb::merkleize` | 128 | 128 |  |
| storage | `rmap` | `rmap::insert` | 5 | 5 | ported by this audit |
| utils | `bitmap` | `bitmap::count_ones` | 24 | 24 | ported by this audit |
| utils | `bitmap` | `bitmap::write` | 24 | 24 | ported by this audit |
| utils | `bitmap` | `bitmap::roaring_insert` | 6 | 3 | ported by this audit; `impl=roaring-rs` rows measure an external Rust crate |
| utils | `bitmap` | `bitmap::roaring_insert_range` | 6 | 3 | ported by this audit; `impl=roaring-rs` rows measure an external Rust crate |
| utils | `bitmap` | `bitmap::roaring_contains` | 6 | 3 | ported by this audit; `impl=roaring-rs` rows measure an external Rust crate |
| utils | `bitmap` | `bitmap::roaring_union` | 4 | 2 | ported by this audit; `impl=roaring-rs` rows measure an external Rust crate |
| utils | `bitmap` | `bitmap::roaring_intersection` | 4 | 2 | ported by this audit; `impl=roaring-rs` rows measure an external Rust crate |
| utils | `bitmap` | `bitmap::roaring_difference` | 4 | 2 | ported by this audit; `impl=roaring-rs` rows measure an external Rust crate |
| utils | `bitmap` | `bitmap::roaring_iteration` | 6 | 3 | ported by this audit; `impl=roaring-rs` rows measure an external Rust crate |
| utils | `bitmap` | `bitmap::roaring_write` | 3 | 3 | ported by this audit |
| utils | `cache` | `cache::get` | 3 | 3 | ported by this audit |
| utils | `cache` | `cache::insert` | 3 | 3 | ported by this audit |
| utils | `cache` | `cache::mixed` | 3 | 3 | ported by this audit |
| utils | `cache` | `cache::refill` | 3 | 3 | ported by this audit |
| utils | `rational` | `rational::log2_ceil` | 24 | 24 | ported by this audit |
| utils | `sequence` | `sequence::cmp_bytes` | 63 | 63 | ported by this audit |
