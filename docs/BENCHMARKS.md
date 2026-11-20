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

It prints the table above and writes the raw medians and the load average for each run to
`.cache/bench-compare/raw.tsv`. Both sides keep their storage benches' files in a scratch
directory under `BENCH_DIR` (default `$TMPDIR` or `/tmp`). commonware gets it through `TMPDIR`
(its tokio runner uses `env::temp_dir()`), and zigware runs from it (its benches use
`./.zig-cache/tmp`).

## Caveats

- **Method from 2026-11-20 on.** `bench-compare.sh` runs rounds in ABBA order (default 4),
  reports the median of per-round ratios, builds commonware with
  `RUSTFLAGS="-C target-cpu=native"` (zigware also builds for the native CPU), and gives each
  row a verdict: "faster" when the median is below 0.95 and every round is below 1, "slower"
  when the median is above 1.05 and every round is above 1, "tie" otherwise. Rows measured
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

- **`ed25519::signature_verification` (1.62×), owned by the crypto lane.** Verification uses
  `std.crypto`'s `Edwards25519.mulDoubleBasePublic` over its radix-2^51 scalar field
  arithmetic. commonware's vendored curve25519 code picks a SIMD backend (AVX2 or IFMA) on
  x86-64, which this Zen CPU supports. Guess: a vectorized field backend, or a wider
  precomputed base-point table for the `s B` half.

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
