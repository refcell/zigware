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
| `journal::fixed_append` | `items=10000 size=32` | 2.00 ms | 456 µs | 0.23× |
| `journal::append_sync` | `journal=fixed mode=sync` | 14.6 µs | 1.55 µs | 0.11× |
| `journal::fixed_replay` | `items=100000 buffer=65536 size=32 read_options=cache` | 690 µs | 817 µs | 1.19× (fixed, see below) |
| `qmdb::apply_batch` | `case=direct variant=any::unordered::fixed::mmb chunk=32 updates=16384` | 1.13 ms | 1.21 ms | 1.07× |
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
- commonware's bench harnesses (journal, qmdb) install mimalloc as the global allocator.
  zigware's benches use their own allocators.
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
  table figure: 481 µs against 690 µs, about 0.70× while loaded. Commonware's replay also
  keeps three reads in flight ahead of the decoder (`Blob::start_read_many`); here the
  blob reads cost about 120 to 270 µs of wall time on tmpfs, so read-ahead is a smaller,
  later step.
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
  runtime lanes.

## bls12381: the remaining benches (2026-11-19, bls-math lane)

The bls12381 benches the table above left out, at `bench-compare.sh`'s settings (1 s warm-up,
3 s measurement, 50 samples), one `conc=1` case per bench. Each side's number is its best
median of two alternating rounds, at a 1-minute load average of 81 (round 1) and 41
(round 2). commonware's best mostly came from the quieter round, so rows near 1.3× are inside
the noise: round 1 alone had `signature_generation` at 0.76×, `aggregate_verify_same_signer`
at 1.07×, `batch_verify_same_signer` at 0.92×, and `combine_signatures` at 1.09×. The golden
DKG rows ran once with 10 samples (commonware's own sample size for them) at a load of 59.
The two assemble rows are a same-load re-run after the fix below (load 67 to 73).

| bench | parameters | commonware | zigware | zigware / commonware |
|---|---|---|---|---|
| `bls12381::signature_generation` | `ns_len=9 msg_len=32` | 257 µs | 385 µs | 1.50× (noise, see above) |
| `bls12381::hash_to_curve` | `n=100 conc=1` | 4.33 ms | 7.37 ms | 1.70× (open) |
| `bls12381::tle_encrypt` | | 1.29 ms | 1.04 ms | 0.80× |
| `bls12381::tle_decrypt` | | 704 µs | 901 µs | 1.28× |
| `bls12381::combine_public_keys` | `pks=1000` | 1.27 ms | 1.22 ms | 0.96× |
| `bls12381::combine_signatures` | `sigs=1000` | 446 µs | 590 µs | 1.32× (noise) |
| `bls12381::batch_to_affine` | `group=g1 n=100` | 31.9 µs | 18.9 µs | 0.59× |
| `bls12381::batch_to_affine` | `group=g2 n=100` | 85.8 µs | 62.7 µs | 0.73× |
| `bls12381::attestation_eq` | `bytes=equal` | 25.4 ns | 119 ns | 4.68× (harness) |
| `bls12381::msm` | `group=g1 n=1000 conc=1` | 14.0 ms | 17.2 ms | 1.22× |
| `bls12381::msm` | `group=g2 n=1000 conc=1` | 40.1 ms | 49.6 ms | 1.23× |
| `bls12381::evaluate_point` | `n=50 t=34 conc=1` | 899 µs | 954 µs | 1.06× |
| `bls12381::batch_verify_same_signer` | `conc=1 msgs=100` | 6.25 ms | 8.24 ms | 1.32× (noise) |
| `bls12381::aggregate_verify_same_signer` | `conc=1 msgs=100` | 4.20 ms | 6.76 ms | 1.61× (noise) |
| `bls12381::scheme_batch_verify_same_message` | `pks=100 conc=1` | 37.3 ms | 38.8 ms | 1.04× |
| `bls12381::scheme_batch_verify_same_signer` | `msgs=100 conc=1` | 33.3 ms | 37.4 ms | 1.12× |
| `bls12381::threshold_recover` | `mode=NonZeroCounter n=100 t=67` | 954 µs | 959 µs | 1.01× |
| `bls12381::threshold_batch_verify_same_message` | `n=10 t=7 invalid=0 conc=1 mode=NonZeroCounter` | 7.83 ms | 2.20 ms | 0.28× |
| `bls12381::threshold_batch_verify_same_message_pre` | `n=10 t=7 invalid=0 conc=1 mode=NonZeroCounter` | 1.48 ms | 1.71 ms | 1.16× |
| `bls12381::threshold_batch_verify_same_signer` | `n=10 t=7 msgs=100 conc=1 mode=NonZeroCounter` | 9.22 ms | 8.53 ms | 0.93× |
| `bls12381::threshold_optimistic_assemble` | `variant=MinPk mode=NonZeroCounter n=100 case=valid` | 7.00 ms | 7.95 ms | 1.14× (fixed, was 2.54×) |
| `bls12381::multisig_optimistic_assemble` | `variant=MinPk n=100 case=valid` | 1.18 ms | 1.43 ms | 1.21× (fixed, was 6.51×) |
| `bls12381::dkg::feldman_desmedt_recovery` | `n=20 t=14 conc=1` | 24.1 ms | 12.8 ms | 0.53× |
| `bls12381::dkg::feldman_desmedt_reshare_recovery` | `n=20 t=14 conc=1` | 45.6 ms | 22.4 ms | 0.49× |
| `bls12381::dkg::golden::deal` | `n=5` | 6.55 s | 7.15 s | 1.09× |
| `bls12381::dkg::golden::verify` | `n=5` | 577 ms | 1.99 s | 3.45× (open) |

- **Optimistic assembly (fixed, f72c0613).** `certificate.Deferred.get()` decoded the
  signature on every call: for MinPk a G2 decompression and subgroup check, about 105 µs in
  ReleaseFast under load, and an assembly reads 67 of them. commonware's `Lazy` caches the
  decoded value in a `OnceLock`. `Deferred` now keeps the value from `init(value)`, decodes
  read bytes once through `decode()`, and compares like `Lazy`'s `PartialEq` (equal bytes,
  else equal decoded values, two failures equal).
- **`attestation_eq` measures the harness.** The comparison is a 48-byte `mem.eql` (0.9 ns).
  `bench.criterion` reads `Clock.awake.now` around every iteration, a pair that costs about
  43 ns under this load, while criterion's `iter_batched` times a whole batch. Passed to the
  parallel lane (`src/bench`).
- **`hash_to_curve` (open, simplex lane).** The bench hashes to G1 (MinSig messages): 74 µs
  against 43 µs per hash. The G2 hash work (67308018, 6e50645b) does not cover it; G1 SSWU,
  its square root, and G1 cofactor clearing are in `arithmetic/map.zig` and `fields.zig`.
- **`dkg::golden::verify` (open).** Both sides run the same algorithm: banderwagon MSMs are
  `msm_naive` on both, and its field `F` multiply is deliberately slow on both. Timings in
  ReleaseFast under load: a BLS `Fr` multiply 26 ns, a banderwagon add 387 ns, a banderwagon
  scalar multiply 166 µs. The next step is a per-phase split (eVRF batch check, IPA, the
  dealing checks) against commonware's.

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

## Appendix: bench coverage

Every Criterion bench in commonware a9ffc25f3 (`benches/` dirs with `criterion_main!`), listed
with `cargo bench --no-run` and each bench binary's `--list`, matched by exact name against
zigware's `--list` output in both standard and full mode (`COMMONWARE_BENCH_FULL=1`; zigware
keeps the largest inputs of some benches to full mode). Each package's benches run under
`zig build bench` (filter with `-Dbench-filter=`). Counts are bench cases (one Criterion name
each); a group is the name before the first `/`.

**2224 of 2262** commonware cases have a zigware bench of the same name. The 38 without one:

- 18 `impl=roaring-rs` rows of the roaring bitmap benches: they measure an external Rust crate.
- 15 `iobuf::iobuf::decode_fixed` cases: the `bytes` and `bytes_ref` modes measure the `bytes`
  crate, and `vec` is the same decode as `vec_slice` here (decided when the bench was ported).
- 5 `engine=avx512` rows of the Reed-Solomon engine benches: zigware has no AVX-512 engine.

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
Crates with no Criterion benches in commonware, so no rows: `resolver`, `broadcast`, and
`collector` (no `[[bench]]` target or `benches/` dir); zigware has none for them either.
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
| cryptography | `reed_solomon` | `reed_solomon::engine_eval_poly` | 8 | 6 | `engine=avx512` missing: zigware has no AVX-512 engine |
| cryptography | `reed_solomon` | `reed_solomon::engine_mul` | 4 | 3 | `engine=avx512` missing: zigware has no AVX-512 engine |
| cryptography | `reed_solomon` | `reed_solomon::engine_fft` | 4 | 3 | `engine=avx512` missing: zigware has no AVX-512 engine |
| cryptography | `reed_solomon` | `reed_solomon::engine_ifft` | 4 | 3 | `engine=avx512` missing: zigware has no AVX-512 engine |
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
