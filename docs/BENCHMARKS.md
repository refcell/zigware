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
| `ed25519::batch_verify_same_message` | `pks=100 conc=1` | 1.38 ms | 1.86 ms | 1.35× (re-run, see below) |
| `bls12381::signature_verification` | `ns_len=9 msg_len=32` | 1.23 ms | 1.59 ms | 1.30× |
| `bls12381::aggregate_verify_same_message` | `pks=1000` | 2.27 ms | 2.16 ms | 0.96× |
| `journal::fixed_append` | `items=10000 size=32` | 2.00 ms | 456 µs | 0.23× |
| `journal::append_sync` | `journal=fixed mode=sync` | 14.6 µs | 1.55 µs | 0.11× |
| `journal::fixed_replay` | `items=100000 buffer=65536 size=32 read_options=cache` | 690 µs | 817 µs | 1.19× |
| `qmdb::apply_batch` | `case=direct variant=any::unordered::fixed::mmb chunk=32 updates=16384` | 1.12 ms | 2.72 ms | 2.43× |
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

- **`ed25519::batch_verify_same_message`, 2.13× to 1.35×.** `verify_shard` summed every
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
- **`qmdb::apply_batch` (2.43×), owned by the storage-qmdb lane
  (`src/storage/qmdb/any/db.zig`, `any/batch.zig`).** Applying 16384 updates runs
  `apply_to_index`, and each diff entry does a snapshot `get_mut`, a linear `find` over the
  key's locations, and an update. `log.apply_batch` also copies the journal batch. Guess: the
  per-key index cursor work and allocations dominate. Compare with commonware's index update
  path, which is allocation-free here and runs over mimalloc.

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
  the final sync, the key cache) before quoting them.

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
subtrees across the strategy, as commonware does) and of six bls12381 groups (100).
`bls12381::aggregate_verify_same_signer` and `evaluate_point` fold and multiply across the
strategy in the bench, because zigware's `combine_messages` and `eval_msm` take no strategy yet. Renamed to commonware's Criterion names:
`curve25519::batch_verify` to `batch_verify::verify_batch_bytes_bench`, and
`iobuf::decode_fixed` to `iobuf::iobuf::decode_fixed`.

Not Criterion benches, so not in the table: `qmdb_gungraun` (an instruction-count harness),
`coding_scheme_sizes` (a size report; zigware's `reed_solomon size (shard)` rows),
`index_scale`, runtime's `storage` workload binary (zigware's `runtime::storage::<workload>`),
and qmdb's `cold_read`, `scale`, and `constantinople` (zigware's `zig build qmdb-<name>`).
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
