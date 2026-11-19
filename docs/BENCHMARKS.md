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
| `ed25519::signature_verification` | `ns_len=9 msg_len=32` | 26.7 µs | 43.3 µs | 1.62× |
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
  at a load average of about 67 measured 3.02 ms against 1.90 ms. The remaining gap is probably
  field arithmetic (unprofiled, as for `signature_verification` below).

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

## Appendix: bench coverage
