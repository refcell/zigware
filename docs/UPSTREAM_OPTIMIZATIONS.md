# Optimizations commonware could adopt

Changes in zigware that make a row faster than commonware at `a9ffc25f3`, where the cause is
an algorithm or a design commonware could take over, not a CPU flag. Every commonware row
below was built with `RUSTFLAGS="-C target-cpu=native"`, so it already gets the same
instruction sets; a row counts only when the win remains after that. Verdicts follow AGENTS.md
rule 11 (ABBA rounds, median of per-round ratios below 0.95, at most n/8 rounds at or above
1). Rows measured before that method are marked as such. AGENTS.md rule 12 asks every lane to
add new entries here, with the bench row, its verdict, and the commit, in the same push.

| Optimization | Row | zigware / commonware | Verdict | Commits |
| --- | --- | --- | --- | --- |
| [Lehmer's `half_size` in ed25519 verify](#ed25519-verify-lehmers-half_size) | `ed25519::signature_verification` | 0.80× (8 rounds) | faster | a1fdd462 |
| [BLS12-381 field arithmetic on IFMA lanes](#bls12-381-on-avx-512-ifma-lanes) | `bls12381::signature_verification` | 0.89× | faster | 93613b46, 40ee19da, 17705256 |
| [Interleaved SHA-NI pairs for short `hash_many` runs](#sha-256-hash_many-in-sha-ni-pairs) | `sha256::hash_many::individual` count=1/7, len=64/256 | 0.73–0.92× (8 rounds) | faster | 17a97b76 |
| [One root compression for short BLAKE3 messages](#blake3-one-root-compression) | `blake3::hash_message` msg_len=256 | 0.79× (8 rounds) | faster | 772e9944 |
| [lthash over a wide XOF and 32-lane state steps](#lthash) | `lthash::add`/`subtract` ≤ 1 KiB, `combine` | 0.52–0.71×, 0.22× (8 rounds) | faster | b23c4c4c |
| [Reserve a compressed batch up front](#journal-reserve-a-compressed-batch-up-front) | `journal::variable_prepare_append` items=32 size=1048576 compression=3 random=true | 0.68× (8 rounds) | faster | d2ab82b1 |
| [Blob I/O issued inline instead of on `spawn_blocking`](#storage-blob-io-without-a-thread-hop) | `freezer::get`, `freezer::put` | 0.03×, 0.07× (pre-ABBA) | see below | runtime design |

## ed25519 verify: Lehmer's half_size

commonware's `curve25519` single-signature check splits the challenge with `half_size`
(`signing/core/scalar.rs`), a bit-at-a-time Euclid that subtracts shifted copies of a 256-bit
remainder. zigware runs Lehmer's algorithm (Knuth 4.5.2 L): runs of quotients taken from the
remainders' leading 64 bits apply as one 2×2 matrix, with an exact step on full remainders
when the leading bits decide none, and a step is taken only while the remainder provably stays
at least 2^126, so `(u, v)` is exactly commonware's. In zigware it went from 3.8 µs to 0.9 µs
of a 16–19 µs verify. Rust lowers a variable 256-bit shift better than Zig, so the saving in
commonware will be smaller, but the step count drops from about one per quotient bit to about
one per 64-bit run.

- Evidence: [BENCHMARKS.md, cryptography](BENCHMARKS.md#cryptography-hashes-ed25519-lthash-2026-11-20-crypto-lane)
  (0.80×, worst round 0.96×; sign 0.79×, from field-level changes that are against `std`, not
  adoptable); [crypto.md](lanes/crypto.md) log, 2026-11-20. The test compares 4,106 inputs
  against commonware's algorithm, and 2 million more matched in ReleaseFast.

## BLS12-381 on AVX-512 IFMA lanes

commonware's BLS12-381 runs on blst. zigware holds eight Fp elements at once, one per 64-bit
lane, as 52-bit limbs in Montgomery form, and multiplies them with `vpmadd52luq`/`vpmadd52huq`
(the instructions ed25519's AVX-512 backend already uses). On top of that it:

- maps up to four messages to G1 lane-wise (SSWU and the 11-isogeny, the square roots and sign
  fixes), with the inversions shared through one scalar safegcd by Montgomery's trick;
- clears the cofactor once on a sum of mapped messages instead of once per message, since
  clearing is multiplication by the fixed `h_eff` (an algebraic change that needs no IFMA);
- runs the final exponentiation's cyclotomic squarings and the Miller loop's accumulator
  squares and line products as three lane products per round (a two-pair Miller loop went
  from 413 µs to 351 µs, thread CPU).

blst has no IFMA path, so `target-cpu=native` gives commonware none of this. Targets without
IFMA keep zigware's scalar code. The aggregate row (`aggregate_verify_same_message`, 1000
keys) is a tie at 1.04×, and the remaining bls12381 rows wait on a quiet native re-run.

- Evidence: README performance table (single verify 0.89×, faster); commit messages of
  93613b46, 40ee19da, 17705256.

## SHA-256 hash_many in SHA-NI pairs

For a batch too short for the 16-lane AVX-512 kernel, commonware hashes one message at a time.
zigware hashes two equal-length messages together through interleaved SHA-NI streams, which
hides SHA-NI's latency, and moves the kernel threshold (`minimum_batch_len`) from 7 to 10. A
batch of 7 × 4 KiB went from 13.6 µs to 9.1 µs, and 2 × 256 B from 298 ns to 207 ns,
standalone; digests are unchanged. Long messages stay at SHA-NI parity (0.99–1.00×).

- Evidence: [BENCHMARKS.md, cryptography](BENCHMARKS.md#cryptography-hashes-ed25519-lthash-2026-11-20-crypto-lane);
  [crypto.md](lanes/crypto.md) log, 2026-11-20.

## BLAKE3: one root compression

A message of at most one chunk is hashed with a single root compression on one lane, instead
of setting up the hasher and running the XOF over a lane's worth of output blocks: 32 bytes
take 99 ns against 133 ns. Worth checking against the `blake3` crate's own short-input path
before adopting; the native row is 0.79× at 256 bytes, both `conc=1` and `conc=8`.

- Evidence: [BENCHMARKS.md, cryptography](BENCHMARKS.md#cryptography-hashes-ed25519-lthash-2026-11-20-crypto-lane);
  [crypto.md](lanes/crypto.md) log, 2026-11-19 and 2026-11-20.

## lthash

lthash's `expand` and `checksum` use a BLAKE3 XOF that compresses whole chunks and emits output
blocks a vector's worth of lanes at a time, and add, subtract, and combine step through the
1024-element `u16` state 32 elements at a time with the XOF writing straight into it. Native
rows: add and subtract up to 1 KiB 0.52–0.71×, `combine` 0.22×, `update` full 0.57×. At 4 KiB
add is a tie (0.96×) and `checksum` is slower (1.07×). How much of this is codegen rather than
a portable change needs checking against commonware's loops before adopting it.

- Evidence: [BENCHMARKS.md, cryptography](BENCHMARKS.md#cryptography-hashes-ed25519-lthash-2026-11-20-crypto-lane);
  [crypto.md](lanes/crypto.md) log, 2026-11-19.

## Journal: reserve a compressed batch up front

commonware's `prepare_append` starts from `Vec::new()` and `compress_into` reserves each
item's `compress_bound` as it goes, so a batch of large items grows by doubling and copies
everything written so far at each step, onto fresh pages. When every item's encoded size is
known first (`FixedSize` values, or a pass over `encode_size()`), the batch can be reserved
once as the sum of `varint + compress_bound(size)`. In zigware this took 32 random 1 MiB items
from 6.9 ms to 4.0 ms (its list grows by half, so it copied more than a doubling `Vec`); the
row is 0.68× at native ABBA, with the encoder changes of the same push included, so treat the
share commonware would gain as unmeasured.

- Evidence: [BENCHMARKS.md, journal zstd](BENCHMARKS.md#journal-zstd-level-3-compression-native-abba-2026-11-20-storage-journal-lane);
  [storage-journal.md](lanes/storage-journal.md) log, 2026-11-20.

## Storage: blob I/O without a thread hop

commonware's tokio storage runs every blob `read_at` and `write_at` on a `spawn_blocking`
thread. zigware's production runtime calls the kernel inline (or through io_uring). Sampling
`/proc/pid/io` over whole freezer runs shows both sides issue about the same syscalls per
operation (about 2 reads per `get`, under 1 write per `put`), but each costs about 4 µs on
commonware against about 0.25 µs on zigware. So the freezer rows (`get` 0.03×, `put` 0.07×,
measured before the native ABBA method) measure blob dispatch, not the freezer.

The same pattern plausibly explains other storage rows that are faster at native ABBA, such as
`journal::append_sync` 0.09×, `journal::fixed_append` 0.26×, `buffer_paged::append` 0.46×,
`journal::variable_read_random` serial 0.21×, and `journal::variable_replay` 0.30×, but those
have not been profiled, so treat the attribution as a hypothesis. All storage rows ran on
tmpfs, where a syscall is cheap; on a real disk the dispatch cost is a smaller share.

- Evidence: [BENCHMARKS.md, freezer](BENCHMARKS.md#freezer-same-work-different-io-dispatch-2026-11-19-clearing-lane),
  [journal](BENCHMARKS.md#journal-every-bench-group-paired-rounds-2026-11-19-storage-journal-lane),
  [storage-merkle](BENCHMARKS.md#storage-merkle-bmt-rmap-variable-journal-native-abba-2026-11-20-storage-merkle-lane).

## Faster, cause not yet isolated

These rows are faster at native ABBA, but no lane has yet named a portable mechanism, so they
are not claimed as adoptable:

- `codec::lazy::get` (100k shared) 0.17× (README table).
- qmdb ([BENCHMARKS.md](BENCHMARKS.md#qmdb-every-bench-group-pinned-abba-2026-11-20-storage-qmdb-lane)):
  `init` any 0.46× and store 0.52×, `generate` keyless 0.51× and store 0.63×,
  `chained_growth` 0.71×. Eight qmdb rows are slower, including every `merkleize` (about 2×).
- archive `restart` and serial `get`, freezer and ordinal groups (clearing and storage-archive
  lanes), and Reed-Solomon encoders and decoders (coding lane, provisional).

## Not included

- The journal's zstd encoder changes (storage-journal, 2026-11-20): branch-free candidate
  selection and continued window indexes are what libzstd already does, and the raw-block and
  Huffman shortcuts are changes to libzstd's own code, not to commonware's.
- ChaCha20 (`seal_open`) and the `sake` handshake: zigware's wins there were against Zig's
  `std`, and commonware already runs aws-lc assembly and dalek's basepoint tables.
- The end-to-end flood throughput (1.87×): part of it is the sender running on its own thread,
  which is the [#5809](UPSTREAM_BUGS.md#flood-sender-starves-its-tokio-worker) fix rather than
  an optimization.
- Wins that come only from building for the native CPU, and fixes that brought zigware up to
  commonware (for example `Deferred`'s cached decode, which matches commonware's `Lazy`).
