# Lane: coding

Owns `src/coding`, `src/storage/bmt/`, and `src/cryptography/reed_solomon/` (taken over from the crypto lane;
add the `pub const reed_solomon` line to `src/cryptography/root.zig`, additive edit).

Reference: `~/.cache/zigware/commonware-ref/{coding,cryptography/src/reed_solomon}`. Coding
commits to shards with storage's bmt and merkle (storage-merkle lane) and cryptography's
hashers (on main).

## Public API (on main)
- `cryptography.reed_solomon`: `Encoder`/`Decoder` (`init(gpa, original_count,
  recovery_count, shard_bytes)`, `deinit(gpa)`, `add_original_shard`, `add_recovery_shard`,
  `encode`, `decode`, `decode_with_recovery`, `decode_with_plan`, `decode_with_recovery_plan`,
  `reset(gpa, ...)`, `supports`), results `EncoderResult` (`recovery(i)`, `recovery_iter()`),
  `DecoderResult`/`RecoveryDecoderResult` (`original(i)`, `original_iter()`, `recovery(i)`,
  `recovery_iter()`; call `deinit()` before the coder's next round), `Plan` (`init(gpa, k, m,
  original_indices, recovery_indices)`, `deinit`), `Error`, `InitError`, `SHARD_CHUNK_BYTES`.
  Advanced: `rate.{HighRate,LowRate,DefaultRate}(Engine)` with `Encoder`/`Decoder`,
  `EncoderWork`/`DecoderWork` reuse via `into_parts`, and `engine.{Naive,Scalar,Simd,DefaultEngine}`.
- `coding.Config` (`minimum_shards`, `extra_shards` as non-zero `u16`s; `total_shards()`,
  codec with `fixed_size` 4, `eql`, `order`) and `coding.assert_scheme(S)`, the comptime
  `Scheme` interface (see `src/coding/root.zig`).
- `coding.ReedSolomon(H)`: `Commitment` (= `H.Digest`), `Shard` (`reed_solomon.Chunk(D)`: `shard`,
  `index`, owned `proof`; codec cfg `ShardCfg{ config, maximum_data_bytes }`), `CheckedShard`
  (`CheckedChunk(H)`), `Error`, `ShardRef`, `max_shard_size(config, data)`,
  `encode(gpa, config, data, strategy) !Encoding(D)` (`commitment`, `shards`, `codeword`;
  `deinit(gpa)`), `check(config, *commitment, index, *shard, strategy)`, `check_many(gpa, config,
  *commitment, []ShardRef, out, strategy)`, `decode(gpa, config, *commitment, []CheckedShard,
  strategy) ![]u8` (caller frees). Strategies are `parallel` strategies; striping uses
  `try_run_batches`. `coding.fuzz` is the `coding/fuzz` reed_solomon target.
- `storage.bmt`: `Builder(H)` (`init(gpa, leaves)`, `add(gpa, *digest) u32`, `build(gpa)`,
  `deinit`), `Tree(D)` (`root()`, `proof(gpa, position, diag)`, `range_proof(gpa, start, end,
  diag)`, `multi_proof(gpa, positions, diag)`, `level(i)`, `deinit`), `Proof(D)` (`leaf_count`,
  owned `siblings`; `verify_element_inclusion(H, position, *leaf, *root, diag)`,
  `verify_multi_inclusion(H, gpa, []Element, *root, diag)`, `verify_range_inclusion(H, gpa,
  position, []D, *root, diag)`, `max_encode_size`, codec with cfg = max items, `clone`, `eql`,
  `deinit`), `Error`, `Diagnostic`, `max_levels`, `fuzz`.

## Decisions
- Errors carry no payload (Zig); names match commonware's `Error` variants.
- Rust drops results to reset the coder; here `result.deinit()` does it. Coders take an
  allocator; decoding allocates nothing (erasure scratch lives in `DecoderWork`).
- The engine is chosen at compile time (`DefaultEngine = Simd`, which is `Scalar` without AVX2
  or NEON)
  instead of runtime CPU detection;
  every engine produces identical bytes. The fused 16-shard AVX-512 derivative leaf is not
  ported (output is identical; it is a speedup).
- Tables live in static memory behind an atomic once-guard, not on the heap.
- `ChaCha8Rng` (`reed_solomon/test_util.zig`) matches `rand_chacha` 0.10 `from_seed`, so shard
  generation and every recovery-hash vector match commonware.
- `reed_solomon.fuzz` drives plans from `invariants.minifuzz.Unstructured` with commonware's
  search limits; the `std.testing.fuzz` targets skip input-rejection errors.

- bmt errors carry no payload; an optional `*bmt.Diagnostic` receives the position commonware's
  `InvalidPosition`/`DuplicatePosition`/`UnsortedPosition` carry. Tree levels live in one flat
  allocation. Positions, leaves, and elements are slices, not iterators, so the iterator-length
  tests (`Misreported`, read counts) have no counterpart; their error cases are ported.
- The bmt fuzz draws an operation tag then its fields from `Unstructured` instead of
  commonware's derived enum layout; the operations and asserted properties are the same.

- Coding shards and checked shards borrow their bytes (from the encoding's `codeword`, or from
  the decoded input) instead of holding a `Bytes` refcount; `Encoding.deinit` frees them.
- Commonware caches one encoder and decoder per thread; here each stripe task creates its own and
  reuses it across its tiles, so the cached-width test (`test_single_stripe_coding_caches_tile_
  width`) has no counterpart. `#[should_panic]` tests (invalid encode parameters, `max_shard_size`
  panics) are assertions and panics here and are not run; `encode_iobufs` is not ported (codec
  has no vectored writes).
- `check_many` writes results into a caller slice; `Explorer`/`explore` shapes are covered by
  running each striped test with `Sequential` and a 4-way `Rayon`.

## Backlog
- [x] reed_solomon: GF(2^16) arithmetic, naive and scalar engines, high/low/default rate
  encoders and decoders, wrappers, results, plans; every recovery-hash vector (slow ones under
  `-Dslow-tests`) and the rate, wrapper, result, and plan tests.
- [x] reed_solomon: port `fuzz.rs` (engine and rate differential fuzzing) as minifuzz searches
  plus `std.testing.fuzz` targets, with every fixed regression case.
- [x] reed_solomon: `@Vector` SIMD engine (`engine.Simd`: AVX2 `vpshufb` multiply kernel under the
  shared transforms), checked against `Scalar` and `Naive` and in the differential fuzz.
- [x] reed_solomon: an aarch64 NEON `tbl` kernel for `Simd` (each 128-bit lane shuffled
  alone), checked under qemu-aarch64 with the reed_solomon tests.
- [x] storage bmt (taken over from storage-merkle): Builder, Tree, single/range/multi proofs and
  verification, codec, every test, RootConformance and CodecConformance<Proof> hashes, and the
  `bmt_operations` fuzz (minifuzz + `std.testing.fuzz`).
- [x] storage bmt benches (`src/storage/bmt/benches.zig`): build, proof, range_proof,
  multi_proof, verify_single, verify_multi, verify_range.
- [x] coding: Config (codec, CodecConformance<Config> hash) and the Scheme interface.
- [x] coding: ReedSolomon scheme (striped encode with a BMT commitment, check, check_many,
  striped decode and reveal), Chunk codec, every lib.rs and reed_solomon.rs test except panic
  tests, pinned commitments and recovery output, CodecConformance<Chunk> hash, the
  unique-commitment and roundtrip minifuzz tests, and the coding/fuzz reed_solomon target.
- [x] coding benches (`src/coding/benches.zig`): `reed_solomon::encode`/`decode` with every
  shard selection and the extra decode cases, and `coding_scheme_sizes` as
  `reed_solomon size (shard)` reporting a `shard_bytes` metric.
- [x] reed_solomon benches (`src/cryptography/reed_solomon/benches.zig`): encoder, decoder,
  high/low rate encoders and decoders, and per-engine eval_poly, mul, fft, and ifft.
- [x] formatting (encode, decode, display) and codec (`codec::lazy::get`) benches, taken over
  from the closed codec lane.

## bmt test tally (2026-11-19, clearing lane)
Commonware's bmt has 66 tests (62 `#[test]`, 2 `#[rstest]`, 2 conformance entries): 64 ported
and 2 not portable (`range_proof_iterator_length` and
`multi_proof_stops_reading_at_first_invalid_position` read iterators; zigware takes slices).
None open. One sub-case could still be added: a multi-proof forged with leaf count
`maxInt(u32)` and an element at that position returns `InvalidPosition(maxInt)`.

## Log
- 2026-11-13: reed_solomon engines, rates, wrappers, results, plans, and test vectors.
- 2026-11-13: reed_solomon differential fuzzing (engine and rate plans, field oracle).
- 2026-11-13: storage bmt (proofs, codec, conformance, fuzz).
- 2026-11-13: coding Config with its conformance hash, and the Scheme interface.
- 2026-11-13: coding ReedSolomon scheme, tests, Chunk conformance hash, and fuzz target.
- 2026-11-13: reed_solomon Simd engine (AVX2 nibble-shuffle kernel), now the default.
- 2026-11-13: benches for coding, bmt, reed_solomon, formatting, and codec.
- 2026-11-13: reed_solomon NEON kernel for `Simd` on aarch64.
- 2026-11-19: bmt test tally against commonware (clearing lane): none open.

## Test audit (2026-11-19, against main)

Every commonware `#[test]` in this lane's crates (macro and rstest cases expanded where noted), matched by reading both sides: ported (a Zig test checks the behavior, often one consolidated test), open, or not portable with the reason. Written by the consensus-marshal lane; tick a box when its test lands.

### coding
| File | Tests | Ported | Open | Not portable |
| --- | --- | --- | --- | --- |
| lib.rs | 5 | 5 | 0 | 0 |
| reed_solomon.rs | 71 | 63 | 0 | 8 |
| Total | 76 | 68 | 0 | 8 |

Counts include tests generated by macros that the input list left out. lib.rs:387 has
`CodecConformance<Config>`. reed_solomon.rs has 3 rstest cases of
`test_recovery_output_format_pinned` (2421), 15 rstest cases of `test_commitment_pinned` (2543),
and `CodecConformance<Chunk<Sha256Digest>>` (3379). All of them are ported: in
config_test.zig, in striped_test.zig as "recovery output format pinned" and "commitments are
pinned (consensus format)", and in scheme_test.zig as "conformance CodecConformance<Chunk...>".

Open:
- None

Not portable:
- `reed_solomon.rs` `test_invalid_total`, `test_invalid_min`,
  `test_max_shard_size_unsupported_counts`, `test_max_shard_size_too_many_shards`,
  `test_max_shard_size_data_beyond_prefix`, `test_max_shard_size_shard_beyond_prefix`:
  `#[should_panic]`; these are assertions in Zig (docs/lanes/coding.md)
- `reed_solomon.rs` `test_single_stripe_coding_caches_tile_width`: checks thread-local cached
  coders; Zig creates a coder per stripe task (documented in coding.md)
- `reed_solomon.rs` `test_chunk_encode_iobufs_matches_encode`: `encode_iobufs` is not ported,
  because the codec has no vectored writes (documented in coding.md)

