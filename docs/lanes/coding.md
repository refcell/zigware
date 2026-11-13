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
  `EncoderWork`/`DecoderWork` reuse via `into_parts`, and `engine.{Naive,Scalar,DefaultEngine}`.
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
- The engine is chosen at compile time (`DefaultEngine = Scalar`) instead of CPU detection;
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

## Backlog
- [ ] storage bmt (moved from storage-merkle): the whole of commonware's storage/src/bmt
  (Builder, root, proofs, multi-proofs, range proofs, codec, conformance, fuzz) at
  `src/storage/bmt/`, with `pub const bmt` in `src/storage/root.zig` (additive edit).
- [x] reed_solomon: GF(2^16) arithmetic, naive and scalar engines, high/low/default rate
  encoders and decoders, wrappers, results, plans; every recovery-hash vector (slow ones under
  `-Dslow-tests`) and the rate, wrapper, result, and plan tests.
- [x] reed_solomon: port `fuzz.rs` (engine and rate differential fuzzing) as minifuzz searches
  plus `std.testing.fuzz` targets, with every fixed regression case.
- [ ] reed_solomon: `@Vector` SIMD engine, checked against `Naive`.
- [x] storage bmt (taken over from storage-merkle): Builder, Tree, single/range/multi proofs and
  verification, codec, every test, RootConformance and CodecConformance<Proof> hashes, and the
  `bmt_operations` fuzz (minifuzz + `std.testing.fuzz`).
- [ ] storage bmt benches once `zig build bench` exists.
- [ ] coding: the Scheme interface, reed_solomon scheme (encode into shards with a BMT
  commitment, check, reshard, decode from any k shards), shard selection, codec encodings
  identical to commonware's. Port lib.rs and reed_solomon.rs tests.
- [ ] Fuzz targets (commonware coding/fuzz) and conformance hashes.

## Log
- 2026-11-13: reed_solomon engines, rates, wrappers, results, plans, and test vectors.
- 2026-11-13: reed_solomon differential fuzzing (engine and rate plans, field oracle).
- 2026-11-13: storage bmt (proofs, codec, conformance, fuzz).
