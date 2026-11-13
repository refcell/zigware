# Lane: utils

Owns `src/utils` (parallel, allocator, and bench moved to the parallel lane).

Reference: `~/.cache/zigware/commonware-ref/{utils,parallel,allocator,bench}`.
`utils` depends on codec; until codec lands, start with the codec-free modules and build the
encoding parts as soon as `codec` has its core API (see docs/lanes/codec.md).

## Public API (on main)
- `utils.faults`: `N3f1`, `N5f1` (`max_faults`, `quorum`, `m_quorum`, `l_quorum`; any int `n`).
- `utils.rng`: `TestRng` (byte-identical to commonware's `TestRng`, i.e. Rust `rand` 0.10
  `StdRng::seed_from_u64`), `ScriptedRng`, `FuzzRng`, `mix64`, and `rand`-identical samplers
  `range_at_most`, `range_less_than`, `boolean`, `bernoulli`, `ratio`, `float64`;
  `random(&rng)` adapts any generator to `std.Random`. Generators are borrowed-slice, no alloc.
- `utils.rng.Uniform(T)`: `rand`'s precomputed `Uniform<T>` (Lemire), distinct from the
  one-shot `range_*` samplers.
- `utils.range`: `Bound(T)`, `contains_cyclic`, `NonEmptyRange(T)` (codec encoding).
- `utils.time`: `Duration` (Rust `Duration` semantics, `parse`, `from_nanos_saturating`,
  `as_millis_u64`), `SystemTime` (`epoch`, `epoch_millis`, `add_jittered`, `limit`,
  `saturating_add`, `from_timestamp(std.Io.Timestamp)`), `sample_duration` (rand-identical).
- `utils.sequence`: `FixedBytes(N)` (`init`, comptime `from_hex`, `zeroize`), `U32`, `U64`,
  `PrefixedU64` (`prefix`, `value`), `VecU64`, `Unit`; all with codec encodings, `order`,
  `eql`, `as_slice`, `{f}` formatting. `utils.Array(T)`/`utils.Span(T)` are comptime checks.
- `utils.bitmap`: `BitMap(N)` (alias `utils.BitMap`, `DefaultBitMap` = 8-byte chunks):
  allocator-explicit `push`/`pop`/`truncate`/`extend_from_bitmap`/`push_chunk`/`prune_chunks`,
  `get`/`set`/`flip`/`set_all`/`flip_all`, `and`/`or`/`xor`, `count_ones`, `is_unset`,
  `iter`, `ones_iter`/`ones_iter_from`/`ones_iter_range`, codec (`Cfg = RangeCfg(u64)`), `{f}`.
  `bitmap.Prunable(N)`: absolute positions over pruned leading chunks (`init_pruned`,
  `prune_to_bit`, `unprune_chunks`, `set_chunk_by_index`, `get_bit`/`set_bit`, `ones_iter_*`,
  codec: pruned count `u64` + `BitMap`, `Cfg` bounds the retained bits).
  `bitmap.historical.BitMap(N)`: a `Prunable` plus reverse diffs per commit (`into_dirty` ->
  `Dirty` with read-through `get_bit`/`get_chunk`, `set_bit`, `push*`, `pop`, `prune_to_bit`;
  `commit(gpa, n)` / `abort`; `apply_batch`, `get_at_commit`, `prune_commits_before`). A failed
  `commit` leaves the `Dirty` unchanged (Rust consumes it).
  `bitmap.readable` is the `Readable` trait (`len`, `pruned_chunks`, `get_chunk`) + `OnesIter`.
- `utils.Hostname` (`utils.hostname`): validated RFC 1035/1123 hostname stored inline
  (`init`, `literal`, `as_str`, `eql`, `order`, `{f}`, `len_max`, `label_len_max`,
  `max_encode_size` = 258), codec as a `RangeCfg(..=253)` byte string; `hostname.Error`.
- `utils.net`: `is_global` (`is_global_v4`/`is_global_v6`), `subnet(ip, SubnetMask)`,
  `Subnet`, `SubnetMask.init(v4_bits, v6_bits)`, `to_ipv4_mapped`, over codec's `IpAddr`.
- `utils.ordered`: `Set(T)`, `Map(K, V)`, `BiMap(K, V)` (sorted, deduplicated; `init` fails
  with `DuplicateKey`/`DuplicateValue`, `from_dedup` drops duplicates; `get`, `position`,
  `as_slice`, `get_value`, `get_key`, `iter_pairs`, `map_values`, `map_values_into`,
  `from_parts`, `truncate`, `{f}`). `Set` has the `Quorum` helpers `quorum(M)`,
  `max_faults(M)`, `key(Participant)`, `index(item) ?Participant`. Codec: `Set` = `Vec<T>`
  (decode rejects unsorted/duplicate), `Map` = keys then values, `Cfg` = `{ range, key, value }`.
  Items order by their `order(a, b)` decl, else `codec.order`. Collections own their items:
  constructors take ownership (releasing on error); `deinit` releases.
- `utils.rng.ChaChaRng(rounds)`, `ChaCha8Rng` (Rust `rand_chacha` 0.10).
- `utils`: `modulo`, `union`, `union_unique`, `Participant`, `NonZero(T)`/`nz`, `GOLDEN_RATIO`,
  `MAX_ALLOCATION_BYTES`.

## Decisions
- RNG interface is `next_u32`/`next_u64`/`fill_bytes`; ports that draw randomness use the
  samplers in `utils.rng` (not `std.Random`) so values match commonware's tests.
- `union_unique`, `Participant` (`UInt<u32>`), and `NonEmptyRange(T)` (start, end; rejects
  `start >= end` as `Invalid`) encode through `codec`. Their conformance hashes need codec's
  `arbitrary` emulation; they are checked in `conformance_test.zig`.
- Conformance: `src/utils/conformance_test.zig` checks every utils/conformance.toml entry
  (copied unchanged next to it) through the shared `conformance.verify` harness with
  `codec.arbitrary` generators; each type's Rust `Arbitrary` derive is a small generator there.
- `src/utils/fuzz.zig` is the utils fuzz driver: a body over `*FuzzRng`, run seeded in
  `zig build test` and under `std.testing.fuzz`.

## Backlog
- [ ] utils basics (done: faults, modulo, union/union_unique, NZ, Participant, rng, range
  without codec; time; remaining: iter, vec, rational, probability, sampling; hostname and net done): `Span`/`Array` traits as comptime interfaces, `union_unique`, `hex`
  re-exports, `modulo`, `NZ*` non-zero helpers, quorum math (`quorum`, `max_faults`),
  `time.rs`, `range.rs`, `iter.rs`, `vec.rs` (NonEmptyVec), `rational`, `probability`,
  `sampling`, `rng.rs` (deterministic test RNG matching commonware's where tests depend on it).
- [x] utils sequence: fixed_bytes, u32, u64, prefixed_u64, vec_u64, unit — with codec.
- [ ] utils bitmap (done: BitMap, Prunable, historical; next:
  roaring): BitMap, prunable, historical, roaring; codec encodings identical.
- [x] utils ordered (Set/Map/BiMap/Quorum) with conformance hashes.
- [ ] utils priority_set, cache (LRU etc.), acknowledgement,
  channel (bounded mpsc, ring, reservation, tracked; keep broadcast-resolver's oneshot.zig) — channels over `std.Io` primitives.
- [ ] Fuzz targets for every decoder (commonware utils/fuzz).

## Log
- 2026-11-13: faults, rng (TestRng/ScriptedRng/FuzzRng + FuzzRng conformance hash), range,
  lib basics.
- 2026-11-13: switched union_unique to codec; Participant and NonEmptyRange codec encodings.
- 2026-11-13: time (Duration, SystemTime, parse, rand-identical jitter) with seeded and
  std.testing.fuzz targets; rng.Uniform.
- 2026-11-13: sequence (FixedBytes, U32, U64, PrefixedU64, VecU64, Unit) with conformance
  hashes; Participant and NonEmptyRange conformance hashes; ChaCha8Rng; utils fuzz driver.
- 2026-11-13: moved utils conformance onto the shared harness (conformance + codec.arbitrary).
- 2026-11-13: BitMap with all mod.rs tests, conformance hash, and a model-based fuzz target.
- 2026-11-13: Hostname (conformance hash) and net is_global/subnet, for p2p.
- 2026-11-13: Prunable bitmap with its tests, conformance hash, and fuzz target.
- 2026-11-13: ordered Set/Map/BiMap/Quorum with tests, conformance hashes, and a set fuzz.
- 2026-11-13: historical bitmap with its tests, randomized checkpoints, and fuzz target.
