# Lane: utils

Owns `src/utils`, `src/parallel`, `src/allocator`, `src/bench`.

Reference: `~/.cache/zigware/commonware-ref/{utils,parallel,allocator,bench}`.
`utils` depends on codec; until codec lands, start with the codec-free modules and build the
encoding parts as soon as `codec` has its core API (see docs/lanes/codec.md).

## Backlog
- [ ] utils basics: `Span`/`Array` traits as comptime interfaces, `union_unique`, `hex`
  re-exports, `modulo`, `NZ*` non-zero helpers, quorum math (`quorum`, `max_faults`),
  `time.rs`, `range.rs`, `iter.rs`, `vec.rs` (NonEmptyVec), `rational`, `probability`,
  `sampling`, `rng.rs` (deterministic test RNG matching commonware's where tests depend on it).
- [ ] utils sequence: fixed_bytes, u32, u64, prefixed_u64, vec_u64, unit — with codec.
- [ ] utils bitmap: BitMap, prunable, historical, roaring; codec encodings identical.
- [ ] utils ordered (Set/Map/Quorum), priority_set, cache (LRU etc.), acknowledgement,
  channel (bounded mpsc, ring, reservation, tracked) — channels over `std.Io` primitives.
- [ ] parallel: `Strategy` (sequential and thread-pool fold), policy, topology. Implement a
  small work-stealing pool on std threads instead of porting rayon line by line.
- [ ] allocator: Zig equivalent of the crate's purpose (an allocator wrapper with metrics
  and purge/reserve config); no mimalloc (zero deps).
- [ ] bench: benchmark workload abstraction used by other packages' benches.
- [ ] Fuzz targets for every decoder (commonware utils/fuzz).

## Log
