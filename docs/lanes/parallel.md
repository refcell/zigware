# Lane: parallel

Owns `src/parallel`, `src/allocator`, `src/bench` (split off the utils lane by the
coordinator; utils keeps `src/utils`).

Reference: `~/.cache/zigware/commonware-ref/{parallel,allocator,bench}`. math, cryptography,
and storage call `Strategy` folds (`hash_many`, MSM, batch verification) and pass `{}` as a
placeholder until this lands, so land `Strategy` first and tell the coordinator its API.

## Backlog
- [ ] parallel: the `Strategy` interface (fold, map, join) with `Sequential` and a
  thread-pool strategy, matching lib.rs semantics and tests. Implement a small
  work-stealing pool on std threads and `std.Io` instead of porting rayon line by line;
  results must not depend on the number of threads.
- [ ] parallel policy.rs and topology.rs (CPU topology, pinning policy), mocks.rs.
- [ ] allocator: an allocator wrapper with commonware's metrics and purge/reserve
  configuration; no mimalloc (zero deps).
- [ ] bench: the benchmark workload abstraction (lib.rs) and its runner/report binary
  (bench/src/bin) as `zig build bench`.
- [ ] Fuzz targets and benches.

## Log
