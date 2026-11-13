# Lane: parallel

Owns `src/parallel`, `src/allocator`, `src/bench` (split off the utils lane by the
coordinator; utils keeps `src/utils`).

Reference: `~/.cache/zigware/commonware-ref/{parallel,allocator,bench}`. math, cryptography,
and storage call `Strategy` folds (`hash_many`, MSM, batch verification) and pass `{}` as a
placeholder until this lands, so land `Strategy` first and tell the coordinator its API.

## Public API (on main)
- `parallel.Sequential` / `parallel.sequential`, `parallel.Rayon` (over `parallel.ThreadPool`,
  created with `ThreadPool.create(gpa, io, .{ .threads = n })`, `Rayon.init(pool)`,
  `.with_parallelism(n)`). Algorithms take `strategy: anytype`; `assert_strategy(S)` checks.
- Operations (ops are structs with `pub fn` methods standing in for closures; inputs are
  slices, items are element pointers, or `parallel.Range`, items are `usize`):
  `run(len, op{serial,parallel})`, `try_run`, `fold(items, op{identity,fold,reduce})`,
  `fold_init(items, op{init,identity,fold(acc,*state,item),reduce})`, `try_fold`,
  `map_into(items, out, op{map})` (no alloc), `map_collect(gpa, items, op)`,
  `map_init_into`/`map_init_collect`, `try_map_into`/`try_map_collect`,
  `map_collect_with_multiplier`, `map_partition_collect(gpa, items, op{map -> {K, ?U}})`,
  `join(a{call}, b{call})`, `sort_by(T, items, ctx, lessThan)`, `sort_unstable_by`,
  `run_batches(len, min_batch_len, multiplier, op{run(batches)})`, `try_run_batches`,
  `run_tiles(len, grids, multiplier, op{run(tiles)})` with `parallel.Grid{rows, tile_cost}`
  and `tiles.fill_collect(gpa, op{init, fill(*state, row, columns), finish(*state, row)})`,
  `parallelism()`. Optional op hooks: `discard(value)`, `deinit_state(*state)`.

## Decisions
- No rayon port: `ThreadPool` is a fork-join pool whose workers are `std.Io.Group.concurrent`
  tasks and whose waits are `std.Io` futexes, so the deterministic runtime can host it. The
  caller runs one job and takes back unstarted jobs; waiting callers help run queued jobs.
- Folds and maps split into `min(len, 64)` balanced chunks regardless of thread count, so a
  fold gives the same result on every pool size (and equals `Sequential` for lawful ops).
- `Rayon` planning parallelism defaults to workers + 1 (the caller helps). With parallelism 1
  every operation runs serially, like commonware's deterministic runtime pool.
- No adaptive policy yet: `Rayon` behaves like commonware's `Rayon::without_policy`.
- Closures are `pub fn` methods on op values (Zig cannot see private decls across files).
- Sorts take Zig's `lessThan(ctx, a, b)` instead of an `Ordering` comparator. Parallel sorts
  sort runs in parallel and merge pairwise with a scratch buffer from the pool's allocator;
  without one they sort serially.
- Fallible ops return the first error in chunk order (commonware allows any).
- `run_tiles` plans at most 64 workers (one pool job each); `Tiles.fill_collect` returns an
  allocated slice and `OutOfMemory` if a worker's result list cannot grow.

## Backlog
- [x] parallel: the `Strategy` interface (fold, map, join) with `Sequential` and a
  thread-pool strategy, matching lib.rs semantics and tests. Implement a small
  work-stealing pool on std threads and `std.Io` instead of porting rayon line by line;
  results must not depend on the number of threads.
- [x] parallel: `run_tiles` (`Grid`, `Tiles`, `Shares` claim/steal) with its tests.
- [ ] parallel: `spawn`/`block_on` over the pool.
- [ ] parallel policy.rs and topology.rs (CPU topology, pinning policy), mocks.rs.
- [ ] allocator: an allocator wrapper with commonware's metrics and purge/reserve
  configuration; no mimalloc (zero deps).
- [ ] bench: the benchmark workload abstraction (lib.rs) and its runner/report binary
  (bench/src/bin) as `zig build bench`.
- [ ] Fuzz targets and benches.

## Log
- 2026-11-13: run_tiles (Grid, Tiles, Shares claim/steal) with ported tile tests.
- 2026-11-13: Strategy interface (Sequential, Rayon over a std.Io fork-join pool), batches,
  parallel sorts, ported lib.rs tests.
