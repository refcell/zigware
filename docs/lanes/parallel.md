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
  `spawn(len, &task)` / `block_on(&task)` with `parallel.Task(Op)` (`op.call()`),
  `parallelism()`. Optional op hooks: `discard(value)`, `deinit_state(*state)`.
  `Rayon.with_policy(&policy)` (with `var policy = parallel.Policy.init(io)`, shareable across
  strategies) makes every operation choose serial or parallel per call site, as commonware's
  default `Rayon` does; without it `Rayon` always runs the parallel shape.

- `parallel.mocks`: `pooled(gpa, io, workers, parallelism)`, `inlined(gpa, io, parallelism)`,
  `pending(gpa, io, workers)`, `Explorer.parallel(rayon)` / `Explorer.seeded(rayon, seed)`,
  and `explore(gpa, io, op{run(explorer)})`, which runs `op` under serial, parallel, and four
  seeded rules and fails with `error.ShapeDependentOutput` if any output differs.

- `bench`: add `src/<package>/benches.zig` exporting `pub fn run(runner: *bench.Runner) !void`;
  it may import its package, the package's deps, and `bench`. `zig build bench` measures it
  (ReleaseFast; `-Dbench-filter=...`, `COMMONWARE_BENCH_FULL=1`), `zig build test` runs every
  benchmark once on smoke inputs. `bench.Benchmark.init(prefix).with_param(k, v)`,
  `runner.inputs.pick(T, smoke, standard, full)`, `runner.run(benchmark, &workload)` with a
  workload of `iter(*W)` and optional `setup`/`before_iter`/`teardown`/`metrics`,
  `runner.allocator`, `runner.io`; `bench.criterion(io, &workload, iters)` (iter_custom),
  `Benchmark.metrics_json`, `bench.Inputs`, `bench.test_mode`.

- `allocator`: `var heap = allocator.Heap.init(io, config); heap.allocator()` gives a
  `std.mem.Allocator`; `heap.read_stats()` (`allocator.Stats`, commonware's fields),
  `heap.contains(ptr)`, `heap.collect()`, `heap.effective`, `heap.status`. `Config` (and
  `Config.default`), `Purge` (`.never`, `.after_ns`), `Reserve.init_pinned/init_unpinned`,
  `EagerCommit`, `good_size(len)`, the constants (`arena_slice_size`, `arena_chunk_size`,
  `large_object_limit`, `arena_max_object_size`), and `allocator.metrics.metrics` (name, help,
  kind, `read(stats)`) for runtime exporters.

## Decisions
- No rayon port: `ThreadPool` is a fork-join pool whose workers are `std.Io.Group.concurrent`
  tasks and whose waits are `std.Io` futexes, so the deterministic runtime can host it. The
  caller runs one job and takes back unstarted jobs; waiting callers help run queued jobs.
- Folds and maps split into `min(len, 64)` balanced chunks regardless of thread count, so a
  fold gives the same result on every pool size (and equals `Sequential` for lawful ops).
- `Rayon` planning parallelism defaults to workers + 1 (the caller helps). With parallelism 1
  every operation runs serially, like commonware's deterministic runtime pool.
- bench: no Criterion or Gungraun; `Runner` warms up by doubling, then takes 20 samples over
  ~1 s and prints min/median/max per iteration. Harnesses are discovered by file, so lanes add
  benches without editing build.zig. The Gungraun tracker binary (bench/src/bin) is not
  ported yet: it drives valgrind; its compare/report logic is next.
- `parallel.policy` ports policy.rs (entries, cadence, placement choice, spawn decisions) with
  its tests and numbers. A call site is a return address instead of `Location::caller()`, and
  the entry tables are bounded (256 run keys, 64 spawn keys); a key that finds its table full
  runs parallel or offloaded, untimed.
- Closures are `pub fn` methods on op values (Zig cannot see private decls across files).
- Sorts take Zig's `lessThan(ctx, a, b)` instead of an `Ordering` comparator. Parallel sorts
  sort runs in parallel and merge pairwise with a scratch buffer from the pool's allocator;
  without one they sort serially.
- `spawn` takes a caller-owned `Task(Op)` instead of returning a future, so it never
  allocates; every spawned task must be `block_on`'d before its pool is destroyed.
- Mocks: a seeded `Explorer` keys its choice by the call's return address (Zig has no
  `#[track_caller]`), so seeds repeat within one build. `pending`'s queued jobs run when
  `block_on` takes them back, since a Zig task must be awaited before it goes out of scope.
- allocator: no mimalloc (zero deps, no libc). `Heap` is a native allocator with mimalloc's
  layout: its size classes, shared pages up to `large_object_limit`, single-block pages above,
  arenas of 64 KiB slices with metadata in front, pinned and unpinned reservations, on-demand
  arenas, delayed purges (madvise) at collections, and pages above `arena_max_object_size`
  (or with alignment beyond a slice) mapped on their own. One lock guards a heap, so `Stats`
  are exact; the mimalloc-only knobs (large OS pages, THP, stats merge threshold) are recorded
  in `effective` but change nothing. A heap is a value, not the process allocator, so
  configuration is per heap rather than once per process.
- `parallel.topology` ports topology.rs's model: `Topology.detect(io)` (sysfs LLC lists, read
  through `std.Io`), `from_lists`, `group_width`, `partition`, `reservations`, and `CpuSet`,
  bounded by `cpus_max` (1024), `domains_max` (256), and `list_len_max` (256). zigware's pool
  is one group, so group leases, homing, and affinity writes (`sched_setaffinity`) are not
  ported; a grouped pool will build on this model.
- Adaptive spawn: every spawner counts as `outside` (pool workers are `std.Io` tasks with no
  identity to record), and a measured offloaded job reports its job and round-trip times when
  `block_on` takes its result, since every Zig task is awaited. Descendant placement is not
  chosen: the pool is one group.
- Fallible ops return the first error in chunk order (commonware allows any).
- `run_tiles` plans at most 64 workers (one pool job each); `Tiles.fill_collect` returns an
  allocated slice and `OutOfMemory` if a worker's result list cannot grow.

## Backlog
- [x] parallel: the `Strategy` interface (fold, map, join) with `Sequential` and a
  thread-pool strategy, matching lib.rs semantics and tests. Implement a small
  work-stealing pool on std threads and `std.Io` instead of porting rayon line by line;
  results must not depend on the number of threads.
- [x] parallel: `run_tiles` (`Grid`, `Tiles`, `Shares` claim/steal) with its tests.
- [x] parallel: `spawn`/`block_on` over the pool.
- [x] parallel mocks.rs (Explorer, explore, pooled, inlined, pending) with its tests.
- [x] parallel policy.rs and topology.rs: the adaptive policy and the topology model.
- [x] parallel: let `Rayon` consult a `Policy` (opt-in `with_policy`), timing runs.
- [x] parallel: adaptive spawn (inline vs offload) through the policy's spawn decisions.
- [x] allocator: an allocator wrapper with commonware's metrics and purge/reserve
  configuration; no mimalloc (zero deps).
- [x] bench: the benchmark workload abstraction (lib.rs) and `zig build bench`.
- [ ] bench: the tracker binary's config, results comparison, and report rendering
  (bench/src/bin) over `zig build bench` output.
- [ ] Fuzz targets and benches.

## Log
- 2026-11-16: adaptive spawn: `Rayon.with_policy` inlines or offloads per call site.
- 2026-11-13: `Rayon.with_policy`: operations adapt once at their outermost call (keyed by
  return address, length bucket, work bucket), meter pool-job busy time, record only successes.
- 2026-11-13: parallel topology model (LLC detection, group width, partition, reservations).
- 2026-11-13: parallel policy (adaptive serial/parallel and inline/offload decisions) with
  ported policy.rs tests.
- 2026-11-13: allocator `Heap` (mimalloc layout, reserve/purge config, Stats, metrics) with
  ported config/size-class/heap tests, a threaded stress test, and seeded and std fuzz.
- 2026-11-13: bench package and `zig build bench` (auto-discovered benches.zig), parallel
  benches; every-op-on-every-strategy test.
- 2026-11-13: mocks (Explorer, explore, pooled, inlined, pending) with ported tests.
- 2026-11-13: spawn/block_on with caller-owned Task over the pool.
- 2026-11-13: run_tiles (Grid, Tiles, Shares claim/steal) with ported tile tests.
- 2026-11-13: Strategy interface (Sequential, Rayon over a std.Io fork-join pool), batches,
  parallel sorts, ported lib.rs tests.
