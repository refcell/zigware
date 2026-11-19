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
- `bench.tracker`: `load_config`, `parse_lines`/`custom_metrics` (Gungraun summaries and
  `metrics_json` lines), `compare`, `load_baseline(dir, path)`, `write_outputs(dir, ...)`
  (`current.toml`, `comparison.toml`, `comment.md`, `summary.toml`), `render_report`.

- `allocator`: `var heap = allocator.Heap.init(io, config); heap.allocator()` gives a
  `std.mem.Allocator`; `heap.read_stats()` (`allocator.Stats`, commonware's fields),
  `heap.contains(ptr)`, `heap.collect()`, `heap.effective`, `heap.status`. `Config` (and
  `Config.default`), `Purge` (`.never`, `.after_ns`), `Reserve.init_pinned/init_unpinned`,
  `EagerCommit`, `good_size(len)`, the constants (`arena_slice_size`, `arena_chunk_size`,
  `large_object_limit`, `arena_max_object_size`, `metadata_group_size`), and `allocator.metrics.metrics` (name, help,
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
  benches without editing build.zig. The tracker binary's logic (config, output parsing,
  comparison, output files, report) is `bench.tracker`; its runner is not ported: it runs
  `cargo bench` under Gungraun and valgrind, requires one callgrind summary per benchmark,
  and its default gates read callgrind metrics, so a zigware runner could gate only custom
  metrics and would have no tracking config to run.
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
  (or with alignment beyond a slice) mapped on their own; alignments of a whole
  `metadata_group_size` (256 MiB) are refused, and `Stats.arenas` excludes pages mapped on
  their own, as in mimalloc. Commonware's allocator integration tests are ported except the
  huge-page-advice ones, which read Linux smaps for mimalloc's THP advice. One lock guards a heap, so `Stats`
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
- bench tracker: commonware reads TOML with the `toml` crate; `bench.tracker.toml` is a small
  iterative TOML subset (no multi-line strings or dates) bounded by `depth_max`. Config
  errors keep commonware's messages (`unknown field`, `must be a non-empty array`, ...).
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
- [x] bench: the tracker's config, output-line parsing, results comparison, output files, and
  report rendering (bench/src/bin), with commonware's tracker tests and fixtures.
- [x] bench: the tracker's runner: not ported (see Decisions; it drives cargo, Gungraun, and
  valgrind).
- [x] allocator: commonware's integration tests (allocator/tests), except huge-page advice.
- [x] Fuzz targets and benches: commonware has no fuzz targets or benches for parallel,
  allocator, or bench; zigware adds seeded and std fuzz (heap, tracker parsers) and parallel
  benches.

## Log
- 2026-11-19: adaptive call sites keyed by `noinline` entry points (release builds merged
  them), measured tests on a virtual `TestClock`; upstream drift to a9ffc25f3 ported
  (fold_plan_tests.zig).
- 2026-11-19: reviewed the 216 not-portable tests; ported the 15 that test API promises
  (pool_api_tests.zig). The pool needed no changes.
- 2026-11-19: the audit's open tests: rayon join/sort/meter/spawn, the adaptive Rayon's
  policy use (adaptive_tests.zig), and policy.rs's spawn-placement, confined, interleaved, and
  worker-spawn tests (policy_late_tests.zig). No open tests remain.
- 2026-11-16: allocator integration tests (arena object limit, configured options, default
  config, cross-thread stats); refuse metadata-group alignments; `Stats.arenas` excludes
  pages mapped on their own. Backlog done.
- 2026-11-16: bench tracker results, comparison, output files, and report, with the ported
  tracker tests, Gungraun fixtures, and seeded and std fuzz of its parsers.
- 2026-11-16: bench tracker config (`bench.tracker.load_config`) over a TOML subset, with
  commonware's config tests and its tracking config as a fixture.
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

## Test audit (2026-11-19, against main)

Every commonware `#[test]` in this lane's crates (macro and rstest cases expanded where noted), matched by reading both sides: ported (a Zig test checks the behavior, often one consolidated test), open, or not portable with the reason. Written by the consensus-marshal lane; tick a box when its test lands.

### parallel (lib.rs, mocks.rs, policy.rs, topology.rs)
| File | Tests | Ported | Open | Not portable |
| --- | --- | --- | --- | --- |
| lib.rs | 106 | 60 | 0 | 46 |
| mocks.rs | 12 | 9 | 0 | 3 |
| policy.rs | 83 | 83 | 0 | 0 |
| topology.rs | 35 | 7 | 0 | 28 |
| Total | 236 | 159 | 0 | 77 |

Open:
- [x] `lib.rs:3790` `spawn_inlines_a_sub_overhead_job`: adaptive spawn honors an inline decision
  (runs on caller)
- [x] `lib.rs:3833` `spawn_keeps_offloading_big_jobs`: adaptive spawn of a 2ms job always runs on
  the pool
- [x] `lib.rs:3885` `measured_run_records_busy_time_of_all_items`: map busy time is the sum of item
  times
- [x] `lib.rs:3894` `measured_join_excludes_idle_waits`: join is charged both sides' work, not the
  joiner's wait
- [x] `lib.rs:3928` `measured_run_excludes_queueing`: busy time excludes the time queued behind busy
  workers
- [x] `lib.rs:4520` `run_batches_runs_serial_decision_on_calling_thread`: serial policy decision
  gives one whole batch
- [x] `lib.rs:4669` `run_batches_records_only_complete_success`: mapping or assembly errors record
  no samples
- [x] `lib.rs:4697` `run_batches_keeps_one_policy_decision_and_fixed_execution`: one run_batches
  makes one policy entry
- [x] `lib.rs:5043` `adaptive_policy_records_all_adaptive_operations`: each of 12 operations makes
  its own entry
- [x] `lib.rs:5095` `adaptive_policy_buckets_by_input_size`: map lens 1, 2, 3 make two entries
- [x] `lib.rs:5106` `adaptive_policy_buckets_by_work_multiplier`: multipliers 1, 2, 3 make two
  entries
- [x] `lib.rs:5117` `adaptive_run_buckets_by_input_size`: run lens 1, 2, 3 make two entries
- [x] `lib.rs:5162` `adaptive_policy_keys_default_methods_by_external_callsite`: fold and
  run_batches key by the caller
- [x] `lib.rs:5175` `adaptive_policy_keys_partition_map_by_external_callsite`: map_partition keys by
  the caller
- [x] `lib.rs:5189` `join_shares_policy_entry_per_callsite`: repeated joins at one site share one
  entry
- [x] `policy.rs:2140` `spawn_placement_recovers_cold_loser`: a cold Wide seed regains the lead at
  its probe
- [x] `policy.rs:2165` `spawn_placement_recovers_after_spike`: one slow Wide sample's lead loss is
  undone
- [x] `policy.rs:2210` `spawn_placement_slow_probe_stays_damped`: a slow probe blends and keeps
  normal backoff
- [x] `policy.rs:2234` `spawn_placement_reverts_lucky_probe`: a lucky Wide probe loses the lead
  within two samples
- [x] `policy.rs:2274` `spawn_round_trip_skips_placement`: a round trip alone seeds no placement
- [x] `policy.rs:2309` `spawn_overflow_leaves_seeds_untouched`: overflow roots don't advance
  placement seeds
- [x] `policy.rs:2487` `choice_local_seed_keeps_serial_due`: seeds Wide, Local, probe, then serial
  seed
- [x] `policy.rs:2518` `confined_seed_preserves_cadence_after_serial`: a late Wide seed sets no
  immediate boundary
- [x] `policy.rs:2550` `confined_wide_leaves_local_seed_due`: a confined Wide caller leaves the
  Local seed due
- [x] `policy.rs:2600` `choice_parallel_estimate_tracks_preferred_placement`: parallel estimate is
  the preferred placement's
- [x] `policy.rs:2668` `busy_budget_ignores_strategy_parallelism`: the serial budget uses busy time
  at parallelism 64
- [x] `policy.rs:2706` `local_busy_time_tracks_recent_runs`: cheaper Local runs lower busy time and
  allow serial
- [x] `policy.rs:2892` `confined_calls_compare_own_placement`: a confined caller races serial
  against its placement
- [x] `policy.rs:2940` `interleaved_callers_choose_fastest_paths`: mixed callers on one entry each
  get their best
- [x] `policy.rs:2990` `confined_calls_rediscover_faster_placement`: confined probes find a
  placement now faster
- [x] `policy.rs:3009` `confined_calls_notice_serial_slowdown`: a confined caller moves off serial
  when it slows
- [x] `policy.rs:3028` `confined_calls_probe_while_serial_wins`: confined probes find their
  placement beats serial
- [x] `policy.rs:3069` `choice_rediscovers_placement_while_serial_wins`: the choice finds a faster
  stale placement
- [x] `policy.rs:3113` `choice_caps_probes_while_serial_wins`: each losing placement is probed once
  per capped interval
- [x] `policy.rs:3151` `choice_ignores_ineligible_serial_when_pacing`: an over-budget serial doesn't
  stretch probe pacing
- [x] `policy.rs:3193` `confined_calls_keep_big_work_parallel`: an over-budget confined placement
  never samples serial
- [x] `policy.rs:3226` `confined_calls_pay_only_own_probes`: a confined caller pays only its own
  cadence's probes
- [x] `policy.rs:3269` `confined_calls_leave_choice_untouched`: Local-only samples leave Wide's seed
  due
- [x] `policy.rs:3322` `interleaved_callers_keep_independent_cadences`: interleaved populations
  decide as if alone
- [x] `policy.rs:3379` `confined_local_samples_update_shared_choice`: confined Local samples move
  the choice to Wide
- [x] `policy.rs:3416` `choice_advances_run_cadence_once`: a choice caller advances the run cadence
  once per call
- [x] `policy.rs:3467` `interleaved_callers_refresh_local_estimate`: the Local estimate follows a
  slowdown under any rhythm
- [x] `policy.rs:3546` `interleaved_callers_rediscover_faster_local_placement`: the choice caller's
  probes return to Local
- [x] `policy.rs:3605` `confined_races_back_off_until_flip`: a close race backs off, then resets on
  a flip
- [x] `policy.rs:3667` `confined_flips_reset_confirmations_between_boundaries`: flips between
  boundaries reset to the base
- [x] `policy.rs:3718` `confined_noisy_races_rediscover_stale_placement`: stale Wide overtakes
  serial at the derived call
- [x] `policy.rs:3835` `spawn_workers_preserve_outside_inline_preference`: worker spawns keep
  outside callers inlining
- [x] `policy.rs:3866` `spawn_workers_learn_inline_preference`: a worker-only site settles inline
- [x] `policy.rs:3890` `spawn_populations_keep_independent_cadences`: worker and outside spawns keep
  separate cadences

Not portable:
- `lib.rs` `forced_parallel_uses_idle_group`, `local_calls_home_group`,
  `nested_calls_record_current_placement`, `unhomed_calls_compare_remote_group`,
  `single_group_places_outside_calls`, `local_nested_calls_stay_on_group`, `wide_nested_calls_span_groups`,
  `sort_inherits_worker_placement`, `local_calls_use_only_group_workers`,
  `spawn_inline_leaves_groups_untouched`,
  `sort_leases_only_its_group`, `join_seeds_wide_then_home_group`,
  `root_keeps_claim_on_execution_group`,
  `root_uses_learned_descendant_width`, `narrow_root_runs_wide_unrecorded`,
  `spawn_inherits_worker_placement`, `spawn_dropped_future_keeps_claims`,
  `spawn_detached_local_keeps_group_busy`, `spawn_detached_wide_keeps_groups_busy`,
  `wide_calls_wake_all_groups`, `spawn_overflow_leaves_placement_untouched`,
  `spawn_moved_future_helps_grouped_workers`, `placed_runs_plan_placement_width`: grouped pools,
  leases, homing, and descendant placement are not ported (lane Decisions: the pool is one group)
- `lib.rs` `single_group_calls_use_pool_workers`: zigware's caller runs one job and helps while it
  waits (lane Decisions), so items do run on the caller
- `lib.rs` `rayon_spawn_propagates_job_panic`, `sequential_spawn_propagates_job_panic`:
  #[should_panic]
- `lib.rs` `spawn_panic_records_nothing`, `panicking_spawns_are_charged_before_they_propagate`:
  panicking jobs caught with catch_unwind
- `lib.rs` `spawn_worker_records_separate_overhead`: every zigware spawner counts as outside; pool
  workers have no identity (lane Decisions)
- `lib.rs` `spawns_awaited_outside_the_pool_are_charged_once`,
  `spawns_awaited_on_a_worker_are_charged_once`,
  `worker_spawns_awaited_outside_the_pool_are_charged_at_most_once`,
  `enclosing_runs_are_charged_for_spawns_of_nested_runs`,
  `fan_out_outside_the_pool_is_charged_for_its_parks`, `measured_run_includes_nested_runs`,
  `block_on_on_a_worker_is_charged_the_job`,
  `block_on_on_a_worker_is_charged_another_strategy_s_job`: rayon per-thread busy accounting of
  awaited and nested work (TestClock, install on a worker); zigware charges a `run` body its wall
  time (rayon.zig)
- `lib.rs` `runs_outside_the_pool_poll_spawns_without_blocking`,
  `block_on_outside_the_pool_charges_the_job_not_the_wait`,
  `block_on_outside_the_pool_charges_the_future_s_own_work`,
  `block_on_outside_the_pool_sums_jobs_and_nested_runs`, `inline_spawns_while_waiting_are_charged`,
  `nested_block_on_keeps_the_outer_wake`, `spawn_future_moved_from_outside_to_worker_keeps_helping`,
  `spawn_driven_inline_on_member_thread`: polling, moving, or block_on of arbitrary futures;
  zigware's spawn takes a caller-owned Task, not a future (lane Decisions)
- `lib.rs` `new_keeps_builder_settings`: rayon builder and worker features (install_in,
  thread names, start handler, use_current_thread, yield_now)
- `mocks.rs` `pending_rejects_single_worker`,
  `parallel_explorer_refuses_to_inline_a_handed_off_job`: #[should_panic]
- `mocks.rs` `explore_drops_its_pool_on_return`: Arc weak-pointer drop check
- `topology.rs` `build_accounts_for_all_workers`, `local_homes_and_reuses_idle_group`,
  `local_keeps_home_after_work_finishes`, `fixed_homes_never_move`, `local_homes_only_idle_groups`,
  `local_concurrent_callers_share_home`, `local_claims_home_set_during_scan`,
  `wide_claims_groups_and_prefers_home`, `root_avoids_home_leased_by_others`,
  `root_homes_or_takes_least_loaded`, `root_widening_refreshes_group_recency`,
  `root_admission_excludes_placement_claims`, `root_admission_stays_within_group_width`,
  `single_group_admits_all_roots`, `single_group_tracks_only_known_domains`,
  `narrow_group_takes_only_wide_calls`, `build_splits_threads_by_domain_width`,
  `build_sizes_groups_by_allowed_cpus`, `fixed_homes_use_effective_worker_count`,
  `partition_homes_groups_at_build`, `floating_workers_exclude_established_homes`,
  `unusable_mask_restores_inherited_mask`, `single_group_keeps_first_home_mask`,
  `narrow_domain_takes_no_home`, `nudge_moves_caller_home_temporarily`,
  `nudge_leaves_caller_in_place`, `nudge_leaves_foreign_workers_in_place`,
  `local_panic_restores_caller_mask`: group leases, homing, and affinity writes are not ported (lane
  Decisions: topology model only, the pool is one group)

### parallel (rayon/)
| File | Tests | Ported | Open | Not portable |
| --- | --- | --- | --- | --- |
| rayon/bridge.rs | 33 | 6 | 0 | 27 |
| rayon/broadcast/test.rs | 13 | 0 | 0 | 13 |
| rayon/join/test.rs | 9 | 3 | 0 | 6 |
| rayon/meter/test.rs | 22 | 3 | 0 | 19 |
| rayon/registry/injector.rs | 1 | 0 | 0 | 1 |
| rayon/registry/test.rs | 32 | 4 | 0 | 28 |
| rayon/sort.rs | 12 | 8 | 0 | 4 |
| rayon/spawn/test.rs | 4 | 2 | 0 | 2 |
| rayon/test.rs | 7 | 2 | 0 | 5 |
| rayon/thread_pool/test.rs | 21 | 5 | 0 | 16 |
| rayon/wake_loom_tests.rs | 3 | 0 | 0 | 3 |
| Total | 157 | 33 | 0 | 124 |

Open:
- [x] `rayon/bridge.rs:1961` `try_fold_stops_at_an_error_and_drops_every_item_once`: try_fold
  stops at the failing item serially; parallel returns one of several errors
- [x] `rayon/join/test.rs:46` `sort`: recursive join quicksort on a pool sorts random data
- [x] `rayon/join/test.rs:55` `sort_in_pool`: recursive join quicksort of 12K items in a pool
- [x] `rayon/join/test.rs:124` `join_counter_overflow`: 500,000 joins on a 2-thread pool all
  run both sides
- [x] `rayon/meter/test.rs:147` `inline_joins_charge_both_sides`: a metered join charges both
  sides' busy time
- [x] `rayon/meter/test.rs:158` `joins_charge_the_stolen_side_but_not_the_wait`: metered join
  charges the stolen side's time, not the wait
- [x] `rayon/meter/test.rs:206` `spawned_jobs_charge_nothing`: spawned jobs run while a metered
  run waits add no busy time
- [x] `rayon/sort.rs:1879` `sorts_presorted_runs`: stable sort of ascending, descending, and
  chunk-reversed inputs
- [x] `rayon/sort.rs:1903` `sorts_zero_sized_values`: stable sort of zero-sized items never
  calls the comparator (sort now returns early for zero-sized items, as commonware's does)
- [x] `rayon/sort.rs:1945` `quicksorts_presorted_reversed_and_equal_inputs`: unstable sort of
  presorted, reversed, equal, perturbed inputs
- [x] `rayon/sort.rs:2014` `quicksorts_zero_sized_values`: unstable sort of zero-sized, empty,
  one-item slices
- [x] `rayon/sort.rs:2031` `an_inconsistent_comparator_still_permutes_the_slice`: random
  comparator keeps every element; a resort restores order
- [x] `rayon/spawn/test.rs:20` `spawn_then_join_in_worker`: a spawn from inside a pool job runs
  and delivers its result
- [x] `rayon/test.rs:47` `check_config_build`: a pool built with N threads reports N threads

Not portable:
- `rayon/bridge.rs` `produce_too_many_items`, `produce_fewer_items`,
  `left_produces_items_with_no_complete`, `right_produces_items_with_no_complete`,
  `left_produces_too_many_items`, `right_produces_too_many_items`, `left_produces_fewer_items`,
  `only_left_result`, `only_right_result`, `reducer_does_not_preserve_order`,
  `right_produces_fewer_items`, `left_panics`, `right_panics`: #[should_panic]
- `rayon/bridge.rs` `try_map_drops_every_item_when_an_output_drop_panics`,
  `a_panicking_map_drops_every_item_and_output_once`, `a_panicking_fold_drops_every_item_once`,
  `operations_require_a_worker`, `collect_drop_on_unwind`, `collect_drop_on_unwind_zst`,
  `produces_items_with_no_complete`, `left_produces_fewer_items_drops`: catch_unwind panics
  and drop counting
- `rayon/bridge.rs` `check_move`, `check_drops`, `drain_producer_drops_unproduced_items`: Rust
  move semantics and drop counting
- `rayon/bridge.rs` `drain_producer_split_at`: rayon's Producer/DrainProducer not ported
  (lane Decisions: no rayon port)
- `rayon/bridge.rs` `reductions_follow_the_tree_of_splits`, `a_stolen_half_splits_again`:
  rayon's adaptive split tree; zigware splits into min(len, 64) balanced chunks (Decisions)
- `rayon/broadcast/test.rs` all 13 (`broadcast_pool`, `spawn_broadcast_pool`,
  `broadcast_self`, `spawn_broadcast_self`, `broadcast_mutual`, `spawn_broadcast_mutual`,
  `broadcast_mutual_sleepy`, `spawn_broadcast_mutual_sleepy`, `broadcast_panic_one`,
  `broadcast_panic_many`, `broadcast_sleep_race`, `broadcast_after_spawn_broadcast`,
  `broadcast_after_spawn`): broadcast API not ported (no rayon port); panic ones also panic
- `rayon/join/test.rs` `panic_propagate_a`, `panic_propagate_b`, `panic_propagate_both`:
  #[should_panic]; `panic_b_still_executes`: catch_unwind
- `rayon/join/test.rs` `join_context_neither`, `join_context_second`: join_context/migrated
  not ported (workers are std.Io tasks with no identity)
- `rayon/meter/test.rs` `charges_the_calling_thread_until_it_leaves`,
  `entering_the_current_context_keeps_charging`, `suspension_charges_nothing_and_resumes`,
  `charges_land_on_the_current_run`, `blocked_threads_are_charged_for_the_wait`,
  `parked_contexts_charge_nothing_until_resumed`,
  `parked_contexts_receive_charges_and_nested_runs`,
  `unparked_work_on_a_parked_context_is_charged`, `parking_nests_and_ignores_no_context`,
  `contexts_are_scoped_to_their_runs`: meter Context/suspend/park/charge API not ported;
  zigware meters pool-job time in `Rayon.execute`
- `rayon/meter/test.rs` `nested_runs_charge_the_enclosing_run_once`,
  `nested_runs_on_workers_charge_the_enclosing_run_once`: zigware adapts and measures only
  the outermost call (lane Log 2026-11-13)
- `rayon/meter/test.rs` `context_is_restored_when_op_unwinds`,
  `unwinding_nested_run_charges_the_enclosing_run`: catch_unwind panics
- `rayon/meter/test.rs` `installs_charge_the_worker_but_not_the_wait`,
  `cross_group_installs_charge_the_worker_but_not_the_wait`,
  `broadcasts_charge_the_worker_but_not_the_wait`, `spawned_broadcasts_charge_nothing`,
  `idle_yields_charge_nothing`: install, groups, broadcast, yield_now not ported
- `rayon/registry/injector.rs` `contended_admission_keeps_worker_available`: grouped
  injector, placements, and yield_now not ported (pool is one group, topology Decision)
- `rayon/registry/test.rs` 28 of 32 (`workers_form_consecutive_groups` ...
  `wide_work_survives_concurrent_local_wakes`): worker groups, Local/Wide placements,
  install, per-worker deques, broadcast, thread names; pool is one group (Decisions)
- `rayon/sort.rs` `test_heapsort`, `test_split_for_merge`: rayon sort internals; zigware
  uses std.sort.block/pdq runs and a pairwise merge (Decisions)
- `rayon/sort.rs` `a_panicking_comparator_keeps_every_element`,
  `a_panicking_comparator_keeps_every_element_in_a_quicksort`: catch_unwind panics
- `rayon/spawn/test.rs` `termination_while_things_are_executing`: every Task must be
  block_on'd before its pool is destroyed (Decisions)
- `rayon/spawn/test.rs` `lifo_order` (the only test_order! expansion): pool queue is FIFO by
  design and has no worker-local deque (pool.zig)
- `rayon/test.rs` `worker_thread_index`, `start_callback_called`,
  `use_current_thread_rejects_a_worker`: thread index, start handler, use_current_thread
  not ported (workers are std.Io tasks; zero-thread pool instead)
- `rayon/test.rs` `check_error_send_sync`: Send/Sync; `pool_operations_require_a_worker`:
  catch_unwind, and zigware ops need no worker
- `rayon/thread_pool/test.rs` `panic_propagate`: #[should_panic]; `panic_thread_name`:
  thread_name and catch_unwind; `failed_thread_stack`: stack_size not ported
- `rayon/thread_pool/test.rs` `spawn_lifo_order`: FIFO queue by design;
  `yield_now_to_spawn`: yield_now not ported
- `rayon/thread_pool/test.rs` `result_wakes_sleeping_worker`,
  `canceled_sender_wakes_sleeping_worker`, `queued_work_wakes_sleeping_worker`,
  `outside_and_foreign_workers_do_not_poll`, `duplicate_wakes_during_poll_are_retained`,
  `retained_wakers_outlive_ready_panic_and_pool`, `nested_waits_service_later_work`,
  `workers_wait_independently`, `result_wakes_later_group_worker`,
  `canceled_sender_wakes_later_group_worker`, `queued_work_wakes_later_group_worker`:
  block_on_worker future polling and wakers not ported (spawn takes a caller-owned Task)
- `rayon/wake_loom_tests.rs` `injection_races_sleep`, `injection_races_local_idle_exit`,
  `injection_races_local_wake_handoff`: loom models of the grouped sleep protocol; no
  grouped pool and no loom

### Not-portable review (2026-11-19)

The 216 not-portable tests were reread now that collector and storage-merkle run real work on
the Rayon strategy and pool. 201 stay not portable: they test rayon's own internals or features
zigware deliberately leaves out (grouped pools, homing, and affinity; broadcast, install, and
yield_now; future polling and wakers; per-thread busy accounting; panics, unwinding, and drop
counting; LIFO deques; thread names and start handlers). 15 test behavior the `parallel` API
promises and are ported in `pool_api_tests.zig`, with placements, worker identities, and
futures dropped. The pool met every one unchanged; each group catches a planted bug (a LIFO
queue, a waiter that neither reclaims nor helps, workers never woken, a dropped policy, swapped
reductions, a skipped join side).
- [x] `lib.rs` `fold_init_wide_seed_preserves_order`: item order across slow items
- [x] `lib.rs` `grouped_jobs_and_runs_complete`: concurrent callers' jobs and maps complete
- [x] `lib.rs` `waiting_worker_runs_queued_dependencies`: a waiting job runs its dependency
- [x] `lib.rs` `nested_calls_use_current_pool`: nested maps use every worker, nothing queued
- [x] `lib.rs` `taken_over_thread_leaves_no_jobs`: a zero-thread pool maps and folds
- [x] `lib.rs` `adaptive_policy_is_scoped_to_rayon`, `adaptive_policy_is_shared_by_clones`,
  `strategy_without_policy_records_nothing`: one test of policy scoping
- [x] `rayon/registry/test.rs` `random_placements_complete`: random job trees from 8 threads
- [x] `rayon/registry/test.rs` `spawn_external_jobs_keep_submission_order`,
  `spawn_contended_producers_keep_submission_order`: FIFO order per producer and thread
- [x] `rayon/registry/test.rs` `install_crosses_pools_and_returns`, `rayon/thread_pool/test.rs`
  `self_install`, `mutual_install`, `mutual_install_sleepy`: nested spawns within and across
  one-worker pools never deadlock (sleeps of 100 ms, not 1 s)

### Upstream drift (2026-11-19, commonware 43b357a41..a9ffc25f3)

The test audit above read commonware at 43b357a41, the reference clone's commit when the audit
landed. Three commits since then touch `parallel/`:
- #5774 (883eae27e) moves the eight fold and map proptests of `lib.rs` (`proptest!`) onto a
  shared `fold_plan::Plan`, checks them on three regression inputs (empty, `[MAX, MAX, MIN]`, and
  `1..=499`) and a minifuzz search, and adds `fuzz.rs` (`test_fuzz_plan`, the `fuzz` feature) and
  the `parallel` libFuzzer target. The checks themselves are unchanged.
- #5691 (162216038) and a later lint pass: `minimum_batch_len` (still `NonZeroUsize`) divides
  without `.get()`, `join::<_, _, (), ()>` annotations in three panic tests, and a dropped
  `clone` in a sort test. No behavior or API change.

Ported:
- [x] `fold_plan.rs` `Plan::regressions` and the eight `Plan` checks, including the two the
  earlier proptest ports did not cover (`fold_equals_fold_init`,
  `map_init_collect_vec_equals_fold_init`): `fold_plan_tests.zig` "fold plan checks pass on the
  regression inputs"
- [x] `fuzz.rs` `test_fuzz_plan` and `fuzz_targets/parallel.rs`: `fold_plan_tests.zig` "fuzz:
  fold plan checks hold on every plan", a seeded fuzz in `zig build test` and a
  `std.testing.fuzz` target, reading the plan as little-endian `i32` words

## Fuzz coverage audit (2026-11-19, commonware a9ffc25f3)

Split with p2p: p2p took the network-facing decoders (p2p, resolver, broadcast, simplex,
marshal). This lane took storage, cryptography, coding, codec, math, runtime buffers, and utils.
Two checks per crate: every commonware `*/fuzz/fuzz_targets/*` target has a zigware
counterpart, and every zigware decoder or state machine has a `std.testing.fuzz` target plus a
seeded fuzz in `zig build test`. Each new or changed body was checked against planted bugs, each
reverted after it failed the body.

Before:
- Commonware targets: storage 44/44, cryptography 23/23, coding, codec 2/2, math, and utils
  16/16 had counterparts. runtime had 0/3: `blob_creation`, `blob_integrity`, and `buffer` had
  no counterpart.
- Fuzz tests missing a coverage-guided half: the crc32, keccak256, sha512, and blake3 hasher
  fuzzes (only sha256 had one), runtime "fuzz paged writer crashes (seeded)", and runtime
  "shuffle is a permutation (seeded fuzz)".
- Decoders with no fuzz at all: `certificate.zig`'s `Signers`, `Attestation`, and `Individual`
  certificate (used by ed25519 and secp256r1), the bls12381 multisig `Certificate`, and the
  golden DKG `Dealing`. The rest of the decoder list is fuzzed from crate-level files
  (bls12381 `fuzz_tests.zig`, codec `fuzz_test.zig`, the qmdb and journal fuzz tests). The
  `read(position)` methods of the storage databases are state machines, which those
  databases' fuzz tests already drive.

Added, each a seeded fuzz scaled by `fuzz_soak` plus a `std.testing.fuzz` target:
- [x] `blob_creation.rs`: runtime `storage/blob_creation_fuzz_test.zig`, with commonware's
  recovery oracle (recreated, kept, or rejected). Image lengths cluster at the torn head and
  the region end. Plants caught: padding check skipped, torn CRC prefix accepted, garbage
  past the head accepted, and the fixed-byte width narrowed.
- [x] `blob_integrity.rs`: runtime `buffer/paged/integrity_fuzz_test.zig`. Plants caught:
  page CRC never checked, a spurious replay checksum error, and a spurious `read_at` error.
- [x] `buffer.rs`: runtime `buffer/buffer_fuzz_test.zig`. It drives all 22 of commonware's
  operations, and it adds model checks commonware lacks: reads match the blob, writes and
  appends read back, and replay matches `read_at`. Plants caught: a `Read` refill one byte
  early, a `Write` tip offset off by one, a recovery truncate one byte short, and a replay page
  missing its last byte.
- [x] The hasher fuzzes: `cryptography/fuzz.zig` `fuzz_hasher` now ends with the
  coverage-guided half, so all five hashers have one. sha256's separate copy is gone.
- [x] Runtime "fuzz paged writer crashes" and "fuzz shuffle is a permutation" now run through
  `utils.fuzz.run`. Plants caught: a recovery truncate one byte short, and a shuffle that
  copies instead of swapping.
- [x] `cryptography/certificate_fuzz_test.zig`: `Signers`, `Attestation`, the ed25519
  certificate, and the bls12381 multisig certificate. Plants caught: an empty signer set
  accepted (both certificates), a signature count above or below the signer count, and the
  participant bound off by one.
- [x] `bls12381/dkg/golden/dealing_fuzz_test.zig`: golden `Dealing`. Plants caught: the
  polynomial bound off by one, the share bound off by one, and a `Set` decode that accepts
  duplicate keys or unsorted keys.

- [x] `bls12381/dkg/golden/evrf_fuzz_test.zig`: `SignedDealerLog`, `DealerLog`,
  `VrfCommitments`, and the eVRF `Proof`. A valid proof needs bulletproofs, so the seeds come from
  one embedded `SignedDealerLog` (`golden/testdata/signed_dealer_log.hex`, 3063 bytes, 2 dealers
  and 3 players, built once in ReleaseSafe from `utils.test_rng`). The seeds are its re-encoded
  parts, plus a `VrfCommitments` with a fourth commitment beside the three-player proof. Inputs
  are mutated (flips, truncation, extension, a duplicated or swapped commitment key) and decoded
  without verifying, under bounds of 1 to 4 players. Plants caught: the commitment and proof-vector
  bounds each off by one, and `Set` accepting duplicate keys or unsorted keys. Not caught: doubling
  the circuit proof's internal length bound. A mutated seed never produces a longer vector that
  still decodes. That bound is checked by `ipa_test.zig` "ipa proof decoding bounds the rounds
  by the length".

After: every commonware fuzz target in these crates has a counterpart (runtime 3/3), every fuzz
test in them has both halves, and every decoder found in the audit has a fuzz.

## blake3 conc=8 at 128 and 256 KiB (2026-11-19)

At 128 and 256 KiB, `blake3::hash_message conc=8` is slower than `conc=1` in zigware but not in
commonware. Both were run on the same desktop at load ~70 to 95, so every number is noisy.

| msg_len | commonware conc=1 | commonware conc=8 | zigware conc=1 | zigware conc=8 |
|---|---|---|---|---|
| 131072 | 39.5 µs | 14.1 µs | 18.4 µs | 42.2 µs |
| 262144 | 39.4 µs | 30.5 µs | 33.1 µs | 50.3 µs |
| 1048576 | 110 µs | 108 µs | 141 µs | 78.5 µs |

The overhead is zigware's, from two sources (measured with probe benches, not committed):
- **Kernel.** `blake3_tree.zig`'s own compression hashes the tree serially in 36 µs at
  128 KiB and 63 µs at 256 KiB, against 18 and 33 µs for std's `Blake3`. That is 2× slower,
  so a split pays twice the hashing before it gains from parallelism. std keeps its SIMD
  chunk kernel (`hashMany`) private, so the tree cannot call it.
- **Dispatch.** `map_into` handing a pool of 8 trivial jobs costs 3.9 µs for 7 jobs and
  8.0 µs for 15. That is around a quarter of the 128 KiB budget, before futex wake latency
  on a loaded machine.

Next step (not done): port std's `hashVec`/`compressChunksParallel` layout (interleaved G
rounds, `std.math.rotr`) into `blake3_tree.zig` so subtrees hash at std's speed. With that,
128 KiB should land near commonware's ratio.
