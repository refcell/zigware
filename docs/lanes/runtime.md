# Lane: runtime

Owns `src/runtime`. This is the most depended-on lane after codec: actor, stream, storage,
p2p, and every protocol run on it. Land the interface and the deterministic runtime first,
document the interface at the top of `src/runtime/root.zig`, and keep it stable.

Reference: `~/.cache/zigware/commonware-ref/runtime`. Zig 0.17.1's `std.Io` already has
fibers, io_uring (`std/Io/Uring.zig`), kqueue, threads, and an interface (vtable) for tasks,
time, files, and network: build on it rather than around it where it fits.

## Backlog
- [x] Interface: `Context` with spawner (spawn, labeled children, abort, join handles),
  clock (current, sleep, sleep_until, timeouts), RNG, network (`Listener`, `Sink`, `Stream`),
  storage (`Blob` with read_at/write_at/resize/sync, partitions open/remove/scan), metrics
  registry, `Signal`/stop. Mirror lib.rs traits.
- [x] deterministic runtime executor: seeded single-threaded executor on fibers, simulated
  time that jumps to the next timer, `auditor`, restart by calling `start` again.
- [x] storage interface (`storage.zig`: `Storage`, `Blob`, layouts, versions, options).
- [x] storage header (`storage/header.zig`), conformance hashes V0Blob, V1Blob, Header.
- [x] in-memory storage (`storage/memory.zig`), storage suite (`storage/tests.zig`), audit
  digests checked against commonware.
- [x] storage in `deterministic.Runner` (`storage()`, `storage_audit()`, crash on restart).
- [x] faulty.rs storage fault injection (`storage/faulty.zig`, `faulty_test.zig`):
  open/read/write/sync/resize/remove/scan fault rates, torn writes (prefix or subset
  retention), partial resizes, a crash journal replayed in issue order;
  `deterministic.Config.storage_faults`, `Runner.storage_fault_config()`.
- [x] audited storage (`storage/audited.zig`, audited.rs events and field order), wrapped
  around faulty storage in `Runner.storage()`.
- [x] metered storage (`storage/metered.zig`): `open_blobs` and the `storage_*` counters;
  `Runner.storage()` is `Metered(Audited(Faulty(Memory)))` under `runtime`.
- [x] mock channel (`mocks.zig`), deterministic network (`network/deterministic.zig`),
  network suite (`network/tests.zig`), `Runner.network()`.
- [x] audited network: the deterministic network and its sinks/streams record
  network/audited.rs events when `Network.auditor` is set; `Runner.network()` sets it.
  Auditor also records `rand` draws.
- [x] metered network (`network/metered.zig` `Metrics`): connections and bandwidth, counted
  by the deterministic network when `Network.metrics` is set; `Runner.network()` sets it.
- [x] Port remaining deterministic.rs tests: auditor history and field separation, clock
  start time, dropped sleepers, duplicate attributes, removed-blob reopen, recover tests
  (fault config, seeded crash writes), storage faults. No counterpart: panic tests
  (`bad_timeout`, `bad_cycle`, `bad_start_time`, label validation, `recover_panic_handling`;
  Zig cannot catch a panic, and these are asserts), waker/poll tests (`alarm_min_heap`,
  `sleep_refreshes_one_alarm`, futures moved between tasks), `external_*`, strategies and
  pools, IoBufs chunking, and
  the logical-open owner tests (Rust `Arc` drop order).
- [x] signal (`signal.zig`: `Signaler`, `Signal`, `Stopper`), commonware's shutdown tests.
- [x] Context (`context.zig`, `supervision.zig`): io, storage, network, `metrics.Scope`
  (runtime-telemetry's), labeled `child`/`with_attribute`, `spawn` with mandatory
  supervision (a finished or aborted parent aborts its descendants), `stop`/`stopped`,
  clock helpers (`timeout`, `sleep_until`); deterministic `register`/`encode`/`stop` audits;
  `deterministic.Runner.start_context`. lib.rs clock, spawn, shutdown, metrics, and storage
  tests (`context_test.zig`: storage operations, blob read/write, resize, many partitions,
  read past length, duplicate open, shared concurrent read).
- [x] Context execution modes: `dedicated()`, `shared(blocking)` (they set the task's
  `execution` metric label; `std.Io` already gives every task its own fiber or pool thread),
  and `strategy(parallelism)` (a `parallel.Rayon` over its own pool: inline on the
  deterministic runner, `parallelism - 1` workers in production). Tests: spawn_dedicated,
  spawn_blocking, select_loop, strategy, nested_strategy_runs_inline.
- lib.rs tests with no counterpart, and why:
  - `read_options_compose`, `write_options_compose`: the options are packed structs of
    bools, with no flag algebra to test.
  - `panic_aborts_root`, `panic_aborts_spawn(_caught)`, `multiple_panics(_caught)`,
    `spawn_blocking_panic(_caught)`, `factory_panic_finishes_running_metric`: Zig cannot
    catch a panic; failures are error unions, which `join` returns.
  - `clock_futures_move_between_tasks`, `handle_can_use_futures_pool`, `late_waker`,
    `circular_reference_prevents_cleanup`, `error_future`: Rust future, waker, and `Drop`
    semantics. A Zig task's function runs on its own fiber and cannot be polled partway
    and moved; handles are joined explicitly.
  - `select_loop`'s middle step (a ready `async {}` branch beats a ready receive) depends
    on `select!` polling branches in order; `std.Io.Select` does not order ready branches.
  - The metrics tests (`metrics_with_attribute`, `register_and_encode`, ...) are ported in
    runtime-telemetry's `registry_test.zig` under descriptive names.
- [x] Context on `production.Runner` (runtime-telemetry's `start_context`); the Context
  suite runs on both runners.
- [x] Runtime task metrics (`runtime_tasks_spawned`/`running`, `runtime_iterations`), written
  by runtime-telemetry (515cd03, 6929fea); `runtime_task_polls` with the root's `kind="Root"`
  series (3b877683).
- [x] iobuf (`iobuf.zig`): `IoBuf` (refcounted immutable view: clone, slice, split_to,
  advance, try_into_mut), `IoBufMut` (fixed capacity, aligned, freeze), `IoBufs` (chunk
  sequence: append, prepend, advance, split_to, coalesce, slices), the IoBuf codec with
  zero-copy `take_encoded`, and `CodecConformance<IoBuf>`.
- [x] iobuf `IoBufsMut` (scatter targets: put_slice, set_len, copy_from_slice, advance,
  freeze, coalesce), `Builder` (inline bytes plus pushed chunks), and `encode_iobufs`.
  `encode_iobufs` pushes payloads without copying for types that declare `write_bufs` and
  `encode_inline_size` (`IoBuf` does); every other type is encoded inline into one buffer.
  zigware's codec has no `write_bufs`, so containers of `IoBuf` (`Vec<IoBuf>`, maps, `Lazy`)
  encode inline: the bytes match, but the payloads are copied. The nested-container, map,
  lazy, and allocation-count `encode_iobufs` tests need that codec support and are not ported.
- [x] utils: `context.select` (commonware `Handle::select`, at most `select_max` handles)
  with handle.rs's select, abort, and tasks_running tests (no counterpart: `AbortOnDrop`,
  `Aborter`, panic interrupts, and self-borrow tests, which are Rust drop and borrow
  rules); supervision.rs's cascade, sibling, deep-chain (50,000 levels), and wide-fanout
  tests on `supervision.Tree`. No counterpart: buffer pools
  (only io_uring's `pool.rs`, which belongs to the production runtime), `abort.rs` (waker
  registration), `cell.rs` (a spawn macro), `thread.rs` (`RUST_MIN_STACK`), and
  supervision.rs's drop and weak-link compaction tests (nodes retire explicitly here).
- [x] Logical opens (memory backend): open.rs's `test_replace_retires_only_matching_
  registrations` ("memory removal retires only matching opens"). `test_open_racing_last_
  blob_drop` relies on Rust `Arc` drop racing an open on another thread: no counterpart.
- [x] Storage test wrappers (`storage/mocks.zig`, commonware mocks.rs and
  mocks/read_gate.rs): `Recording`, `WriteFault`, `SyncFault`, `MutationFault` (fail or park
  after n mutations), and `ReadGated`, each a `Wrapper(Policy)` over `storage.Storage`, with
  mocks.rs's wrapper tests. `DelayedSyncContext`/`PendingSyncs` are `mocks.DelayedSync` and
  `DelayedSynced` (delayed_sync.zig, async start_sync step 1). No counterpart:
  `MigratingReadBlob` (moves a half-polled read), read batches (no `read_many`).
- [x] The backends' `start_sync` tests (ported by the glue lane, 2026-11-19): audited
  `test_audited_start_sync`, metered `test_metered_start_sync_increments_metric`, faulty
  `test_faulty_storage_start_sync_always_fails` and
  `test_dropped_completed_start_sync_clears_the_crash_epoch`, tokio/mod.rs
  `test_start_sync_dropped_receiver` (production/storage_test.zig), and iouring.rs
  `test_unpolled_sync_completion_releases_hold` on the ring storage, without its
  `pending.owes` half (no pending-sync debt; a reopen checks the bytes instead).
- [x] `conformance.StorageConformance(Workload)` (conformance.rs): runs a workload on a
  runner seeded with the case seed and commits `storage_audit()`, in `conformance.verify`'s
  `commit(gpa, seed)` shape; its three audit tests.
- [x] memory/mod.rs: crash-write merging and subset writes keeping v0/v1 headers.
- [x] storage/benches (the filesystem workload bench): `src/runtime/storage/benches/`
  (config, filesystem, runner, workload, report) run from `src/runtime/benches.zig` as
  `runtime::storage::<workload>` on the threaded and io_uring backends. commonware has no
  tests there; `zig build test` builds each config through the ported flag parser, runs every
  workload for 10 ms on a 64 KiB file, and renders both reports. `tokio` maps to the threaded
  backend; Tokio's `--global-queue-interval` has no counterpart.
- No counterpart elsewhere in the crate: utils/mod.rs `Blocker` (a waker-driven thread
  parker), macros.rs (`select!`; `std.Io.Select`), and process/metered.rs (process metrics of
  the production runtime, runtime-telemetry's).
- Moved to the runtime-telemetry lane: telemetry (`src/runtime/telemetry/`) and the
  production runtime (`src/runtime/production/`, io_uring/kqueue storage and network).
  `src/runtime/buffer/` belongs to storage-journal.

## Decisions
- The deterministic executor implements `std.Io` (`deterministic.Runner.io()`): tasks
  (`async`/`concurrent`/groups), futexes, sleep, clocks, and randomness on stackful fibers
  (`fiber.zig`). So `std.Io.Mutex`, `Condition`,
  `Event`, `Queue` (bounded mailboxes), and `Select` are deterministic with no extra API.
- Abort is a `std.Io` cancelation request (`error.Canceled` at the next cancelation point);
  Zig cannot drop a task mid-await. When the root finishes, leftover tasks are canceled and
  drained; tasks still blocked uncancelably are discarded without running their defers.
- No `catch_panics`: a panic aborts the process. Stalls and timeouts return
  `error.Stalled` / `error.Timeout` from `Runner.start` instead of panicking.
- The runtime RNG is `utils.rng.TestRng` (commonware's `StdRng`); the ready queue is
  shuffled with rand 0.10's algorithm (`rng.shuffle`). The auditor uses commonware's hasher,
  but fibers block at different points than polled futures, so auditor digests are only
  comparable between zigware runs. Storage audits (contents only) will match commonware.
- One `Runner` can `start` several roots in sequence; time, RNG, auditor (and later storage)
  carry over. This replaces commonware's `Checkpoint`/`recover`.
- Fibers switch through an out-of-line naked function (`fiber.switch_naked`) that saves
  every callee-saved register and the FP control state; `std.Io.fiber.contextSwitch` was
  dropped because LLVM miscompiled its inline asm in optimized builds on aarch64 and x86_64.
- `Storage` and `Blob` are vtable values like `std.Io`. Zig errors carry no payload, so
  storage errors keep commonware's variant names without partition/name details.
  `Blob.read_at` fills a caller buffer (commonware's `read_at_buf`); `read_many` is not
  ported (callers loop). `Blob.start_sync` returns a `runtime.storage.Completion`; a backend
  without a `start_sync` entry (memory, audited, metered, faulty, file) syncs inline and
  returns a ready completion, as commonware's memory backend does.
  `Blob.close` replaces drop: handles must be closed, and closing does not sync.
- Network backends are duck-typed (`Listener`, `Accepted`, `Connection` declared by the
  backend) rather than vtables, so sinks and streams stay concrete and inlinable. The mock
  channel keeps `src/stream/mocks.zig`'s method shapes; unlike that stand-in, a canceled send
  closes the sink (commonware drops it), so the peer's pending recv fails.
- Fibers are entered with a null return address (tail jump from `trampoline`), so DWARF and
  frame-pointer unwinders stop at the entry function; a call left x30 pointing into the
  trampoline on aarch64 and unwinders looped. Stacks have a guard page at both ends (Linux).
- `Signal` is reference-counted with an explicit `deinit` (Rust drops it), and `wait` may be
  called again after it resolves. `Stopper.stop` takes an `Io.Timeout`.
- The mock channel accepts a zero buffer size, as commonware does. Like commonware, a recv
  waiting for n bytes and a send of fewer than n that exceeds the buffer block each other;
  callers frame their reads.
- `Context(Network)` is a plain value, generic over the backend's network type
  (`deterministic.Context` for the simulated network). `spawn(function, args)` calls
  `function(task_ctx, args...)` and consumes the context, as commonware does: spawn several
  tasks from `ctx.child(label)`; spawning twice from one context panics. A `Handle` must be
  joined, aborted, or detached exactly once (Rust drops it; a detached task keeps running
  under supervision and is reaped later). Abort is a `std.Io` cancelation, so an aborted
  task's result is `error.Closed` only if it had not already returned. `join` claims the
  task only after it ended, so an ancestor aborted while a task joins its child still
  cancels that child; a canceled `join` returns `error.Canceled` and detaches the task, as
  dropping a commonware `Handle` future does.
- Supervision nodes live in a fixed pool (`Config.max_contexts`, default 16384); a full
  pool panics. `child` reserves a node at once (so children made before a spawn die with
  that task, as in commonware), and the node is reclaimed when its subtree is aborted, i.e.
  when the task spawned from it (or an ancestor) ends. Zig has no drop, so a child context
  that never spawns holds its node until then: make long-lived child contexts once rather
  than per message.
- Faulty storage draws from the runtime RNG and journals by the memory backend's blob
  generation. Commonware's faulty is generic over its backing storage; zigware's keeps memory
  as its only backend (so DSTs and the runner are unchanged) and instead takes any blob that
  reaches a memory incarnation through `faulty.Storage.wrap`, which is how the
  `OperationGate` tests (`faulty_gate_test.zig`) gate a backing write or sync mid-operation.
  Its `start_sync` forwards to the inner blob: a ready result retires the journal at once, a
  pending one journals a sync cut that `crash` honours only once it succeeded. Setting
  `Storage.io` serializes each handle's mutations behind a mutex, as commonware's per-blob
  lock does; it stays unset (no lock) under the deterministic runner. The runner
  crashes storage when each run ends, as commonware does, so `storage_audit` after a run
  includes the crash replay.
- `Context.sleep_until` clamps deadlines past `context.deadline_max` (2262):
  `std.Io.Threaded` cannot represent later ones.
- An aborted task's alarms are freed with it, so a run whose only alarm belonged to an
  aborted sleeper reports `error.Stalled`; commonware keeps a dropped sleep's alarm and
  reports a timeout (`test_dropped_sleeper_beyond_timeout`).
- The memory backend guards its state with one spin lock that never blocks inside, so it
  is safe across threads and never yields a fiber while held.
- A task that was canceled after its function returned (while it aborts its own subtree)
  keeps its result: `Header.returned` is set under the tree lock before that abort, and only
  tasks that had not returned are closed.
- The audited network is built into the deterministic network (an optional `*Auditor` on
  `Network`, `mocks.Audit` on each half) rather than a wrapper type, so the runner's
  network type is unchanged for lanes that name it. Sent buffers hash as one length-prefixed
  payload, so chunking never changes the audit (test_auditor_ignores_buffer_chunking).
  Metered network works the same way; the production network can count into the same
  `network.metered.Metrics`. Not ported: the shared-owner test (a Zig blob handle has one
  owner). Metered `start_sync` counts a sync, as `sync` does.
- `IoBuf` keeps commonware's ownership rules with explicit `deinit`: a native buffer is one
  allocation with a refcounted header, so building one allocates once and clones, slices, and
  splits allocate nothing (commonware avoids even the header record until the first share).
  `IoBuf.deinit` takes a `gpa` it ignores, to fit the codec's `deinit(gpa)` contract.
  `IoBufs` and `IoBufsMut` share `ChunkList`: up to three chunks inline, a list from the
  fourth on, which it keeps (commonware shrinks back to Single/Pair/Triple). The network `Sink.send`
  contract still takes `[]const []const u8`; `IoBufs.slices` adapts a chunk sequence to it.
- The runner registers its storage and network metrics on first `storage()`/`network()`
  (the runner must not move by then) and panics if that registration runs out of memory.

## Log
- 2026-11-13: fibers, rand-compatible shuffle, deterministic executor implementing `std.Io`.
- 2026-11-13: naked-function fiber switch (fixes ReleaseSafe crashes on x86_64 and aarch64).
- 2026-11-13: storage interface, blob header with conformance hashes, memory backend and
  the storage suite.
- 2026-11-13: runner storage, mock channel, deterministic network and network suite.
- 2026-11-13: fiber unwind fix for aarch64 (stack traces on fibers), signal/Stopper.
- 2026-11-16: Context with supervision, clock, stop, and metrics on `deterministic.Runner`.
- 2026-11-16: Context suite on production; faulty storage wired into the runner.
- 2026-11-16: remaining deterministic.rs tests.
- 2026-11-16: detached-task drain race and canceled-after-return race fixed; auditor records
  rand, storage, and network events; metered storage and network; iobuf.
- 2026-11-16: `select`; `join` claims only ended tasks (an aborted joiner no longer
  blocks its child's abort); supervision.rs tests; utils triage.
- 2026-11-16: storage test wrappers; remaining memory and iobuf tests.
- 2026-11-19 (clearing lane): `buffer/sync_wait_test.zig` ports the paged writer's flush,
  snapshot, replay, and truncate waits on an outstanding `start_sync`, its start_sync flush
  failure, and the 10 range-sync tests of `buffer/mod.rs` and `paged/writer.rs` as write and
  total-sync counts (commonware's full plus range syncs) via the new `buffer.mocks.Storage`
  `syncs` and `resizes` counters; zigware's `Blob` has no range sync, so only the split is
  unchecked.

## Test audit (2026-11-19, against main)

Drift check (commonware 43b357a41 to a9ffc25f3, p2p lane, 2026-11-19): 162216038 drops a clone in an
iouring test and restructures the test-only flush-failure injection in `storage/iouring.rs`.
Behavior is unchanged and there is nothing to port.

Every commonware `#[test]` in this lane's crates (macro and rstest cases expanded where noted), matched by reading both sides: ported (a Zig test checks the behavior, often one consolidated test), open, or not portable with the reason. Written by the consensus-marshal lane; tick a box when its test lands.

### runtime (everything but iouring/, storage/, iobuf/)
| File | Tests | Ported | Open | Not portable |
| --- | --- | --- | --- | --- |
| conformance.rs | 3 | 3 | 0 | 0 |
| deterministic.rs | 50 | 34 | 0 | 16 |
| lib.rs | 59 | 50 | 0 | 9 |
| mocks.rs | 20 | 19 | 0 | 1 |
| network/audited.rs | 5 | 4 | 0 | 1 |
| network/deterministic.rs | 2 | 2 | 0 | 0 |
| network/iouring.rs | 14 | 9 | 0 | 5 |
| network/metered.rs | 3 | 3 | 0 | 0 |
| network/tokio.rs | 7 | 7 | 0 | 0 |
| process/metered.rs | 2 | 1 | 0 | 1 |
| telemetry/metrics/batched.rs | 4 | 4 | 0 | 0 |
| telemetry/metrics/histogram.rs | 1 | 1 | 0 | 0 |
| telemetry/metrics/mod.rs | 18 | 17 | 0 | 1 |
| tokio/runtime.rs | 21 | 6 | 0 | 15 |
| utils/abort.rs | 11 | 1 | 0 | 10 |
| utils/buffer/mod.rs | 46 | 39 | 0 | 7 |
| utils/buffer/paged/cache.rs | 49 | 17 | 0 | 32 |
| utils/buffer/paged/mod.rs | 17 | 13 | 0 | 4 |
| utils/buffer/paged/read.rs | 17 | 6 | 0 | 11 |
| utils/buffer/paged/sealed.rs | 26 | 23 | 0 | 3 |
| utils/buffer/paged/tip.rs | 13 | 1 | 0 | 12 |
| utils/buffer/paged/view.rs | 4 | 4 | 0 | 0 |
| utils/buffer/paged/writer.rs | 96 | 81 | 0 | 15 |
| utils/buffer/tip.rs | 7 | 5 | 0 | 2 |
| utils/handle.rs | 19 | 10 | 0 | 9 |
| utils/mod.rs | 3 | 0 | 0 | 3 |
| utils/supervision.rs | 9 | 4 | 0 | 5 |
| Total | 526 | 364 | 0 | 162 |

Open (none are in runtime/src/telemetry/, the runtime-telemetry lane's directory):
- [x] `deterministic.rs:1742` `test_logical_open_releases_retained_mutations`: unsynced fragments of
  a closed open are not replayed after reopen
- [x] `network/audited.rs:233` `test_trait`: network suite over the audited deterministic network
  (auditor set)
- [x] `network/audited.rs:252` `test_stress_trait`: stress suite over the audited deterministic
  network (slow)
- [x] `network/iouring.rs:608` `test_queued_accept_and_empty_operations_without_worker`: io_uring
  network: empty sends, recv(0), peek on fresh accept succeed
- [x] `network/iouring.rs:810` `test_unbuffered_mode`: io_uring network with read_buffer_size 0
  leaves nothing buffered
- [x] `network/iouring.rs:884` `test_peek_with_buffered_data`: io_uring buffered peek, shorter
  refill, and direct path keep prefix
- [x] `network/iouring.rs:947` `test_large_recv_skips_internal_buffer`: recv of exactly
  read_buffer_size bypasses the buffer (io_uring)
- [x] `network/iouring.rs:975` `test_socket_options_on_accept_and_dial`: tcp_nodelay and zero_linger
  applied on accept and dial
- [x] `network/metered.rs:201` `test_stress_trait`: stress suite over the metered network (slow)
- [x] `process/metered.rs:116` `test_process_metrics_init`: process metrics report RSS above 1 MiB
  and virtual memory >= RSS
- [x] `tokio/runtime.rs:1027` `test_storage_blob_layout_restriction`: runner storage layout policy:
  reject other layouts untouched, create allowed one
- [x] `tokio/runtime.rs:1620` `test_process_rss_metric`: production runner publishes a positive
  runtime_process_rss gauge
- [x] `utils/buffer/mod.rs:891` `test_read_resize_to_zero`: Read.resize(0) truncates the blob; a
  reopened reader's read fails
- [x] `utils/buffer/paged/cache.rs:1419` `test_clear_does_not_orphan_recached_page`: re-caching
  after clear keeps live pages reachable as slots are reused
- [x] `utils/buffer/paged/cache.rs:1624` `test_cache_clear_forces_uncached_blob_read`: after clear,
  a cached page is re-read from the blob with dont_cache
- [x] `utils/buffer/paged/cache.rs:1723` `test_cache_max_page`: caching and reading a page at the
  largest page-aligned offset
- [x] `utils/buffer/paged/cache.rs:1840` `test_read_after_misses_rejects_corruption`: batched miss
  read fails on a corrupt page and does not cache it
- [x] `utils/buffer/paged/cache.rs:1881` `test_read_many_into_reads_each_missing_page_once`:
  read_many_into reads each missing page once despite eviction
- [x] `utils/buffer/paged/cache.rs:3361` `test_cache_at_high_offset`: caching two minimum-size pages
  just below u64::MAX
- [x] `utils/buffer/paged/tip.rs:466` `test_page_geometry_handles_one_and_non_power_of_two`: tip
  drain with page size 1, a non-power-of-two size, and u16::MAX
Not portable:
- `deterministic.rs` `test_retired_write_owner_releases_other_blob`,
  `test_sync_retirement_progresses_with_namespace_open`: write-owner `Drop` callbacks and `Arc` drop
  order (runtime.md: logical-open owner tests)
- `deterministic.rs` `test_paced_future_moves_between_tasks`, `test_external_realtime`,
  `test_external_realtime_variable`, `test_realtime_no_skip`: deterministic `external` feature
  (real-time pacing); runtime.md: `external_*` not ported
- `deterministic.rs` `test_recover_panic_handling`, `test_context_return`,
  `test_external_simulated`: panic recovery across runners, a context outliving its runner, and the
  `external` feature; `test_bad_start_time`: `start_time_ns` is a `u64`, so no time before the epoch
  exists. Their other `#[should_panic]` tests are death tests in `panic_test.zig`
- `deterministic.rs` `test_borrowed_non_send_root`: compile-time check that the root needs no
  `Send`/`'static` bound
- `deterministic.rs` `test_parallel_strategy_spawn_completes`,
  `test_strategies_reuse_pool_across_runners`, `test_pool_survives_suspension`: runtime.md backlog:
  deterministic "strategies and pools" tests have no counterpart
- `deterministic.rs` `test_alarm_min_heap`, `test_sleep_refreshes_one_alarm_after_repolling`:
  waker/poll internals (runtime.md names `alarm_min_heap`, `sleep_refreshes_one_alarm`)
- `lib.rs` `test_blob_version`: `BlobVersion` is a `u16` alias; test checks Rust Display/Debug/Range
  impls
- `lib.rs` `test_handle_can_use_futures_pool`, `test_clock_futures_move_between_tasks`,
  `test_circular_reference_prevents_cleanup`, `test_late_waker`: Rust future, waker, and `Drop`
  semantics (runtime.md lib.rs no-counterpart list)
- `lib.rs` `test_read_options_compose`, `test_write_options_compose`: runtime.md: "the options are
  packed structs of bools, with no flag algebra to test"
- `lib.rs` `test_factory_panic_finishes_running_metric`: reads a metric after catching a panic;
  the other `#[should_panic]` tests are death tests in `panic_test.zig`
- `lib.rs` `test_select`: runtime.md: `select!` polls branches in order; `std.Io.Select` does not
  order ready ones
- `network/audited.rs` `test_stream_preserves_chunking`: Zig `Stream.recv` fills a caller buffer;
  there is no `IoBufs` chunk structure
- `network/iouring.rs` `test_cancelled_recv_retains_descriptor_until_completion`: asserts `Arc`
  strong counts on the socket descriptor
- `network/iouring.rs` `test_pending_network_operations_observe_worker_closure`,
  `test_carried_receive_deadline_completes_without_rescheduling`: polls futures by hand (manual
  waker, retained across worker shutdown)
- `network/iouring.rs` `test_cancel_accept_before_service_preserves_next_connection`: zigware's
  io_uring backend runs only send/recv on the ring, not accept
- `network/iouring.rs` `test_submit_recv_returns_bytes_for_this_call`: tests commonware's internal
  `submit_recv` prefix-buffer API, absent in zigware
- `process/metered.rs` `test_allocator_metrics_skipped_without_mimalloc`: mimalloc allocator
  metrics; zigware has no mimalloc feature
- `telemetry/metrics/mod.rs` `test_registered_with_registration_notifies_on_last_drop`:
  runtime-telemetry.md: "No custom `Registration::from(guard)`"
- `tokio/runtime.rs` `test_join_all_aborts_all_tasks_before_waiting`,
  `test_join_all_drains_completions_concurrently`, `test_join_all_drops_outputs_before_waiting`:
  runtime.md: `AbortOnDrop` has no counterpart (Rust drop rules)
- `tokio/runtime.rs` `test_root_destruction_can_spawn_work_before_shutdown`: spawns from a root
  future's `Drop`
- `tokio/runtime.rs` `test_runner_owns_runtime_when_context_escapes`,
  `test_runner_returns_strategy_after_pool_work`: a `Context`/strategy returned from `start`
  outliving the runner (Rust ownership)
- `tokio/runtime.rs` `test_strategy_spawn_keeps_sibling_futures_polling`,
  `test_root_factory_builds_runtime_futures`: Rust future polling: `select!` over a pending strategy
  job / eager root factory
- `tokio/runtime.rs` `test_storage_blob_layout_restriction_rejects_empty_range`,
  `test_runner_propagates_panic_during_drain`, `test_disposal_panic_is_task_panic`,
  `test_disposal_panic_reported_before_tracker_release`,
  `test_runner_resumes_strategy_panic_payload_after_pool_work`: `#[should_panic]` or panic
  propagation/`catch_unwind`; Zig cannot catch a panic
- `tokio/runtime.rs` `test_default_thread_stack_size_uses_system_default`,
  `test_thread_stack_size_override`: runtime.md: `thread.rs` (`RUST_MIN_STACK`) has no counterpart
- `utils/abort.rs` `wrapper_adds_one_pointer`, `abort_before_poll_skips_future`,
  `abort_wakes_latest_waker`, `abort_wakes_repeatedly_registered_waker`,
  `task_registers_waker_with_new_vtable`, `abort_wakes_task_behind_reused_waker_addresses`,
  `concurrent_abort_and_poll`, `abort_races_first_poll`, `abort_races_repeat_poll_same_waker`,
  `abort_races_repeat_poll_new_waker`: runtime.md: `abort.rs` (waker registration) has no
  counterpart
- `utils/buffer/mod.rs` `test_read_cancelled_refill_rewinds`: storage-journal.md: delayed or
  cancelled reads (`MigratingReadBlob`, parked reads)
- `utils/buffer/mod.rs` `test_read_structure_single_vs_chunked`: storage-journal.md: `IoBuf`
  ownership/chunk structure (reads copy into caller buffers)
- `utils/buffer/paged/cache.rs` `test_read_cached_many_across_chunks`,
  `test_read_cached_many_stale_hint_after_eviction`,
  `test_read_cached_many_cross_blob_hint_collision`,
  `test_read_cached_many_sparse_page_number_keeps_hints_fixed`: Rust cache's slot-hint and
  resolution-chunk internals; zigware's page cache has no slot hints
- `utils/buffer/paged/cache.rs` `test_read_many_into_joins_fetch_in_flight`,
  `test_overlapping_reads_read_each_page_once`,
  `test_joining_many_pages_selects_all_before_driving`,
  `test_read_joins_unpolled_batch_under_eviction`, `test_read_joining_batch_outlives_its_starter`,
  `test_joined_read_finishes_before_its_batch`, `test_batch_read_polled_once_per_completion`,
  `test_reader_that_stops_driving_rewakes_waiting_reader`,
  `test_reader_that_stops_driving_rewakes_waiting_reader_on_tokio`,
  `test_starting_read_waits_for_its_batch_to_end`, `test_failed_page_fails_its_readers`,
  `test_failed_read_fails_readers_still_waiting`, `test_read_fails_as_soon_as_any_source_fails`,
  `test_each_page_routes_to_its_joiners_only`, `test_many_reads_join_one_page`,
  `test_subscription_dropped_unpolled_gets_no_pages`,
  `test_page_delivered_before_batch_fails_still_serves_its_reader`,
  `test_cancelled_joins_do_not_disturb_other_reads`, `test_dropped_batches_are_unregistered`,
  `test_batch_whose_driver_was_dropped_is_not_joined`, `test_overlapping_reads_with_cancellations`,
  `test_concurrent_reads_read_each_page_once`,
  `test_concurrent_reads_with_eviction_and_cancellation`,
  `test_page_fetches_entry_removed_when_first_fetcher_cancelled`,
  `test_followers_keep_single_flight_after_first_fetcher_cancellation`,
  `test_page_fetch_error_removes_entry_for_all_waiters`,
  `test_cancelled_stale_waiter_preserves_new_fetch`: storage-journal.md: the page cache "does not
  share in-flight reads" (joins, batches)
- `utils/buffer/paged/cache.rs` `test_observed_miss_filled_before_completion`: relies on a Rust
  future doing nothing until first polled
- `utils/buffer/paged/mod.rs` `test_corrupt_page_rejects_short_blob`,
  `test_validate_read_ranges_rejects_buffer_len_mismatch`,
  `test_validate_read_ranges_rejects_overlapping_ranges`,
  `test_validate_read_ranges_rejects_unsorted_ranges`: `#[should_panic]` or panic
  propagation/`catch_unwind`; Zig cannot catch a panic
- `utils/buffer/paged/read.rs` `test_replay_buf_bytes_share_pages`: storage-journal.md: `IoBuf`
  ownership/chunk structure (reads copy into caller buffers)
- `utils/buffer/paged/read.rs` `test_failed_read_ahead_is_read_again_on_demand`,
  `test_retry_does_not_wait_on_queued_reads`, `test_batches_split_the_buffer`,
  `test_fill_keeps_batches_in_flight`, `test_seek_discards_the_batches_in_flight`,
  `test_failed_fill_reads_the_same_batch_again`, `test_dropped_fill_reads_the_same_batch_again`,
  `test_batches_landing_before_and_after_their_wait_are_served`,
  `test_read_error_after_the_batch_fails_the_fill`: read-ahead is ported opt-in (storage
  `Config.read_ahead`, `Blob.start_read`, up to 3 batches in flight in `paged.Replay`;
  read_ahead_test.zig checks it against the appended bytes), but these tests drive commonware's
  fault-injecting mock blob and per-batch futures, which have no counterpart here. Off by default:
  each start is a `std.Io` task hand-off, which made fixed replay about 4x slower on tmpfs
- `utils/buffer/paged/read.rs` `test_replay_is_sync`: compile-time Rust `Sync` bound check
- `utils/buffer/paged/sealed.rs` `test_sealed_read_many_into_rejects_unsorted_offsets`:
  `#[should_panic]` or panic propagation/`catch_unwind`; Zig cannot catch a panic
- `utils/buffer/paged/sealed.rs` `test_replay_preserves_tail_during_partial_page_rewrite`:
  storage-journal.md: `SplitWriteBlob` partial-page rewrite races
- `utils/buffer/paged/tip.rs` `test_typed_append_rejects_short_encoding`,
  `test_typed_append_rejects_long_encoding`, `test_zero_page_size_is_rejected`,
  `test_misaligned_capacity_is_rejected`, `test_full_page_seed_is_rejected`,
  `test_full_page_replacement_is_rejected`: `#[should_panic]` or panic propagation/`catch_unwind`;
  Zig cannot catch a panic
- `utils/buffer/paged/tip.rs` `test_extension_preserves_prior_allocation_pointers`,
  `test_typed_append_crosses_allocations_and_pages`, `test_zero_size_typed_append_stays_detached`,
  `test_drain_reuses_independent_partial_page`,
  `test_drain_keeps_chunks_and_detaches_mutable_suffix`, `test_replace_detaches_prior_owners`:
  storage-journal.md: tip is one contiguous allocation, not chained zero-copy chunks
- `utils/buffer/paged/writer.rs` `test_cancelled_recovery_read_cannot_repopulate_after_truncate`,
  `test_snapshot_fetch_populates_shared_cache_across_append`: storage-journal.md: delayed or
  cancelled reads (`MigratingReadBlob`, parked reads)
- `utils/buffer/paged/writer.rs` `test_append_variable_value_encodes_in_place`,
  `test_to_physical_pages_preserves_chunk_owners`: storage-journal.md: `IoBuf` ownership/chunk
  structure (reads copy into caller buffers)
- `utils/buffer/paged/writer.rs` `test_read_many_into_rejects_invalid_buffer_len`,
  `test_read_many_into_rejects_unsorted_offsets`, `test_read_many_into_rejects_overlapping_offsets`:
  `#[should_panic]` or panic propagation/`catch_unwind`; Zig cannot catch a panic
- `utils/buffer/paged/writer.rs` `test_recoverable_prefix_len_batches_reads`: storage-journal.md:
  "`recoverable_prefix_len` reads one page at a time"
- `utils/buffer/paged/writer.rs` `test_sync_preserves_partial_tip_allocation`: storage-journal.md:
  tip is one contiguous allocation, not chained zero-copy chunks
- `utils/buffer/paged/writer.rs` `test_torn_extension_with_new_footer_recovers_previous_prefix`:
  storage-journal.md: "the torn-extension blob" not ported
- `utils/buffer/tip.rs` `test_tip_slice_uses_resolved_bounds`,
  `test_tip_writable_copies_when_slice_is_live`: storage-journal.md: `IoBuf` ownership/chunk
  structure (reads copy into caller buffers)
- `utils/handle.rs` `tasks_running_decreased_immediately_on_abort_via_aborter`: runtime.md:
  `Aborter` has no counterpart
- `utils/handle.rs` `abort_on_drop_cancels_pending_join`,
  `abort_on_drop_join_all_drains_pending_task`, `join_all_aborts_before_destruction`,
  `abort_on_drop_completion_leaves_producer_running`: runtime.md: `AbortOnDrop` has no counterpart
  (Rust drop rules)
- `utils/handle.rs` `completion_handle_abort_stops_waiting`: `Handle::from_receiver` (oneshot-backed
  handle) has no counterpart
- `utils/handle.rs` `interrupt_observes_panic_sent_while_completing`: `#[should_panic]` or panic
  propagation/`catch_unwind`; Zig cannot catch a panic
- `utils/handle.rs` `task_keeps_self_borrow_across_suspension`: runtime.md: self-borrow tests are
  Rust borrow rules
- `utils/handle.rs` `abort_idle_task_after_skipped_registration`: waker registration skipped on
  repeat polls (Tokio/io_uring poll internals)
- `utils/mod.rs` `test_blocker_waits_until_wake`, `test_blocker_handles_pre_wake`,
  `test_blocker_reusable_across_signals`: runtime.md: utils/mod.rs `Blocker` (a waker-driven thread
  parker) has no counterpart
- `utils/supervision.rs` `drop_deep_clone_chain_without_stack_growth`,
  `child_reaping_batches_compaction_for_clone_heavy_parent`,
  `child_reaping_scales_with_list_length`, `aborted_children_still_count_toward_batched_reaping`,
  `unique_ancestor_release_counts_stale_child_on_surviving_root`: runtime.md: supervision.rs drop
  and weak-link compaction tests (nodes retire explicitly)

### runtime (storage/, iobuf/)
| File | Tests | Ported | Open | Not portable |
| --- | --- | --- | --- | --- |
| storage/audited.rs | 8 | 5 | 2 | 1 |
| storage/faulty.rs | 51 | 47 | 1 | 3 |
| storage/header.rs | 21 | 21 | 0 | 0 |
| storage/hold.rs | 2 | 0 | 2 | 0 |
| storage/iouring.rs | 66 | 13 | 16 | 37 |
| storage/memory/mod.rs | 15 | 15 | 0 | 0 |
| storage/memory/open.rs | 2 | 1 | 0 | 1 |
| storage/metered.rs | 7 | 5 | 0 | 2 |
| storage/pending.rs | 8 | 0 | 0 | 8 |
| storage/tokio/blob.rs | 23 | 1 | 2 | 20 |
| storage/tokio/blob/aio.rs | 7 | 0 | 0 | 7 |
| storage/tokio/mod.rs | 42 | 10 | 9 | 23 |
| storage/tracker.rs | 4 | 0 | 0 | 4 |
| iobuf/buf.rs | 60 | 20 | 1 | 39 |
| iobuf/bufs.rs | 98 | 54 | 7 | 37 |
| iobuf/owner.rs | 36 | 0 | 0 | 36 |
| Total | 450 | 192 | 40 | 218 |

Open:
- [x] `storage/audited.rs:266` `test_audited_blob_forwards_read_options`: audited blob passes each
  read's options unchanged to the inner blob
- [x] `storage/audited.rs:485` `test_audited_blob_writes_preserve_chunking_and_options`: inner
  blob sees the original chunk count and write options
- [x] `storage/faulty.rs:1942` `test_faulty_blob_forwards_read_options_without_faults`: fault-free
  faulty blob forwards dont_cache reads to the inner blob
- [x] `storage/faulty.rs` `test_start_sync_returns_before_backing_completion`,
  `test_dropped_start_sync_epoch_is_linearized_with_overlapping_write`,
  `test_completed_backing_write_cannot_record_after_later_full_sync`,
  `test_full_sync_epoch_is_linearized_with_overlapping_write` (`faulty_gate_test.zig`): faulty
  over a gated backing blob (`Storage.wrap`) instead of a tokio or io_uring one
- [x] `storage/hold.rs:120` `test_hold_name_rejected_as_partition`: `.hold` is rejected as a
  partition name
- [x] `storage/hold.rs:125` `test_acquire_fails_on_unusable_root`: storage init fails when the
  root path is a regular file
- [x] `storage/iouring.rs:1155` `test_large_contiguous_write_returns_kernel_error`: huge write to
  /dev/full returns the kernel error
- [x] `storage/iouring.rs:1386` `test_v1_paged_alignment`: paged writer on a V1 blob keeps each
  page on one aligned 4 KiB disk page
- [x] `storage/iouring.rs:1737` `test_scan_rejects_non_file_entries`: scanning a partition holding
  a subdirectory fails PartitionCorrupt
- [x] `storage/iouring.rs:1755` `test_remove_reports_missing_targets`: remove reports
  PartitionMissing, then BlobMissing in an existing partition
- [x] `storage/iouring.rs:1778` `test_scan_ignores_non_utf8_file_names`: scan skips non-UTF-8 file
  names instead of failing
- [x] `storage/iouring.rs:1848` `test_open_reports_partition_creation_failure`: open fails when the
  partition path is a regular file
- [x] `storage/iouring.rs:1874` `test_open_reports_blob_open_failure_for_directory_path`: open
  fails when the blob path is a directory
- [x] `storage/iouring.rs:1906` `test_write_range_overflow_before_registration`: writes whose
  physical end overflows u64 fail OffsetOverflow
- [x] `storage/iouring.rs:1957` `test_read_range_overflow_before_registration`: reads at
  overflowing physical offsets fail OffsetOverflow; empty reads succeed
- [x] `storage/iouring.rs:2000` `test_blob_offset_overflow_guards`: read/write/resize at logical
  u64::MAX fail OffsetOverflow before any I/O
- [x] `storage/iouring.rs:2064` `test_resize_reports_kernel_error`: resize on a socket descriptor
  reports BlobResizeFailed
- [x] `storage/iouring.rs:2174` `test_blob_sync_reports_kernel_error`: sync on a socket descriptor
  reports BlobSyncFailed
- [x] `storage/iouring.rs:2769` `test_clean_sync_is_skipped`: sync with no mutation since the last
  sync skips the fsync
- [x] `storage/tokio/blob.rs:2017` `test_invalid_write_range_leaves_open_clean`: overflowing write
  ranges fail OffsetOverflow and mutate nothing
- [x] `storage/tokio/mod.rs:669` `test_v1_paged_alignment`: paged writer on a V1 blob keeps each
  page on one aligned 4 KiB disk page
- [x] `storage/tokio/mod.rs:1102` `test_partition_scan_waits_for_sync`: scanning an inherited
  partition waits for its directory fsync
- [x] `storage/tokio/mod.rs:1163` `test_partition_scan_sync_failure`: failed partition directory
  fsync fails the scan; the next scan retries
- [x] `storage/tokio/mod.rs:1187` `test_partition_open_syncs_once`: first open of an inherited blob
  fsyncs its partition directory once
- [x] `storage/tokio/mod.rs:1217` `test_partition_sync_creation_and_removal`: directory fsyncs on
  partition creation, inheritance, and removal
- [x] `storage/tokio/mod.rs:1279` `test_blob_remove_sync_failure_retires_partition`: failed fsync
  after blob removal is redone by the next scan
- [x] `storage/tokio/mod.rs:1364` `test_first_open_flushes_existing_blob`: first open of an existing
  blob per instance fsyncs it once
- [x] `storage/tokio/mod.rs:1441` `test_remove_forgets_first_open_names`: removing a blob or
  partition forgets its first-open flushed names
- [x] `storage/tokio/mod.rs:1669` `test_clean_sync_is_skipped`: sync with no mutation since the last
  sync skips the fsync
- [x] `iobuf/buf.rs:2386` `test_iobufmut_try_with_alignment_declines_impossible_layouts`: oversized
  aligned allocations fail instead of panicking
- [x] `iobuf/bufs.rs:3075` `test_iobufsmut_emptiness_with_reserved_capacity`: is_empty, advance,
  put across up to 8 reserved-capacity chunks
- [x] `iobuf/bufs.rs:3523` `test_iobufsmut_try_into_single`: IoBufsMut as_single succeeds for one
  chunk, fails for two
- [x] `iobuf/bufs.rs:4235` `test_nested_container_encode_iobufs_matches_encode`: encode_iobufs of
  Option/Vec byte fields equals encode
- [x] `iobuf/bufs.rs:4244` `test_map_encode_iobufs_matches_encode`: encode_iobufs of BTreeMap and
  HashMap byte values equals encode
- [x] `iobuf/bufs.rs:4257` `test_lazy_encode_iobufs_matches_encode`: encode_iobufs of Lazy and
  deferred Lazy equals encode, one chunk
- [x] `iobuf/bufs.rs:4273` `test_encode_iobufs_without_inline_bytes_does_not_allocate`:
  encode_iobufs of an empty array allocates nothing
- [x] `iobuf/bufs.rs:4281` `test_non_empty_range_encode_iobufs_matches_encode`: encode_iobufs of a
  NonEmptyRange of byte values equals encode

The tokio/mod.rs partition-sync tests run on every platform with
`Config.sync_inherited_partitions` set (it defaults to commonware's non-Linux only).

Not portable:
- `storage/iouring.rs` `test_dirty_sync_waits_without_blocking_other_io`,
  `test_recreated_blob_does_not_wait_for_removed_opens_gate`: zigware's file storage has no
  per-open durability permit, and its `start_sync` syncs inline on its caller
- `storage/iouring.rs` `test_sync_dir_reports_missing_directory`: zigware's `sync_dir` takes an
  open `Dir`, so there is no missing path to report
- `storage/tokio/blob.rs` `test_header_read_after_payload_shrink`: open reads the header under
  the storage mutex while no handle of the blob can be open (`BlobAlreadyOpen`), so its length
  cannot go stale; `header.resolve` asserts the read covers it
- `storage/iouring.rs` `test_queued_write_and_start_sync_finish_through_shutdown`: a
  registration queued beyond a full ring and finished by the driver at shutdown; zigware's ring
  submits and waits on its caller, so nothing is queued
- `storage/tokio/blob.rs` `test_reopen_after_start_sync_completion`: pauses tokio's sync
  worker (`after_start_sync`) and counts the reopen's flush of the pending-sync debt
  (`pending.rs`); zigware syncs on the caller and keeps no such debt
- `storage/faulty.rs` `test_write_config_arbitrary_is_compact_and_covers_grid`: Rust `Arbitrary`
  impl for `WriteConfig`; faulty.zig has none
- `storage/memory/open.rs` `test_open_racing_last_blob_drop`: runtime.md: "relies on Rust `Arc`
  drop racing an open on another thread: no counterpart"
- `storage/metered.rs` `test_shared_blob_owners_share_metrics`; `storage/tokio/mod.rs`
  `test_shared_blob_dirty_state`: shared `Arc<Blob>` owners; runtime.md: "a Zig blob handle has
  one owner"
- `storage/pending.rs` (all 8: `test_last_generation_drop_during_settle`,
  `test_last_generation_drop_during_admit`, `test_wait_observes_settling_predecessor`,
  `test_debt_is_established_by_the_next_open`, `test_failures_stay_until_forgotten`,
  `test_stale_settlement_leaves_a_recreated_name_alone`, `test_live_open_refuses_a_second_admit`,
  `test_generations_retire_and_release_clean_entries`); `storage/tracker.rs` (all 4:
  `test_synced_writes_are_clean`, `test_unlanded_write_is_not_credited`,
  `test_write_racing_sync_stays_dirty`, `test_first_failure_is_retained`): runtime-telemetry.md:
  "Commonware's async-drop settlement (`pending.rs`) has no counterpart: `close` is synchronous";
  the tracker only feeds that debt accounting
- `storage/iouring.rs` `test_dirty_drop_leaves_its_flush_to_the_next_open`,
  `test_failed_creation_does_not_publish_unsynced_header`,
  `test_failed_creation_over_torn_header_recreates`, `test_durable_writes_need_no_reopen_sync`,
  `test_orphaned_failed_durable_write_poisons_the_open`, `test_orphaned_write_lands_before_reopen`,
  `test_remove_live_dirty_owner_leaves_no_debt`, `test_recreate_reopen_ignores_removed_handle`,
  `test_multibatch_durable_write_covers_prior_mutations`,
  `test_trailing_sync_credits_at_completion`, `test_synced_drop_leaves_no_debt`,
  `test_orphaned_write_delays_settlement`, `test_waiting_open_cancelled_or_removed`,
  `test_untouched_creation_needs_no_reopen_flush`, `test_flush_failure_is_retained`,
  `test_completion_failure_poisons_open`, `test_completion_failure_is_retained`: pending.rs debt,
  settlement, and retained-failure machinery (same runtime-telemetry.md decision)
- `storage/tokio/mod.rs` `test_reopen_flushes_dirty_predecessor`,
  `test_partition_open_sync_failure_keeps_content_debt`, `test_first_open_flush_failure_is_retained`,
  `test_synced_drop_leaves_no_debt`, `test_recreate_reopen_flushes_replacement`,
  `test_failed_creation_does_not_publish_unsynced_header`,
  `test_failed_creation_over_torn_header_recreates`, `test_remove_live_dirty_owner_leaves_no_debt`,
  `test_durable_writes_need_no_reopen_flush`, `test_orphaned_write_lands_before_reopen`,
  `test_untouched_creation_needs_no_reopen_flush`, `test_flush_failure_is_retained`,
  `test_durable_write_retains_prior_flush_failure`, `test_completion_failure_is_retained`,
  `test_cancelled_completion_failure_is_retained`,
  `test_removed_incarnation_completion_publishes_nothing`, `test_remove_forgets_debt`: pending.rs
  debt and settlement (same decision)
- `storage/tokio/blob.rs` `test_overlapping_durability_failure`,
  `test_reopen_replacement_after_gated_mutation`, `test_reopen_after_gated_mutation`,
  `test_reopen_after_retirement_before_admission`, `test_reopen_canceled_during_final_metadata`,
  `test_reopen_canceled_during_wait_keeps_debt`: pending.rs settlement of gated or canceled
  operations (same decision)
- `storage/iouring.rs` `test_read_many_indexes_every_range`,
  `test_read_many_serves_unaligned_ranges_directly`, `test_read_many_sees_unsynced_buffered_writes`,
  `test_read_many_reports_unservable_range`, `test_batches_register_every_read_together`,
  `test_read_many_serves_more_ranges_than_the_ring_holds`,
  `test_read_many_registers_on_its_first_polling_worker`,
  `test_plain_thread_observes_direct_reads_and_fallbacks`,
  `test_paged_batch_abandoned_by_starter_and_joiners`; `storage/tokio/blob.rs`
  `test_read_many_indexes_every_range`, `test_read_many_retired_runtime_reports_error`,
  `test_read_many_at_signed_limit`, `test_read_many_beyond_single_read_limit`,
  `test_read_many_serves_unaligned_ranges_directly`, `test_read_many_sees_unsynced_buffered_writes`,
  `test_read_many_reports_unservable_range`: no `read_many` (runtime.md decision quoted above)
- `storage/iouring.rs` `test_direct_descriptor_reads_the_held_inode`,
  `test_read_at_serves_uncached_reads_directly`, `test_rejected_direct_open_reads_buffered`,
  `test_read_at_falls_back_to_buffered_reads`, `test_direct_descriptor_is_shared_across_workers`;
  `storage/tokio/blob.rs` `test_read_at_serves_uncached_reads_directly`,
  `test_read_at_falls_back_to_buffered_reads`, `test_cache_bypass_is_ignored_off_linux`,
  `test_cache_bypass_retry_decision`; `storage/tokio/blob/aio.rs` (all 7:
  `test_failed_submission_keeps_slab_until_reads_complete`, `test_submission_beyond_one_slab_fails`,
  `test_submission_survives_signals`, `test_direct_open_retries_after_descriptor_limit`,
  `test_read_many_serves_more_ranges_than_one_submission`,
  `test_reads_without_context_are_served_individually`,
  `test_read_direct_covers_the_aligned_superset`): O_DIRECT / native AIO for uncached reads;
  runtime-telemetry.md: "`dont_cache` read/write hints are accepted and ignored"
- `storage/iouring.rs` `test_dropped_durable_write_retains_hold_through_shutdown`,
  `test_hold_retained_by_open_blob`, `test_pending_blob_operations_observe_worker_closure`;
  `storage/tokio/mod.rs` `test_hold_waits_for_straggling_remove`, `test_hold_retained_by_open_blob`,
  `test_canceled_open_retires_result_before_retry`, `test_open_dropped_mid_creation`: futures
  dropped or held half-polled, handles outliving their storage (Zig: every handle closed before
  `deinit`; runtime.md: a task "cannot be polled partway and moved")
- `storage/iouring.rs` `test_read_at_buf_preserves_multichunk_layout`: multi-chunk `IoBufsMut`
  read target; runtime.md: "`Blob.read_at` fills a caller buffer"
- `storage/tokio/blob.rs` `test_fused_write_error_is_recorded_before_buffer_drop`: Rust `Drop` of
  the payload owner; `test_reopen_syncs_fallback_write_after_owner_panic`: catches a panic
- `iobuf/buf.rs` `test_iobuf_copy_to_slice_past_end`, `test_iobuf_copy_to_bytes_past_end`,
  `test_iobuf_slice_inclusive_end_overflow`, `test_iobuf_slice_excluded_start_overflow`,
  `test_iobufmut_copy_to_slice_past_end`, `test_iobufmut_copy_to_bytes_past_end`,
  `test_iobufmut_put_bytes_past_capacity`, `test_iobufmut_put_past_capacity`,
  `test_iobufmut_put_does_not_trust_lying_buf`,
  `test_iobufmut_with_capacity_rejects_oversized_request`, `test_iobufmut_set_len_overflow`:
  #[should_panic] on methods or `RangeBounds` zigware lacks, or `error.OutOfMemory` here; the other
  seven are death tests in `iobuf_panic_test.zig`
- `iobuf/buf.rs` `test_iobuf_from_conversions_are_zero_copy`,
  `test_iobuf_additional_conversion_and_trait_paths`, `test_iobuf_from_bytes_zero_copy_round_trip`,
  `test_iobuf_from_bytes_mut_zero_copy`, `test_iobuf_static_into_bytes_uses_from_static`,
  `test_iobuf_vec_adoption_round_trip_zero_copy`, `test_iobufmut_decode_preserves_byte_fields`,
  `test_take_owned_other_containers`, `test_iobufmut_additional_conversion_and_trait_paths`,
  `test_iobufmut_from_bytesmut_preserves_capacity`,
  `test_iobufmut_from_bytes_reuses_unique_allocation`, `test_iobufmut_from_vec_preserves_capacity`:
  From/Into `Bytes`, `BytesMut`, `Vec`, arrays, and `Bytes` decoding
- `iobuf/buf.rs` `test_iobuf_copy_to_slice_paths`, `test_iobufmut_copy_to_slice_tracks_len_and_cap`,
  `test_iobufmut_put_bytes_success`, `test_iobufmut_put_multi_chunk_source`: `Buf`/`BufMut` trait
  methods; `test_iobuf_slice_excluded_start_bound`: `RangeBounds` `Bound::Excluded`;
  `test_handle_auto_traits`: Send/Sync/Unpin/UnwindSafe
- `iobuf/buf.rs` `test_unshared_lifecycle_keeps_descriptor`, `test_first_share_promotes_once`,
  `test_slice_promotes_from_source_view`, `test_aligned_descriptor_promotes_from_unaligned_view`,
  `test_clone_of_empty_cursor_keeps_allocation`, `test_moves_and_empty_views_do_not_promote`,
  `test_partial_split_promotes_and_shares`, `test_bytes_from_unshared_view_keeps_allocation`,
  `test_freeze_tail_overflow_allocates_record`, `test_concurrent_first_clones_share_one_record`:
  owner descriptor promotion and record refcounts; runtime.md: one allocation with a refcounted
  header ("commonware avoids even the header record until the first share")
- `iobuf/owner.rs` `test_allocation_rejects_isize_max_overflow`,
  `test_allocation_rejects_non_power_of_two_alignment`, `test_adopt_vec_rejects_unallocated_vec`:
  #[should_panic]
- `iobuf/owner.rs` (other 33: `test_format_64_round_trips`,
  `test_format_64_rejects_fields_that_do_not_fit`, `test_format_32_round_trips`,
  `test_format_32_rejects_fields_that_do_not_fit`, `test_format_tail_replacement_keeps_layout`,
  `test_format_without_bits_describes_nothing`, `test_heap_allocation_is_exact_and_aligned`,
  `test_heap_zeroed_only_exposes_usable_region`, `test_heap_capacity_is_not_rounded`,
  `test_descriptor_recovers_base_from_any_view`, `test_frozen_tail_overflow_allocates_record`,
  `test_vec_adoption_keeps_allocation_and_capacity`, `test_vec_adoption_exact_size_is_native`,
  `test_adopt_vec_with_capacity_but_no_length`, `test_external_owner_refcount`,
  `test_external_owner_keeps_inner_bytes_alive`, `test_empty_owner_has_no_record`,
  `test_heap_owner_shared_clone_and_drop`, `test_shared_release_panics_before_releasing_storage`,
  `test_shared_promotion_publishes_two_references`, `test_losing_promotion_retains_winner`,
  `test_exclusive_promotion_stores_record`, `shared_clone_drop_releases_exactly_once`,
  `clone_races_concurrent_drop`, `is_unique_races_final_drop`,
  `payload_writes_happen_before_race_final_release`,
  `payload_writes_happen_before_fast_path_release`, `promotion_publishes_record_to_observer`,
  `losing_promotion_retains_winner`, `promoted_try_into_mut_observes_prior_accesses`,
  `promoted_fast_path_release_observes_prior_accesses`, `promoted_concurrent_drops_release_once`,
  `exclusive_promotion_shares_record_across_threads`): owner word, descriptor packing, Vec
  adoption, and refcount/drop ordering (many under loom); zigware's owner is one allocation
  header (runtime.md IoBuf decision)
- `iobuf/bufs.rs` `test_iobufs_copy_to_bytes_past_end`,
  `test_iobufsmut_advance_mut_past_end_triple`, `test_iobufsmut_advance_mut_past_end_chunked`,
  `test_inline_overflow_panics`, `test_put_exceeding_capacity_panics`: #[should_panic] on
  `copy_to_bytes`, `put` from a `Buf`, `put_u8`, or the Triple/Chunked representations zigware
  lacks; the other nine are death tests in `iobuf_panic_test.zig`
- `iobuf/bufs.rs` `test_take_owned_front_chunk`, `test_iobuf_owner_record_allocations`,
  `test_iobufs_chunked_split_allocations`, `test_iobufsmut_fast_path_shapes`,
  `test_iobufsmut_noncanonical_chunk_and_chunk_mut_paths`, `test_iobuf_internal_chunk_helpers`,
  `test_inline_segments_share_one_record`: Single/Pair/Triple/Chunked representation, private
  helpers, owner-record allocation counts; runtime.md: `ChunkList` keeps its list "(commonware
  shrinks back to Single/Pair/Triple)"
- `iobuf/bufs.rs` `test_iobufs_from_iter_and_array_shapes`,
  `test_iobufs_from_iter_and_array_drop_empty_buffers`, `test_iobufs_from_iter_error_releases_buffers`,
  `test_iobufsmut_from_iter_and_array_shapes`,
  `test_iobufsmut_from_iter_and_array_preserve_capacity`, `test_iobufsmut_from_vec`,
  `test_iobufsmut_default`, `test_iobufsmut_from_array`, `test_iobufsmut_from_vec_u8_preserves_capacity`,
  `test_iobufs_additional_shape_and_conversion_paths`,
  `test_iobufsmut_additional_shape_and_conversion_paths`: From/FromIterator/Default conversions
  (Vec, arrays, `Bytes`, `BytesMut`, `Arc` strong counts)
- `iobuf/bufs.rs` `test_iobufsmut_decode_preserves_byte_fields`, `test_iobufsmut_matches_bytesmut_chain`,
  `test_iobufsmut_buf_matches_bytes_chain`: `Bytes` decoding and `bytes` `Chain`/`chain_mut`
  oracles
- `iobuf/bufs.rs` `test_iobufs_copy_to_bytes_pair_and_triple`,
  `test_iobufs_copy_to_bytes_chunked_four_plus`, `test_iobufs_copy_to_bytes_edge_cases`,
  `test_iobufs_chunks_vectored_multiple_slices`, `test_iobufsmut_copy_to_bytes`,
  `test_iobufsmut_copy_to_bytes_chunked_four_plus`, `test_iobufsmut_copy_to_bytes_canonicalizes_pair`,
  `test_iobufsmut_chunks_vectored_multiple_slices`, `test_iobufsmut_advance_mut_success_paths`,
  `test_iobufsmut_advance_mut_zero_noop_when_full`, `test_chunk_mut_and_advance_mut`: `Buf`/`BufMut`
  trait methods (`copy_to_bytes`, `chunks_vectored`, `chunk_mut`, `advance_mut`)

