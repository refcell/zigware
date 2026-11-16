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
  by runtime-telemetry (515cd03, 6929fea). Not yet: `runtime_task_polls` and the root's
  `kind="Root"` series.
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
  mocks.rs's wrapper tests. No counterpart: `DelayedSyncContext`/`PendingSyncs` (no
  `start_sync`), `MigratingReadBlob` (moves a half-polled read), read batches (no
  `read_many`).
- [x] `conformance.StorageConformance(Workload)` (conformance.rs): runs a workload on a
  runner seeded with the case seed and commits `storage_audit()`, in `conformance.verify`'s
  `commit(gpa, seed)` shape; its three audit tests.
- [x] memory/mod.rs: crash-write merging and subset writes keeping v0/v1 headers.
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
  `Blob.read_at` fills a caller buffer (commonware's `read_at_buf`); `read_many` and
  `start_sync` are not ported (callers loop, and `sync` is synchronous in zigware).
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
  generation. It has no `start_sync` (zigware's `sync` is synchronous), so commonware's
  start_sync, async-gating, and read-option recording tests are not ported. The runner
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
  `network.metered.Metrics`. Not ported: metered `start_sync` and shared-owner tests (no
  `start_sync`; a Zig blob handle has one owner).
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
