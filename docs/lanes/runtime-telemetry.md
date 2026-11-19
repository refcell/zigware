# Lane: runtime-telemetry

Owns `src/runtime/telemetry/` (split off the runtime lane) and, since its telemetry backlog
finished, the production runtime: `src/runtime/production/` (commonware's `iouring/`,
`tokio/`, `storage/iouring.rs`, `storage/tokio`, `network/iouring.rs`, `network/tokio.rs`). Add `pub const telemetry` to
`src/runtime/root.zig` (additive edit).

Reference: `~/.cache/zigware/commonware-ref/runtime/src/telemetry` (metrics: registry,
registration, histogram, batched, status, task; traces: collector, status). Everything
records metrics through this registry (actor mailboxes, p2p, storage, consensus), so land
the registry API first and report it.

## Public API (on main)

`runtime.telemetry.metrics` (`src/runtime/telemetry/metrics/`):
- `Registry.init(gpa)` / `deinit()` (every handle released first), `register(name, help,
  attributes: []const Attribute, metric) !Registered(M)` (takes ownership; a duplicate name and
  attributes returns the existing metric), `encode(gpa) ![]u8` (OpenMetrics text, byte-identical
  to commonware/prometheus-client 0.25, ending `# EOF\n`), `count()`.
- `Scope` (the metrics half of commonware's `Supervisor` + `Metrics`): `Scope.init(&registry)`,
  `child(label)` (prefix `a_b`, rejects `runtime*`), `sub_registry(label)` (runtime's own
  metrics), `with_attribute(key, value)` (sorted, replaces), `prefix()`, `register(name, help,
  metric)`, `counter`, `gauge`, `histogram(name, help, buckets)`, `family(L, M, name, help)`,
  `encode(gpa)`. A plain value with inline bounded storage; copy it into children freely.
- `Registered(M)`: `metric() *M`, `clone()`, `deinit()`, `detached(gpa, metric)`. Aliases
  `Counter`, `Gauge`, `Histogram`, `CounterFamily(L)`, `GaugeFamily(L)`.
- `raw.Counter` (`inc`, `inc_by`, `get`), `raw.Gauge` (`inc`, `dec`, `inc_by`, `dec_by`, `set`,
  `get`, `try_set`, `try_set_max`), `raw.Histogram.init(bounds)` (`observe`, `get_sum`,
  `get_count`), `raw.Family(L, M)` (`init(gpa)`, `init_with(gpa, prototype)`, `get_or_create(L)`,
  `get`, `remove`, `count`). `L` is a struct whose fields are the labels, in order; values are
  strings, integers, bools, enums (tag name, or `label_value()`), optionals, or `{f}` types.
- `Buckets.network`, `.local`, `.cryptography`; `metric_samples(text, name)`,
  `has_metric_value(text, name, value)` (commonware test utils); `is_valid_label`,
  `validate_label`, `metrics_prefix`; `dtoa.format` (Rust `dtoa` float formatting).

`runtime.resolver` (`src/runtime/resolver.zig`), commonware's `Resolver`:
- `Context.resolve(host) ![]codec.IpAddr` (free with `ctx.gpa()`; `error.ResolveFailed` when
  nothing resolves) and, on the deterministic runner, `Context.resolver_register(host,
  ?addresses)`. The deterministic `Dns` table belongs to the runner, so it survives restarts,
  and audits `resolver_register` and `resolve` with commonware's encoding. Production asks
  the system through `std.Io` (`production/resolver.zig`; port 0, the hosts file, then DNS).

## Decisions
- Handles are values (`clone`/`deinit` replace `Clone`/`Drop`). Each clone counts as a claim,
  so commonware's claims-versus-clones distinction is internal only; the observable rule (the
  metric leaves the registry when the last handle goes) is the same. Metric storage has its own
  reference count so a `Batched` writer can outlive the registration, as with commonware's `Arc`.
- No custom `Registration::from(guard)`: nothing outside commonware's own tests uses it.
- Registering one key with two metric types, or a family with two help texts or types, panics as
  in commonware; those `should_panic` tests have no counterpart (Zig tests cannot catch panics).
- Locks are spin locks (`std.atomic.Mutex`): critical sections never block or yield, so on the
  deterministic runtime they never spin, and record/release paths need no `Io`.
- Family entries encode in insertion order. prometheus-client iterates a `HashMap` (no stable
  order); multi-entry family output therefore matches commonware line-for-line but not in order.
- Floats are formatted by a port of the `dtoa` crate (Grisu2, not shortest), checked against the
  crate on edge cases and a 200,000-value hash; `std.fmt`'s output differs for some values.
- Golden expositions in the tests were generated with prometheus-client 0.25 itself.
- Drop guards (`ScopedTimer`, `CounterGuard`) become explicit `finish` calls for `defer`.
  `Timed::time_some` (wraps a future) has no counterpart; callers observe a `Timer` on success.
- `Scope` stays under 640 bytes (asserted) so a context can copy it into a task closure (the
  deterministic runner caps closures at 1 KiB): prefix up to 128 bytes, 4 attributes of up to
  96-byte values.
- Traces have no global subscriber (library code never touches global state): components take
  a `Tracer` (from `Context.tracer(target)`, over the runner's `Config.subscriber`) and tests
  read a `Collector`. A subscriber is a type-erased callback with a level filter, so a
  component without one pays one branch per event and formats nothing. Spans are
  explicit values with parent pointers instead of a task-local current span. The collector is
  bounded (`event_count_max`, overflow counted in `dropped`); commonware keeps every event.
- OTLP export is not ported (no OpenTelemetry dependency); `status` records the status on the
  span so tests can check it.

- `std.Io.Uring` (and so `std.Io.Evented` on Linux) does not compile in Zig 0.17.1
  (`batchAwaitConcurrent` switches on a `net_accept` operation `Io.Operation` lacks). The
  production runtime therefore runs on `std.Io.Threaded` (Linux and macOS); io_uring comes
  from our own backend over `std.os.linux.IoUring` behind the same storage/network vtables.
- Production storage (`production/storage.zig`) works on any `Io`: `<root>/<partition>/
  <hex(name)>`, `.hold` advisory lock, creation fsyncs the directory (and the root for a new
  partition) then writes the header with set_len(0)/write/fsync, removal fsyncs the parent,
  and the first open of an existing blob per instance fsyncs it. Commonware's async-drop
  settlement (`pending.rs`) has no counterpart: `close` is synchronous, so a handle's writes
  have reached the file before the next open. `dont_cache` read/write hints are accepted and
  ignored (std.Io has no per-call cache control).
- Production TCP (`production/network.zig`) follows commonware's tokio network: one socket
  split into a sink (closing it shuts down the write side) and a `BufReader`-like stream
  (`read_buffer_size`, 0 for unbuffered, large reads bypass the empty buffer), the same
  `Config` defaults (TCP_NODELAY, zero linger, 10 s connect, 60 s read and write timeouts),
  and `error.Timeout` (added to `network.Error`, commonware `Error::Timeout`).
  The listener does not set SO_REUSEADDR (std's `reuse_address` also sets SO_REUSEPORT, which
  would let a second bind of a live port succeed); zero linger already avoids TIME_WAIT.
- Two `std.Io.Threaded` 0.17.1 limits are worked around in `production/network.zig`: connect
  with a timeout panics (TODO), so a dial makes its own nonblocking connect and polls for it in
  20 ms slices, checking for cancellation between them, then hands `Threaded` the blocking
  socket; poll timeouts round down to whole milliseconds and can fire up to 1 ms early, so after an
  early timeout the operation waits out the deadline and retries once.
- `std.Io.Threaded` 0.17.1 `Future.create` does not reserve room for the result's
  misalignment: a future whose result is 16-byte aligned (anything holding an `i96`, such as
  `Io.Duration` or `Io.Clock.Timestamp`) is overrun by up to 8 bytes, which corrupts the heap.
  Sinks and streams keep their timeouts as `u64` nanoseconds for this reason.
- `production.Runner` owns its `std.Io.Threaded`, initializes in place (storage and network
  hold its `Io`), and `start` runs the root function on the calling thread. `start_context`
  runs it with a root `production.Context` (the runtime lane's `Context` over TCP), like
  `deterministic.Runner.start_context`; tasks it spawns are aborted when it returns.
- macOS CI (ReleaseSafe) once failed the TCP stress test with 552 leaks: one stress client
  returned an error mid-stream (96 accepted plus 95 dialed connections leaked; no data
  mismatch was reported), and the suite's early return leaked the rest. With the failing step
  logged, one of three manual ReleaseSafe runs (`macos-slow.yml`, run 43821271906) failed the
  same way: `stress client: dial failed: ConnectionFailed`, then `stress server: recv 0
  failed`, so the server had accepted the connection the client reported failed. A dial used
  to race `Threaded`'s blocking connect against a sleep, and cancel the sleep once the connect
  won. `Threaded` cancels a blocked syscall with `SIG.IO`, and a late signal can land on the
  thread after it has picked up another task's connect. `Threaded` retries an interrupted
  connect, and on Darwin the retry fails with EALREADY while the first attempt connects
  (`error.ConnectionPending`). The nonblocking connect above has no sleep task and no retried
  connect. Six manual ReleaseSafe runs after the fix all passed, where one in three had failed
  before. Audit: no other call that `Threaded` retries after EINTR is unsafe (reads, writes,
  polls, accepts, sleeps, futex waits, close), and library code no longer uses its connect
  (AGENTS.md pitfalls).
- io_uring (`production/ring.zig`) is a driver, not an executor: tasks stay on `std.Io`, and
  blob read/write/fsync and socket recv/sendmsg go through io_uring workers. Each commonware
  worker thread owns a ring; tasks on `std.Io.Threaded` are threads, so each thread that
  performs I/O owns a worker ring (`SINGLE_ISSUER | DEFER_TASKRUN`, registered with
  `REGISTER_RING_FDS`), created on its first operation and found through a 4-entry
  thread-local cache keyed by ring id. The thread submits and waits in one `io_uring_enter`
  (`EXT_ARG` timed waits of at most 20 ms), checking `io.checkCancel()` between slices, since
  `Threaded` interrupts only its own system calls. A canceled or timed-out operation is
  canceled with `ASYNC_CANCEL`, and the thread waits for both completions. A ring has room for
  256 workers; a thread without one (ring full, or the kernel refused it a ring) does its I/O
  through `std.Io`. Kernels before 6.1 get plain rings; before 5.11 (no `EXT_ARG`), none.
  Commonware's iouring executor (tasks scheduled on the ring thread) is not ported.
- io_uring stays off by default (`Config.io_uring`), like commonware's `iouring-network` and
  `iouring-storage` features over its tokio default. Per-thread workers reach parity with
  `std.Io.Threaded` but do not clearly beat it, so the default does not change.
  `zig build bench -Dbench-filter=runtime::` tracks both backends (ReleaseSafe, medians,
  loaded 32-core desktop):
  - `runtime::network::echo`, 16 connections × 1000 × 4 KiB: Threaded 24.9 ms, io_uring 23.6 ms
    (15 runs). With 64 × 4000 (`COMMONWARE_BENCH_FULL=1`): 205 ms and 197 ms.
  - `runtime::storage`, 8 blobs × 256 × 4 KiB written, synced, and read back: 30 ms each,
    within noise, since btrfs fsync dominates.
  Ping-pong echo is bound by wakeups, which both backends pay. io_uring saves Threaded's poll
  before each timed read, and little else, because a thread-per-task runtime cannot batch
  submissions. Earlier designs were far slower: one issuing ring thread 0.54 s and SQPOLL
  0.5 s, against Threaded's 60-90 ms on 16 × 4000.
- io_uring tests skip when the kernel cannot give a ring: unsupported, or `io_uring_setup`
  fails with ENOMEM because the user's locked-memory limit (shared by all of the user's
  processes, 8 MiB by default) is used up by other rings on the machine.
- `production.telemetry.serve(io, gpa, &scope, &server)` serves `GET /metrics` (commonware
  `tokio::telemetry::init`'s axum route, same `text/plain; version=0.0.4` content type) on its
  own `std.Io.net.Server`, outside the runtime network like commonware. It answers one request
  per connection, one connection at a time, until canceled; run it with `io.concurrent`.
  Log and OTLP setup are not ported: there is no global subscriber, and a runner's
  `Config.subscriber` takes events instead (see traces above).
- The production network stress tests run only with `-Dslow-tests` (commonware's
  `test_group("slow")`).

## Backlog
- [x] production runtime over `std.Io`: a `Runner` with the same surface as
  `deterministic.Runner` (io, storage, network, metrics), file-backed `runtime.storage`, and
  TCP `runtime.network`, passing `run_storage_tests`, `run_network_tests`, the network stress
  suite, and tokio's own storage and network tests.
- [x] Our own io_uring backend (`std.os.linux.IoUring`) behind the same storage and network,
  since `std.Io.Uring` does not compile, passing `run_storage_tests` and `run_network_tests`.
- [x] io_uring throughput: one issuing ring thread with batched submission (about 3× faster).
- [x] io_uring: one ring per worker thread (commonware's layout), at parity with Threaded;
  `runtime::network::echo` and `runtime::storage` benches; io_uring stays opt-in.
- [x] Runtime DNS `Resolver`: the deterministic table and the production system resolver,
  with `test_resolver` and `test_recover_dns_mappings_persist`.
- [x] Tracing events: level, target, message, and fields, delivered to a subscriber the
  runner carries (`Config.subscriber`, `Context.tracer`), free when nobody subscribes; a
  `Collector` subscribes for examples/ui's logger. Told p2p and consensus-simplex.
- [x] Executor-side `runtime_tasks_*` metrics (handed over by the runtime lane).
- [x] metrics registry: counters, gauges, histograms (bucket layout as commonware), label
  sets, families, registration/scoping by component label, and Prometheus text exposition
  byte-identical to commonware's output for the same metrics. No allocation on the record
  path. Port the tests.
- [x] metrics: batched, status, task (per-task metrics), histogram helpers (timers).
- [x] traces: span collector and status for tests (what commonware's tests assert on).
- [x] Hook into `runtime.deterministic.Runner`: the runner owns a registry and `metrics()`
  returns the root scope (a small additive edit to `deterministic.zig`).
- [x] With the runtime lane's `Context`: the context carries a `Scope` (runtime lane), the
  deterministic runner records `runtime_iterations`, and `Context.spawn` records
  `runtime_tasks_spawned` and `runtime_tasks_running` keyed by `task.Label` (the spawning
  context's label, never its attributes). Ported `test_count_running_tasks`,
  `test_metrics_spawn_attribute_cardinality`, and handle.rs's `tasks_running_*` tests; they
  run on both runners.
- [x] `runtime_task_polls` (deterministic: one per fiber resume) and the root task's
  `kind="Root"` series. `Context.spawn` names the fiber it starts through
  `Runtime.label_hook`; the deterministic runner copies the name into the task (also what
  `process_task` audits, as commonware's `label.name()`). A plain `io.concurrent` fiber takes
  its spawner's label, as commonware polls a task's inner futures within the task.

## Log
- 2026-11-13: metrics registry, scopes, raw metrics, dtoa, byte-identical exposition.
- 2026-11-13: batched, status, task labels, histogram timers.
- 2026-11-13: traces: Tracer, spans, Collector with commonware's assertions, status, traced.
- 2026-11-13: `deterministic.Runner.metrics()` over a runner-owned registry.
- 2026-11-13: production file storage passes `run_storage_tests` plus tokio's file tests.
- 2026-11-13: production TCP passes `run_network_tests`, the stress suite, and tokio's network
  tests; `production.Runner` ties io, file storage, TCP, and metrics together.
- 2026-11-13: io_uring driver; storage and TCP pass their suites over it; `Config.io_uring`.
- 2026-11-13: `production.telemetry`: the `/metrics` HTTP endpoint.
- 2026-11-13: io_uring: one ring thread issues every entry (`SINGLE_ISSUER | DEFER_TASKRUN`).
- 2026-11-16: `production.Runner.start_context`; stress-test diagnostics and `macos-slow.yml`.
- 2026-11-16: `runtime_task_polls` with task labels on deterministic fibers.
- 2026-11-16: `runtime_iterations`, `runtime_tasks_spawned`, `runtime_tasks_running`. The
  manual macOS slow run (Debug) passed the TCP stress test in 57 s; the ReleaseSafe failure
  has not recurred.
- 2026-11-16: io_uring: one worker ring per thread; runtime benches; io_uring stays opt-in.
- 2026-11-16: traces: `Subscriber`, `Event`, and `Context.tracer` over the runner's subscriber.
- 2026-11-16: `runtime.resolver`: `Context.resolve` on both runners, deterministic DNS table.

## Test audit (2026-11-19, against main)

Every commonware `#[test]` in this lane's crates (macro and rstest cases expanded where noted), matched by reading both sides: ported (a Zig test checks the behavior, often one consolidated test), open, or not portable with the reason. Written by the consensus-marshal lane; tick a box when its test lands.

### runtime (iouring/)
| File | Tests | Ported | Open | Not portable |
| --- | --- | --- | --- | --- |
| iouring/driver.rs | 40 | 3 | 3 | 34 |
| iouring/idle.rs | 12 | 0 | 0 | 12 |
| iouring/mailbox.rs | 5 | 0 | 0 | 5 |
| iouring/operation.rs | 21 | 0 | 1 | 20 |
| iouring/pool.rs | 10 | 0 | 0 | 10 |
| iouring/queue.rs | 34 | 0 | 0 | 34 |
| iouring/request.rs | 26 | 1 | 8 | 17 |
| iouring/slab.rs | 5 | 0 | 0 | 5 |
| iouring/sleep.rs | 13 | 0 | 0 | 13 |
| iouring/sockaddr.rs | 2 | 0 | 0 | 2 |
| iouring/spinner.rs | 14 | 0 | 0 | 14 |
| iouring/task.rs | 32 | 0 | 0 | 32 |
| iouring/tasks.rs | 13 | 0 | 0 | 13 |
| iouring/tests.rs | 96 | 2 | 1 | 93 |
| iouring/timeout.rs | 17 | 0 | 0 | 17 |
| iouring/waiter.rs | 15 | 2 | 2 | 11 |
| iouring/waker.rs | 42 | 0 | 0 | 42 |
| Total | 397 | 8 | 15 | 374 |

Open:
- [x] `iouring/driver.rs:1355` `test_expired_registration_never_stages`: an already-expired
  deadline submits nothing
- [x] `iouring/driver.rs:1537` `test_completion_wins_cancellation`: a success CQE after cancel
  keeps its result
- [x] `iouring/driver.rs:2929` `test_enter_distinguishes_timeout_from_failure`: enter treats
  ETIME as a timeout, other errors as failure
- [x] `iouring/operation.rs:369` `test_expired_registration_does_not_consume_ready_data`:
  expired recv leaves socket data unread
- [x] `iouring/request.rs:1439` `test_cqe_result_from_raw_retryable_codes`: EAGAIN, EWOULDBLOCK,
  and EINTR results retry
- [x] `iouring/request.rs:1526` `test_scalar_length_prefix_boundary`: an I/O length above
  u32::MAX is clamped per SQE
- [x] `iouring/request.rs:1537` `test_scalar_builders_preserve_partial_progress`: resubmitted
  send/recv/read SQEs start after prior progress
- [x] `iouring/request.rs:1574` `test_active_send_paths`: send retries EAGAIN, crosses buffers,
  maps errors to SendFailed
- [x] `iouring/request.rs:1613` `test_active_recv_paths`: recv retry, exact vs. partial
  completion, EOF and error mapping
- [x] `iouring/request.rs:1652` `test_active_read_at_paths`: read_at retries, accumulates, short
  read gives InsufficientLength, EIO ReadFailed
- [x] `iouring/request.rs:2125` `test_large_single_write_preserves_progress_and_durability`:
  write above u32::MAX bytes completes across CQEs
- [x] `iouring/request.rs:2167` `test_active_write_at_paths`: write_at retries, keeps its prefix,
  0/EIO/ECANCELED give WriteFailed
- [x] `iouring/tests.rs:1082`
  `test_nested_same_directory_rejected_before_closure_and_outer_remains_usable`: second runner
  on a held dir fails first
- [x] `iouring/waiter.rs:991` `test_cancellation_preserves_terminal_results`: a result or error
  that beats cancel wins over Timeout
- [x] `iouring/waiter.rs:1026`
  `test_orphaned_reads_and_sends_stop_before_staging_or_after_partial_completion`: dropped
  op stops after partial progress

Not portable:
- [executor] means the lane decision in docs/lanes/runtime-telemetry.md: "Commonware's
  iouring executor (tasks scheduled on the ring thread) is not ported"; tasks stay on `std.Io`
- `iouring/mailbox.rs` `test_take_requires_empty_scratch`, `iouring/spinner.rs`
  `test_new_panics_when_budget_exceeds_max`, `iouring/tasks.rs`
  `test_drain_of_an_open_set_is_rejected`: #[should_panic], and the type is in the
  [executor] that was not ported
- `iouring/task.rs` (all 32), `iouring/tasks.rs` (other 12), `iouring/pool.rs` (all 10),
  `iouring/queue.rs` (all 34), `iouring/idle.rs` (all 12), `iouring/spinner.rs` (other 13),
  `iouring/mailbox.rs` (other 4): task cells, task sets, work-stealing run queues, the
  global queue, idle/search accounting, the idle spinner, and the cross-worker mailbox are
  all [executor] parts; `std.Io.Threaded` schedules Zig tasks
- `iouring/waker.rs` (all 42): eventfd/futex parking and wake dedup for ring threads
  [executor]. A Zig worker blocks only in its own `io_uring_enter` and never takes wakes
  from other threads
- `iouring/sleep.rs` (all 13): the executor's timer registry [executor]. Zig sleeps go
  through `std.Io` (`ctx.sleep`)
- `iouring/tests.rs` (93; all but 1082, 1114, 3661): end-to-end tests of commonware's
  iouring Runner as an executor [executor]: root/spawn/dedicated/foreign-context placement,
  factories and reservations, worker startup failure, panic containment and policy, TLS
  teardown, shutdown and teardown ordering, work stealing and global-queue intervals,
  search counts, worker-closure lifetimes of operations and direct/paged reads, the
  pending-operations gauge, queued writes drained at shutdown, and config validation of
  executor settings (workers, queue interval, spinner, timeout wheel); includes the
  rstest cases of `test_worker_closure_wakes_shared_observers_before_forwarding` and
  `test_paged_replay_survives_the_worker_that_issued_its_reads_closing`
- `iouring/operation.rs` (20; all but 369): async `Operation` handles registered on a worker,
  with observer/waker clones, forwarding to other threads, escaping a worker's closure, and
  queuing behind a full ring. Zig's `perform` is synchronous on the calling thread's ring
  (one op plus its cancel), so operations never move, queue, or get orphaned [executor]
- `iouring/driver.rs` (31): `test_unconsumed_results_leave_staging_and_deadline_tracking`,
  `test_cancelled_backlog_compacts_at_staging_limit`,
  `test_expired_backlog_compacts_at_staging_limit`,
  `test_staging_limit_parks_and_preserves_fifo_across_growth`,
  `test_queued_expiry_and_cancellation_progress_at_staging_limit`,
  `test_unconsumed_result_releases_staging_capacity`,
  `test_staging_discards_stale_ids_with_full_sq`,
  `test_advance_timeouts_ignores_stale_entry_after_slot_reuse`,
  `test_deadline_registration_uses_refreshed_wheel`,
  `test_unsupported_deadline_is_rejected_without_submission`,
  `test_cancel_acknowledgement_invariants`,
  `test_request_retirement_releases_hold_before_cancel_acknowledgement`,
  `test_orphaned_follow_up_cannot_stage_reused_slot`,
  `test_orphaned_read_retries_do_not_requeue`, `test_expiring_bucket_preserves_unconsumed_success`,
  `test_stale_waiter_identity_cannot_orphan_reused_slot`,
  `test_deferred_taskrun_is_serviced_during_busy_turn`,
  `test_wake_poll_alone_does_not_require_kernel_service`,
  `test_skipped_park_keeps_deferred_service_obligation`, `test_publish_wakes_eventfd_blocked_loop`,
  `test_park_rearms_wake_poll_with_full_sq`,
  `test_transient_flush_without_sq_progress_returns_through_service`,
  `test_partial_completion_releases_capacity_to_next_queued_request`,
  `test_same_open_sync_waits_for_failure_accounting`,
  `test_durable_write_keeps_permit_through_follow_up_sqes`,
  `test_blocked_durability_does_not_count_as_ready_during_compaction`,
  `test_durability_admitted_after_service_registers_its_wait`,
  `test_foreign_durability_release_wakes_closed_worker_park`,
  `test_shutdown_finishes_orphaned_write_and_detached_sync`,
  `test_busy_service_and_expired_park_do_not_sleep`,
  `test_every_enter_reports_a_dropped_completion`: internals of commonware's multiplexed
  driver: the staging queue and SQ limit, waiter-slot reuse, the timeout wheel, the
  wake-poll/eventfd park, deferred-taskrun service, per-open durability permits, orphaned
  ops, and CQ overflow. Zig has one op plus one cancel per thread ring, so there is no
  queue, slab, wheel, park, permit, or overflow
- `iouring/driver.rs` `test_cancelled_direct_reads_retain_their_owners_until_completion`,
  `test_forwarded_direct_read_falls_back_through_its_observer`,
  `test_direct_reads_are_served_by_the_direct_descriptor`: O_DIRECT reads; zigware storage
  has no direct-I/O path
- `iouring/request.rs` `test_direct_read_covers_the_aligned_superset`,
  `test_direct_chunks_progress_under_every_page_cap`, `test_direct_read_completion_sequences`,
  `test_direct_fallback_rereads_the_range_and_keeps_buffered_progress`: O_DIRECT reads (none in
  zigware)
- `iouring/request.rs` `test_uncached_read_fallback_preserves_progress_and_is_shared_with_writes`,
  `test_queued_cache_fallbacks_retry`, `test_uncached_sync_write_retries_without_hint_when_unsupported`:
  RWF_DONTCACHE hint fallback; Zig ring ops pass no rw flags
- `iouring/request.rs` `test_sync_completion_credits_only_its_successful_barrier`,
  `test_durability_completion_retains_failure`: commonware's per-open durability tracker
  (fused RWF_DSYNC writes, sync barriers); Zig's fsync is a plain synchronous op
- `iouring/request.rs` `test_connect_completion_rules`, `test_poll_completion_rules`: connect and
  accept-poll over the ring; Zig does only recv/sendmsg there (connect/accept use `std.Io`)
- `iouring/request.rs` `test_write_cursor_retains_owners_across_batches`,
  `test_write_cursor_single_and_overrun`, `test_partial_progress_retires_reentrant_panicking_owner`,
  `test_complete_preserves_status_and_read_buffers`: Rust ownership of `IoBufs` owners across
  SQEs (drop timing, reentrant/panicking destructors)
- `iouring/request.rs` `test_request_metadata_and_sqe_tags`,
  `test_read_builders_reject_invalid_buffer_bounds`: commonware `Request` enum metadata and
  builder assertions with no Zig counterpart type
- `iouring/waiter.rs` (11): `test_user_data_encoding`,
  `test_cqe_resolves_full_generation_after_kernel_wrap`,
  `test_retained_result_does_not_count_as_pending_or_recycle_early`,
  `test_exhausted_generation_retires_slot_after_result_consumption`,
  `test_observer_refresh_and_completion_defer_waking`, `test_invalid_ids`,
  `test_failed_sqe_construction_keeps_request_unsubmitted`,
  `test_queued_timeout_retains_result_until_drop`,
  `test_close_defers_local_and_forwarded_notifications`,
  `test_close_clears_results_and_keeps_unobserved_syncs`,
  `test_growth_preserves_in_flight_identity_and_counts`: generational waiter slab, user_data
  encoding, retained results, and worker close. Zig uses fixed user_data 1 (op) and 2 (cancel)
  and returns results directly
- `iouring/timeout.rs` (all 17): the timeout wheel; Zig uses `EXT_ARG` timed enters of at
  most 20 ms against a per-op deadline
- `iouring/slab.rs` (all 5): the generational slab behind waiters and timers; none in Zig
- `iouring/sockaddr.rs` (both 2): raw sockaddr conversion for ring connect; Zig never
  connects over the ring

Behavior gap found by the audit: `production/ring.zig` `abort` waits for the operation and its cancel, then returns the error even when the operation completed, so a recv that lost a cancel or timeout race drops bytes it already read. commonware keeps the completed result (iouring `driver.rs:1537`, `waiter.rs:991`). Fixed in 130412f: an operation that completes first keeps its result and a consumed cancellation is re-armed. Two more gaps found while porting the rest, fixed with their tests: `perform` staged an operation for an already-canceled task, so a recv could consume ready data and a retry after EAGAIN or partial progress resubmitted (`waiter.rs:1026`); and a second storage on a root this process already held waited on its own process's lock forever, where commonware rejects a nested runtime before taking the hold (`tests.rs:1082`). `production.storage` now keeps a process-wide set of held roots and fails such an init with `error.Io`.

