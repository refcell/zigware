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
  a `Tracer` (from the runtime context once hooked up) and tests read a `Collector`. Spans are
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
  with a timeout panics (TODO), so a dial races the connect against a sleep with `Io.Select`;
  poll timeouts round down to whole milliseconds and can fire up to 1 ms early, so after an
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
  mismatch was reported), and the suite's early return leaked the rest. The cause is not
  known yet. The stress cases now log the failing step and error, and `macos-slow.yml` runs
  `-Dslow-tests` on macOS in Debug by hand.
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
  Log and OTLP setup are not ported (no global subscriber; see traces above).
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
- [ ] Tracing events: level, target, message, and fields, delivered to a subscriber the
  runtime or Context carries, free when nobody subscribes; examples/ui's logger subscribes
  with its JSON and text formats. Then tell p2p and consensus-simplex.
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
