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
  hold its `Io`), and `start` runs the root function on the calling thread.

## Backlog
- [x] production runtime over `std.Io`: a `Runner` with the same surface as
  `deterministic.Runner` (io, storage, network, metrics), file-backed `runtime.storage`, and
  TCP `runtime.network`, passing `run_storage_tests`, `run_network_tests`, the network stress
  suite, and tokio's own storage and network tests.
- [ ] Our own io_uring backend (`std.os.linux.IoUring`) behind the same storage and network,
  since `std.Io.Uring` does not compile; run on Linux through `just test-linux` / CI.
- [ ] Executor-side `runtime_tasks_*` metrics, if the runtime lane hands them over.
- [x] metrics registry: counters, gauges, histograms (bucket layout as commonware), label
  sets, families, registration/scoping by component label, and Prometheus text exposition
  byte-identical to commonware's output for the same metrics. No allocation on the record
  path. Port the tests.
- [x] metrics: batched, status, task (per-task metrics), histogram helpers (timers).
- [x] traces: span collector and status for tests (what commonware's tests assert on).
- [x] Hook into `runtime.deterministic.Runner`: the runner owns a registry and `metrics()`
  returns the root scope (a small additive edit to `deterministic.zig`).
- [ ] With the runtime lane, once `Context` lands (runtime lane, thread
  T-01a1d57b-1bfd-71b8-940f-5663d558c803): the context carries a `Scope` (`child`,
  `with_attribute`, `register`, `encode`), audits `register`/`encode` like commonware, and the
  executor records `runtime_iterations`, `runtime_tasks_spawned`, `runtime_tasks_running`, and
  `runtime_task_polls` keyed by `task.Label`; then port `test_count_running_tasks` and
  `test_metrics_spawn_attribute_cardinality`.

## Log
- 2026-11-13: metrics registry, scopes, raw metrics, dtoa, byte-identical exposition.
- 2026-11-13: batched, status, task labels, histogram timers.
- 2026-11-13: traces: Tracer, spans, Collector with commonware's assertions, status, traced.
- 2026-11-13: `deterministic.Runner.metrics()` over a runner-owned registry.
- 2026-11-13: production file storage passes `run_storage_tests` plus tokio's file tests.
- 2026-11-13: production TCP passes `run_network_tests`, the stress suite, and tokio's network
  tests; `production.Runner` ties io, file storage, TCP, and metrics together.
