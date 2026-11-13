# Lane: runtime-telemetry

Owns `src/runtime/telemetry/` (split off the runtime lane). Add `pub const telemetry` to
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

## Backlog
- [x] metrics registry: counters, gauges, histograms (bucket layout as commonware), label
  sets, families, registration/scoping by component label, and Prometheus text exposition
  byte-identical to commonware's output for the same metrics. No allocation on the record
  path. Port the tests.
- [x] metrics: batched, status, task (per-task metrics), histogram helpers (timers).
- [ ] traces: span collector and status for tests (what commonware's tests assert on).
- [ ] Hook into `runtime.deterministic.Runner` (coordinate with the runtime lane, thread
  T-01a1d57b-1bfd-71b8-940f-5663d558c803) so `Context`/`metrics()` returns the registry.

## Log
- 2026-11-13: metrics registry, scopes, raw metrics, dtoa, byte-identical exposition.
- 2026-11-13: batched, status, task labels, histogram timers.
