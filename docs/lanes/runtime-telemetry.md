# Lane: runtime-telemetry

Owns `src/runtime/telemetry/` (split off the runtime lane). Add `pub const telemetry` to
`src/runtime/root.zig` (additive edit).

Reference: `~/.cache/zigware/commonware-ref/runtime/src/telemetry` (metrics: registry,
registration, histogram, batched, status, task; traces: collector, status). Everything
records metrics through this registry (actor mailboxes, p2p, storage, consensus), so land
the registry API first and report it.

## Backlog
- [ ] metrics registry: counters, gauges, histograms (bucket layout as commonware), label
  sets, families, registration/scoping by component label, and Prometheus text exposition
  byte-identical to commonware's output for the same metrics. No allocation on the record
  path. Port the tests.
- [ ] metrics: batched, status, task (per-task metrics), histogram helpers (timers).
- [ ] traces: span collector and status for tests (what commonware's tests assert on).
- [ ] Hook into `runtime.deterministic.Runner` (coordinate with the runtime lane, thread
  T-01a1d57b-1bfd-71b8-940f-5663d558c803) so `Context`/`metrics()` returns the registry.

## Log
