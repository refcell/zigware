# Lane: runtime

Owns `src/runtime`. This is the most depended-on lane after codec: actor, stream, storage,
p2p, and every protocol run on it. Land the interface and the deterministic runtime first,
document the interface at the top of `src/runtime/root.zig`, and keep it stable.

Reference: `~/.cache/zigware/commonware-ref/runtime`. Zig 0.17.1's `std.Io` already has
fibers, io_uring (`std/Io/Uring.zig`), kqueue, threads, and an interface (vtable) for tasks,
time, files, and network: build on it rather than around it where it fits.

## Backlog
- [ ] Interface: `Context` with spawner (spawn, labeled children, abort, join handles),
  clock (current, sleep, sleep_until, timeouts), RNG, network (`Listener`, `Sink`, `Stream`),
  storage (`Blob` with read_at/write_at/resize/sync, partitions open/remove/scan), metrics
  registry, `Signal`/stop. Mirror lib.rs traits.
- [ ] deterministic runtime: seeded single-threaded executor, simulated time that jumps to
  the next timer, `auditor` (hash of all events, compare runs), checkpoint/restart
  (`recover`), deterministic network and in-memory storage with fault injection (faulty.rs).
  Port deterministic.rs tests.
- [ ] iobuf (IoBuf/IoBufs pooled buffers) and utils (buffer pools, handle, signal,
  supervision).
- [ ] storage: header.rs blob header format byte-identical, audited, metered, memory.
- [ ] production runtime over `std.Io` (io_uring on Linux, kqueue on macOS): network and
  storage. Linux tests via `just test-linux`.
- [ ] telemetry: metrics registry (counters, gauges, histograms) with text exposition.

## Log
