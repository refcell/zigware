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

## Decisions
- The deterministic executor implements `std.Io` (`deterministic.Runner.io()`): tasks
  (`async`/`concurrent`/groups), futexes, sleep, clocks, and randomness on stackful fibers
  (`fiber.zig`, built on `std.Io.fiber.contextSwitch`). So `std.Io.Mutex`, `Condition`,
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

## Log
- 2026-11-13: fibers, rand-compatible shuffle, deterministic executor implementing `std.Io`.
