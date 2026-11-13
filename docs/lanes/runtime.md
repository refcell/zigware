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
- [x] deterministic runtime executor: seeded single-threaded executor on fibers, simulated
  time that jumps to the next timer, `auditor`, restart by calling `start` again.
- [x] storage interface (`storage.zig`: `Storage`, `Blob`, layouts, versions, options).
- [x] storage header (`storage/header.zig`), conformance hashes V0Blob, V1Blob, Header.
- [x] in-memory storage (`storage/memory.zig`), storage suite (`storage/tests.zig`), audit
  digests checked against commonware.
- [x] storage in `deterministic.Runner` (`storage()`, `storage_audit()`, crash on restart).
- [ ] faulty.rs storage fault injection; audited and metered storage wrappers.
- [x] mock channel (`mocks.zig`), deterministic network (`network/deterministic.zig`),
  network suite (`network/tests.zig`), `Runner.network()`.
- [ ] audited and metered network wrappers.
- [ ] Port remaining deterministic.rs tests.
- [ ] iobuf (IoBuf/IoBufs pooled buffers) and utils (buffer pools, handle, signal,
  supervision).
- [ ] (moved to the runtime-telemetry lane) production runtime over `std.Io` (io_uring on Linux, kqueue on macOS): network and
  storage. Linux tests via `just test-linux`.
- Telemetry (`src/runtime/telemetry/`, metrics registry and traces) moved to the
  runtime-telemetry lane. `src/runtime/buffer/` belongs to storage-journal.

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
- The memory backend guards its state with one spin lock that never blocks inside, so it
  is safe across threads and never yields a fiber while held.

## Log
- 2026-11-13: fibers, rand-compatible shuffle, deterministic executor implementing `std.Io`.
- 2026-11-13: naked-function fiber switch (fixes ReleaseSafe crashes on x86_64 and aarch64).
- 2026-11-13: storage interface, blob header with conformance hashes, memory backend and
  the storage suite.
- 2026-11-13: runner storage, mock channel, deterministic network and network suite.
