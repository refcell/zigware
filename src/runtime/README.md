# runtime

Execute asynchronous tasks with a configurable scheduler.

A Zig port of commonware's
[`commonware-runtime`](https://github.com/commonwarexyz/monorepo/tree/main/runtime).

## Status

Upstream stability varies by primitive. **BETA** (wire and storage formats are stable, and
breaking changes come with a migration path): the core traits (spawner, clock, network,
storage), the tokio runtime, `iobuf`, `utils` (including `buffer` and `signal`), `telemetry`,
the blob header, and the metered storage, network, and process modules. Everything else is
**ALPHA** (breaking changes expected), including `deterministic`, `mocks`, `conformance`,
io_uring, and the audited, faulty, and memory storage. See commonware's
[stability levels](https://github.com/commonwarexyz/monorepo#stability).
Every backlog item in [docs/lanes/runtime.md](../../docs/lanes/runtime.md) is checked off.
`telemetry/` and `production/` are tracked in
[docs/lanes/runtime-telemetry.md](../../docs/lanes/runtime-telemetry.md), and `buffer/` in
[docs/lanes/storage-journal.md](../../docs/lanes/storage-journal.md). Every backlog item in
both is checked off.

## Modules

- `context` ([context.zig](context.zig)): `Context(Network)`, what a task is given to spawn,
  sleep, store, connect, and register metrics.
- `deterministic` ([deterministic.zig](deterministic.zig)): a runtime that runs tasks as fibers
  on one thread, in an order chosen by a seed.
- `production` ([production/mod.zig](production/mod.zig)): real time, files on disk, and TCP,
  on `std.Io.Threaded`, with optional io_uring.
- `fiber` ([fiber.zig](fiber.zig)): stackful fibers and their context switch.
- `supervision`, `signal` ([supervision.zig](supervision.zig), [signal.zig](signal.zig)): the
  tree of tasks an ending task takes down with it, and one-time shutdown broadcasts.
- `storage` ([storage.zig](storage.zig)): partitions of named blobs, as vtable interfaces.
- `network`, `mocks` ([network.zig](network.zig), [mocks.zig](mocks.zig)): the network
  interface, and the in-memory sink and stream pair under the deterministic network.
- `resolver` ([resolver.zig](resolver.zig)): DNS resolution of a host name.
- `iobuf` ([iobuf.zig](iobuf.zig)): `IoBufMut`, `IoBuf`, and chunk sequences for I/O.
- `buffer` ([buffer/mod.zig](buffer/mod.zig)): read and write buffers over a blob.
- `telemetry` ([telemetry/mod.zig](telemetry/mod.zig)): metrics and traces.
- `conformance` ([conformance.zig](conformance.zig)): commits a workload's storage audit as a
  conformance hash.
- `process.metered` ([process/metered.zig](process/metered.zig)): resident and virtual memory
  size of the process, on Linux only.

## Testing

```sh
zig build test-runtime                              # unit tests and seeded fuzz
zig build bench -Dbench-filter=runtime::            # I/O backend benchmarks (ReleaseFast)
```

Other bench prefixes: `buffer_paged::` and `iobuf::`. `zig build test` also runs each
benchmark once on its smoke inputs. For long fuzz runs, use
`zig build test --fuzz -Doptimize=ReleaseSafe`. The production network stress tests run only
with `-Dslow-tests`.

## Differences from commonware

- Tasks are stackful fibers, not polled futures. The deterministic runner implements
  `std.Io`, so `std.Io.Mutex`, `Condition`, `Queue`, and `Select` are deterministic. See the
  [runtime lane decisions](../../docs/lanes/runtime.md#decisions).
- Fibers block at different points than polled futures, so auditor digests compare only
  between zigware runs. Storage audits match commonware. See the
  [runtime lane decisions](../../docs/lanes/runtime.md#decisions).
- Abort is a `std.Io` cancelation, and a panic aborts the process. A `Handle` must be joined,
  aborted, or detached exactly once. See the
  [runtime lane decisions](../../docs/lanes/runtime.md#decisions).
- A `Runner` can `start` several roots in sequence, which replaces `Checkpoint` and `recover`.
  See the [runtime lane decisions](../../docs/lanes/runtime.md#decisions).
- Blobs sync synchronously and must be closed. `read_many` and `start_sync` are not ported.
  See the [runtime lane decisions](../../docs/lanes/runtime.md#decisions).
- The production runtime runs on `std.Io.Threaded`, because `std.Io.Uring` does not compile in
  Zig 0.17.1. io_uring is our own backend and stays off by default. See the
  [runtime-telemetry lane decisions](../../docs/lanes/runtime-telemetry.md#decisions).
- Traces have no global subscriber. Components take a `Tracer` from the context. See the
  [runtime-telemetry lane decisions](../../docs/lanes/runtime-telemetry.md#decisions).
