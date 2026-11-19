# actor

Safely coordinate concurrent components.

A Zig port of commonware's
[`commonware-actor`](https://github.com/commonwarexyz/monorepo/tree/main/actor).

## Status

**BETA** upstream: wire and storage formats are stable, and breaking changes come with a migration
path. See commonware's [stability levels](https://github.com/commonwarexyz/monorepo#stability).
The zigware port is complete. [docs/lanes/actor-stream.md](../../docs/lanes/actor-stream.md)
tracks it, including its test audit.

## Modules

- `Feedback`, `Unreliable(T)` ([root.zig](root.zig)): the outcome of submitting work to a
  bounded endpoint (accepted, backed off, or closed), optionally wrapped for endpoints that may
  reject work.
- `mailbox` ([mailbox.zig](mailbox.zig)): a bounded message queue with caller-managed overflow,
  which actors use as their inbox.

## Testing

```sh
zig build test-actor                    # unit tests, including the seeded mailbox fuzz
zig build bench -Dbench-filter=mailbox  # mailbox benchmarks (ReleaseFast)
```

`zig build test` also runs each benchmark once on its smoke inputs.

## Differences from commonware

All of these are recorded in the
[actor-stream lane decisions](../../docs/lanes/actor-stream.md#decisions).

- The mailbox keeps commonware's lock-free ready queue and activity word, but a futex word
  replaces `AtomicWaker`. Every wait goes through `std.Io`, so it also runs on the
  deterministic runtime.
- Handles are values: `clone` and `deinit` replace `Clone` and `Drop`. A dropped message goes
  through its type's optional `discard`.
- `mailbox.new` takes no metrics context, so its backoff counter is detached.
  `new_with_metrics` registers the counter as `<scope>_backoff_total`.
- There are no loom tests, because Zig has no loom. `std.Io.Threaded` stress tests cover the
  same lock-free paths.
  Concurrency is tested on the deterministic runtime and with a seeded FIFO fuzz instead.
