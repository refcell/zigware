# broadcast

Disseminate data over a wide-area network.

A Zig port of commonware's
[`commonware-broadcast`](https://github.com/commonwarexyz/monorepo/tree/main/broadcast).

## Status

**BETA** upstream: wire and storage formats are stable, and breaking changes come with a migration
path. See commonware's [stability levels](https://github.com/commonwarexyz/monorepo#stability).
The zigware port's backlog is done.
[docs/lanes/broadcast-collector.md](../../docs/lanes/broadcast-collector.md) tracks it. Its
[test audit][ta] counts 30 commonware tests, all ported.

[ta]: ../../docs/lanes/broadcast-collector.md#test-audit-broadcast-2026-11-19-commonware-43b357a41

## Modules

- `Feedback`, `assert_broadcaster` ([root.zig](root.zig)): the comptime `Broadcaster` interface.
  Feedback says whether the local request was accepted, not whether recipients got it.
- `digested` ([digested.zig](digested.zig)): `Digested(T)`, a shared, reference-counted value
  paired with its digest.
- `buffered` ([buffered/mod.zig](buffered/mod.zig)): an `Engine` that broadcasts messages to
  peers, caches messages from them, and serves cached messages through its `Mailbox`.

## Testing

```sh
zig build test-broadcast                      # engine tests and the fuzz targets, seeded
zig build test --fuzz -Doptimize=ReleaseSafe  # long coverage-guided fuzz runs
```

The engine tests run many engines on `p2p.simulated` and the deterministic runtime.
[fuzz.zig](fuzz.zig) ports commonware's `broadcast_engine_operations` target as a minifuzz test,
a coverage-guided test, and a seeded random-input test.

## Differences from commonware

All of these are recorded in the
[broadcast-collector lane decisions](../../docs/lanes/broadcast-collector.md#decisions).

- `broadcast.Digested` owns its value and counts references, because the cache, waiters, and
  responders share decoded values. It hashes inline instead of on a `Strategy`.
- The buffered config has no `Strategy`. The ingress task decodes inline, blocks peers whose
  messages fail to decode, and drops decoded messages beyond the receiver's capacity.
- The engine's `select_loop!` is a signal fed by an ingress task and two forwarders. It is
  checked in commonware's biased order: peer sets, mailbox, network.
- `count_running_tasks` has no counterpart. The shutdown tests check that aborted engines free
  everything and close their mailboxes.
