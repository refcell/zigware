# resolver

Resolve data identified by a fixed-length key.

A Zig port of commonware's
[`commonware-resolver`](https://github.com/commonwarexyz/monorepo/tree/main/resolver).

## Status

**BETA** upstream: wire and storage formats are stable, and breaking changes come with a migration
path. See commonware's [stability levels](https://github.com/commonwarexyz/monorepo#stability).
The zigware port's backlog is done.
[docs/lanes/broadcast-resolver.md](../../docs/lanes/broadcast-resolver.md) tracks it. Its
[test audit][ta] counts 178 commonware tests: 173 ported, 0 open, and 5 not portable.

[ta]: ../../docs/lanes/broadcast-resolver.md#test-audit-resolver-2026-11-19-commonware-43b357a41

## Modules

- `Fetch`, `Delivery`, `Outcome`, `Predicate`, and the `assert_*` interface checks
  ([root.zig](root.zig)): fetch requests, deliveries, consumer verdicts, and the comptime
  `Consumer`, `Resolver`, and `TargetedResolver` interfaces.
- `subscribers` ([subscribers.zig](subscribers.zig)): tracks the subscribers waiting on each key.
- `ingress` ([ingress.zig](ingress.zig)): a mailbox message that coalesces fetches by key and
  prunes queued work with retain predicates.
- `delivery` ([delivery.zig](delivery.zig)): tracks pending consumer deliveries and their
  verdicts.
- `opaque` ([opaque.zig](opaque.zig)): a resolver over an opaque fetcher, with retries. Named
  `@"opaque"` because `opaque` is a Zig keyword.
- `p2p` ([p2p/mod.zig](p2p/mod.zig)): resolves keys over a p2p network: the wire format, peer
  scores, the `Fetcher` that tracks requests to peers, the `Engine`, its `Mailbox`, and mocks.

## Testing

```sh
zig build test-resolver                       # unit, engine, and seeded fuzz tests
zig build test --fuzz -Doptimize=ReleaseSafe  # long coverage-guided fuzz runs
```

The engine tests run many engines on `p2p.simulated` and the deterministic runtime. One test runs
on p2p's authenticated lookup network over the deterministic transport. A 16-seed DST sweep runs
the engine on lossy links and checks every retained key arrives exactly once. The fuzz tests
check the wire decoder and model-check the subscriber tracker, ingress, fetcher, and delivery
tracker.

## Differences from commonware

All of these are recorded in the
[broadcast-resolver lane decisions](../../docs/lanes/broadcast-resolver.md#decisions).

- Actors wait on one `delivery.Signal` instead of `select_loop!`. Each turn handles one event in
  commonware's arm order. Fetch aborts are `std.Io` cancelations.
- Retain predicates are `Predicate(K, S)` values with at most 64 bytes of inline state, so they
  queue in a mailbox without allocating.
- Trace spans point at their parents, so resolvers keep an owned root copy per subscriber. The
  first fetch's span wins.
- The p2p fetcher keeps peers, blocked peers, and per-key targets in sorted arrays instead of
  hash maps. It is deterministic under the deterministic runtime.
- `Delivery.subscribers` is a slice instead of a `NonEmptyVec`. Wire `encode_iobufs` has no
  counterpart, since there is no `IoBufs` yet.
