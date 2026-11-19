# p2p

Communicate with authenticated peers.

A Zig port of commonware's
[`commonware-p2p`](https://github.com/commonwarexyz/monorepo/tree/main/p2p).

## Status

Upstream stability varies by primitive. `simulated` is **ALPHA**: breaking changes are expected.
`authenticated`, `types`, `utils`, and the root traits are **BETA**: wire and storage formats are
stable, and breaking changes come with a migration path. See commonware's
[stability levels](https://github.com/commonwarexyz/monorepo#stability).
The p2p lane's own backlog is done. [docs/lanes/p2p.md](../../docs/lanes/p2p.md) tracks it. Its
[test audit](../../docs/lanes/p2p.md#test-audit-p2p-2026-11-19-commonware-43b357a41) counts 476
commonware tests: 359 ported, 86 open, 31 not portable. `authenticated/lookup/` belongs to the
parallel lane ([docs/lanes/parallel.md](../../docs/lanes/parallel.md)).

## Modules

- `Channel`, `Message(P)`, `Recipients(P)`, and the `assert_*` interface checks
  ([root.zig](root.zig)): channel ids, received messages, recipient sets, and the comptime
  `Sender`, `Receiver`, `Manager`, and `Blocker` interfaces.
- `types` ([types.zig](types.zig)): `Ingress` and `Address`, the addresses a peer dials and
  connects from.
- `sizing` ([sizing.zig](sizing.zig)): message and peer-set size limits.
- `rate_limit` ([rate_limit.zig](rate_limit.zig)): `Quota` and `KeyedRateLimiter`, a keyed GCRA
  rate limiter.
- `utils` ([utils/mod.zig](utils/mod.zig)): rate-limited senders, a latest-value `Watch`,
  codec-wrapped channels, a channel muxer, and mocks.
- `simulated` ([simulated/mod.zig](simulated/mod.zig)): a simulated network with configurable
  latency, jitter, drops, bandwidth limits, and blocking.
- `authenticated` ([authenticated/mod.zig](authenticated/mod.zig)): networks of authenticated
  peers. [`lookup`](authenticated/lookup/mod.zig) dials peers at known addresses, and
  [`discovery`](authenticated/discovery/mod.zig) finds addresses from bootstrappers.
- `fuzz` ([fuzz.zig](fuzz.zig)): p2p's seeded fuzz driver and decoder fuzz targets.

## Testing

```sh
zig build test-p2p                            # unit, network, and seeded fuzz tests
zig build test --fuzz -Doptimize=ReleaseSafe  # long coverage-guided fuzz runs
```

The network tests run many nodes on the deterministic runtime, over `simulated` or over the
deterministic transport. The fuzz targets in [fuzz/](fuzz/) drive the simulated, discovery, and
lookup networks.

## Differences from commonware

All of these are recorded in the [p2p lane decisions](../../docs/lanes/p2p.md#decisions).

- The simulated network runs operations in the caller's task under one `Io.Mutex`, not in an
  actor. One `run` task delivers into per-peer, per-channel mailboxes. Send order and arrival
  times per link match commonware, but `priority` does not reorder sends.
- The authenticated router is shared state behind a lock, not an actor. A frame is encoded once
  and queued on each recipient's outbox in the caller's task.
- Discovery runs its dialer, listener, handshakes, and connections as tasks in one `Io.Group`.
  The tracker is locked state instead of an actor. A finished listener or dialer does not stop
  the network; cancelation does.
- Message payloads are byte slices until the runtime lane ports `IoBuf`.
- `Quota` and `KeyedRateLimiter` live in p2p until the runtime lane takes them. Keys sit in a
  sorted array, so the limiter is deterministic.
- Link latency samples match `rand_distr`'s `Normal` bit for bit. Whole-run random streams can
  still differ, because the scheduler and the network's task layout differ from commonware's.
