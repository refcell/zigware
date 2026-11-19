# collector

Collect responses to committable requests.

A Zig port of commonware's
[`commonware-collector`](https://github.com/commonwarexyz/monorepo/tree/main/collector).

## Status

**ALPHA** upstream: breaking changes are expected. See commonware's
[stability levels](https://github.com/commonwarexyz/monorepo#stability).
The zigware port's backlog is done, with every `ingress.rs` and `mod.rs` test ported.
[docs/lanes/broadcast-collector.md](../../docs/lanes/broadcast-collector.md) tracks it.

## Modules

- `Feedback`, `assert_originator`, `assert_handler`, `assert_monitor` ([root.zig](root.zig)):
  the comptime `Originator`, `Handler`, and `Monitor` interfaces.
- `p2p` ([p2p/mod.zig](p2p/mod.zig)): an `Engine` that sends requests and collects responses
  over a p2p network, its `Mailbox` (an `Originator`), and mocks.

## Testing

```sh
zig build test-collector                      # engine tests and the fuzz target, seeded
zig build test --fuzz -Doptimize=ReleaseSafe  # long coverage-guided fuzz runs
```

The engine tests run many engines on `p2p.simulated` and the deterministic runtime.
[fuzz.zig](fuzz.zig) ports commonware's `collector` target as a minifuzz test, a
coverage-guided test, and a seeded random-input test.

## Differences from commonware

All of these are recorded in the
[broadcast-collector lane decisions](../../docs/lanes/broadcast-collector.md#decisions).

- The engine's `select_loop!` is a signal fed by forwarders, checked in a biased order: mailbox,
  handler replies, requests, responses.
- Each handler reply is awaited by its own task in an `Io.Group`, in place of commonware's
  futures `Pool`.
- Commonware's collector has no conformance hashes. The mocks check the request and response
  encodings byte for byte.
- `count_running_tasks` has no counterpart. The shutdown tests check that aborted engines free
  everything and close their mailboxes.
- The fuzz target draws its inputs like commonware's `arbitrary` impls. Its `Recipients::Some`
  shuffle is checked against rand 0.10.3 vectors.
