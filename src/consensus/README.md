# consensus

Order opaque messages in a Byzantine environment.

A Zig port of commonware's
[`commonware-consensus`](https://github.com/commonwarexyz/monorepo/tree/main/consensus).

## Status

Upstream stability varies by primitive. `simplex`, `marshal`, `types`, and the reporters are
**BETA**: wire and storage formats are stable, and breaking changes come with a migration path.
`aggregation` is **ALPHA**: breaking changes are expected. Some parts of the BETA modules are
ALPHA too, such as marshal's erasure-coded variant and simplex's secp256r1 scheme. See
commonware's [stability levels](https://github.com/commonwarexyz/monorepo#stability).

The zigware port is in progress. Three lane files track it:

- [docs/lanes/consensus-simplex.md](../../docs/lanes/consensus-simplex.md) tracks the root,
  `types`, `reporter`, and `simplex`. Its backlog is done except the 96 voter-actor tests of
  `actors/voter/mod.rs`, which are not ported yet.
- [docs/lanes/consensus-marshal.md](../../docs/lanes/consensus-marshal.md) tracks `marshal`
  and `aggregation`. Its test tally ports 188 of the 197 tests in `marshal/standard/mod.rs`
  and 100 of the 101 in `marshal/coding/mod.rs`; the rest cannot be ported. Nothing is open
  in aggregation.
- [docs/lanes/broadcast-collector.md](../../docs/lanes/broadcast-collector.md) tracks
  `marshal/coding`, the erasure-coded variant.

## Modules

- `types` ([types.zig](types.zig)): `Epoch`, `Height`, `View`, `Round`, their deltas and
  ranges, `TermLength`, and `FixedEpocher`.
- `traits` ([traits.zig](traits.zig)): commonware's consensus traits (`Automaton`, `Relay`,
  `Reporter`, `Block`, ...) as comptime interfaces.
- `reporter` ([reporter.zig](reporter.zig)): `Optional(R)` and `Reporters(R1, R2)`, which
  reports to two reporters and returns the worst feedback.
- `simplex` ([simplex/root.zig](simplex/root.zig)): simplex-like BFT agreement with an
  embedded VRF and succinct certificates: wire types, signing schemes, electors, the voter,
  batcher, and resolver actors, and the `Engine` that runs them.
- `marshal` ([marshal/root.zig](marshal/root.zig)): ordered delivery of finalized blocks to
  the application, in a standard variant (whole blocks) and an erasure-coded variant
  (`coding`).
- `aggregation` ([aggregation/root.zig](aggregation/root.zig)): recovers quorum certificates
  over an externally synchronized sequence of items.

## Testing

```sh
zig build test-consensus                         # unit tests, DSTs, and seeded minifuzz
zig build test-consensus -Dslow-tests            # also the large tests and every scheme
zig build test-consensus -Doptimize=ReleaseSafe  # optimized, with safety checks
zig build test --fuzz -Doptimize=ReleaseSafe     # long coverage-guided fuzz runs
```

In Debug, marshal and aggregation run their multi-node tests with ed25519 only, and simplex
shrinks its engine DSTs. Conformance hashes that need BLS or ed25519 key generation skip in
Debug without `-Dslow-tests`.
The fuzz targets in [fuzz/](fuzz/) each have a seeded minifuzz test and a `std.testing.fuzz`
test.

## Differences from commonware

- `Automaton` methods block on `std.Io` (`propose(io, ctx) !?Digest`) instead of returning
  oneshot receivers. Callers run them with `io.async` to wait on several at once.
  ([simplex decisions](../../docs/lanes/consensus-simplex.md#decisions))
- `Epoch`, `Height`, `View`, and their deltas are non-exhaustive `enum(u64)` types. They compare
  with `==` and never mix with each other or with raw integers.
  ([simplex decisions](../../docs/lanes/consensus-simplex.md#decisions))
- Actors replace `select_loop!` with an inbox: one pump task per source feeds a bounded queue,
  and the actor handles one event at a time. Time and randomness come from `std.Io`, so the
  deterministic runtime replays a run.
  ([simplex decisions](../../docs/lanes/consensus-simplex.md#decisions))
- The simplex engine takes a built elector, which the caller owns, instead of an elector
  config. ([simplex decisions](../../docs/lanes/consensus-simplex.md#decisions))
- Marshal's archive writes are durable when they return, so its syncs finish inside the event
  that starts them. A storage or allocation error ends the marshal actor with the error, where
  commonware panics. ([marshal decisions](../../docs/lanes/consensus-marshal.md#decisions))
- Error variants carry no payload. For example, `Certificate.from_acks` returns
  `InsufficientAttestations` without the expected and found counts.
  ([marshal decisions](../../docs/lanes/consensus-marshal.md#decisions))
- The erasure-coded marshal's shard engine awaits reconstruction jobs in submission order,
  where commonware yields them as they finish.
  ([broadcast-collector decisions](../../docs/lanes/broadcast-collector.md#decisions))
