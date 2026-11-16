# Lane: consensus-marshal

Owns `src/consensus/aggregation/` and `src/consensus/marshal/`, except
`src/consensus/marshal/coding/` (the erasure-coded variant), which the broadcast-collector
lane owns along with its `pub const coding` line in `marshal/root.zig`. That lane builds on
this lane's `core.variant` contracts (`assert_variant`, `assert_buffer`, `ExpectedCommitment`),
core Actor and Mailbox, application, ancestry, config, and mocks (block, application,
verifying, store, and the shared harness, which `coding/harness.zig` extends). Add the
`pub const` lines to `src/consensus/root.zig` (owned by consensus-simplex; additive edits).

Reference: `~/.cache/zigware/commonware-ref/consensus/src/{aggregation,marshal}`.

Aggregation (about 4.6k Rust lines) needs only what is on main: consensus types,
cryptography's certificate schemes (ed25519, secp256r1, bls12381 multisig and threshold),
`actor.mailbox`, `utils` oneshot, `runtime.telemetry.metrics`, and `p2p.simulated`. Do it first.

Marshal (about 57k lines) orders finalized blocks from simplex into an application. It uses
`broadcast.buffered` and `resolver.p2p` (broadcast-resolver lane, in progress),
`storage.archive` (storage-archive lane, in progress), and `coding` (on main). Start with its
pure parts (ancestry, store traits, limits, config, conformance types, coding shard types),
then the core and standard actors as those packages land.

## Public API (on main)
- `consensus.aggregation.types`: `Item(D)` (height, digest; also the certificate `Subject`,
  signing the encoded item under `Namespace`), `Namespace` (`_AGG_ACK` suffix), `Ack(S, D)`
  (`sign(gpa, *const S, epoch, item) !?Ack`, `verify(gpa, rng, *const S, strategy)`),
  `TipAck(S, D)`, `Certificate(S, D)` (`from_acks(gpa, *const S, acks, strategy)`, `verify`,
  `clone`, `deinit`), `Activity(S, D)` (`ack`/`certified`/`tip`, `height()`), `Error`,
  `blockable(err)`. All with codec and `arbitrary`.
- `consensus.aggregation.scheme`: `ed25519.Scheme(D)`, `secp256r1.Scheme(D, P)`,
  `bls12381_multisig.Scheme(D, P, V)`, `bls12381_threshold.Scheme(D, P, V)`, each with
  `fixture(S, gpa, rng, namespace, n)`; `assert_scheme(S, D)`.
- `consensus.aggregation.max_payload_size(S, D)`; `consensus.aggregation.SafeTip(P)`
  (`init(gpa, *const Set)`, `reconcile`, `update`, `get`, `deinit`).
- `consensus.aggregation.Engine(P)`: `create(gpa, io, storage, *const Scope, Config(P))`,
  `start(sender, receiver)` (a `std.Io` future; cancel it to stop), `run`, `destroy`. `P`
  declares `Scheme`, `Provider` (`scheme(epoch) ?*const Scheme`), `Digest`, `Automaton`
  (`propose(io, height) Cancelable!?Digest`), `Reporter`, `Monitor` (`subscribe()` returning
  the epoch and a subscription with `recv() Cancelable!?Epoch`), `Blocker`, `Strategy`.
  `Config(P)` mirrors commonware's fields (durations as `utils.Duration`, non-zero integers
  checked by `assert_valid`). `aggregation.metrics.Metrics`.
- `consensus.aggregation.mocks`: `Application` (`Strategy`: correct, incorrect, skip),
  `Monitor`, `Provider(S)`, `Reporter(S, D)` and `ReporterMailbox(S, D)` (`get_tip`,
  `get_contiguous_tip`, `get`).

## Decisions
- `Item(D)` is the certificate subject itself (passed by value); commonware uses `&Item<D>`.
- `Error` variants carry no payload. `Certificate.from_acks` returns `InsufficientAttestations`
  without commonware's expected/found counts.
- `SafeTip` allocates its validator, tip, and heap arrays at `init` (heaps are sorted
  (height, count) arrays in place of `BTreeMap`), so updates and reconciles never allocate.
  Its `should_panic` tests have no counterpart (Zig cannot catch panics); a seeded fuzz
  against a sorting reference covers the heaps instead.
- The engine waits on one `Io.Condition`: the network receiver, the epoch subscription, and
  each digest request run as `std.Io` tasks that hand results to an inbox; due rebroadcasts
  bound the wait. Each turn handles one event in commonware's `select_loop!` order. Acks per
  height sit in one array sorted by (epoch, signer) instead of nested `BTreeMap`s; pending and
  confirmed heights are sorted arrays (`height_map.zig`).
- The engine owns `config.reporter` and releases it in `destroy`. Broadcasts that the network
  refuses are dropped (rebroadcasts retry), as in commonware.
- The deterministic runtime freed tasks with stale timeout alarms still queued, which crashed
  the first multi-node aggregation run; `Runner.destroy_task` now drops a task's alarms
  (small integration fix in the runtime lane's file).
- The aggregation conformance hashes use test-local wire types for
  `bls12381_threshold::Scheme<_, MinSig>` (a MinSig point with commonware's `G1::arbitrary`),
  as simplex does; the BLS conformance and codec tests skip in Debug without `-Dslow-tests`.

## Backlog
- [x] aggregation: types (all 5 conformance hashes match), scheme, limits, safe_tip.
- [x] aggregation: config, metrics, engine, mocks; mod.rs `all_online` with ed25519.
- [ ] aggregation: the rest of mod.rs (byzantine proposer, unclean shutdowns, lossy links,
  determinism, one offline, partition, insufficient validators, 1k) with every scheme, and
  the three engine.rs unit tests.
- [ ] marshal: ancestry, store, limits, config, conformance types, application traits.
- [ ] marshal resolver, core, standard (and coding) actors with their mocks and tests.
- [ ] Fuzz targets (consensus/fuzz entries for aggregation and marshal).

## Log
- 2026-11-13: aggregation types, schemes, limits, safe_tip; 5 conformance hashes match.
- 2026-11-13: aggregation config, metrics, mocks, engine; all_online passes (ed25519).
