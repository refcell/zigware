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
  `get_contiguous_tip`, `get`), `scheme.Scheme(D)` (ledger-backed mock) and `scheme.fixture`.

- `consensus.marshal.core.variant`: `ExpectedCommitment(C)` (`trusted`/`untrusted`,
  `commitment()`), `assert_variant(V)` (the contract in the file header: `Block`,
  `ApplicationBlock`, `StoredBlock`, `Commitment`, commitment accessors, `check_payload`,
  `decode_block`, `into_stored`, `restore`, `restore_across`, `into_shared`,
  `from_application_block`, size bounds), `assert_buffer(B)`.
- `consensus.marshal.standard.Standard(B)`: the standard variant (`Block` is
  `broadcast.Digested(B)`, `StoredBlock` is `B`, the commitment is the block digest).
- `consensus.marshal.resolver.handler`: `Key(D)` (`block`/`finalized`/`notarized`, codec,
  `order`, `arbitrary`; conformance hash matches), `Annotation`, `Finalized`, `Request(D)`
  (`split()` into key and annotation, `above_height_floor`), `above_height_floor(D, ...)`.
- `consensus.marshal.limits`: `max_payload_size(V, S, participants, block_config)`,
  `max_backfill_size`, `max_block_size`.
- `consensus.marshal.mocks.block`: `EmptyBlock(H)`, `Block(H, C)` (context, precomputed
  digest), `ready(B, gpa, block)`.

## Decisions
- Marshal blocks keep commonware's trait method names (`height()`, `parent()`, `digest()`,
  `context()`), so mock block fields are `height_value`, `parent_value`, and so on.
- `Item(D)` is the certificate subject itself (passed by value); commonware uses `&Item<D>`.
- `Error` variants carry no payload. `Certificate.from_acks` returns `InsufficientAttestations`
  without commonware's expected/found counts.
- `SafeTip` allocates its validator, tip, and heap arrays at `init` (heaps are sorted
  (height, count) arrays in place of `BTreeMap`), so updates and reconciles never allocate.
  Its `should_panic` tests have no counterpart (Zig cannot catch panics); a seeded fuzz
  against a sorting reference covers the heaps instead.
- The engine waits on one `Io.Condition`: the network receiver, the epoch subscription, and
  each digest request run as `std.Io` tasks that hand results to an inbox; due rebroadcasts
  bound the wait. Each turn handles one event in commonware's `select_loop!` order.
  The receiver task waits on a second condition: `std.Io.Condition` counts signals, not
  waiters, so a timed-out engine wait could take the receiver's signal and leave it asleep
  (a lost wakeup that stalled the engine once rebroadcasts were short). Messages queue in a
  bounded ring (256): every hand-off between tasks costs a deterministic-runtime cycle
  (1 ms), so a one-message slot capped each engine near 500 messages/s and the backlog
  starved acks under commonware's short-rebroadcast tests. Acks per
  height sit in one array sorted by (epoch, signer) instead of nested `BTreeMap`s; pending and
  confirmed heights are sorted arrays (`height_map.zig`).
- A canceled engine run is an unclean shutdown (commonware drops the future): the journal
  closes without a final sync, so only what was already synced survives the restart.
- Like commonware, certified heights stay in `pending` (pruned only below
  `tip - activity_timeout`) and keep being rebroadcast; ported as is.
- Debug builds run the multi-node tests with ed25519 only (unoptimized P-256 and BLS take
  tens of seconds per run); `-Dslow-tests` or a release build runs every scheme. Scenario
  fixtures draw their keys from the runtime RNG as commonware's do; the restart and
  admission tests use a fixed RNG, as commonware's `test_rng`.
- `distinct states` compares neighbors from different scheme families only: the Zig
  auditor hashes the task schedule alone (commonware's also hashes RNG draws and other
  runtime events), and MinPk and MinSig runs of one BLS scheme schedule identically.
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
- [x] aggregation: the rest of mod.rs (byzantine proposer, unclean shutdowns, lossy links,
  determinism, distinct states, one offline, partition, insufficient validators, admitted
  signer, 1k on the mock scheme) with every scheme, and the engine.rs unit tests except the
  `should_panic` one.
- [x] marshal: core variant contract, standard variant, resolver `Key` (conformance hash),
  limits, mocks/block.
- [ ] marshal: ancestry, store, config, application traits, core floor/cache/mailbox.
- (marshal/coding/ belongs to the broadcast-collector lane: types, shards, variant,
  validation, marshaled, and coding/mod.rs tests, on top of core.)
- [ ] marshal resolver, core, standard (and coding) actors with their mocks and tests.
- [ ] Fuzz targets (consensus/fuzz entries for aggregation and marshal).

## Log
- 2026-11-13: aggregation types, schemes, limits, safe_tip; 5 conformance hashes match.
- 2026-11-13: aggregation config, metrics, mocks, engine; all_online passes (ed25519).
- 2026-11-16: aggregation fault tests (byzantine, unclean shutdowns, lossy, determinism,
  partition, offline, insufficient, admitted signer) pass with every scheme in ReleaseSafe;
  fixed two engine liveness bugs (lost receiver wakeup, one-message inbox).
