# Lane: consensus-marshal

Owns `src/consensus/aggregation/` and `src/consensus/marshal/`, except
`src/consensus/marshal/coding/` (the erasure-coded variant), which the broadcast-collector
lane owns along with its `pub const coding` line in `marshal/root.zig`. That lane builds on
this lane's `core.variant` contracts (`assert_variant`, `assert_buffer`, `ExpectedCommitment`),
core Actor and Mailbox, application, ancestry, config, and mocks (block, application,
verifying, store, and the shared harness, which `coding/harness.zig` extends). Add the
`pub const` lines to `src/consensus/root.zig` (owned by consensus-simplex; additive edits).

Reference: `~/.cache/zigware/commonware-ref/consensus/src/{aggregation,marshal}`.

Thread: https://ampcode.com/threads/T-01a1d5ef-5571-7424-8220-609c9811da57 (message it with
send_thread_message).

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
- `consensus.marshal.Config(P)` and `Start(S, C, B)` (`genesis` or `floor`); `P` declares
  `Scheme`, `Provider`, `Epocher`, `Strategy`, `ApplicationBlock`, `Block`, `Commitment`.
- `consensus.marshal.store`: `Certificates(A, S, B, C)` and `Blocks(A, Block)` over an
  immutable or prunable archive `A` (borrowed), `Identifier(D)` (`index` or `key`).
- `consensus.marshal.mocks.block`: `EmptyBlock(H)`, `Block(H, C)` (context, precomputed
  digest), `ready(B, gpa, block)`.
- Variant contract additions: `clone_block(*const Block) Block` and
  `deinit_block(gpa, *Block)`, so core owns blocks of either variant. `assert_buffer`
  documents the Zig `Buffer` signatures: `find_by_digest`/`find_by_commitment` (`!?Block`),
  `subscribe_by_digest`/`subscribe_by_commitment` (`!?oneshot.Receiver(Block)`), and
  `send(round, block, recipients) !void`.
- `consensus.marshal.core.floor`: `Processed` (`block`/`absent`, `height`, `anchor`),
  `Cutoff` (`round`/`epoch`, `covers`, `order`, `max`), `Floor`, `closed_epoch(epocher,
  anchor)`, `retained_from(epocher, witnessed, retention)`, `State(S, C, Aborter)` (durable
  floors, the configured and pending floor finalizations, `witness`, `take_matching`,
  `permits`, `fetch_if_permitted`, `fetch_targeted_if_permitted`,
  `fetch_finalizations_if_permitted` over any resolver), `FetchAdmission`. The resolver
  handler adds `Request.above_round_floor` and `above_round_floor(D, ...)`.
- `consensus.marshal.core`: `staged.Staged(V)`, `certified.Certified(C)`,
  `acks.PendingAcks(A)` (an `utils.acknowledgement` ring), `durability.DispatchGate` and
  `durable(result, round, name)`, `stream.Stream` (processed height and round floor in one
  metadata store), `subscriptions.Subscriptions(V, Aborter)` with `Key`/`KeyFor(V)`, and
  `cache.Manager(V, S)` (per-epoch prunable archives: `put_verified`, `put_certified`,
  `put_notarized`, `put_notarization`, `put_finalization`, getters, `find_block_matching`,
  `prune_by_view`, `prune_by_height`, `load_persisted_epochs`).
- `consensus.marshal.ancestry`: `assert_ancestry` (`Block`, `peek`, `next`, `clone`,
  `deinit`), `assert_block_provider` (`subscribe_parent(*const Digested) !Receiver`),
  `from_iter(B, gpa, blocks)` (`Bounded(B)`), `with_prefix(Tail, gpa, blocks, tail)`
  (`Prefixed(Tail)`), `AncestorStream(M)` (prefetching parent walk), `has_contiguous_height`,
  `is_parent`, `is_contiguous_chain`.
- `consensus.marshal.application.validation`: `Stage` (`store(marshal, round, block)`),
  `is_valid_reproposal_at_verify`, `is_inferred_reproposal_at_certify`,
  `is_block_in_expected_epoch`.
- `consensus.marshal.application.gates`: `Gates(D, V)` (shared handle: `insert`, `take`,
  `take_staged`, `send_staged`, `claim`, `retain_after`, `stage`), `GateOutcome`, `Gate`,
  `Ack`, `Staged(B)`, `resolve`, `forward`, `drive`.
- `consensus.marshal.core.mailbox`: `Message(S, V)` (`{ gpa, body }`, 20 request kinds,
  `name`, `stale`, `response_closed`, `discard`, `handle`), `Pending(S, V)` (the overflow
  policy), `Identifier(D)` (`height`/`digest`/`latest`), `DigestFallback`,
  `CommitmentFallback`, and `Mailbox(S, V)` (`init(gpa, io, sender, max_pending_acks)`,
  `get_info`, `get_block`, `get_finalization`, `get_processed`, `get_anchor`,
  `get_verified`, `hint_finalized`, `subscribe_by_digest`, `subscribe_by_commitment`,
  `hint_notarized`, `proposed`, `prepared`, `verified_deferred`, `verified`, `certified`,
  `set_floor`, `prune`, `forward`, and the consensus `Reporter` `report`). As the ancestry
  `BlockProvider`: `Block` (the application block), `subscribe_parent(child)` (through the
  variant's `subscribe_parent(mailbox, child)`; `Standard` fetches by commitment bounded by
  the parent height), `ancestor_stream(initial, fetch_duration)`, and
  `ancestry_from(fallback, digest, fetch_duration)` (commonware `ancestry`).
- `consensus.marshal.resolver.handler`: `Message(D)` (`deliver`/`produce`, with its overflow
  policy), `Handler(D)` (the resolver `Consumer` and `Producer`; copies borrowed deliveries),
  `init(D, gpa, io, scope, capacity)` returning `{ receiver, handler }`; `Annotation.order`
  and `Finalized.order` (Rust's derived `Ord`).
- `consensus.marshal.resolver.p2p`: `Config(P, C, B)`, `Mailbox(D, P)`, and
  `Resolver(D, P, C, B, NetS, NetR)` with `init(gpa, io, scope, config, sender, receiver)`
  returning `{ receiver, handler, mailbox, future }` (the engine borrows `handler`).
- `consensus.marshal.application.relay.broadcast(S, V, gates, marshal, commitment, plan)`:
  relays a simplex `Plan` (prepare once, persist on propose, forward a copy of the plan's
  borrowed recipients).
- `consensus.marshal.application.build`: `Resolved(D, S, N, M)` (`reuse{digest, block}`,
  `skip`, `build{ancestry, metadata}`), `propose(D, ctx, application, registry,
  consensus_context, checks, seal, build_duration) !oneshot.Receiver(D)`, and `prepare(...)
  !oneshot.Receiver(Handoff(D))`. Each runs detached from `ctx.child`; the contracts for
  `application`, `checks`, and `seal` are in the file's header. Dropping the receiver
  cancels the checks and the build.
- `consensus.marshal.core.Actor(P)`: `P` declares the `Config` parameters plus `Variant`,
  `Acknowledgement`, `Certificates`/`Blocks` (`store` adapters), `Application` (a `Reporter`
  of `Update`), `Buffer` (`assert_buffer`), `Resolver` (a targeted resolver of
  `handler.Key`), and optionally `Context` (default `runtime.deterministic.Context`).
  `init(ctx, finalizations_by_height, finalized_blocks, config) !{ actor, mailbox, floor }`
  (borrows the archives, takes `config.start`); `actor.start(application, buffer,
  resolver_receiver, resolver) !Handle(anyerror!void)` takes ownership of all four and runs
  until the mailbox or the handler closes, an acknowledgement is dropped, or the task is
  aborted; the actor frees itself. `actor.deinit()` frees one never started.
- `consensus.marshal.core.NoBuffer(V, PublicKey)` (`.{ .gpa = gpa }`), for an actor without
  a broadcast buffer (commonware `start_unbuffered`); `core.delivery.PendingVerification`.
- `consensus.marshal.Update(B, A)`: `tip{round, height, digest}` and `block{block:
  broadcast.Digested(B), ack: A}`; the application owns both and must acknowledge.

- `consensus.marshal.standard.Buffer(B, P)`: the core `Buffer` over a
  `broadcast.buffered.Mailbox(P, B)` (owned; `init(mailbox)`, `deinit`); passes
  `core.variant.assert_buffer`.
- `consensus.marshal.mocks.harness` (commonware `mocks/harness.rs`, shared parts): constants
  (`num_validators`, `quorum`, `blocks_per_epoch`, `link`), `S` (ed25519 under
  `fast_schemes`, threshold VRF MinPk otherwise), `fixture`, `Provider`, `make_raw_block`,
  `genesis_parent`, `TestNetwork` (`start`, `link_all`, `stop`), `max_message_size(V)`,
  `make_finalization`, `make_notarization` (and `_of(C, ...)` for any commitment, over pub
  `certify_votes`), `Archives(StoredBlock)` (= `ArchivesOf(D, StoredBlock)`) (both immutable archives,
  owning their partition names), and `StandardHarness`: `Validator(App)` with
  `setup(ctx, network, me, provider, max_pending_acks, app) !*Self` (resolver, broadcast,
  archives, actor) and `crash()`, plus `make_test_block`, `propose`, `verify`, `digest`,
  `commitment`, `certify`, `genesis_block`, `height`. `App` needs `Activity`, `clone`, `deinit`, and `report`
  (`mocks.Application(B)` fits).

## standard/mod.rs test split
commonware `standard/mod.rs` (14.9k lines) is split by line range of that file. Each owner
ports its range's tests and the helpers defined in it, into
`src/consensus/marshal/standard/tests/<file>.zig`, wired with one
`test { _ = @import("tests/<file>.zig"); }` line in `standard/root.zig`.
- Shared helpers, `tests/common.zig`, owned by the deployer thread (T-01a1d5b9) and landed
  first, on its own: `RecordingBuffer`, `RecordingResolver`, `NoopConsumer`,
  `StaticProducer`, `wait_until`, `HoldingBlockReporter`, `ApplicationReporter`,
  `start_standard_actor` (lines 6221-6739), and `PacedStore`, `prunable_finalized_stores`,
  `test_config` (10362-10611).
- consensus-marshal (this lane), `tests/scenarios.zig` and `tests/restart.zig`: lines
  169-2591 (provider/digest-once tests, every harness scenario wrapper: finalize, hailstorm,
  ack pipeline, genesis, recoverable/certify family, sync floor, prune, subscribe, get_info,
  get_block, hint_finalized, ancestry stream, broadcast caches; restart repair), except
  1987-2543, the seed helpers in `tests/seed.zig` (lines 638-797), and harness.rs's scenario
  functions in `mocks/harness.zig` so coding reuses them.
- bls-math thread (T-01a1d57b-1003), `tests/cache_epoch.zig`: lines 1987-2543 (cache epoch
  reopen, far-epoch writes, interrupted destroy, start_sync covers prior writes).
- bls-math also: harness.rs 3442-end scenarios in `mocks/scenarios_queries.zig`, with
  their standard wrappers (standard/mod.rs 563-631, 2544-2591) in `tests/queries.zig`.
- lookup thread (T-01a1d59c), `tests/wrappers.zig` and `tests/dispatch.zig`: lines
  2592-6220 (buffered floor anchors, inline/deferred wrapper tests, certify/verify fetch
  paths, propose/prepare paths, reproposal and ancestry validation, sync failure panics,
  certified-covered). Lines 10612-12604 (cache writes, notarized decode, finalization
  sync, staged dispatch, relay sends, forward, hint_finalized) moved to the runtime thread
  (T-01a1d57b-1bfd), `tests/dispatch.zig`. Done 2026-11-19: 23 of 24 tests, plus
  `parse_processed_height`. The three paced-sync tests (finalization_sync_does_not_block_mailbox,
  stale_floor_anchor_holds_dispatch_until_durable, overlapping_finalized_syncs_release_per_batch)
  are ported but skipped behind `pooled_finalized_sync` until `start_finalized_sync` runs off
  the actor loop, as commonware pools it. cache_writes_do_not_clone_block_payloads is not
  ported: it counts Rust `Clone` calls on the block's context, and Zig copies a value-type
  block implicitly with no hook to count (shared blocks are refcounted `Digested` handles).
- deployer thread (T-01a1d5b9), `tests/floor.zig`: lines 6740-10611 (redelivery,
  start/set floor, floor anchors and acks, delivery verification across scopes, processed
  and round floors, unverifiable delivery, sync dispatch). Done 2026-11-18: 39 of 43 tests;
  the 3 `should_panic` tests and the identity-job gate have no Zig counterpart (file header).
- runtime thread (T-01a1d57b-1bfd), `tests/coverage.zig`: lines 12605-14905 (prune,
  pipelined handoff, reproposal coverage across restarts, closed-epoch floors, cache
  retention).
- coding/mod.rs's tests belong to broadcast-collector (T-01a1d58d), on
  `mocks/harness.zig` plus its own `coding/harness.zig`.
- commonware runs each scenario on `InlineHarness` and `DeferredHarness`, which only
  delegate to `StandardHarness`; in Zig each runs once on `StandardHarness`.

## Decisions
- The actor follows commonware's biased `select_loop!` order: before an acknowledgement,
  mailbox, or resolver event it takes every ready buffer waiter (its slot, or a block already
  in its channel), then every resolved acknowledgement, even when their inbox notices have
  not arrived. So ack-then-`get_processed` sees the new height, and a query after the buffer
  hands a floor anchor over sees the installed floor. Commonware's first arm (pooled sync
  completions) has no counterpart, since zigware's syncs complete inside their event.
- `storage.archive.immutable` borrows its config's partition names (its ordinal opens
  section blobs lazily), so `harness.Archives` owns them for the archives' lifetime.
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
- `distinct states` compares every neighboring scheme, as commonware does, now that the
  runtime auditor records rand, storage, and network events (220473e).
- The engine owns `config.reporter` and releases it in `destroy`. Broadcasts that the network
  refuses are dropped (rebroadcasts retry), as in commonware.
- The deterministic runtime freed tasks with stale timeout alarms still queued, which crashed
  the first multi-node aggregation run; `Runner.destroy_task` now drops a task's alarms
  (small integration fix in the runtime lane's file).
- The aggregation conformance hashes use test-local wire types for
  `bls12381_threshold::Scheme<_, MinSig>` (a MinSig point with commonware's `G1::arbitrary`),
  as simplex does; the BLS conformance and codec tests skip in Debug without `-Dslow-tests`.

- Marshal's core types port commonware's `Arc`-shared blocks as variant handles:
  `clone_block` adds a reference, `deinit_block` drops one; staging, subscriptions, and
  caches own what they hold.
- The Zig archives' `start_sync` finishes the sync before returning, so the cache's
  `put_*`/`start_sync_*` calls are durable on return instead of returning sync handles.
  `durable(result, round, name)` keeps commonware's policy: shutdown (`Canceled`/`Closed`)
  reports not durable, any other sync failure panics (no `should_panic` test in Zig).
- Buffer waiters and the pending floor's waiter are aborted through an `Aborter` type
  parameter (`abort(*Aborter)`), which the actor supplies from its waiter tasks (one inbox
  fed by tasks, as simplex's voter does).

- Ancestry streams block in `next` on the runtime's `std.Io` instead of being polled; a
  parent already available when subscribed is buffered at once, so `peek` and prefetching
  behave as in commonware. Commonware's `should_panic` ancestry cases are covered through
  `is_contiguous_chain` (Zig cannot catch panics).
- The gates' staged ack is `oneshot.Sender(void)`, sent once the block is persisted (the
  Zig caches are durable on return), instead of a sync handle.
- Mailbox messages are `{ gpa, body }`: the body owns its blocks, certificates, `some`
  recipients, hint targets, and responders, and `discard` frees them when the mailbox drops
  the message. `proposed`/`verified`/`certified` acks are `oneshot.Sender(void)` for the
  same reason as the gates. Tracing spans are not carried. `report` borrows the activity
  (as simplex's voter expects), sends a copy, and panics on allocation failure as Rust
  aborts, since the `Reporter` contract cannot return an error.

- The actor is one task over the simplex `Inbox`: pumps feed it the mailbox and the
  resolver handler, buffer waiters and a watcher on the current application ack push their
  completions, and events are handled in arrival order rather than `select_loop!`'s
  priority. Archive writes are durable when they return, so commonware's pooled syncs
  (`start_finalized_sync`, notarization syncs) complete inside the event that starts them
  and release the dispatch gate there; the gate still holds dispatch between a buffered
  write and that sync. A storage or allocation error ends the actor with the error where
  commonware panics. The actor is split into `actor.zig` (state, init, loop, waiters),
  `actor_ingress.zig` (mailbox), `actor_backfill.zig` (resolver), and `actor_finalize.zig`
  (storage, floors, repair, dispatch) to keep files and functions within TigerStyle.

## Backlog
- [x] Pool the finalized-archive sync (`actor_finalize.start_finalized_sync` runs inline;
  commonware pools it). Then flip `pooled_finalized_sync` in `standard/tests/dispatch.zig`
  (3 skipped tests: mailbox not blocked by a sync, per-batch release, stale floor anchor).
- [x] aggregation: types (all 5 conformance hashes match), scheme, limits, safe_tip.
- [x] aggregation: config, metrics, engine, mocks; mod.rs `all_online` with ed25519.
- [x] aggregation: the rest of mod.rs (byzantine proposer, unclean shutdowns, lossy links,
  determinism, distinct states, one offline, partition, insufficient validators, admitted
  signer, 1k on the mock scheme) with every scheme, and the engine.rs unit tests except the
  `should_panic` one.
- [x] marshal: core variant contract, standard variant, resolver `Key` (conformance hash),
  limits, mocks/block.
- [x] marshal: store adapters over both archives.
- [x] marshal: config.
- [x] marshal core: floor, staged, certified, acks, durability, stream, subscriptions,
  cache.
- [x] marshal: ancestry, application validation and gates.
- [x] marshal: core mailbox with its overflow policy and tests.
- [x] marshal: application relay.
- [x] marshal: resolver handler messages and p2p init.
- [x] marshal: application build (prepare and propose tasks).
- [x] marshal: core actor, delivery, `Update` (smoke tests: in-order dispatch, two-node
  produce/deliver backfill with walkback repair and a forged certificate).
- [x] marshal: mocks/harness.rs shared parts and `StandardHarness`, `standard.Buffer`
  (smoke test: 4 validators finalize 24 blocks over p2p.simulated).
- [ ] marshal: harness.rs scenario functions, then this lane's slice of standard/mod.rs's
  tests (see "standard/mod.rs test split"; the lookup thread owns standard/{validation,
  inline,deferred} and mocks/{application,resolver,store,strategy,verifying}).
- [x] aggregation: the full `distinct states` comparison on the new runtime auditor.
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
- 2026-11-16: marshal variant contract, standard variant, resolver key, limits, block mocks,
  store adapters, config; core floor, staged, certified, acks, durability, stream,
  subscriptions, and cache with their commonware tests.
- 2026-11-16: marshal ancestry streams, application validation, and certification gates.
- 2026-11-16: marshal core mailbox, overflow policy, and its commonware tests; relay;
  resolver handler messages and the p2p resolver wiring.
- 2026-11-16: marshal ancestry provider on the mailbox; application prepare and propose
  tasks.
- 2026-11-16: marshal core actor (mailbox, resolver backfill, finalized chain, floors,
  repair, dispatch), delivery, and `Update`.
- 2026-11-16 (parallel lane): standard validation, the inline standard wrapper (tests on a
  stand-in marshal actor until the harness lands), and mocks verifying, store, resolver,
  and application (`mocks.Application(B)`: shared handle with clone/deinit, auto or manual
  acknowledgement).
- 2026-11-16 (parallel lane): the deferred standard wrapper (`standard.Deferred`) with
  commonware's deferred.rs tests on a stand-in marshal actor. The restart halves of the two
  restart tests wait for the harness.
- 2026-11-16: marshal harness (shared parts, StandardHarness) and `standard.Buffer`; posted
  the standard/mod.rs test split.
- 2026-11-18: standard/mod.rs restart tests (trailing, internal, multiple trailing, large
  pending tip, surfaces unfinalized block, stores late finalization, consistent no-op, local
  cache repair) with the seed helpers; fixed a finalization leak in `repair_trailing`.
- 2026-11-18: core cache: a failed epoch destroy closes only the archives it did not destroy
  (found by bls-math's interrupted-destroy test); harness hooks for coding (`ArchivesOf`,
  `make_*_of`).
- 2026-11-18: `mocks.scenarios` (`Cluster(H)`, generic `Finalize(H)`; harnesses export their
  signing setup). The finalize test is skipped until resolver.p2p keeps up with network
  responses (resolver lane, T-01a1d5b9).
- 2026-11-18: actor drains resolved acks before mailbox/resolver events; bls-math takes
  harness.rs 3442-end (`mocks/scenarios_queries.zig`, `standard/tests/queries.zig`).
- 2026-11-18: standard late-finalization tests (kept once for a repaired block, dropped
  below a floor) in `tests/late_finalization.zig`; finalize scenario unskipped by the
  resolver fix (fd079c5).
- 2026-11-18: kept-finalization prune restart and late-finalization batch dispatch tests
  (1219-1599 done); actor takes ready buffer waiters before acks, mailbox, and resolver
  events (commonware's biased order), with a regression test in `tests/restart.zig`.
- 2026-11-18: aggregation "determinism" runs one seed on ed25519 outside nightly, and
  "unclean byzantine shutdown" runs only under `-Dslow-tests` (CI wall time).
- 2026-11-18: `store.start_sync` returns a `store.Durable` handle; a delayed (paced) finalized
  sync is pooled in `Actor.Syncs` and released per batch, ahead of every other event.
