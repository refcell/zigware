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
- Shared helpers, `tests/common.zig`, owned by the deployer thread
  (T-01a1d5b9-c237-73f2-a935-c93580e28133) and landed first, on its own: `RecordingBuffer`,
  `RecordingResolver`, `NoopConsumer`, `StaticProducer`, `wait_until`,
  `HoldingBlockReporter`, `ApplicationReporter`, `start_standard_actor` (lines 6221-6739),
  and `PacedStore`, `prunable_finalized_stores`, `test_config` (10362-10611).
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
- deployer thread (T-01a1d5b9-c237-73f2-a935-c93580e28133), `tests/floor.zig`: lines
  6740-10611 (redelivery, start/set floor, floor anchors and acks, delivery verification
  across scopes, processed and round floors, unverifiable delivery, sync dispatch). Done
  2026-11-18: 39 of 43 tests;
  the 3 `should_panic` tests and the identity-job gate have no Zig counterpart (file header).
- runtime thread (T-01a1d57b-1bfd), `tests/propose_validation.zig`: lines 4994-5931 of
  the wrappers range (propose and prepare paths, propose rebuilds after restart, the
  deferred unlinked-parent handoff, reproposal, ancestry, and application-verify checks).
  Done 2026-11-19: all 7 tests, each on both wrappers where commonware runs both. The 4
  sync-failure panic tests after them (5932-6150) have no Zig counterpart.
  Two planted bugs survive, as accepted gaps: dropping the epoch precheck is masked by the
  reproposal check, which also checks the epoch (commonware's tests share the gap), and
  skipping the boundary re-proposal in `build.propose_task` has no generic plant (standard
  and coding blocks free differently); prepare and propose_paths still cover the boundary.
- runtime thread (T-01a1d57b-1bfd), `tests/recoverable.zig`: lines 176-432 (local blocks
  hash once and replay once, with `mocks.DigestCounter` counting `Block.digest` calls; the
  block provider's parent walkback by commitment) and the recoverable/certify family
  (514-562) as generic scenarios in `mocks/scenarios_recoverable.zig` (harness.rs
  1009-1876, done: success-implies-recoverable for proposed/verified/certified, certify
  persists equivocated block, later-view certify survives pruning, reverify same round
  after restart for verified/certify, delivery visibility). Collector can run them on the
  coding harness. Each group fails a planted bug (unsynced cache puts, notarized-write
  skips, index-only verified dedupe, deferred same-view sync, dispatch before sync).
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

## Test tally (2026-11-19, against main)

Every `fn test_*` in commonware's `marshal/standard/mod.rs` and `marshal/coding/mod.rs`, by
line, with where its Zig counterpart lives. Coding's in-progress owner: broadcast-collector (all 7). Counts:

| File | Ported | In progress | Not portable | Total |
| --- | --- | --- | --- | --- |
| standard/mod.rs | 184 | 0 | 9 | 193 |
| coding/mod.rs | 89 | 7 | 1 | 97 |

`mocks/harness.rs` has no tests of its own: all 31 generic scenario functions are ported
(`mocks/scenarios.zig`, `scenarios_queries.zig`, `scenarios_recoverable.zig`) and run through
the standard wrappers above. `conformance.rs`'s StandardStorageConformance workload is in
`marshal/conformance.zig` (hash unreachable, see Log); CodingStorageConformance is the
coding lane's. Commonware has no marshal fuzz targets; AGENTS.md's fuzz bodies
(seeded and `std.testing.fuzz`, each with a planted bug caught) cover the resolver `Key`
codec, `Annotation` order, standard `decode_block`, `DispatchGate`, `PendingAcks`, `Staged`,
the mailbox overflow policy, and the ancestor stream. Not portable: the 8 `should_panic` tests (7 standard, 1 coding), because a Zig
test cannot catch a panic (zigware panics with commonware's message in the floor and genesis
cases, and returns the storage error, stopping the actor, in the sync-failure cases);
`cache_writes_do_not_clone_block_payloads`
(it counts implicit Rust payload clones; Zig blocks are refcounted handles and cache writes
encode from a borrow), and `resolver_delivery_waits_for_identity_job` (it gates the strategy
job that digests a delivered block; standard's `decode_block` digests inline, so there is no
job to gate, and `mocks/strategy.rs`'s GatedStrategy has no other user).

#### standard/mod.rs

- L176 `test_standard_local_blocks_compute_digest_once_and_replay_once`: ported (standard/tests/recoverable.zig)
- L378 `test_standard_block_provider_parent_fetches_by_commitment`: ported (standard/tests/recoverable.zig)
- L433 `test_standard_finalize_good_links`: ported (standard/tests/scenarios.zig)
- L442 `test_standard_finalize_bad_links`: ported (standard/tests/scenarios.zig)
- L451 `test_standard_finalize_good_links_quorum_sees_finalization`: ported (standard/tests/scenarios.zig)
- L460 `test_standard_finalize_bad_links_quorum_sees_finalization`: ported (standard/tests/scenarios.zig)
- L469 `test_standard_hailstorm_restarts`: ported (standard/tests/scenarios.zig)
- L478 `test_standard_hailstorm_multi_restarts`: ported (standard/tests/scenarios.zig)
- L490 `test_standard_hailstorm_restarts_across_epochs`: ported (standard/tests/scenarios.zig)
- L496 `test_standard_ack_pipeline_backlog`: ported (standard/tests/scenarios.zig)
- L502 `test_standard_ack_pipeline_backlog_persists_on_restart`: ported (standard/tests/scenarios.zig)
- L508 `test_standard_genesis_emitted_once`: ported (standard/tests/queries.zig)
- L514 `test_standard_proposed_success_implies_recoverable_after_restart`: ported (standard/tests/recoverable.zig)
- L520 `test_standard_verified_success_implies_recoverable_after_restart`: ported (standard/tests/recoverable.zig)
- L526 `test_standard_certify_persists_equivocated_block`: ported (standard/tests/recoverable.zig)
- L532 `test_standard_verified_after_restart_reverify_same_round_implies_recoverable`: ported (standard/tests/recoverable.zig)
- L539 `test_standard_certify_after_restart_reverify_same_round_implies_recoverable`: ported (standard/tests/recoverable.zig)
- L545 `test_standard_certified_success_implies_recoverable_after_restart`: ported (standard/tests/recoverable.zig)
- L551 `test_standard_certify_at_later_view_survives_earlier_view_pruning`: ported (standard/tests/recoverable.zig)
- L557 `test_standard_delivery_visibility_implies_recoverable_after_restart`: ported (standard/tests/recoverable.zig)
- L563 `test_standard_sync_height_floor`: ported (standard/tests/queries.zig)
- L569 `test_standard_reject_stale_block_delivery_after_floor_update`: ported (standard/tests/queries.zig)
- L575 `test_standard_commitment_fetch_height_hint_mismatch_wakes_subscriber`: ported (standard/tests/queries.zig)
- L581 `test_standard_prune_finalized_archives`: ported (standard/tests/queries.zig)
- L587 `test_standard_floor_retains_processed_predecessor`: ported (standard/tests/queries.zig)
- L593 `test_standard_subscribe_basic_block_delivery`: ported (standard/tests/queries.zig)
- L599 `test_standard_subscribe_multiple_subscriptions`: ported (standard/tests/queries.zig)
- L605 `test_standard_subscribe_canceled_subscriptions`: ported (standard/tests/queries.zig)
- L611 `test_standard_subscribe_blocks_from_different_sources`: ported (standard/tests/queries.zig)
- L617 `test_standard_get_info_basic_queries_present_and_missing`: ported (standard/tests/queries.zig)
- L623 `test_standard_get_info_latest_progression_multiple_finalizations`: ported (standard/tests/queries.zig)
- L629 `test_standard_get_block_by_height_and_latest`: ported (standard/tests/queries.zig)
- L798 `test_standard_restart_repairs_trailing_missing_finalized_block`: ported (standard/tests/restart.zig)
- L898 `test_standard_restart_repairs_internal_missing_finalized_block`: ported (standard/tests/restart.zig)
- L1022 `test_standard_restart_surfaces_block_without_finalization`: ported (standard/tests/restart.zig)
- L1116 `test_standard_stores_reported_finalization_for_processed_block`: ported (standard/tests/restart.zig)
- L1219 `test_standard_keeps_late_finalization_for_repaired_block_once`: ported (standard/tests/late_finalization.zig)
- L1312 `test_standard_drops_finalization_for_block_below_floor`: ported (standard/tests/late_finalization.zig)
- L1368 `test_standard_kept_finalization_survives_prune_and_restart`: ported (standard/tests/late_finalization.zig)
- L1487 `test_standard_late_finalization_in_batch_keeps_dispatch`: ported (standard/tests/late_finalization.zig)
- L1600 `test_standard_restart_repairs_multiple_trailing_missing_finalized_blocks`: ported (standard/tests/restart.zig)
- L1713 `test_standard_restart_repairs_large_pending_tip_by_commitment`: ported (standard/tests/restart.zig)
- L1829 `test_standard_restart_no_trailing_finalizations_is_noop`: ported (standard/tests/restart.zig)
- L1907 `test_standard_restart_repairs_trailing_block_from_local_cache`: ported (standard/tests/restart.zig)
- L1987 `test_cache_load_persisted_epochs_finds_blocks`: ported (standard/tests/cache_epoch.zig)
- L2068 `test_cache_restart_after_far_epoch_write_reopens_only_written_epochs`: ported (standard/tests/cache_epoch.zig)
- L2121 `test_standard_start_floor_restart_before_anchor_reopens_only_floor_epoch`: ported (standard/tests/cache_epoch.zig)
- L2189 `test_cache_write_to_skipped_epoch_initializes_on_demand`: ported (standard/tests/cache_epoch.zig)
- L2267 `test_cache_restart_reopens_epoch_left_by_interrupted_destroy`: ported (standard/tests/cache_epoch.zig)
- L2379 `test_cache_prune_stopped_inside_epoch_destroy_finishes_after_restart`: ported (standard/tests/cache_epoch.zig)
- L2495 `test_cache_start_sync_notarizations_covers_prior_write`: ported (standard/tests/cache_epoch.zig)
- L2544 `test_standard_get_block_by_commitment_from_sources_and_missing`: ported (standard/tests/queries.zig)
- L2550 `test_standard_get_finalization_by_height`: ported (standard/tests/queries.zig)
- L2556 `test_standard_hint_finalized_triggers_fetch`: ported (standard/tests/queries.zig)
- L2562 `test_standard_ancestry_stream`: ported (standard/tests/queries.zig)
- L2568 `test_standard_finalize_same_height_different_views`: ported (standard/tests/queries.zig)
- L2574 `test_standard_init_processed_height`: ported (standard/tests/queries.zig)
- L2580 `test_standard_broadcast_caches_block`: ported (standard/tests/queries.zig)
- L2586 `test_standard_rejects_block_delivery_below_floor`: ported (standard/tests/queries.zig)
- L2592 `test_standard_buffered_block_installs_floor_anchor`: ported (standard/tests/wrappers.zig)
- L2756 `test_standard_unsubscribed_buffered_anchor_installs_floor`: ported (standard/tests/wrappers.zig)
- L2761 `test_standard_late_subscription_observes_buffered_anchor_floor`: ported (standard/tests/wrappers.zig)
- L2768 `test_standard_start_floor_buffered_anchor_installs_floor`: ported (standard/tests/wrappers.zig)
- L2811 `test_standard_closed_floor_waiter_preserves_subscriptions`: ported (standard/tests/wrappers.zig)
- L2872 `test_standard_floor_preserves_registered_subscriptions`: ported (standard/tests/wrappers.zig)
- L3004 `test_standard_resolver_floor_anchor_install_wakes_subscriber`: ported (standard/tests/wrappers.zig)
- L3110 `test_standard_below_floor_anchor_delivery_wakes_subscriber`: ported (standard/tests/wrappers.zig)
- L3502 `test_inline_pending_conflicting_verify_does_not_poison_certification`: ported (standard/tests/wrappers.zig)
- L3507 `test_deferred_pending_conflicting_verify_does_not_poison_certification`: ported (standard/tests/wrappers.zig)
- L3755 `test_inline_scripted_byzantine_parent_equivocation`: ported (standard/tests/wrappers.zig)
- L3760 `test_deferred_scripted_byzantine_parent_equivocation`: ported (standard/tests/wrappers.zig)
- L3906 `test_inline_certify_ancestor_below_finalized_round_after_prune`: ported (standard/tests/wrappers.zig)
- L3917 `test_deferred_certify_ancestor_below_finalized_round_after_prune`: ported (standard/tests/wrappers.zig)
- L3927 `test_inline_certify_fork_below_finalized_round_after_prune`: ported (standard/tests/wrappers.zig)
- L3934 `test_deferred_certify_fork_below_finalized_round_after_prune`: ported (standard/tests/wrappers.zig)
- L4010 `test_inline_later_epoch_activity_releases_earlier_epoch`: ported (standard/tests/wrappers.zig)
- L4019 `test_deferred_later_epoch_activity_releases_earlier_epoch`: ported (standard/tests/wrappers.zig)
- L4027 `test_inline_same_epoch_activity_keeps_gates`: ported (standard/tests/wrappers.zig)
- L4035 `test_deferred_same_epoch_activity_keeps_gates`: ported (standard/tests/wrappers.zig)
- L4041 `test_standard_certify_first_block_fetches_genesis_parent`: ported (coding/mod_test.zig)
- L4119 `test_standard_switch_wrapper_at_epoch_boundary`: ported (standard/tests/wrappers.zig)
- L4281 `test_standard_verify_missing_candidate_waits_without_fetching`: ported (coding/mod_test.zig)
- L4357 `test_standard_certify_missing_candidate_fetches_by_round`: ported (coding/mod_test.zig)
- L4498 `test_standard_certify_bumps_notarized_fetch_for_pending_verify`: ported (standard/tests/wrappers.zig)
- L4575 `test_standard_certify_retains_transient_buffer_hit_through_eviction`: ported (coding/mod_test.zig)
- L4637 `test_standard_deferred_certify_falls_back_after_canceled_verify`: ported (standard/tests/wrappers.zig)
- L4713 `test_standard_verify_height_lie_parent_fetch_is_round_bound`: ported (standard/tests/fetch.zig)
- L4820 `test_standard_verify_parent_fetch_invalid_first_retries`: ported (standard/tests/fetch.zig)
- L4994 `test_propose_paths`: ported (standard/tests/propose_validation.zig)
- L5175 `test_propose_rebuilds_after_restart`: ported (standard/tests/propose_validation.zig)
- L5323 `test_prepare_paths`: ported (standard/tests/propose_validation.zig)
- L5465 `test_deferred_handoff_rejects_unvalidated_parent_link`: ported (standard/tests/propose_validation.zig)
- L5545 `test_verify_reproposal_validation`: ported (standard/tests/propose_validation.zig)
- L5691 `test_verify_rejects_invalid_ancestry`: ported (standard/tests/propose_validation.zig)
- L5839 `test_application_verify_failure`: ported (standard/tests/propose_validation.zig)
- L5932 `test_mailbox_verified_sync_failure_panics`: not portable (see above)
- L5989 `test_mailbox_certified_sync_failure_panics`: not portable (see above)
- L6043 `test_notarization_sync_failure_panics`: not portable (see above)
- L6104 `test_get_info_by_digest_read_failure_panics`: not portable (see above)
- L6151 `test_certified_covered_by_verified_write_recoverable_after_restart`: ported (standard/tests/wrappers.zig)
- L6740 `test_standard_application_shutdown_redelivers_pending_ack_after_restart`: ported (standard/tests/floor.zig)
- L6850 `test_standard_actor_starts_without_buffer`: ported (standard/tests/floor.zig)
- L6894 `test_standard_start_floor_rejects_invalid_finalization`: not portable (see above)
- L6927 `test_standard_set_floor_rejects_invalid_finalization`: not portable (see above)
- L6959 `test_standard_start_floor_fetches_async_and_serves_requests`: ported (standard/tests/floor.zig)
- L7028 `test_standard_start_floor_applies_local_anchor_without_fetch`: ported (standard/tests/floor.zig)
- L7128 `test_standard_start_floor_height_one_without_metadata_delivers_anchor`: ported (standard/tests/floor.zig)
- L7184 `test_standard_set_floor_holds_dispatch_until_anchor_arrives`: ported (standard/tests/floor.zig)
- L7276 `test_standard_floor_jump_ignores_stale_application_ack`: ported (standard/tests/floor.zig)
- L7375 `test_standard_local_floor_jump_ignores_stale_application_ack`: ported (standard/tests/floor.zig)
- L7460 `test_standard_set_floor_repairs_gap_after_anchor_arrives`: ported (standard/tests/floor.zig)
- L7550 `test_standard_local_floor_anchor_resumes_gap_repair`: ported (standard/tests/floor.zig)
- L7628 `test_standard_newer_pending_floor_supersedes_older_anchor`: ported (standard/tests/floor.zig)
- L7802 `test_standard_set_floor_applies_buffered_anchor_on_notarization`: ported (standard/tests/floor.zig)
- L7867 `test_standard_pending_floor_releases_buffer_waiter`: ported (standard/tests/floor.zig)
- L7969 `test_standard_pending_floor_drops_in_flight_ack_before_anchor`: ported (standard/tests/floor.zig)
- L8072 `test_standard_local_floor_below_in_flight_keeps_pending_ack`: ported (standard/tests/floor.zig)
- L8141 `test_standard_set_floor_below_processed_height_preserves_in_flight_ack`: ported (standard/tests/floor.zig)
- L8265 `test_standard_floor_with_stored_predecessor_reports_block`: ported (standard/tests/floor.zig)
- L8326 `test_standard_same_height_floor_anchor_keeps_pending_ack`: ported (standard/tests/floor.zig)
- L8407 `test_standard_stale_floor_anchor_advances_round_floor`: ported (standard/tests/floor.zig)
- L8497 `test_standard_floor_anchor_uses_parent_digest_as_commitment`: ported (standard/tests/floor.zig)
- L8575 `test_standard_notarized_delivery_wakes_fetch_by_round_subscriber`: ported (standard/tests/floor.zig)
- L8654 `test_standard_notarized_delivery_rejects_wrong_round`: ported (standard/tests/floor.zig)
- L8707 `test_standard_notarized_delivery_ignored_without_full_scheme`: ported (standard/tests/floor.zig)
- L8750 `test_standard_finalized_delivery_verifies_with_verify_only_scope`: ported (standard/tests/floor.zig)
- L8838 `test_standard_finalized_delivery_rejects_different_block_bytes`: ported (standard/tests/floor.zig)
- L8940 `test_standard_resolver_delivery_waits_for_identity_job`: not portable (see above)
- L9052 `test_standard_finalized_delivery_rejects_epoch_mismatch`: ported (standard/tests/floor.zig)
- L9104 `test_standard_finalized_delivery_verifies_after_scope_retires`: ported (standard/tests/floor.zig)
- L9171 `test_standard_notarized_delivery_verifies_after_scope_retires`: ported (standard/tests/floor.zig)
- L9236 `test_standard_finalized_delivery_rejects_foreign_certificate_after_scope_retires`: ported (standard/tests/floor.zig)
- L9301 `test_standard_finalized_batch_verifies_each_epoch_under_admission_scope`: ported (standard/tests/floor.zig)
- L9406 `test_standard_processed_round_skips_fetch_and_preserves_subscription`: ported (standard/tests/floor.zig)
- L9485 `test_standard_finalization_rejects_processed_round_block_fetch`: ported (standard/tests/floor.zig)
- L9553 `test_standard_restart_rejects_mismatched_genesis_anchor`: not portable (see above)
- L9599 `test_standard_processed_round_restored_after_restart`: ported (standard/tests/floor.zig)
- L9700 `test_standard_round_floor_does_not_restore_missing_next_block`: ported (standard/tests/floor.zig)
- L9800 `test_standard_round_floor_restores_unacknowledged_anchor`: ported (standard/tests/floor.zig)
- L9889 `test_standard_set_floor_prunes_round_bound_fetches`: ported (standard/tests/floor.zig)
- L9967 `test_standard_round_floor_advance_releases_superseded_pending_floor`: ported (standard/tests/floor.zig)
- L10119 `test_standard_unverifiable_delivery_is_ignored`: ported (standard/tests/floor.zig)
- L10275 `test_standard_dispatches_finalized_blocks_after_sync`: ported (standard/tests/floor.zig)
- L10612 `test_standard_cache_writes_do_not_clone_block_payloads`: not portable (see above)
- L10723 `test_standard_notarized_delivery_decodes_after_verification`: ported (standard/tests/dispatch.zig)
- L10819 `test_standard_finalization_sync_does_not_block_mailbox`: ported (standard/tests/dispatch.zig)
- L10942 `test_standard_stale_floor_anchor_holds_dispatch_until_durable`: ported (standard/tests/dispatch.zig)
- L11144 `test_standard_overlapping_finalized_syncs_release_per_batch`: ported (standard/tests/dispatch.zig)
- L11256 `test_standard_dispatch_delivers_staged_block_without_archive_read`: ported (standard/tests/dispatch.zig)
- L11431 `test_standard_staged_dispatch_deduplicates_finalizations`: ported (standard/tests/dispatch.zig)
- L11436 `test_standard_staged_dispatch_deduplicates_preexisting_block`: ported (standard/tests/dispatch.zig)
- L11558 `test_standard_staged_blocks_bounded_drain`: ported (standard/tests/dispatch.zig)
- L11563 `test_standard_staged_blocks_bounded_floor`: ported (standard/tests/dispatch.zig)
- L11569 `test_standard_does_not_restage_dispatched_block`: ported (standard/tests/dispatch.zig)
- L11669 `test_standard_update_block_processed_height_invariant`: ported (standard/tests/dispatch.zig)
- L11782 `test_standard_forward_unknown_block_is_noop`: ported (standard/tests/dispatch.zig)
- L11824 `test_standard_proposed_broadcasts_then_persists`: ported (standard/tests/dispatch.zig)
- L11921 `test_standard_propose_relay_after_claim_sends_once`: ported (standard/tests/dispatch.zig)
- L11989 `test_standard_restage_after_prune_sends_once`: ported (standard/tests/dispatch.zig)
- L12060 `test_standard_propose_relay_sends_staged_block`: ported (standard/tests/dispatch.zig)
- L12122 `test_standard_prepare_relay_sends_once_and_propose_stores`: ported (standard/tests/dispatch.zig)
- L12203 `test_standard_boundary_restage_sends_once`: ported (standard/tests/dispatch.zig)
- L12367 `test_standard_proposed_conflicting_blocks_both_ack`: ported (standard/tests/dispatch.zig)
- L12414 `test_standard_forward_cached_block_sends_to_peers`: ported (standard/tests/dispatch.zig)
- L12462 `test_standard_hint_finalized_below_floor_is_noop`: ported (standard/tests/dispatch.zig)
- L12514 `test_standard_hint_finalized_skips_when_already_finalized`: ported (standard/tests/dispatch.zig)
- L12562 `test_standard_hint_finalized_emits_targeted_fetch`: ported (standard/tests/dispatch.zig)
- L12605 `test_standard_prune_above_floor_is_rejected`: ported (standard/tests/coverage.zig)
- L13077 `test_pipelined_handoff_retains_completed_build_until_parent_certification`: ported (standard/tests/coverage.zig)
- L13082 `test_pipelined_handoff_retains_build_across_parent_certification`: ported (standard/tests/coverage.zig)
- L13087 `test_pipelined_handoff_releases_abandoned_build_after_finalization`: ported (standard/tests/coverage.zig)
- L13111 `test_standard_prune_keeps_round_floor_evidence_for_configured_floor_restart`: ported (standard/tests/coverage.zig)
- L13459 `test_standard_reproposal_floor_below_processed_is_covered_after_prune_restart`: ported (standard/tests/coverage.zig)
- L13515 `test_standard_reproposal_reported_below_processed_survives_restart_before_ack`: ported (standard/tests/coverage.zig)
- L13557 `test_standard_reproposal_delivered_below_processed_survives_restart_before_ack`: ported (standard/tests/coverage.zig)
- L13625 `test_standard_late_finalization_block_delivered_below_processed_survives_restart_before_ack`: ported (standard/tests/coverage.zig)
- L13736 `test_standard_reproposal_delivered_as_pending_floor_anchor_survives_restart_before_ack`: ported (standard/tests/coverage.zig)
- L13834 `test_standard_reproposal_reported_for_pruned_block_is_covered_without_fetch`: ported (standard/tests/coverage.zig)
- L13902 `test_standard_set_floor_for_installed_anchor_is_covered`: ported (standard/tests/coverage.zig)
- L14011 `test_standard_restored_closed_epoch_floor_is_written_back`: ported (standard/tests/coverage.zig)
- L14027 `test_standard_restored_closed_epoch_floor_is_written_back_over_round_floor`: ported (standard/tests/coverage.zig)
- L14044 `test_standard_closed_epoch_floor_restores_from_unacknowledged_successor`: ported (standard/tests/coverage.zig)
- L14091 `test_standard_certificate_only_successor_closes_no_epoch`: ported (standard/tests/coverage.zig)
- L14156 `test_standard_closed_epoch_floor_restores_from_installed_anchor`: ported (standard/tests/coverage.zig)
- L14227 `test_standard_cache_prunes_behind_covered_reproposals`: ported (standard/tests/coverage.zig)
- L14291 `test_standard_restored_witnessed_round_prunes_cache_after_restart`: ported (standard/tests/coverage.zig)
- L14487 `test_standard_cache_keeps_previous_epoch_through_retention_window`: ported (standard/tests/coverage.zig)
- L14537 `test_standard_cache_retention_counts_retired_epochs_once`: ported (standard/tests/coverage.zig)
- L14567 `test_standard_reproposal_reported_above_processed_before_ack_survives_restart`: ported (standard/tests/coverage.zig)
- L14631 `test_standard_reproposal_reported_for_installed_anchor_before_ack_survives_restart`: ported (standard/tests/coverage.zig)
- L14730 `test_standard_reproposal_floor_above_processed_is_covered_on_restart`: ported (standard/tests/coverage.zig)
- L14826 `test_standard_ack_of_certificate_less_boundary_block_closes_its_epoch`: ported (standard/tests/coverage.zig)
- L14871 `test_standard_floor_applied_below_processed_in_open_epoch_survives_restart_before_ack`: ported (standard/tests/coverage.zig)

#### coding/mod.rs

- L440 `test_config`: ported (coding/mod_test.zig)
- L688 `test_coding_notarized_delivery_rejects_dishonest_payload_config`: ported (coding/mod_test.zig)
- L766 `test_coding_block_provider_parent_fetches_by_commitment`: ported (coding/mod_test.zig)
- L805 `test_coding_verify_missing_candidate_waits_without_fetching`: ported (coding/mod_test.zig)
- L865 `test_coding_verify_member_accepts_without_assigned_shard`: ported (coding/mod_test.zig)
- L929 `test_coding_certify_missing_candidate_fetches_by_round`: ported (coding/mod_test.zig)
- L998 `test_coding_certify_pending_verify_fetches_by_round`: ported (coding/mod_test.zig)
- L1123 `test_coding_later_epoch_activity_releases_earlier_epoch`: ported (coding/mod_test.zig)
- L1131 `test_coding_same_epoch_activity_keeps_gates`: ported (coding/mod_test.zig)
- L1141 `test_coding_certify_retains_transient_buffer_hit_through_eviction`: ported (coding/mod_test.zig)
- L1201 `test_coding_finalize_good_links`: ported (coding/tests/scenarios.zig)
- L1211 `test_coding_finalize_bad_links`: ported (coding/tests/scenarios.zig)
- L1221 `test_coding_finalize_good_links_quorum_sees_finalization`: ported (coding/tests/scenarios.zig)
- L1231 `test_coding_finalize_bad_links_quorum_sees_finalization`: ported (coding/tests/scenarios.zig)
- L1241 `test_coding_hailstorm_restarts`: ported (coding/tests/scenarios.zig)
- L1251 `test_coding_hailstorm_multi_restarts`: ported (coding/tests/scenarios.zig)
- L1264 `test_coding_hailstorm_restarts_across_epochs`: ported (coding/tests/scenarios.zig)
- L1269 `test_coding_ack_pipeline_backlog`: ported (coding/tests/scenarios.zig)
- L1274 `test_coding_ack_pipeline_backlog_persists_on_restart`: ported (coding/tests/scenarios.zig)
- L1280 `test_coding_dispatch_delivers_staged_block_without_archive_read`: ported (coding/mod_test.zig)
- L1355 `test_coding_genesis_emitted_once`: ported (coding/tests/queries.zig)
- L1360 `test_coding_proposed_success_implies_recoverable_after_restart`: ported (coding/tests/queries.zig)
- L1365 `test_coding_verified_success_implies_recoverable_after_restart`: ported (coding/tests/queries.zig)
- L1370 `test_coding_certified_success_implies_recoverable_after_restart`: ported (coding/tests/queries.zig)
- L1375 `test_coding_delivery_visibility_implies_recoverable_after_restart`: ported (coding/tests/recoverable.zig)
- L1380 `test_coding_sync_height_floor`: ported (coding/tests/queries.zig)
- L1385 `test_coding_prune_finalized_archives`: ported (coding/tests/queries.zig)
- L1390 `test_coding_floor_retains_processed_predecessor`: ported (coding/tests/queries.zig)
- L1395 `test_coding_rejects_block_delivery_below_floor`: ported (coding/tests/queries.zig, "coding reject stale block delivery after floor update")
- L1400 `test_coding_commitment_fetch_height_hint_mismatch_wakes_subscriber`: ported (coding/tests/queries.zig)
- L1405 `test_coding_subscribe_basic_block_delivery`: ported (coding/tests/queries.zig)
- L1410 `test_coding_subscribe_multiple_subscriptions`: ported (coding/tests/queries.zig)
- L1415 `test_coding_subscribe_canceled_subscriptions`: ported (coding/tests/queries.zig)
- L1420 `test_coding_subscribe_blocks_from_different_sources`: ported (coding/tests/queries.zig)
- L1425 `test_coding_get_info_basic_queries_present_and_missing`: ported (coding/tests/queries.zig)
- L1430 `test_coding_get_info_latest_progression_multiple_finalizations`: ported (coding/tests/queries.zig)
- L1435 `test_coding_get_block_by_height_and_latest`: ported (coding/tests/queries.zig)
- L1440 `test_coding_get_block_by_commitment_from_sources_and_missing`: ported (coding/tests/queries.zig)
- L1445 `test_coding_get_finalization_by_height`: ported (coding/tests/queries.zig)
- L1450 `test_coding_hint_finalized_triggers_fetch`: ported (coding/tests/queries.zig)
- L1455 `test_coding_ancestry_stream`: ported (coding/tests/queries.zig)
- L1460 `test_coding_finalize_same_height_different_views`: ported (coding/tests/queries.zig)
- L1465 `test_coding_certify_persists_equivocated_block`: ported (coding/tests/recoverable.zig)
- L1470 `test_coding_verified_after_restart_reverify_same_round_implies_recoverable`: ported (coding/tests/recoverable.zig)
- L1475 `test_coding_certify_after_restart_reverify_same_round_implies_recoverable`: ported (coding/tests/recoverable.zig)
- L1480 `test_coding_certify_at_later_view_survives_earlier_view_pruning`: ported (coding/tests/recoverable.zig)
- L1485 `test_coding_certify_first_block_fetches_genesis_parent`: ported (coding/mod_test.zig)
- L1570 `test_coding_repair_reads_buffer_only_ancestor`: ported (coding/mod_test.zig)
- L1648 `test_coding_init_processed_height`: ported (coding/tests/queries.zig)
- L1653 `test_coding_broadcast_caches_block`: ported (coding/tests/queries.zig)
- L1662 `test_certify_lower_view_after_higher_view`: ported (coding/mod_test.zig)
- L1786 `test_marshaled_reproposal_validation`: ported (coding/mod_test.zig)
- L2048 `test_invalid_reproposal_does_not_open_reconstruction`: ported (coding/mod_test.zig)
- L2143 `test_coding_reproposal_recreates_shard_state_after_eviction`: ported (coding/mod_test.zig)
- L2297 `test_coding_reproposal_verify_fetches_block_by_parent_round`: in progress (broadcast-collector)
- L2399 `test_marshaled_rejects_mismatched_context_digest`: ported (coding/mod_test.zig)
- L2493 `test_reproposal_certify_recovers_after_verify_receiver_drop`: ported (coding/mod_test.zig)
- L2594 `test_reproposal_missing_block_does_not_synthesize_false`: ported (coding/mod_test.zig)
- L2694 `test_core_subscription_closes_when_coding_reconstruction_fails`: ported (coding/mod_test.zig)
- L2766 `test_coding_floor_preserves_registered_commitment_subscription`: ported (coding/mod_test.zig)
- L2846 `test_marshaled_rejects_unsupported_epoch`: ported (coding/mod_test.zig)
- L2983 `test_marshaled_rejects_invalid_ancestry`: ported (coding/mod_test.zig)
- L3145 `test_certify_without_prior_verify_crash_recovery`: ported (coding/mod_test.zig)
- L3243 `test_certify_without_prior_verify_honors_application_rejection`: ported (coding/mod_test.zig)
- L3341 `test_certify_reconstructs_from_buffered_gossip_shards`: ported (coding/mod_test.zig)
- L3457 `test_certify_reconstructs_with_buffered_assigned_shard`: ported (coding/mod_test.zig)
- L3466 `test_certify_reconstructs_while_reproposal_verify_awaits_block`: ported (coding/mod_test.zig)
- L3474 `test_verify_resolves_once_assigned_shard_arrives`: ported (coding/mod_test.zig)
- L3663 `test_malformed_commitment_config_rejected_at_deserialization`: ported (coding/mod_test.zig)
- L3691 `test_certify_propagates_application_verify_failure`: ported (coding/mod_test.zig)
- L3788 `test_certify_not_poisoned_by_equivocating_parent_verify`: ported (standard/deferred_test.zig)
- L3917 `test_backfill_block_mismatched_commitment`: ported (coding/mod_test.zig)
- L4031 `test_coding_finalized_block_delivery_skips_recoding`: ported (coding/mod_test.zig)
- L4088 `test_coding_coalesced_block_delivery_trusts_finalized_subscriber`: ported (coding/mod_test.zig)
- L4157 `test_coding_finalized_block_delivery_rejects_digest_mismatch`: ported (coding/mod_test.zig)
- L4208 `test_coding_finalized_height_delivery_rejects_digest_mismatch`: ported (coding/mod_test.zig)
- L4316 `test_coding_ancestry_block_delivery_recomputes_root`: in progress (broadcast-collector)
- L4380 `test_coding_optimistic_ancestry_conflicts_with_certified_cache`: in progress (broadcast-collector)
- L4572 `test_coding_certified_ancestry_delivery_skips_recoding`: in progress (broadcast-collector)
- L4672 `test_coding_certification_retention_follows_finalized_tip`: in progress (broadcast-collector)
- L4796 `test_coding_notarized_delivery_recomputes_root`: in progress (broadcast-collector)
- L4843 `test_coding_untrusted_delivery_rejects_mismatched_root`: in progress (broadcast-collector)
- L4936 `test_coding_floor_anchor_panics_on_parent_commitment_mismatch`: not portable (see above)
- L4989 `test_coding_default_prepare_declines`: ported (coding/tests/propose_test.zig)
- L5045 `test_marshaled_missing_scheme_skips_propose_and_verify`: ported (coding/tests/propose_test.zig)
- L5104 `test_marshaled_certify_persists_block_before_resolving`: ported (coding/tests/propose_test.zig)
- L5239 `test_marshaled_proposed_block_persists_across_restart`: ported (coding/tests/propose_test.zig)
- L5366 `test_marshaled_propose_relay_sends_staged_block`: ported (standard/tests/dispatch.zig)
- L5473 `test_coding_prepare_relay_sends_once_and_propose_stores`: ported (coding/tests/propose_test.zig)
- L5592 `test_coding_propose_relay_after_claim_sends_once`: ported (coding/tests/propose_test.zig)
- L5679 `test_coding_prepare_waits_for_parent_without_fetching`: ported (coding/tests/propose_test.zig)
- L5769 `test_coding_prepare_skips_parent_outside_epoch`: ported (coding/tests/propose_test.zig)
- L5855 `test_coding_prepare_builds_on_epoch_genesis`: ported (coding/tests/propose_test.zig)
- L5943 `test_prepare_rebuilds_despite_verified_block_on_restart`: ported (coding/tests/propose_test.zig)
- L6116 `test_propose_reuses_reproposed_boundary_block_on_restart`: ported (standard/deferred_test.zig)
- L6221 `test_certify_releases_conflicting_verification`: ported (standard/deferred_test.zig)
- L6333 `test_certify_releases_conflicting_reproposal`: ported (coding/tests/propose_test.zig)

## Backlog
- [x] Marshal fuzz outside coding/ (`marshal/fuzz.zig`; overflow policy in
  `core/mailbox_test.zig`, ancestor stream in `ancestry.zig`).
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
  responses (resolver lane, T-01a1d5b9-c237-73f2-a935-c93580e28133).
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
- 2026-11-18: generic `mocks/scenarios.Hailstorm(H)` (harness.rs 448-1008) with the three
  standard wrappers; a short storm per shape runs outside `-Dslow-tests`.
- 2026-11-18: generic `mocks/scenarios.AckPipeline(H)` (`backlog`, `persists_on_restart`;
  harness.rs 3235-3441) with the standard wrappers.
- 2026-11-18: finalize bad-links and quorum-sees-finalization wrappers (lossy ones skip in
  Debug without `-Dslow-tests`). My 169-1218/1600-1986/2544-2591 range: digest-once (176),
  block-provider parent fetch (378), and the recoverable/certify family (514-562) went to
  runtime; sync_height_floor and reject_stale (563, 569, 2586) are bls-math's queries slice.
- 2026-11-19: bls-math finished harness.rs 3442-end (20 scenarios, `tests/queries.zig`);
  reject_stale's retired fetch matches commonware's set_floor retain. bls-math takes fuzz.
- 2026-11-19: parallel lane finished `tests/wrappers.zig` (2592-4712, 6151-6220): floor
  anchors, epoch gates, conflicting verify, below-finalized prune, genesis parent, epoch
  switch, missing-candidate fetch paths, scripted equivocation on simplex, and the covered
  restart. 4713-4993 went to examples (`tests/fetch.zig`), 4994-5931 to runtime
  (`tests/propose_validation.zig`). The four sync-failure panic tests (5932-6150) have no Zig
  counterpart (a Zig test cannot catch a panic). `mocks.GatedStrategy` is deferred: it needs
  an async `Strategy.spawn`, and its only user is outside this range.
- 2026-11-19: `marshal/conformance.zig` ports StandardStorageConformance's workload. Its audit
  is deterministic per seed, but commonware's hash (e22663c9) is unreachable: the workload's
  block count and timestamps come from the runtime RNG the scheduler shuffles with, and
  zigware's actor runs a different task set, so the streams diverge (checked: hash differs).
- 2026-11-19: marshal fuzz: 8 bodies, each against a model or round trip, each catching a
  planted bug. The mock `Block` carries its digest in its encoding (as commonware's), so
  decode_block's mutation property runs on `EmptyBlock`, which digests every field.
