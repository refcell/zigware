# Lane: glue

Owns `src/glue`.

Reference: `~/.cache/zigware/commonware-ref/glue` (about 68k Rust lines): `simulate` (2.3k,
a test harness), `transfers` (4.4k with tests and benches), `stateful` (about 33k), and `dkg`
(about 28k). The clearing lane runs this lane while it waits on qmdb `current`; when
`current`'s database lands, clearing comes first again.

## Public API (on main)
- `glue.simulate`: `ProgressTracker(P)` (`init`, `deinit`, `observe(update)` failing with
  `ForkAtHeight`/`ForkAtRound`, `all_reached`, `min_view`, `max_round`, `tracked_count`,
  `unique_digests_at`), `FinalizationUpdate(P)` (borrows its digest), `Action(P)`,
  `Schedule(P)` (`add` fails with `OutOfOrder`), `Crash(P)`, `HeightRange`, `FaultConfig`.
- `glue.simulate.Plan(D)`: a struct with the builder's fields and defaults (`engine`, `seed`,
  `link`, `crashes`, `required_finalizations` = 10, `exit_condition`, `timeout`,
  `storage_fault`, `finalization_properties`, `properties`); `run(gpa)`,
  `run_with_seed(gpa, seed)`, `run_in_context(ctx, plan, runner)`, `validate`; `Result`
  (`state`, `tracker`, `crashes`, `scheduled_actions`, `delayed_started`, `deinit`);
  `PlanError`. An engine definition `D` (see `engine.zig`) declares `PublicKey`, `Engine`,
  `State`, `participants`, `channels` (`[]const ChannelSpec`), `max_message_size`,
  `init(InitContext(P)) !struct { Engine, State }`, `start(Engine) !Handle(void)`, and
  optionally `deinit_state`. Engines report through `Monitor(P).send(update)`.
- `ExitCondition(P, S).from(&value)` with `MinimumFinalizations` and `ProcessedHeightAtLeast`;
  `FinalizationProperty(S).from(&value)` and `Property(P, S).from(&value)`; `Team(D)`.
- `glue.transfers`: `Plan(K, A)` (`init(gpa, transfers, seed, strategy, &rejection)`,
  `init_with_hasher`, `keys`, `len`, `settle(gpa, reads, strategy, &rejection) []Slot(A)`,
  `deinit`), `Selection(K, A)` (`init(seed)`, `touch`, `keys`, `register`,
  `apply(gpa, transfers, accepted)`, `settle`, `deinit`), `Change(A)` (`debiting`,
  `crediting`, `applying`, `with_effect`), `Entry(K, A)`, `Slot(V)` (`keep`, `put`,
  `delete`), `Rejection(K)` (`reason`, `key`), `Reason`, `Error` (`Rejected` or
  out-of-memory), `SeededHasher`. Account and transfer contracts are in `transfers/mod.zig`.

## Decisions
- Rust traits with async methods (`EngineDefinition`, `ExitCondition`, `Property`) become
  comptime-duck-typed parameters or small vtables; their `async fn`s are plain functions,
  since zigware tasks run on fibers.
- `Schedule.add` returns `error.OutOfOrder` where commonware panics, so its test ports.
- `ProgressTracker` keeps the distinct digests per round in a list (commonware's `HashSet`).
- `PlanBuilder` is folded into `Plan`: field defaults replace the builder, and a multi-seed run
  is a loop over `run_with_seed`. Exit conditions and properties are borrowed pointers, so a
  stateful property needs a fresh value per run (commonware rebuilds them per seed).
- `select_loop!` becomes one event queue (`events.zig`): reports, scheduled crashes and
  restarts, restart delays, and the random-crash ticker all push into it; the plan pops one
  event at a time and wakes at least every 25 ms for polling exit conditions.
- `transfers`: a rejection carries a key, so plans and settles return `error.Rejected` and
  fill a caller's `Rejection`; under a parallel strategy each batch records its own and the
  first in batch order is reported (commonware reports any offender).
- `transfers`: `Plan.init` and `Selection.init` take the hash seed (commonware's `new` draws it
  from `ahash`'s random state), since library code takes randomness from its caller. Keys are
  hashed with Wyhash over their bytes; the hash never leaves the process.
- `transfers`: an account without effects declares `Effect = enum {}` (commonware's
  `Infallible`); plans store `void` for it, since Zig cannot allocate an empty enum.
- `transfers.Slot` is qmdb's `storage.qmdb.any.batch.Slot`, so settled slots feed a staged
  merkleize directly.
- A failed check (exit condition, property) is logged at info, not commonware's error level:
  the returned `PlanError` reports it, and a warning on stderr makes the build runner print
  test-glue under "failed command" even when every test passes.
- Commonware's panics for unexercised faults (random crashes, schedules, delays, processed
  height windows) and duplicate strategies are `PlanError`s, so their tests port.

## Backlog
- [x] simulate: tracker, action (Schedule, Action, Crash) with their tests.
- [x] simulate: processed, property, exit conditions, engine definition, team, plan (the
  driver) with the plan tests and their stub engines.
- [ ] simulate: `MonitorReporter` waits on marshal's `Update`/`Tip` (consensus-marshal).
- [x] transfers: `Plan`, `settle`, and `Selection`, with the plan, settle, and selection tests
  that need no database.
- [x] transfers: the nonced-account (effect) tests.
- [x] transfers: the remaining database-free tests (edge cases, seeded key orders, bucketing,
  random batches against their flat entries, `u256` amounts).
- [x] transfers (owner: thread T-01a1d58d-7682-700c-a399-735d897bbd46): see the transfers
  section below.
- [ ] stateful: see the stateful section below (curve25519/utils thread).
- [ ] dkg (coding thread).

## transfers (owner: thread T-01a1d58d-7682-700c-a399-735d897bbd46)

Owns the benches and database-backed tests of `src/glue/transfers/` (clearing ported `Plan`,
`settle`, `Selection`, and the database-free tests).

- [x] benches (`src/glue/transfers/benches.zig`, run through `src/glue/benches.zig`):
  `transfers::{plan,settle,select}` with commonware's parameters (`transfers`, `accounts`,
  `effects=none|nonce`, `conc=1|8`).
- [x] database tests on qmdb `any` (unordered, fixed values) in `db_test.zig`: execute settles
  batches, roots do not depend on order, select merkleizes the accepted candidates, selection
  reads later rounds through expand, execute carries nonces across batches, select merkleizes
  the accepted signed candidates. `Balance` and `Nonced` gained codec methods to be qmdb
  values.
- [x] the execute tests (settles batches, order-independent roots) over `any` ordered and
  `current` unordered and ordered (32-byte bitmap chunks, as commonware's `current_config`).
- [x] `stateful_current_batches_select_and_execute_signed_candidates` on `stateful.db.current`
  (stage, expand, staged merkleize), with `select_merkleizes_the_accepted_signed_candidates`
  on `NoncedCurrent` (ordered fixed `current`) as in commonware.
- [x] `stateful_any_batches_select_and_execute_as_qmdb` on `stateful.db.any` staging. Every
  commonware transfers test now has a counterpart.

## stateful (owner: thread T-01a1d57b-0146-77aa-87b0-e622089ce218)

Owns `src/glue/stateful/` (commonware `glue/src/stateful`, about 37k lines: `actor/{core,
processor,syncer}`, `db` with `any`, `compact`, `current`, `immutable`, `keyless`, and `p2p`,
`probe`, and `tests`). Waits on qmdb `current` (storage-qmdb-sync) for `db.current` and on
marshal's actors (consensus-marshal) for the actor; until then it ports what is independent.

### Public API (on main)
- `glue.stateful.Finality` (`candidate`, `finalized`).
- `glue.stateful.db`: `Shared(DB)` (`init(gpa, io, label, db)`, `deinit`, `read` →
  `ReadGuard.get`, `write` → `WriteSlot` with `put` or `lose`, `reader`, `is_lost`), `Reader`,
  `BatchContext`, `Barrier` (`durable`, `first_failure`), `Env` (`gpa`, `io`, `storage`,
  `scope`, `child`), `validate_initialization`, `targets_eql`, `assert_managed_db` (the
  ManagedDb contract is in `db/mod.zig`'s docs). Database sets: `Shared(DB)` itself (`open`,
  `initial_sync_targets`, `new_batches`, `fork_batches`, `matches_sync_targets`, `readers`,
  `apply`, `finalize`, `prune`, `committed_targets`) and `Tuple(.{ DB1, ..., DB8 })` with the
  same methods over tuples.
- `glue.stateful.db.any.Any(Db, Hasher)`: the ManagedDb of a `storage.qmdb.any.Db`, with
  `Unmerkleized` (`write`, `with_metadata`, `get`, `get_many`, `stage(keys, out)` → `Staged`,
  `merkleize`), `Staged` (as `Current`'s: `with_metadata`, `len`, `is_empty`, `expand`,
  `merkleize(slots, unstaged)`, `deinit`), and `Merkleized`
  (`root`, `new_batch`, `get`, `get_many`, `clone`, `deinit`); `SyncTarget` is
  `qmdb.sync.Target`.
- `glue.stateful.db.current.Current(Db)`: the ManagedDb of a `storage.qmdb.current.Db`, with
  `Unmerkleized` (`write`, `with_metadata`, `get`, `get_many`, `stage(keys, out)` → `Staged`,
  `merkleize`), `Staged` (`with_metadata`, `len`, `is_empty`, `expand(keys, out)` → `Range`,
  `merkleize(slots, unstaged)`, `deinit`), and `Merkleized` (`root`, `ops_root`, `new_batch`,
  `get`, `get_many`, `clone`, `deinit`). Its `SyncTarget` is the ops root over
  `[sync_boundary, size)`.
- `glue.stateful.db.sync` (also `db.Anchor`, `db.TipUpdate`): `Anchor(D)` (`height`, `round`,
  `digest`, `eql`), `TipUpdate(D, T)` (`init`, `with_observation(gpa, io, anchor, targets)`
  → update and a `oneshot.Receiver(void)`, `record(context)` calling
  `context.record(anchor, targets)` then resolving the observer, `discard`),
  `dispatch_queued_tips(D, T, *?ring.Receiver(TipUpdate), ring.Sender(T), *Anchor, *T)`,
  `DbSyncState`, `CoordinatorAction(D, T)` (`wait`, `dispatch`, `converged`), and
  `CoordinatorState(D, T)` (`init(db_count, anchor, targets)`, `record_reached`,
  `record_tip_update`, `next_action`, `should_dispatch`, `mark_reached_same_target`).
- `glue.stateful.db.p2p.max_payload_size(F, D, max_serve_ops, op_size)`: the bound on every
  state sync request and response framed by the resolver.
- `glue.stateful.db.p2p.Handler(F, S)`: the resolver engine's consumer (`deliver(delivery,
  value)` → `oneshot.Receiver(bool)`) and producer (`produce(key)` →
  `oneshot.Receiver(Produced)`), forwarding `EngineMessage(F, S)` (`deliver`, `produce`) to the
  actor's `actor.mailbox`; `Subscriber(Reply)` compares by `id`.
- `glue.stateful.probe`: `Sample(S, D)` (`init(gpa, minimum_epoch)`, `awaits(peer)`,
  `record(peer, finalization)` taking ownership, `select(committee_size, judge)` with
  `judge.judgeable(*const Finalization)`, `get_floor`, `reset`, `deinit`), `Message(S, V)`
  (`request`, `response: Finalization`; codec, `max_encode_size`), `Tag`,
  `max_payload_size(V, S, participants)`. The DKG probe can reuse `Sample` as commonware's does.
- `glue.stateful.probe.Discovery(S, D, Provider)`: the probe actor's I/O-free state.
  `init(gpa, provider, minimum_epoch)`, `subscribe(oneshot.Sender(Floor))` → whether to start a
  round, `request_round()` → committee to solicit (or null), `receive(peer, payload, rng,
  strategy)` → `Verdict` (`ignore`, `block`, `recorded`), `attach`, `finished`, `retrying`,
  `selected_floor`, `deinit`. `Floor(S, D)` is the owned finalization a subscriber receives.
- `glue.stateful.probe.Probe(P)` (`P` declares `Scheme`, `Digest`, `Provider`, `Source`,
  `Blocker`, `NetSender`, `NetReceiver`):
  `init(gpa, io, Config, net_sender, net_receiver)` → `{ probe, mailbox }`, `run(rng,
  strategy)`, `deinit`. `Mailbox` has `subscribe()` → `oneshot.Receiver(Floor)` and
  `attach(source)`. `MarshalSource(marshal.core.Mailbox(S, V))` serves marshal's latest
  finalization (`get_info(.latest)` then `get_finalization`).
- `glue.stateful.SyncPlan(S, V)` (`actor.SyncPlan`): `init(env, partition_prefix)` (env has
  `gpa`, `storage`), `deinit`, `may_sync`, `completed`, `floor`, `set_floor(*const
  Finalization)` (stores a copy; ignores floors not at a later round), `set_completed(height)`,
  `marshal_start(B, genesis)` (a marshal `Start`; the floor is a copy the caller frees),
  `should_sync(requested)`. `SyncState(S, C)` is its persisted record (tag 0 in progress with
  a finalization, tag 1 complete with a height), byte-identical to commonware's.
- `glue.stateful.actor.pruning`: `PruneConfig` (`maintenance_interval`,
  `retained_marshal_blocks`, `retained_qmdb_blocks`; `validate`), `Pruning(T)` (`init(gpa,
  config, max_pending_acks, offset)`, `random(gpa, config, max_pending_acks, std.Random)`,
  `observe(height, targets)` → `?Prune(T)`, `deinit`), `ExecutionStep(D)`, `Disposition`, and
  `FinalizationBoundary(D)` (`disposition`, `completed`).

### Decisions
- ManagedDb and DatabaseSet are comptime contracts. Mutations take `*Self` and return errors
  where commonware moves the database by value and panics: a failed mutation loses the member
  (`WriteSlot.lose` closes it), later access panics, and the set returns the error for
  `Stateful` to stop on. Tuple opens close the members already opened on failure.
- `Shared` locks reads exclusively: storage reads take `*Db` (journal reads fill buffers), so
  concurrent readers would race. commonware's read lock is shared; the outcome is the same.
- Tuple sets mutate members one at a time, each under only its own lock (commonware joins
  them; it also never holds two members' locks). The concurrency and cancellation tests of
  tuple applies have no counterpart until members run concurrently.
- zigware databases persist synchronously in `finalize` (`start_sync` completes at once), so a
  `Barrier` holds each member's outcome instead of runtime handles.
- `probe.Sample` keeps replies in a peer-sorted list (commonware's `BTreeMap`), so ties
  between equal rounds resolve as commonware's do, and owns recorded finalizations.
- `SyncPlan` mutates in place (commonware consumes and returns it) and returns storage errors
  (commonware panics); a backward completion height is an assertion.
- `Current` covers unordered fixed `current` databases, the only ones on main; ordered and
  variable follow storage-qmdb-sync. Its crash-recovery test (deterministic storage faults)
  waits on a storage fault harness; the bounded-init test covers its durable-discard checks.
- `CoordinatorState` holds at most `max_databases` (8) databases and their assigned
  generations in fixed arrays (commonware: a `Vec` and a `BTreeMap`); generations are `u64`.
  `max_payload_size` returns `error.TooManyOperations` above `u32` where commonware panics.
- `EngineMessage.deliver` owns copies of the delivery's subscribers and value (the engine
  lends them); the overflow policy drops peer requests and deliveries whose requester left.
- The probe actor splits into `Discovery` (pure, tested without a network) and a driver that
  performs its sends and blocks; probe/mod.rs's protocol tests run against `Discovery`.
- `Pruning` keeps its retention window in a ring allocated at init (commonware grows a
  `VecDeque`); an invalid config or phase returns `error.InvalidPruneConfig` where commonware
  panics.
- `Any` takes the hasher as a parameter (the storage `Db` does not expose it) and uses
  commonware's 64-byte bitmap chunks in tests. Staged `merkleize` consumes the staged batch
  also on error.

### Backlog
- [x] db: `Shared`, `Reader`, `Barrier`, single and tuple sets, with mod.rs's set tests.
- [x] db/any: the ManagedDb adapter with any.rs's stale-read and apply-does-not-finalize tests.
- [x] db/any: `stage`/`expand`/staged `merkleize` with any.rs's staged test.
- [ ] db/any: variable values, ordered.
- [x] db/current: the unordered fixed ManagedDb with staging and current.rs's tests.
- [ ] db/current: ordered and variable (after storage-qmdb-sync), the crash-recovery test.
- [ ] db: keyless, immutable, compact.
- [x] db: `Anchor`, `TipUpdate`, `dispatch_queued_tips`, and the generation coordinator with
  mod.rs's tests of them, a regroup test, and the channel edge cases.
- [x] db/p2p: `max_payload_size` with limits.rs's widest-encodings test.
- [x] db/p2p: `Handler` and `EngineMessage` with handler.rs's overflow test.
- [ ] db: state sync engines (`StateSyncDb`, `StateSyncSet`, `drain_generation_updates`, the
  single and tuple sync loops) and their tests; db/p2p (actor, mailbox; waits on qmdb's sync
  `Source` and engine).
- [x] probe: `Sample`, wire `Message`, `max_payload_size` with limits.rs's widest-encodings
  test and sample selection tests.
- [x] probe: `Discovery` with probe/mod.rs's protocol tests (selection, late subscribers,
  pausing, blocking, epoch filtering).
- [x] probe: the actor driver (simplex `Inbox` over mailbox and network, retry deadline,
  service from a source) with an in-memory actor test.
- [ ] probe: a DST over marshal's harness and p2p.simulated.
- [x] actor: `SyncPlan` and `SyncState` with plan.rs's tests.
- [x] actor: the processor's prune schedule and finalization boundary with their tests.
- [ ] actor: processor state, syncer plan, core (after marshal); tests (single and
  multi db apps, floor, properties).

## Log
- 2026-11-16: lane started; simulate's progress tracker and actions with their tests.
- 2026-11-16: simulate's plan driver, team, engine contract, exit conditions, and properties,
  with commonware's 9 plan tests and a duplicate-strategy test (20 glue tests).
- 2026-11-16 (stateful): db core (`Shared`, sets, `Barrier`) and the `any` adapter with their
  commonware tests.
- 2026-11-16 (stateful): probe sample, wire messages, and payload bound.
- 2026-11-16 (stateful): `SyncPlan` with its persisted `SyncState`.
- 2026-11-16 (stateful): the processor's prune schedule and finalization boundary.
- 2026-11-16: transfers `Plan` (partitioned parallel build), `settle`, and `Selection` with
  commonware's 39 database-free tests under every execution shape (75 glue tests);
  `transfers.Slot` is qmdb's `any.batch.Slot`. The transfers lane
  (T-01a1d58d-7682-700c-a399-735d897bbd46) takes over the benches and database tests.
- 2026-11-16 (stateful): the `current` ManagedDb adapter with staging.
- 2026-11-16 (stateful): state sync anchors, tip updates, the generation coordinator, and the
  p2p payload bound.
- 2026-11-16 (stateful): the db/p2p resolver handler.
- 2026-11-18 (stateful): staged `stage`/`expand`/`merkleize` on the `any` adapter.
- 2026-11-16: transfers benches (plan, settle, select) and 13 database tests on qmdb `any`
  and `current`, one through `stateful.db.current`.
- 2026-11-18: the stateful `any` transfers test; transfers is fully ported.
- 2026-11-18 (stateful): the probe's discovery state.
- 2026-11-18 (stateful): the probe actor driver; `consensus.simplex.actors.inbox` exported.

## dkg (owner: coding lane, thread T-01a1d58d-bff1-75a1-8ccb-4b8dd7bc9755)

Owns `src/glue/dkg`. Reference: `glue/src/dkg` (about 24k Rust lines).

### Public API (on main)
- `glue.dkg`: `assert_reshare_block`, `assert_registrar`, `assert_secret_store`,
  `assert_participants_provider` (commonware's `ReshareBlock`, `Registrar`, `SecretStore`,
  `ParticipantsProvider` as comptime interfaces), `max_payload_size(V, P, max)`.
- `dkg.types`: `SchemeInfo(V, P)` (`init(public_key, players, sharing, ?share)` picks
  `signer`/`member`/`verifier`), `EpochOutcome`, `Participants(P)` (`validate`,
  `tracked_peers`, codec cfg = max participants), `EpochInfo(V, P, D)` (`participants`,
  `peers`, `max_encode_size_with`; decode rejects a directory that does not name exactly the
  epoch's peers), `Payload(V, P, D)` (`dealer_log`/`epoch_info`), `Message(V, P)`
  (`dealer`/`ack`), `InfoCfg`, `max_participants`. All own their memory (`deinit`, `clone`,
  `eql`).
- `dkg.network`: `Addresses(P)` (address directory), `DirectoryOps(P, D)` (dispatch over
  `utils.sequence.Unit` and `Addresses`), `Tracked(P)`, `assert_manager`,
  `KeyOnlyManager(M)`, `AddressableManager(M)` (`track` fails with `MissingAddress` before
  activating anyone; `missing_address` names the peer).
- `dkg.fence`: `Fence` (`init(io)`, `mark`, `close`, `gate`), `Gate` (`wait`, `poll`).
- `dkg.state_sync`: `StateSync(S, D, V, Dir)` (epoch info and finalized floor, codec cfg
  `{ info, certificate }`), `Plan(S, D, V, Dir)` (`init(gpa, io, storage, config, provided)`
  persists provided material, `disabled`, `resolve(storage, recovered_epoch)` returns a copy),
  `Config`, `recovered_epoch(processed, epocher)`.
- `dkg.reshare`: `Event(V, P)` (the recovery journal's codec), `Store(V, P, D, SS)` (`init`
  replays the journal, `commit_epoch`, `current_info`, `share`, `seed`, `seed_or_random`,
  `prune`, `logs`/`has_log`/`dealings`/`acks`, `append_dealing`/`append_ack`/`append_log`,
  `create_dealer`, `create_player`, `create_player_with_logs`), `Dealer(V, S)` (`handle`,
  `finalize`, `finalized`, `clear_finalized`, `shares_to_distribute`,
  `has_acknowledgement_quorum`), `Player(V, S)` (`handle`), `AckOutcome`.
- `dkg.reshare.Mailbox(T)` (`T` declares `Block`, `Ack`, `Ancestry`; `init(gpa, io, sender)`,
  `next_log(height) !?LogReservation`, `epoch_info(ancestry) !EpochInfoResponse`,
  `report(Update)`), `Message(T)`, `LogReservation(T)` (`take_payload`, `included`, `deinit`
  releases the log), `EpochInfoResponse(Payload)` (`available`/`unavailable`); `report` takes
  `consensus.marshal.Update(B, A)`. `dkg.reshare.Metrics(P)`
  (`init(gpa, scope)`, `reconcile`, `set_epoch`, `set_phase`, `record_share`, `record_ack`,
  `record_success`), `Phase`.
- `dkg.reshare.actor.Actor(T)` (`T` adds `Signer`, `Manager`, `Blocker`, `Provider`,
  `SecretStore`, `Registrar`, `Marshal` (`get_block(.{ .height })`), and `Strategy` to the
  mailbox's parameters; `assert_types`): `init(gpa, io, scope, Config(T))` returns the actor
  and its `Mailbox`; `setup_epoch(store, state_sync) !Setup` (`follow` or `participate:
  PreparedEpoch`), `prepare_epoch`, `follow(store) !Flow`, `covered`, `advance`,
  `register_epoch`, `recovered_share`. `ContractError`, `Flow` (`proceed`/`stop`).
- `dkg.reshare.actor.setup`: `FinalizedTip(D)`, `startup(B, processed, floor)`,
  `state_sync_skips_inclusion_prefix`, `recovered_share(V, store, key, info)`,
  `register_and_mark(registrar, io, fence, epoch, info)`, `dealer_for_phase`.
- `dkg.reshare.actor.inclusion`: `PendingLogs(V, P)` (sorted, `put_first` keeps the
  earliest), `PendingLogScan`, `pending_logs(B, gpa, scan, *ancestry) !?PendingLogs`,
  `validate_future_participants`, `ArtifactRequests(A, R)`, `Ceremony`, `VerifiedLogs`,
  `Verification(V, P)` (`retain`, `ready`).
- `dkg/tests/mocks.zig` (test fixtures): `StoreHarness`, `TestStore`, `MockBlock(Dir)`/`TestBlock`, `EncodedPayload`,
  `genesis_block`, `child`, `MemorySecretStore`, `StaticParticipants`, `MockConsumer`.

### Decisions
- Rust's async trait methods block on the runtime's `std.Io` (as in `consensus.traits`).
- `Fence` is one shared object: the owner calls `close` where Rust drops the `Fence`.
- `MissingAddress(P)` is an error code; `network.missing_address` returns the peer.
- `state_sync.Plan` is one shared object (Rust clones an `Arc`); both actors take a pointer.
  Its `init` returns `EpochMismatch`/`InvalidMaterial` and storage errors where commonware
  panics, so the `should_panic` tests port as error checks.
- The reshare `Store` takes the secret store by pointer; its methods may fail (`!void`,
  `!?T`), and storage failures are errors where commonware panics. Dealers and players
  borrow the round's `Info`.
- A reshare `next_log` message carries no sender of the actor's mailbox: the actor answers
  with the payload and `Mailbox.next_log` wraps it in a `LogReservation` with its own sender.
  The overflow policy runs under the mailbox lock and could not drop a message owning a
  sender. A canceled `next_log` closes its responder and releases a log that already arrived.
- Reshare metrics: the telemetry family has no `clear`, so `Metrics` tracks the peers each
  family exports and `reconcile` removes those that left their role.
- Inclusion's pending-log scan runs on the caller's task; canceling it ends a stalled read
  with `error.Canceled` (commonware's shutdown signal). `validate_future_participants`
  returns errors where commonware panics.
- The reshare actor returns `ContractError`s where commonware panics on marshal or provider
  contract violations, so its `should_panic` tests check errors; the run loop stops on them.
  Collaborators the caller owns (manager, blocker, provider, registrar, fence) are pointers.
- dkg logs rejections of peer-supplied input (detached or truncated ancestry, invalid
  pending logs) at info, not commonware's warn: tests hit them on purpose, and a warning on
  stderr makes test-glue print a failed-command block in every push (as simulate, 3244236).

### Backlog
- [x] types (with conformance hashes), limits, fence, network.
- [x] state_sync (`Plan`, `StateSync` codec and conformance).
- [x] reshare: store (journal `Event` codec and conformance) with its 6 tests.
- [x] reshare: mailbox and metrics with their tests; the shared test mocks.
- [x] reshare actor: setup's helpers with commonware's 5 setup tests.
- [x] reshare actor: inclusion's scan, request queue, and verification retention with
  commonware's 9 helper tests (the whole-window tests land with the actor).
- [x] reshare actor: core, setup, and follower mode, with the follower tests and the
  applied-tip contract checks.
- [ ] reshare actor: dealing, inclusion, and dkg windows; the run loop; application.
- [ ] bootstrap, probe (wire with conformance, discovery, service), orchestrator.
- [ ] tests: the dkg and reshare harnesses, properties, and mocks; lookup's peer-activation
  test.

### Log
- 2026-11-16: types, network, limits, and fence with their tests; 8 types and network
  conformance hashes match commonware's.
- 2026-11-16: state_sync's `StateSync` and `Plan` with commonware's 8 tests; both `StateSync`
  conformance hashes match.
- 2026-11-16: reshare's recovery store with commonware's 6 tests; the `Event` hash matches.
- 2026-11-16: reshare mailbox and metrics with commonware's tests; shared DKG test mocks;
  setup's helpers with its 5 tests.
- 2026-11-18: inclusion's pending-log scan, request queue, and verification retention.
- 2026-11-18: the reshare actor's core, setup, and follower mode.
