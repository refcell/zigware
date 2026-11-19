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
  optionally `deinit_state`. Engines report through `Monitor(P).send(update)`, or put
  `MonitorReporter(P, R).init(pk, monitor, inner)` in marshal's reporter chain.
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
- [x] simulate: `MonitorReporter` (examples lane): forwards marshal's `Update.tip` to the
  plan's `Monitor`, then every update to the wrapped reporter.
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
- `glue.stateful.db.keyless.Keyless(F, E, C, H)`: the ManagedDb of a `storage.qmdb.keyless.Db`
  (fixed or variable by the encoding `E` and journal `C`), with `Unmerkleized` (`append`,
  `with_metadata`, `with_inactivity_floor`, `get(loc)`, `get_many(locs, out)`, `merkleize`) and
  `Merkleized` (`root`, `bounds`, `new_batch`, `get`, `get_many`, `clone`, `deinit`). Its
  `SyncTarget` is the root over `[sync_boundary, size)`.
- `glue.stateful.db.immutable.Immutable(F, K, E, C, H, T)`: the ManagedDb of a
  `storage.qmdb.immutable.Db` (fixed or variable), with `Unmerkleized` (`set`, `with_metadata`,
  `with_inactivity_floor`, `get(key)`, `get_many(keys, out)`, `merkleize`) and `Merkleized`
  (`root`, `bounds`, `new_batch`, `get`, `get_many`, `clone`, `deinit`).
- `glue.stateful.db.compact.Compact(F, O, H)`: the ManagedDb of a `storage.qmdb.compact.Db`
  over keyless or immutable operations `O`, with `Unmerkleized` (`append` for keyless, `set` for
  immutable, `with_metadata`, `with_inactivity_floor`, `merkleize`; no reads) and `Merkleized`
  (`root`, `bounds`, `new_batch`, `clone`, `deinit`). Its `SyncTarget` is a
  `qmdb.sync.CompactTarget` (root and size).
- `glue.stateful.db.state_sync`: `SyncEngineConfig`, `Channels(Target)` (borrowed
  `tip_updates` and `finish`, owned `reached_target`), the StateSyncDb contract
  (`assert_state_sync_db`; `T.sync_db(env, config, source, target, channels, sync_config)`),
  `sync_standard_db(DB, ...)` and `sync_compact_db(DB, ...)` over `qmdb.sync`, and
  `sync_shared(T, D, env, config, source, anchor, target, tip_updates, sync_config)` →
  `Synced(T, D)` (`databases`, `anchor`), the single-database coordinator. The keyless,
  immutable, and compact adapters implement `sync_db`.
- `glue.stateful.db.state_sync.sync_tuple(types, D, env, config, sources, anchor, targets,
  tip_updates, sync_config, ?*?Failure)` → `tuple.Synced(types, D)`: tuple sets' state sync
  over `sync.CoordinatorState`. Each member syncs in its own task beside a reporter of the
  generations it reached. On failure it returns the first failing member's error, and
  `Failure` names its index and type (commonware's error string).
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
- `glue.stateful.actor.Pending(D, B)`: the processor's speculative state over batches `B`
  (`clone`, `deinit`). `init(gpa, anchor)`, `cache(digest, Entry)` (only blocks at later rounds
  linked to the branch; takes the batch either way), `get`, `contains`, `speculative_len`,
  `descendants(digest, round, *Set)`, `boundary(digest, round)` → `FinalizationBoundary`,
  `retain_branch(anchor, parent, *const B)` → forks pruned, `remove`, `clear`, `deinit`.
- `glue.stateful.actor.Execution(P)` (`P` declares `App`, `Databases`, `Provider`; see
  execution.zig for the `App.process` contract): the processor's shared execution layer.
  `init(gpa, io, databases, anchor)`, `fork_batches(parent)`, `cache_pending`, `retain_branch`,
  `process_candidate(app, *Ancestry)`, the flight registry (`join_flight(app, ancestry)` →
  `?*Flight` with `wait`, then `release`; `process_shared`; `flights_idle`), and replay
  (`prepare_replay`, `next_replay`, `rebuild_pending(app, *Provider, target)`). `Finality`,
  `PrepareBatchesError` (`Invalid`, `Incomplete`).
- `glue.stateful.actor.Processor(P)` (`P` as for `Execution`; `App` adds `Captured`, `capture`,
  and `finalized`): `init(gpa, io, app, databases, anchor, ?Pruning)`, `boundary(block)`,
  `redelivered(block)`, `finalize(*const Provider, block, start_barrier)` → `Applied{barrier,
  prune}`, `branch_anchor`, `flights_idle`, `deinit`. `actor.Boxed(B)` is the type-erased
  ancestry (commonware `BoxedAncestry`).
- `glue.stateful.actor.Verifier(P)` (`Processor.verifier()`; `P.Provider` adds
  `canonical_digest(Height) !?Digest`): `prepare(*Provider, ancestry, verify)` → `Prepared`,
  `next(*const Provider, *Prepared)` → `?Next{step, ancestry}`, `process(ancestry)`.
  `Prepared.finish` returns the ancestry a proposal builds on.
- `glue.stateful.actor.Durability` (core): `init(gpa, durable)`, `record(height, Exact)`,
  `record_duplicate`, `applied`, `covers`, `needs_barrier`, `set_barrier(db.Barrier)`,
  `complete()` (acknowledges what the barrier made durable; false on a failed barrier),
  `deinit` (cancels the rest). `db.Barrier.record` is public for set implementations.
- `glue.stateful.actor.Verifications(P)` (core; `P` adds `Recover`, a proposal awaiting its
  parent's state): `init(gpa, io, verifier, provider)`, `schedule(Request)` (`verify{ancestry,
  verification: oneshot.Sender(bool)}` or `recover`), `complete_ready`, `complete_next`,
  `pause(?Boundary)`, `resume`, `builds` (recovered proposals), `len`, `deinit`.
- `glue.stateful.actor.Mailbox(P)` (core; the marshal application and `Reporter`):
  `init(gpa, io, actor.mailbox.Sender(Message))`, `clone`, `deinit`, `prepare(ctx, context,
  ancestry, input)` → `Handoff(Digested)`, `propose(...)` → `?Digested`, `verify(ctx, context,
  ancestry)` → `bool` (no verdict waits until cancelled, never `false`), `report(Update)`,
  `subscribe_databases()`. `ProposalRequest` is the verifications handler's `Recover`.
- `glue.stateful.db.p2p.Mailbox(DB, F, Op, D)`: the `qmdb.sync` Source over the resolver
  actor's mailbox. `init(io, actor.mailbox.Sender(Message))`, `clone`, `deinit`,
  `attach_database(db.Shared(DB))`, `serve(gpa, request)` → `Served` (first candidate and its
  `Feedback`; `error.ResponseDropped` when the actor drops the fetch). `Message(DB, F, Op, D)`
  keeps only the latest attachment and live fetches while the mailbox is full.

### Decisions
- Tuple state sync keeps each member's newest pending reached generation in a slot rather than
  commonware's bounded mailbox with a per-database overflow policy. A member reports
  non-decreasing generations and the coordinator ignores generations a member no longer has,
  so the events the slot drops are ones commonware's coordinator would ignore
  (broadcast-resolver lane).
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
- A processor flight is a task started with `io.concurrent` that stores its result and sets
  an `Io.Event` (commonware's `Shared` future). The last request to `release` it unregisters,
  cancels, and frees it. A request admitted while a cancelled flight unwinds starts a fresh
  one; commonware's synchronous drop prevents that overlap, and here the pending cache makes
  the duplicate processing idempotent. The application is a handle copied per call (Rust
  `Clone`), and every ancestry is marshal's `AncestorStream` (commonware boxes any ancestry).
- A verification answers `false` only for `error.Invalid`/`error.Incomplete`; every other
  outcome (`error.Waiting`, cancellation, allocation or spawn failure) drops the oneshot unsent,
  which consensus reads as no verdict and leaves to its timeout, as marshal's wrappers do
  (70c082e). A waiting block is never voted against; a test pins this.
- The verifications handler runs each phase as an `io.concurrent` task that posts its work to
  a completion list the actor drains (commonware polls the phases in a `FuturesUnordered`).
- Where commonware's verification future stays pending forever (missing ancestry or a
  canonical block marshal lacks), `Verifier.prepare` returns `error.Waiting`; the core actor
  leaves such a request unanswered until its caller cancels.
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
- [x] actor: the processor's speculative `Pending` state (cache, descendants, retain_branch).
- [x] actor: the processor's execution layer (flights, forking, candidate processing, replay)
  with commonware's flight and replay tests.
- [x] actor: the processor's finalization (`Processor.finalize`, boundary, redelivery) with
  commonware's finalization tests.
- [x] db/p2p: the `Mailbox` sync source and its overflow policy.
- [ ] db/p2p: the resolver actor (serving peers, response checks) on `qmdb.sync.sync`.
- [x] actor: the processor's `Verifier` (prepare, step order, shared processing).
- [x] actor/core: `Durability` (barriers and the acknowledgements awaiting them).
- [x] actor/core: the `Verifications` handler (phases, admission, pause/resume, answers).
- [x] actor/core: the mailbox (overflow, prepare/propose/verify/report, subscribe_databases).
- [ ] actor/core: propose, processing loop, syncing; app tests (after marshal); tests (single and
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
- 2026-11-18 (stateful): the processor's speculative `Pending` state.
- 2026-11-18 (stateful): the processor's execution layer and flight registry.
- 2026-11-18 (stateful): the processor's finalization path and boxed ancestry.
- 2026-11-18 (stateful): the db/p2p `Mailbox` sync source with commonware's mailbox tests.
- 2026-11-19 (stateful): the processor's `Verifier`.
- 2026-11-19 (stateful, broadcast-resolver lane): the `keyless` ManagedDb adapter.
- 2026-11-19 (stateful, broadcast-resolver lane): the `immutable` and `compact` ManagedDb
  adapters.
- 2026-11-19 (stateful, broadcast-resolver lane): single-database state sync and the
  adapters' `sync_db`.
- 2026-11-19 (stateful, broadcast-resolver lane): tuple-set state sync.
- 2026-11-19 (stateful): the core actor's `Durability`.
- 2026-11-19 (stateful): the core actor's `Verifications` handler; waiting verifies abstain.
- 2026-11-19 (stateful): the core actor's mailbox.

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
- `dkg.orchestrator`: `max_payload_size(S, D, n)`; `Mailbox(B, A)` (a marshal reporter:
  `init(sender)`, `report(Update)` forwards blocks and ignores tips) and `Message(B, A)`
  (`finalized{block, ack}`, reliable overflow); `Actor(T)` with `init(ctx, Config(T)) !{
  Actor, Mailbox }`, `run(votes, certificates, resolver: Channel) !void`, `deinit`, and
  `ContractError`; `Config(T)`, `SimplexConfig(L)`. `T` declares `Context`, `Block`, `Ack`,
  `Scheme`, `Provider` (`scheme(epoch) ?*const Scheme`), `Manager`, `Marshal`
  (`get_processed`, `get_block`, `hint_finalized`), `Blocker`, `ElectorConfig`, `Elector`,
  `build_elector(config, gpa, n) !Elector`, `Automaton` (a pointer), `Relay`, `Reporter`,
  `Strategy`, `Sender`, and `Receiver`.
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
- The dealing window keeps commonware's mailbox-biased `select_loop!` by draining the mailbox
  with `try_recv` first, then racing the mailbox against the channel with `Io.Select`; when
  both finish in one race, both are handled, mailbox first. A window's epoch, store, dealer,
  and player travel together as `dealing.Window(T).Session`.
- Inclusion's dealer-log verification (commonware's spawned `VerificationTask`) runs on the
  caller's task in `artifact.Artifacts(T).verify`; the window decides when to call it.
  Invalid local state, mismatched directories, and a missing final payload are errors.
- The inclusion window races the mailbox, a scan of a fresh copy of the scanned request's
  ancestry, and that requester leaving (`Sender.closed`) with `Io.Select`, mailbox first.
  A scan that loses the race restarts next iteration; a finalized block marks it stale.
- zigware's marshal application contract has no `Input` type, so `reshare.Application(A, T)`
  passes the reshare payload to the inner application as an extra `propose`/`prepare`
  argument (`?Payload`, owned by the inner application) instead of commonware's
  `Input { upstream, payload }`.
- One-shot DKG reports its outcome on a `oneshot.Sender(Actor(T).DkgOutcome)` in
  `Mode.dkg.completion` (commonware's `DkgCompletion` callback); a failed manager `track`
  is logged at info and completes the ceremony without an output, as commonware does.
- orchestrator actor: commonware's panics (marshal skipped the final block, a boundary block
  without the next epoch's `EpochInfo`, no scheme for an entered epoch) are
  `ContractError`s that `run` returns. The run loop races the two backup channels,
  `Engine.wait_stopped` (a canceled `Handle.join` would detach the engine), and the mailbox,
  then handles every source that finished, in commonware's `select_loop!` order. Marshal sits
  behind the same small reader interface the reshare actor uses. The `latest_epoch` gauge is
  not carried.

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
- [x] reshare actor: the dealing window with dealing.rs's 2 tests.
- [x] reshare actor: inclusion's artifact derivation (verify, derive, commit_final,
  observe_dealer_log) with 3 of its artifact tests.
- [x] reshare actor: the inclusion window loop with `redelivered_receipts_survive_phase_
  changes` and `pr_5263_regression`.
- [x] reshare actor: the reshare-mode epoch loop (`run.Runner(T).run_epochs` and
  `participate`) over a `p2p.utils.mux` handle.
- [x] reshare actor: one-shot DKG mode (`dkg.Dkg(T).run_dkg`, terminal, restart from the
  stored final block), with a singleton ceremony test driven through the mailbox.
- [x] reshare actor: `run.Runner(T).run`, the actor task over its dealing channel (mux,
  startup tip, state-synced epoch registration, DKG or reshare mode).
- [x] reshare: the `Application` wrapper with 9 of application.rs's tests (final-block
  proposal and verification, phase gating of dealer logs, reservation release).
- [ ] reshare: application.rs's prepare and dropped-proposal tests.
- [ ] reshare actor: resolving the startup from marshal's anchor and the state-sync plan
  (commonware `start`'s preamble) (store init, mux, state-sync
  resolution, startup tip); inclusion's remaining window tests (gated and stalled ancestry, scan
  yielding to finalization, closed verification) and `finalization_error_panics`; the dkg
  window; the run loop; application.
- [x] orchestrator: limits (`max_payload_size`) with `prefixes_simplex`.
- [x] orchestrator: the actor, with tests of the epoch transition, catch-up hints, and
  missing schemes.
- [ ] orchestrator: mod.rs's cluster tests, on bls-math's node composition. (bootstrap and
  probe moved to other lanes, which own src/glue/dkg/bootstrap/ and src/glue/dkg/probe/.)
- [x] ~~tests: the dkg and reshare harnesses, properties, and mocks; lookup's peer-activation
  test.~~ Moved to the bls-math lane (T-01a1d57b-1003).
- [x] orchestrator: mailbox (`Mailbox(B, A).report`, reliable overflow).

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
- 2026-11-18: simulate's `MonitorReporter` (examples lane), with its tests.
- 2026-11-18: the dealing window; both of dealing.rs's tests catch a planted bug.
- 2026-11-18: inclusion's artifact derivation; its 3 tests catch planted outcome and share
  bugs.
- 2026-11-18: the inclusion window loop; its 2 tests catch a late scan start and a lost
  redelivery acknowledgement.
- 2026-11-18: the reshare epoch loop; its test catches a skipped dealing window.
- 2026-11-18: `Runner(T).run`; the epoch-loop test now runs through it and catches an
  inverted mode dispatch.
- 2026-11-19: orchestrator limits; its test catches a missing subchannel prefix.
- 2026-11-19: the reshare `Application` wrapper; its tests catch an accepted final-payload
  mismatch, a kept reservation after a declined proposal, and an ungated dealer log.
- 2026-11-18: one-shot DKG mode; a singleton ceremony completes through the mailbox
  (dealing, next_log, inclusion, epoch_info), and the test catches a lost outcome.
- 2026-11-19: orchestrator mailbox; its test catches an overflow policy that drops reports.
- 2026-11-19: orchestrator actor; its tests catch an early boundary acknowledgement, a
  missing skipped-block check, and an ignored future-epoch hint.

## dkg probe/bootstrap (owner: p2p lane)

The p2p lane owns `src/glue/dkg/probe/` and `src/glue/dkg/bootstrap/` (agreed with the glue
lane on 2026-11-19). The glue lane keeps the reshare actor, the application, and the
orchestrator.

- [x] probe wire (`Tag`, `Message`, `read_request`, `read_response`, `read_block`) and limits
  (`max_payload_size`), with limits.rs's `widest_encodings` test; both `probe::wire`
  conformance hashes match commonware's (in `conformance_test.zig`).
- [x] probe mailbox and actor (discovery, service), with mod.rs's 20 tests on the simulated
  network. A `MemorySource` stands in for commonware's marshal-backed source (it answers by
  height, as marshal's `get_finalization`/`get_block` do); `MarshalSource` adapts marshal.
- [x] discovery.rs's 4 decoding tests (standard and coding variants, mock and BLS threshold
  schemes); marshal's `mocks.Block(Sha256, CodingContext)` stands in for `CodingBlock`.
- [ ] bootstrap engine (bootstrap/mod.rs), with its tests: moved to bls-math on 2026-11-19.

### Log
- 2026-11-19: probe wire and limits; the `Tag` and `Message` hashes match, and the message
  hash catches a planted narrow timestamp.
- 2026-11-19: probe actor (discovery, service, mailbox) with mod.rs's tests; they catch a
  responder mismatch, blocking stale replies, a late failover, a wrong boundary height, and
  kept subscribers after a failed activation.
- 2026-11-19: discovery.rs's decoding tests; they catch a block decoded as untrusted.

## dkg bootstrap and test harnesses (owner: bls-math lane)

The bls-math lane owns `src/glue/dkg/bootstrap/` and `src/glue/dkg/tests/` other than the
shared `tests/mocks.zig`, which takes additive edits only (agreed with the glue and p2p lanes on
2026-11-19). The glue lane keeps reshare/ and orchestrator/.

- [x] mocks.rs's network fixtures (`FailingManager`, `DirectoryManager`, `FilteredReceiver`,
  `widest_addresses`) in `tests/mocks_network.zig`, re-exported by `tests/mocks.zig`.
- [x] tests/dkg/properties.rs (`DkgOutcome`). `expected` is comptime, since
  `simulate.Property` needs a constant `name`.
- [x] bootstrap `Block` and `max_payload_size`, with mod.rs's `max_encode_size_covers_widest_block`
  and `covers_every_component` (128 participants behind -Dslow-tests in Debug).
- [ ] bootstrap `Engine` and `rejects_unsupported_sharing_mode`.
- [ ] tests/dkg/harness.rs and mod.rs's 14 ceremony tests on the bootstrap engine (the lossy,
  filtered, crash, and laggard plans behind -Dslow-tests).
- [ ] tests/reshare harness, properties, and mod.rs's ceremony tests (needs the orchestrator).
- [ ] lookup's peer-activation tests.

### Log
- 2026-11-19: the network mocks and `DkgOutcome`; the tests catch a planted skipped
  output-agreement check and an inverted epoch filter.
- 2026-11-19: bootstrap's block and payload bound; the tests catch a missing payload-flag
  byte and a dropped marshal term.
