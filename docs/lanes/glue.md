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
- Commonware's panics for unexercised faults (random crashes, schedules, delays, processed
  height windows) and duplicate strategies are `PlanError`s, so their tests port.

## Backlog
- [x] simulate: tracker, action (Schedule, Action, Crash) with their tests.
- [x] simulate: processed, property, exit conditions, engine definition, team, plan (the
  driver) with the plan tests and their stub engines.
- [ ] simulate: `MonitorReporter` waits on marshal's `Update`/`Tip` (consensus-marshal).
- [ ] transfers: the parts that need no qmdb (`select`, planning), their tests and benches.
- [ ] transfers: the rest (needs qmdb).
- [ ] stateful: see the stateful section below (curve25519/utils thread).
- [ ] dkg (coding thread).

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
  `Unmerkleized` (`write`, `with_metadata`, `get`, `get_many`, `merkleize`) and `Merkleized`
  (`root`, `new_batch`, `get`, `get_many`, `clone`, `deinit`); `SyncTarget` is
  `qmdb.sync.Target`.
- `glue.stateful.probe`: `Sample(S, D)` (`init(gpa, minimum_epoch)`, `awaits(peer)`,
  `record(peer, finalization)` taking ownership, `select(committee_size, judge)` with
  `judge.judgeable(*const Finalization)`, `get_floor`, `reset`, `deinit`), `Message(S, V)`
  (`request`, `response: Finalization`; codec, `max_encode_size`), `Tag`,
  `max_payload_size(V, S, participants)`. The DKG probe can reuse `Sample` as commonware's does.

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
- `Any` takes the hasher as a parameter (the storage `Db` does not expose it) and uses
  commonware's 64-byte bitmap chunks in tests. `stage`/`expand` wait on storage-qmdb's
  `any` staging API.

### Backlog
- [x] db: `Shared`, `Reader`, `Barrier`, single and tuple sets, with mod.rs's set tests.
- [x] db/any: the ManagedDb adapter with any.rs's stale-read and apply-does-not-finalize tests.
- [ ] db/any: `stage`/`expand` (needs storage's staging API), variable values, ordered.
- [ ] db: keyless, immutable, compact; current (after qmdb `current`).
- [ ] db: state sync (`StateSyncDb`, `StateSyncSet`, `Anchor`, `TipUpdate`, the generation
  coordinator) and its tests; db/p2p (handler, actor, mailbox, limits).
- [x] probe: `Sample`, wire `Message`, `max_payload_size` with limits.rs's widest-encodings
  test and sample selection tests.
- [ ] probe: the actor (solicit, collect, retry, serve), after marshal's mailbox.
- [ ] actor: processor state, syncer plan, core (after marshal); tests (single and
  multi db apps, floor, properties).

## Log
- 2026-11-16: lane started; simulate's progress tracker and actions with their tests.
- 2026-11-16: simulate's plan driver, team, engine contract, exit conditions, and properties,
  with commonware's 9 plan tests and a duplicate-strategy test (20 glue tests).
- 2026-11-16 (stateful): db core (`Shared`, sets, `Barrier`) and the `any` adapter with their
  commonware tests.

- 2026-11-16 (stateful): probe sample, wire messages, and payload bound.
