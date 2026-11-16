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
- [ ] stateful, dkg.

## Log
- 2026-11-16: lane started; simulate's progress tracker and actions with their tests.
- 2026-11-16: simulate's plan driver, team, engine contract, exit conditions, and properties,
  with commonware's 9 plan tests and a duplicate-strategy test (20 glue tests).
