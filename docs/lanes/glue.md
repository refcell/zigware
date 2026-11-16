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

## Decisions
- Rust traits with async methods (`EngineDefinition`, `ExitCondition`, `Property`) become
  comptime-duck-typed parameters or small vtables; their `async fn`s are plain functions,
  since zigware tasks run on fibers.
- `Schedule.add` returns `error.OutOfOrder` where commonware panics, so its test ports.
- `ProgressTracker` keeps the distinct digests per round in a list (commonware's `HashSet`).

## Backlog
- [x] simulate: tracker, action (Schedule, Action, Crash) with their tests.
- [ ] simulate: processed, property, exit conditions, engine definition, team, plan (the
  driver) with the plan tests and their stub engines.
- [ ] simulate: `MonitorReporter` waits on marshal's `Update`/`Tip` (consensus-marshal).
- [ ] transfers: the parts that need no qmdb (`select`, planning), their tests and benches.
- [ ] transfers: the rest (needs qmdb).
- [ ] stateful, dkg.

## Log
- 2026-11-16: lane started; simulate's progress tracker and actions with their tests.
