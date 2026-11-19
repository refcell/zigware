# glue

Default constructions that span multiple primitives.

A Zig port of commonware's
[`commonware-glue`](https://github.com/commonwarexyz/monorepo/tree/main/glue).

## Status

**ALPHA** upstream: breaking changes are expected. See commonware's
[stability levels](https://github.com/commonwarexyz/monorepo#stability).
The zigware port is in progress. [docs/lanes/glue.md](../../docs/lanes/glue.md) tracks it.
Every commonware test in `simulate` and `transfers` has a counterpart. `stateful` and `dkg`
still have open backlog items, including some of `stateful`'s processing tests and the
`dkg` reshare ceremony tests.

## Modules

- `simulate` ([simulate/mod.zig](simulate/mod.zig)): a harness for deterministic simulations
  of validator stacks, with injected faults, progress tracking, and property checks.
- `stateful` ([stateful/mod.zig](stateful/mod.zig)): speculative and finalized QMDB state for
  applications built on consensus, with peer state sync and floor discovery.
- `dkg` ([dkg/root.zig](dkg/root.zig)): BLS12-381 threshold key generation with a one-shot
  bootstrap ceremony, and resharing across application epochs.
- `transfers` ([transfers/mod.zig](transfers/mod.zig)): settling and selecting batches of
  balance transfers against a QMDB database.

## Testing

```sh
zig build test-glue                      # unit tests and DSTs
zig build test-glue -Dslow-tests         # also the large DSTs and dkg ceremonies
zig build bench -Dbench-filter=transfers # transfers benchmarks (ReleaseFast)
```

`zig build test` also runs each benchmark once on its smoke inputs.

## Differences from commonware

- Rust traits with async methods (`EngineDefinition`, `ExitCondition`, `Property`) become
  comptime duck-typed parameters or small vtables, and their `async fn`s are plain functions.
  ([glue decisions](../../docs/lanes/glue.md#decisions))
- `simulate`'s `PlanBuilder` is folded into `Plan`: field defaults replace the builder, and a
  multi-seed run is a loop over `run_with_seed`.
  ([glue decisions](../../docs/lanes/glue.md#decisions))
- Many of commonware's panics are errors here, so their tests port: `simulate` returns
  `PlanError`s ([glue decisions](../../docs/lanes/glue.md#decisions)), failed `stateful`
  database mutations return their error
  ([stateful decisions](../../docs/lanes/glue.md#decisions-1)), and the `dkg` actors return
  `ContractError`s ([dkg decisions](../../docs/lanes/glue.md#decisions-2)).
- `transfers.Plan.init` and `Selection.init` take the hash seed from the caller, where
  commonware draws it from `ahash`'s random state.
  ([glue decisions](../../docs/lanes/glue.md#decisions))
- `dkg`'s reshare `Application` passes the inner application `application.Input(T)`
  (`{ gpa, payload }`), which is commonware's `Input` without `upstream`.
  ([dkg decisions](../../docs/lanes/glue.md#decisions-2))
- Failed `simulate` checks and `dkg`'s rejections of peer input log at info, not at
  commonware's error or warn level. ([glue decisions](../../docs/lanes/glue.md#decisions),
  [dkg decisions](../../docs/lanes/glue.md#decisions-2))
