# clearing

Settle actions at scale.

A Zig port of commonware's
[`commonware-clearing`](https://github.com/commonwarexyz/monorepo/tree/main/clearing).

## Status

**ALPHA** upstream: breaking changes are expected. See commonware's
[stability levels](https://github.com/commonwarexyz/monorepo#stability).
The zigware port is complete. [docs/lanes/clearing.md](../../docs/lanes/clearing.md) tracks it.

## Modules

- `bajillion` ([bajillion/mod.zig](bajillion/mod.zig)): an operator settles payments between
  accounts in epochs, validators check and certify each close, and a ledger posts the
  certified summaries and pays out withdrawals.

## Testing

```sh
zig build test-clearing                     # unit tests, including the seeded fuzz targets
zig build bench -Dbench-filter=clearing::   # zigware's own clearing benchmarks (ReleaseFast)
```

`zig build test` also runs each benchmark once on its smoke inputs. Five of the six model
workloads run only with `-Dslow-tests`. For long, coverage-guided fuzzing, run
`zig build test --fuzz -Doptimize=ReleaseSafe`.

## Differences from commonware

All of these are recorded in the
[clearing lane decisions](../../docs/lanes/clearing.md#decisions).

- Errors carry no payload. For example, `WrongEpoch` drops its expected and found epochs.
- `Close::check` is `Checked(P, H, A).check(O, ...)`, and it borrows the close instead of
  consuming it.
- `settle` and `apply` borrow the databases instead of consuming and returning them. After a
  database error, the caller reopens both databases.
- `Flows` collects one part per payment, deposit, and withdrawal, then sorts and merges.
  Commonware uses a `HashMap` and then sorts. The sums are exact, so the flows match.
- model.rs runs on zigware's own explicit-state checker instead of Stateright. It searches
  depth first on one thread and is bounded at 1 << 23 states.
