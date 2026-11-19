# parallel

Parallelize fold operations with pluggable execution strategies.

A Zig port of commonware's
[`commonware-parallel`](https://github.com/commonwarexyz/monorepo/tree/main/parallel).

## Status

Stability upstream varies by primitive. lib.rs puts the `Strategy` trait, `Sequential`,
`Batches`, `Grid`, and `Tiles` in the **BETA** scope. With `std`, so are `Rayon`, `ThreadPool`,
and the `rayon`, `policy`, and `topology` modules. `mocks`, `fold_plan`, and `fuzz` are ALPHA.
See commonware's [stability levels](https://github.com/commonwarexyz/monorepo#stability).
Every backlog item in [docs/lanes/parallel.md](../../docs/lanes/parallel.md) is done, and its
test audit lists no open tests.

## Modules

- `Sequential`, `sequential` ([sequential.zig](sequential.zig)): runs every operation on the
  calling thread, in input order.
- `Rayon` ([rayon.zig](rayon.zig)): runs operations on a shared `ThreadPool`. `with_policy`
  makes it adaptive.
- `ThreadPool`, `ThreadPoolConfig` ([pool.zig](pool.zig)): a small fork-join pool whose
  workers start through `std.Io`.
- `assert_strategy` ([root.zig](root.zig)): checks at compile time that a type implements the
  strategy interface. [strategy.zig](strategy.zig) writes its operations once over each
  strategy's primitives.
- `Range`, `Partitioned` ([ops.zig](ops.zig)): the inputs a strategy iterates, and shared
  serial bodies.
- `Batches` ([strategy.zig](strategy.zig)), `Grid`, `Tiles` ([tiles.zig](tiles.zig)):
  `run_batches` and `run_tiles`.
- `Task` ([task.zig](task.zig)): one CPU-bound job submitted with `spawn` and awaited with
  `block_on`.
- `Policy` ([policy.zig](policy.zig)): adaptive serial or parallel, and inline or offload,
  decisions.
- `Topology` ([topology.zig](topology.zig)): the host's last-level cache domains, and how
  workers split into groups.
- `Clock`, `TestClock` ([clock.zig](clock.zig)): the clock that times measured runs.
- `mocks` ([mocks.zig](mocks.zig)): mock strategies, such as `Explorer`, for testing code that
  is generic over a strategy.

## Testing

```sh
zig build test-parallel                       # unit tests
zig build bench -Dbench-filter=parallel::     # fold and sort benchmarks (ReleaseFast)
```

`zig build test` also runs each benchmark once on its smoke inputs.

## Differences from commonware

All of these are recorded in the
[parallel lane decisions](../../docs/lanes/parallel.md#decisions).

- There is no rayon port. `ThreadPool` is a fork-join pool whose workers are
  `std.Io.Group.concurrent` tasks, so the deterministic runtime can host it.
- Folds and maps split into `min(len, 64)` balanced chunks, whatever the thread count. A fold
  gives the same result on every pool size.
- Closures are `pub fn` methods on operation values. Sorts take Zig's `lessThan(ctx, a, b)`
  instead of an `Ordering` comparator.
- `spawn` takes a caller-owned `Task(Op)` instead of returning a future, so it never
  allocates. Every spawned task must be `block_on`'d before its pool is destroyed.
- Fallible operations return the first error in chunk order. Commonware allows any.
- The pool is one group, so `topology` ports only the model: group leases, homing, and affinity
  writes are not ported.
