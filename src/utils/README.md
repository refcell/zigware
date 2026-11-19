# utils

Leverage common functionality across multiple primitives.

A Zig port of commonware's
[`commonware-utils`](https://github.com/commonwarexyz/monorepo/tree/main/utils).

## Status

Stability upstream varies by primitive. lib.rs puts `faults`, `sequence`, `hostname`, `bitmap`,
`cache`, `handles`, `iter`, `ordered`, `prefetch`, `probability`, `range`, `sampling`, and `vec`
in the **BETA** scope. With `std`, so are `rng`, `acknowledgement`, `net`, `time`, `rational`,
`priority_set`, `channel`, `concurrency`, `futures`, `sync`, and `thread_local`. `fuzz`,
`amount`, the test generators in `rng`, and `bitmap::roaring` are ALPHA, and so are a few items
inside `range` and `rng`.
See commonware's [stability levels](https://github.com/commonwarexyz/monorepo#stability).
Every backlog item in [docs/lanes/utils.md](../../docs/lanes/utils.md) is done, and every open
test its test audit lists is checked off.

## Modules

- `faults` ([faults.zig](faults.zig)): the `N3f1` and `N5f1` Byzantine fault models.
- `rng` ([rng.zig](rng.zig)): deterministic generators for tests and fuzzing. `TestRng` is
  byte-identical to commonware's.
- `fuzz` ([fuzz.zig](fuzz.zig)): the seeded fuzz driver over `FuzzRng`, used by other
  packages' fuzz tests too.
- `range` ([range.zig](range.zig)): cyclic spans and `NonEmptyRange(T)`.
- `bitmap` ([bitmap.zig](bitmap.zig)): `BitMap(N)`, `Prunable(N)`, `historical`, `roaring`, and
  `Atomic`.
- `sequence` ([sequence.zig](sequence.zig)): fixed and variable byte sequences used as keys and
  values. `Span` and `Array` are comptime checks.
- `Hostname` ([hostname.zig](hostname.zig)): a hostname validated against RFC 1035/1123.
- `net` ([net.zig](net.zig)): subnet grouping and `is_global` for IP addresses.
- `ordered` ([ordered.zig](ordered.zig)): sorted, deduplicated `Set`, `Map`, and `BiMap`, with
  quorum helpers on `Set`.
- `handles` ([handles.zig](handles.zig)): an open-addressing multimap from 64-bit hashes to
  caller-owned handles.
- `acknowledgement` ([acknowledgement.zig](acknowledgement.zig)): acknowledging that a task
  completed.
- `Cache` ([cache.zig](cache.zig)): a fixed-capacity key-value cache with Clock2Q+ replacement.
- `BigRational` ([rational.zig](rational.zig)): exact rational numbers over big integers.
- `Probability` ([probability.zig](probability.zig)): a platform-independent probability and
  sampler.
- `vec`, `iter` ([vec.zig](vec.zig), [iter.zig](iter.zig)): `Bounded(T)`, `NonEmptyVec(T)`, and
  iterators with extra invariants.
- `channel` ([channel/mod.zig](channel/mod.zig)): `oneshot`, `mpsc`, `ring`, `reservation`,
  `fallible`, and `tracked`.
- `sampling` ([sampling.zig](sampling.zig)): weighted random sampling.
- `PrioritySet` ([priority_set.zig](priority_set.zig)): a set iterated in priority order.
- `time` ([time.zig](time.zig)): `Duration`, `SystemTime`, and `NonZeroDuration`.
- `concurrency` ([concurrency.zig](concurrency.zig)): non-blocking concurrency limits.
- `prefetch` ([prefetch.zig](prefetch.zig)): cache-line prefetch hints and a lookahead cursor.
- `Cached` ([thread_local.zig](thread_local.zig)): thread-local caching of objects that are
  expensive to build.
- `amount` ([amount.zig](amount.zig)): unsigned integers with overflow-aware arithmetic.
- `sync` ([sync.zig](sync.zig)): `UpgradableRwLock`.
- `futures` ([futures.zig](futures.zig)): task pools over `std.Io`.
- `Participant`, `NonZero`, `union_unique`, `modulo` ([root.zig](root.zig)): small helpers from
  commonware's lib.rs.

## Testing

```sh
zig build test-utils  # unit, conformance, and seeded fuzz tests
```

For long, coverage-guided fuzz runs, use `zig build test --fuzz -Doptimize=ReleaseSafe`.

## Differences from commonware

All of these are recorded in the [utils lane decisions](../../docs/lanes/utils.md#decisions).

- The RNG interface is `next_u32`, `next_u64`, and `fill_bytes`. Ports draw through the samplers
  in `utils.rng`, not `std.Random`, so values match commonware's tests.
- `sync` uses `std.Io.Mutex`, `RwLock`, and `Condition` in place of the `parking_lot` and
  `tokio` locks. `Exclusive` and the traced locks are not ported.
- `futures` pools run functions as `std.Io` tasks instead of holding futures. Aborting is an
  explicit `Aborter.abort()`, not a drop. `OptionFuture`, `rebind`, and `Shared` are not ported.
- `channel.tracked` batch IDs are plain hashable values copied into the tracker. Guards are
  (tracker, sequence) pairs with per-sequence reference counts, not per-message `Arc`s.
- Every utils/conformance.toml entry is checked through the shared `conformance.verify`
  harness, with `codec.arbitrary` generators.
