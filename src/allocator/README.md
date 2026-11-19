# allocator

Allocate and manage memory.

A Zig port of commonware's
[`commonware-allocator`](https://github.com/commonwarexyz/monorepo/tree/main/allocator).

## Status

**ALPHA** upstream: breaking changes are expected. See commonware's
[stability levels](https://github.com/commonwarexyz/monorepo#stability).
The allocator backlog in [docs/lanes/parallel.md](../../docs/lanes/parallel.md) is done.
Commonware's integration tests are ported, except the huge-page-advice ones.

## Modules

- `Heap` ([heap.zig](heap.zig)): a `std.mem.Allocator` with mimalloc's layout. `allocator()`
  hands it out; `read_stats`, `contains`, and `collect` inspect and purge it.
- `Config`, `Purge`, `Reserve`, `EagerCommit`, `Status`, `Effective` ([config.zig](config.zig)):
  a heap's configuration, mirroring commonware's mimalloc options, and what the heap runs with.
  The arena geometry constants live here too.
- `good_size` ([size_class.zig](size_class.zig)): mimalloc's size classes, so a request gets
  the same block size as under commonware's mimalloc.
- `Stats` ([stats.zig](stats.zig)): a heap's statistics, with the fields of commonware's
  mimalloc `Stats`.
- `metrics` ([metrics.zig](metrics.zig)): each exported `Stats` field with its name, help text,
  and kind, so a runtime can register every series.
- [arena.zig](arena.zig) and [os.zig](os.zig): arenas of 64 KiB slices, and the OS mappings,
  unmappings, and purges a heap uses.

## Testing

```sh
zig build test-allocator  # unit and integration tests, including the seeded heap fuzz
```

A `std.testing.fuzz` target drives the heap too; for long runs use
`zig build test --fuzz -Doptimize=ReleaseSafe`.

## Differences from commonware

All of these are recorded in the
[parallel lane decisions](../../docs/lanes/parallel.md#decisions).

- There is no mimalloc: zigware has no C dependencies. `Heap` is a native allocator with
  mimalloc's layout, size classes, arenas, reservations, and delayed purges.
- A heap is a value, not the process allocator, so configuration is per heap rather than once
  per process.
- One lock guards a heap, so `Stats` are exact.
- The mimalloc-only knobs (large OS pages, transparent huge pages, the stats merge threshold)
  are recorded in `effective` but change nothing.
- The huge-page-advice integration tests are not ported: they read Linux smaps for mimalloc's
  THP advice.
