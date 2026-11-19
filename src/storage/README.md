# storage

Persist and retrieve data from an abstract store.

A Zig port of commonware's
[`commonware-storage`](https://github.com/commonwarexyz/monorepo/tree/main/storage).

## Status

Upstream stability **varies by primitive**. These modules are **BETA**: archive, freezer, index,
journal, metadata, ordinal, rmap, and translator. A few items inside index and journal are
ALPHA, such as `journal::authenticated` and `index::immutable`. Everything else is **ALPHA**:
bmt, merkle (mmr, mmb), bitmap, qmdb, cache, and queue. See commonware's
[stability levels](https://github.com/commonwarexyz/monorepo#stability).

Six lane files track the zigware port:
[storage-merkle](../../docs/lanes/storage-merkle.md),
[storage-journal](../../docs/lanes/storage-journal.md),
[storage-archive](../../docs/lanes/storage-archive.md),
[storage-qmdb](../../docs/lanes/storage-qmdb.md),
[storage-qmdb-sync](../../docs/lanes/storage-qmdb-sync.md), and
[coding](../../docs/lanes/coding.md) (for bmt). Every backlog item is ticked except two:
storage-qmdb's upstream 102430409 (the store's strategy and any's shared batched read), and
storage-merkle's byte-exact zstd item, whose six pieces are all ticked.

## Modules

- `archive` ([archive/mod.zig](archive/mod.zig)): a write-once key-value store for ordered data.
- `bitmap`, `AuthenticatedBitMap` ([bitmap/mod.zig](bitmap/mod.zig)): authenticated bitmaps.
- `bmt` ([bmt/mod.zig](bmt/mod.zig)): a stateless binary Merkle tree.
- `cache` ([cache/mod.zig](cache/mod.zig)): a prunable cache for ordered data.
- `freezer` ([freezer/mod.zig](freezer/mod.zig)): an immutable key-value store.
- `index` ([index/mod.zig](index/mod.zig)): memory-efficient maps over translated keys.
- `journal` ([journal/mod.zig](journal/mod.zig)): append-only logs for arbitrary data.
- `merkle`, `mmr`, `mmb` ([merkle/mod.zig](merkle/mod.zig)): Merkle-family structures.
- `metadata` ([metadata/mod.zig](metadata/mod.zig)): a small key-value store with atomic commits.
- `ordinal` ([ordinal/mod.zig](ordinal/mod.zig)): a persistent index from sparse indices to values.
- `qmdb` ([qmdb/mod.zig](qmdb/mod.zig)): authenticated databases inspired by QMDB.
- `queue` ([queue/mod.zig](queue/mod.zig)): a durable, at-least-once delivery queue.
- `refcount` ([refcount.zig](refcount.zig)): atomic reference counts for shared batches.
- `rmap`, `RMap` ([rmap/mod.zig](rmap/mod.zig)): disjoint, inclusive ranges.
- `translator` ([translator.zig](translator.zig)): key translators for an index.

## Testing

```sh
zig build test-storage                    # unit tests, including the seeded fuzz
zig build bench -Dbench-filter=journal    # one module's benchmarks (ReleaseFast)
zig build qmdb-cold-read -- <args>        # opt-in QMDB harnesses with commonware's arguments;
zig build qmdb-constantinople -- <args>   # also qmdb-scale (see storage-qmdb.md)
```

Benchmark prefixes are `archive`, `bmt`, `freezer`, `index`, `journal`, `merkle`, `metadata`,
and `qmdb`. `zig build test` also runs each benchmark once on its smoke inputs. For long,
coverage-guided fuzzing, run `zig build test --fuzz -Doptimize=ReleaseSafe`.

## Differences from commonware

- Errors are payload-free error sets. Commonware's section, offset, and size payloads are
  dropped ([storage-journal decisions](../../docs/lanes/storage-journal.md#decisions),
  [storage-qmdb decisions](../../docs/lanes/storage-qmdb.md#decisions)).
- Where commonware consumes a handle on a failed call, the cache, prunable archive, and
  metadata are left failed instead, and only `deinit` may follow
  ([storage-archive decisions](../../docs/lanes/storage-archive.md#decisions)).
- There is no C libzstd. Journals decompress with `std.compress.zstd`. They compress with a
  port that writes exactly libzstd 1.5.7's level-3 frames, and the configured level is not
  read ([storage-journal decisions](../../docs/lanes/storage-journal.md#decisions)).
- Sealed traits become comptime interfaces. Examples are qmdb's value encodings
  (`value.Fixed(V)`, `value.Variable(V)`) and the compact `Db(F, O, H)`
  ([storage-qmdb decisions](../../docs/lanes/storage-qmdb.md#decisions),
  [storage-qmdb-sync decisions](../../docs/lanes/storage-qmdb-sync.md#decisions)).
- qmdb databases are single-owner, with no `RwLock` around the activity bitmap. Harness modes
  that commonware runs as concurrent futures issue the same reads one after another
  ([storage-qmdb decisions](../../docs/lanes/storage-qmdb.md#decisions)).
- qmdb's parallel snapshot build (`init_concurrency`, qmdb/snapshot_parallel.zig) runs in
  barrier steps over a `parallel` strategy instead of commonware's tasks and channels. It
  builds the same snapshot as the serial build under every strategy shape
  ([storage-qmdb decisions](../../docs/lanes/storage-qmdb.md#decisions)).
- Benchmarks measure on production disk storage under `.zig-cache/tmp`. Smoke runs use
  in-memory storage and smaller inputs
  ([storage-journal decisions](../../docs/lanes/storage-journal.md#decisions)).
