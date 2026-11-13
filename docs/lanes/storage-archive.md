# Lane: storage-archive

Owns `src/storage/{archive,freezer,ordinal,cache}`. Add your `pub const` lines to
`src/storage/root.zig` (additive edits).

Reference: `~/.cache/zigware/commonware-ref/storage/src/{archive,freezer,ordinal,cache}`. These
build on the storage-journal lane's journals (`storage.journal.segmented` fixed, variable,
glob, oversized; `journal.contiguous` fixed), `storage.metadata`, `storage.rmap`,
`storage.translator`, and `storage.index`, all persisted through `runtime.storage` and tested
on `runtime.storage.memory.Storage` with `crash()` for recovery. The fixed and variable
segmented journals are on main; glob, oversized, and contiguous fixed are landing next from
storage-journal (thread T-01a1d58d-a981-75c2-966d-93dcd484f46b).

## Backlog
- [x] cache (over the variable segmented journal): put, get, prune, recovery; conformance
  (`StorageConformance<CacheWorkload>`, `CodecConformance<Record<u64>>`), `cache_operations`
  fuzz.
- [ ] ordinal (over contiguous fixed journal + metadata + rmap). Comes before freezer: the
  contiguous fixed journal lands before oversized.
- [ ] freezer: the hash table over fixed + oversized journals, checkpoints, resize, recovery
  after crash, conformance hashes for every on-disk format.
- [ ] archive: the `Archive` interface, prunable (index + journal) and immutable (freezer +
  ordinal + metadata) archives; port their test suites including crash recovery.
- [ ] Fuzz targets (storage/fuzz entries for these modules) and metrics through
  `runtime.telemetry.metrics`.

## Public API (on main)
- `storage.cache`: `Cache(V)` with `init(gpa, storage, scope, Config(V))` (replays the
  journal), `get` (caller frees with `codec.free`), `has`, `first`, `next_gap` (`rmap.Gap`),
  `missing_items(start, out)`, `put`, `put_sync`, `sync`, `prune`, `deinit`, `destroy`;
  `Config(V)`; `Record(V)` (varint index + value). Metrics `items_tracked`, `gets`, `has`,
  `syncs` register under the given `metrics.Scope`.

## Decisions
- Storage conformance: `StorageConformance<W>` commits seeds directly on
  `runtime.storage.memory.Storage` with a `TestRng` seeded by the case seed (commonware's
  deterministic runner context RNG) and commits `audit()`; the hashes match commonware's.
  `src/storage/conformance.toml` is commonware's `storage/conformance.toml`, unchanged.
- cache: mutating methods leave the cache failed on error (only `deinit` may follow) where
  commonware consumes the handle. The index is a hash map; ordered queries go through the
  `RMap`, and `prune` removes indices by walking the pruned ranges. `missing_items` writes
  into a caller buffer whose length is `max`. Pending sections are a sorted list.
- Tests that commonware runs at 100,000 and 5,000 items (`slow` group) run at 2,000 and 600.

## Log
- 2026-11-13: cache with its ported tests, crash recovery, both conformance hashes, and the
  `cache_operations` fuzz target.
