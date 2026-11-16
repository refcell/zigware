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
- [x] ordinal: raw index blobs behind `runtime.buffer.Write` + rmap + committed bitmaps
  (commonware builds it on blobs, not the contiguous journal); recovery, conformance
  (`StorageConformance<OrdinalWorkload>`, `CodecConformance<Record<u32>>`),
  `ordinal_operations` fuzz.
- [x] freezer and archive on-disk records with their codec conformance hashes (freezer
  `Checkpoint`, `Cursor`, `Entry`, `Record<U64>`; prunable `Record<U64>`; immutable `Record`).
- [x] freezer: the hash table over the oversized journal, checkpoints, incremental resize,
  recovery after crash; `StorageConformance<FreezerWorkload>` (512 cases) matches; ported
  tests and a `freezer_operations` fuzz target.
- [x] prunable archive over the oversized journal with validation markers, the translated
  key table (`utils.handles.Table`), put_multi; `StorageConformance<ArchivePrunableWorkload>`
  (128 cases) matches; ported tests (shared archive tests included) with crash recovery;
  `archive_prunable_operations` and `archive_prunable_recovery` fuzz targets.
- [ ] immutable archive (freezer + ordinal + metadata);
  `StorageConformance<ArchiveImmutableWorkload>`, its tests, `archive_immutable_recovery`
  fuzz.
- [ ] Fuzz targets (storage/fuzz entries for these modules) and metrics through
  `runtime.telemetry.metrics`.

## Public API (on main)
- `storage.cache`: `Cache(V)` with `init(gpa, storage, scope, Config(V))` (replays the
  journal), `get` (caller frees with `codec.free`), `has`, `first`, `next_gap` (`rmap.Gap`),
  `missing_items(start, out)`, `put`, `put_sync`, `sync`, `prune`, `deinit`, `destroy`;
  `Config(V)`; `Record(V)` (varint index + value). Metrics `items_tracked`, `gets`, `has`,
  `syncs` register under the given `metrics.Scope`.
- `storage.ordinal`: `Ordinal(V)` for fixed-size codec values with `init(gpa, storage, scope,
  Config, ?[]const SectionBits)` (and `init_diagnostic` reporting the failing index), `put`,
  `get`, `has`, `next_gap`, `ranges`, `ranges_from`, `first_index`, `last_index`,
  `missing_items`, `prune`, `sync`, `deinit`, `destroy`; `Record(V)`, `BitMap`,
  `SectionBits{section, bits: ?*const BitMap}`, `bits_for_indices`/`free_bits`, `Error`
  (runtime storage errors plus `InvalidBlobName`, `InvalidRecord`, `MissingRecord`).
- `storage.freezer`: `Freezer(K, V)` with `init(gpa, storage, scope, Config(V), ?Checkpoint)`,
  `put -> Cursor`, `get(.{ .key = &k } | .{ .cursor = c })`, `has`, `sync -> Checkpoint`,
  `close -> Checkpoint`, `deinit`, `destroy`, `resizing`, `resizable_entries`; records
  `Cursor`, `Checkpoint`, `Entry`, `Record(K)`.
- `storage.archive.prunable`: `Archive(T, K, V)` (translator `T`, fixed-size key `K`) with
  `init(gpa, storage, scope, Config(T, V))`, `put`, `put_sync`, `put_multi`,
  `put_multi_sync`, `get(.{ .index = i } | .{ .key = &k }) -> ?V`, `has`, `get_all(gpa, i)
  -> ?[]V`, `has_at(i, &k)`, `sync`, `start_sync`, `prune(min)`, `next_gap` (`rmap.Gap`),
  `missing_items(start, out)`, `ranges`, `ranges_from` (`[]const rmap.Range`),
  `first_index`, `last_index`, `deinit`, `destroy`. Metrics `items_tracked`, `keys_tracked`,
  `indices_pruned`, `unnecessary_reads`, `gets`, `has`, `syncs`.

## Decisions
- Storage conformance: `StorageConformance<W>` commits seeds directly on
  `runtime.storage.memory.Storage` with a `TestRng` seeded by the case seed (commonware's
  deterministic runner context RNG) and commits `audit()`; the hashes match commonware's.
  `src/storage/conformance.toml` is commonware's `storage/conformance.toml`, unchanged.
- cache: mutating methods leave the cache failed on error (only `deinit` may follow) where
  commonware consumes the handle. The index is a hash map; ordered queries go through the
  `RMap`, and `prune` removes indices by walking the pruned ranges. `missing_items` writes
  into a caller buffer whose length is `max`. Pending sections are a sorted list.
- ordinal: committed bits are a slice of `SectionBits` sorted by section (commonware's
  `BTreeMap<u64, &Option<BitMap>>`); error payloads (the failing index) come back through
  `init_diagnostic`. Commonware's delayed-sync and recording contexts become the storage
  mock's mutation budget and write counter. Whole-section replay reads `replay_buffer`
  bytes at a time straight from the blob.
- Arbitrary generators: a `#[derive(Arbitrary)]` enum picks its variant as
  `(u64(u32) * variants) >> 32` (arbitrary 1.4); byte-array newtype keys (`U64`,
  `FixedBytes`) fill byte by byte (`freezer.records.arbitrary_key`).
- freezer: `get` takes a tagged `Identifier` union; `close` frees the freezer on success.
  The freezer_operations fuzz uses a small key pool so chains collide and keys shadow, and
  checks every key after crash restores against the model at the last checkpoint.
- prunable archive: methods take `*Self`; an error from `put`, `put_multi`, `sync`, or
  `prune` leaves the archive failed (only `deinit` may follow). Syncs complete before
  returning, so `start_sync` is `sync` and the requested-section set is always the pending
  one; commonware's pipelined start_sync tests have no counterpart. Sections are a sorted
  list of `(start, slot)`; extra multi-put positions are a hash map pruned by scan. The
  recovery fuzz injects faults with the storage mock's mutation budget and a crash (no torn
  writes or delayed syncs) and checks retained entries against synced ones, per-section
  prefixes, the range helpers, and a second reopen.
- Tests that commonware runs at 100,000 and 5,000 items (`slow` group) run at 2,000 and 600.

## Log
- 2026-11-13: cache with its ported tests, crash recovery, both conformance hashes, and the
  `cache_operations` fuzz target.
- 2026-11-13: ordinal with its ported tests (recovery from committed bits, torn tails,
  clearing unmarked runs), both conformance hashes, and the `ordinal_operations` fuzz target.
- 2026-11-13: freezer and archive record codecs, the `archive.Identifier` interface type, and
  six codec conformance hashes.
- 2026-11-13: freezer over the oversized journal with its ported tests, storage conformance
  hash, and the `freezer_operations` fuzz target.
- 2026-11-16: prunable archive with its ported tests, storage conformance hash, and the
  `archive_prunable_operations` and `archive_prunable_recovery` fuzz targets.
