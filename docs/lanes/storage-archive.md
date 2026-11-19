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
- [x] immutable archive (freezer + ordinal + metadata commit record);
  `StorageConformance<ArchiveImmutableWorkload>` (128 cases) matches; ported tests (shared
  archive tests included) with crash recovery and interrupted destroy;
  `archive_immutable_recovery` fuzz.
- [x] Fuzz targets (storage/fuzz entries for these modules: `cache_operations`,
  `ordinal_operations`, `freezer_operations`, `archive_prunable_operations`,
  `archive_prunable_recovery`, `archive_immutable_recovery`) and metrics through
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
- `storage.archive.immutable`: `Archive(K, V)` with `init(gpa, storage, scope, Config(V))`,
  `put` (a no-op on a stored index), `put_sync`, `get(.{ .index = i } | .{ .key = &k })`,
  `has`, `sync`, `start_sync`, `next_gap`, `missing_items(start, out)`, `ranges`,
  `ranges_from`, `first_index`, `last_index`, `deinit`, `destroy`. Freezer and ordinal
  metrics register under the scope's `freezer` and `ordinal` children; the archive's own
  `gets`, `has`, `syncs` under the scope.

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
- prunable archive: methods take `*Self`; an error from `put`, `put_multi`, `sync`,
  `start_sync`, or `prune`, or a failed `start_sync` completion, leaves the archive failed
  (only `deinit` may follow). `start_sync`, `put_start_sync`, and `put_multi_start_sync`
  return a `runtime.storage.Completion` (async start_sync step 4): pending sections move into
  `requested`, kept until a blocking `sync` and trimmed by `prune`, and
  `Oversized.start_sync_tracked` starts the journals' syncs and records them in each
  section's barrier, publishing a marker only once its sync is observed to have succeeded.
  Markers still persist synchronously, so the 4 marker-pipeline tests wait for metadata's
  `start_sync` completion (storage-merkle's step 2c). Blocking `sync` stays on the journals'
  blocking syncs. Marshal waits on the completions at once until its step 6. Sections are a sorted
  list of `(start, slot)`; extra multi-put positions are a hash map pruned by scan. The
  recovery fuzz runs on faulty storage (see the fault model below) and checks retained
  entries against synced ones, per-section prefixes, the range helpers, and a second reopen.
- immutable archive: the metadata commit record is opened first and drives both stores
  (no committed checkpoint means an empty freezer; omitted ordinal sections are removed).
  `sync` syncs the freezer, then the ordinal, then commits the metadata (commonware joins the
  first two). The interrupted-destroy test runs every removal budget up to a full destroy
  instead of sampling removal faults by seed. Its recovery fuzz runs on faulty storage, followed
  by commonware's faulted recovery chain.
- Recovery fuzz fault model (2026-11-16, replacing the interim mutation-budget model the
  coordinator accepted): `archive_prunable_recovery`, `archive_immutable_recovery`, and
  `freezer_recovery` run on `runtime.storage.faulty` over the memory backend
  (`archive/faults.zig`), with the fault RNG seeded by the input: failed and torn writes
  (prefix and subset retention), failed syncs, removes, and partial resizes, and a crash that
  replays unsynced writes with their retention. `Faults.faulted_recovery` ports commonware's
  chain of one to four reopens, each under one drawn mutation fault and crashing into the
  next. Rates and the chain are drawn by a ChaCha test RNG instead of commonware's
  `Entropy`-driven rng, so inputs do not replay commonware's corpus byte for byte. Delayed
  and out-of-order syncs (`PendingSyncs`, abandoned `start_sync`) have no counterpart:
  zigware's `sync` is synchronous, so there are no pending syncs to reorder.
- Commonware's `slow` group (`many_keys_{prunable,immutable}_large` at 50,000 keys,
  `archive_many_keys_and_restart` at 100,000, and `archive_keys_and_restart_determinism` at
  5,000) runs at those sizes only with `-Dslow-tests`; every `zig build test` runs the same
  bodies at 1,000 keys.

## Test tally (2026-11-19, clearing lane)
Commonware's `#[test]`, `#[test_traced]`, and `#[rstest]` functions and `conformance_tests!`
entries, matched to zigware tests by what they check (zigware folds many into one test).

| module | tests | ported | partial | open | not portable |
|---|---|---|---|---|---|
| archive | 93 | 89 | 0 | 4 | 0 |
| freezer | 33 | 33 | 0 | 0 | 0 |
| ordinal | 44 | 44 | 0 | 0 | 0 |
| cache | 14 | 14 | 0 | 0 | 0 |
| storage `utils.rs` (`bits_for_indices`, in ordinal) | 1 | 1 | 0 | 0 | 0 |

The 11 pipelined `start_sync` and in-flight sync tests are in
`archive/prunable/start_sync_test.zig` (2026-11-19).

Open (they need marker syncs in flight, metadata `start_sync` from step 2c):
- [ ] `test_startup_marker_failure_fails_next_sync`,
  `test_start_sync_publishes_closed_section_boundary`,
  `test_sync_publishes_closed_section_boundary`,
  `test_start_sync_withholds_marker_for_unproven_boundary`.

Open:
- [x] freezer regressions: `issue_2966_regression` (resize writes no valid epoch-0 slot into
  empty entries), `issue_2955_regression` (both slots' CRCs corrupt: reopen does not panic).
- [x] freezer checkpoints: no checkpoint deletes a partial sync resize, a close-started
  resize, and a completed resize; an empty checkpoint deletes data; a non-empty checkpoint
  against an empty table is `CheckpointMismatch` (the check exists, no test reaches it).
- [x] freezer corruption: a corrupted committed value fails only its read; a committed value
  section short by one byte fails init, again on retry.
- [x] archive (prunable, `durability_test.zig`): below-floor `put_sync` and `put_multi_sync`
  make earlier buffered writes durable; prune clears the marker before section reuse; three
  put_syncs into three sections reopen; interrupted destroy and destroy interrupted inside
  the journals (81 combinations).
- [x] archive (prunable): six kinds of marker damage never mutate either journal; a corrupt
  floor page is rejected before suffix repair; a torn index tail under a marker.
- [x] archive (prunable) durability counts: startup publishes the marker without a data
  resync; markers lag one sync; markers batched per section; an empty sync publishes the
  final boundary; a reused section restarts its barrier. These count syncs through
  `runtime.storage.mocks.Recordings.syncs`.

Partial:
- [x] archive immutable interrupted destroy: also runs with `mocks.Storage.keep_unsynced`
  (commonware's crash retention 1.0), so recovery sees the uncommitted put on disk.
- [x] archive `many_keys_{prunable,immutable}_large`: 50,000 keys under `-Dslow-tests`.
- [x] freezer: `recovery_zeroes_torn_table_slot`, `checkpoint_rewinds_completed_resize`,
  short-table mismatch with retry and unchanged length. Determinism runs commonware's 1,000
  keys under `-Dslow-tests` and 60 keys per push.
- [x] ordinal `init_clears_unmarked_records` checks that recovery issues one sync.
- [x] `bits_for_indices` has a direct test (utils.rs `test_bits_for_indices`).

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
- 2026-11-16: immutable archive with its ported tests, storage conformance hash, and the
  `archive_immutable_recovery` fuzz target. Backlog complete.
- 2026-11-16: recovery fuzzers moved to faulty storage (torn writes and failed syncs) with
  commonware's faulted recovery chain; added the `freezer_recovery` fuzz target.
- 2026-11-19: test tally of archive, freezer, ordinal, and cache against commonware (clearing lane).
- 2026-11-19: freezer's 9 open storage.rs tests ported, each failing under a planted bug;
  archive's slow 50,000-key many-keys tests and 100,000/5,000-key restart tests run under
  `-Dslow-tests` (clearing lane).
- 2026-11-19: 11 of the prunable archive's open tests (marker lag and batching counted
  through `Recordings.syncs`, below-floor syncs, marker reuse, interrupted destroys), each
  failing under a planted bug (clearing lane).
- 2026-11-19: the prunable archive's last 3 open tests (marker damage, floor rejection before
  suffix repair, torn index tail); archive open: 0 (clearing lane).
- 2026-11-19: the freezer, ordinal, and `bits_for_indices` partials completed; only archive's
  immutable interrupted destroy stays partial (clearing lane).
- 2026-11-19: immutable interrupted destroy with unsynced writes kept; no partials left
  (clearing lane).
- 2026-11-19: freezer determinism at 60 keys per push and commonware's 1,000 under
  `-Dslow-tests` (it was the slowest test here at 9.9 s in Debug; clearing lane).
- 2026-11-19: async start_sync step 4: the prunable archive's pipelined `start_sync` with
  `requested`, oversized's tracked start_sync on the journals' started syncs, and 11 of the
  15 pipelined tests (clearing lane).
