# Lane: storage-journal

Owns `src/storage/{journal,metadata,queue}` and `src/runtime/buffer/` (commonware's
`runtime/src/utils/buffer`: read/write buffers, tip, and `paged`; handed over from the runtime
lane by the coordinator because the journal is its main user). Add your `pub const` lines to
`src/storage/root.zig` (owned by storage-merkle; additive edits).

Reference: `~/.cache/zigware/commonware-ref/storage/src/{journal,metadata,queue}`. These
persist through the runtime's storage (`Storage` partitions and `Blob` read_at, write_at,
resize, sync), `runtime.storage`, with the in-memory backend `runtime.storage.memory`.

## Backlog
- [x] runtime buffer paged core: page format (two-slot CRC record), tip buffer, page cache,
  `Writer` (append, bulk append, sync, recovery open/truncate with staged shrink), `Replay`,
  `recoverable_prefix_len`; `runtime.buffer`.
- [x] runtime buffer `Write` and its tip (write.rs, tip.rs) with their tests.
- [x] runtime buffer `Read` (read.rs) with mod.rs's read tests; `read` copies into the caller's
  buffer (one refill buffer allocated at `init`) and rewinds on failure.
- [x] paged `Writer.read_many_into`/`read_ranges_into`/`try_read_ranges_sync_into` with
  writer.rs's and view.rs's batch-read tests (cache tried for every range before any blob read).
- [x] paged `View` (view.rs) shared by `Writer` and `Sealed`; `Sealed` (sealed.rs) with
  `Writer.seal`/`snapshot`/`try_snapshot` and sealed.rs's tests (paged/sealed_test.zig).
  Not ported: `test_sealed_read_many_into_rejects_unsorted_offsets` (a should_panic: unsorted
  offsets are an assert), `test_sealed_reads_while_seal_sync_pending` (syncs are synchronous,
  so `seal` returns a durable view and has no handle), and the two `SplitWriteBlob`
  partial-page rewrite races (writes cannot pause mid-call on a synchronous blob).
- [x] journal frame format and durability (frame.rs, durability.rs), byte-identical.
- [x] journal/segmented: section manager and fixed segmented journal (append, read, replay,
  prune, bounded init, floors and checkpoint restore), torn-page repair; tests incl.
  corruption and interrupted-open crash tests.
- [x] journal/segmented: variable journal (varint frames, optional zstd) with recovery and
  its ported tests.
- [x] journal/segmented: glob (CRC-trailed values located by an external index) with its
  `Recovery` and ported tests.
- [x] journal/segmented: oversized journal (fixed index plus glob values, checkpoint restore
  and marker-tracked recovery) with its core tests.
- [x] journal/segmented: the rest of oversized.rs's recovery tests (61 ported in
  oversized_recovery_test.zig). No counterpart: the value-alignment sync-concurrency test
  and the dropped-`start_sync`-handle test (syncs complete serially and synchronously). The
  dropped-replay read-gate test is ported as a `Canceled` value read.
- [x] `ReadOptions` (the `dont_cache` hint) through replay: `Writer.replay`/`view_replay` and
  `Sealed.replay` take it, and the segmented fixed, variable, and oversized configs carry
  `replay_read_options` (default `.{}`). Ported the fixed, variable, and oversized
  `replay_propagates_read_options` tests and sealed.rs's dont_cache cold-cache test.
- [x] journal/contiguous: fixed journal (checkpoint, blob partition, recovery with watermark
  and clear intent, bounded open, `init_at_size`, `clear_to_size`, replay batches) with the
  shared contiguous suite and the checkpoint tests.
- [x] journal/contiguous: fixed.rs's partition, replay, codec-error, interrupted
  `init_at_size`/`destroy`, repair, stale-hint, legacy-watermark, and commit tests.
- [x] journal/contiguous: the rest of fixed.rs's tests: handed to storage-merkle (2026-11-18),
  which ports them in new sibling test files.
- [x] journal/contiguous: variable journal (data blobs plus a fixed offsets journal,
  offset rebuild from the watermark, torn-tail and torn-page repair, prune/append crash
  alignment, `init_at_size`/`clear_to_size` under a staged offsets intent, compression,
  prepared appends, replay batches, `Backing`) with the shared suite and core recovery tests.
- [x] journal/contiguous: the rest of variable.rs's ~150 tests: handed to storage-merkle
  (2026-11-18), which ports them in new sibling test files.
- [x] journal/authenticated.rs backing contract: `assert_backing`, `last_matching`, `covers`,
  `Stored`, `init_sync`, with the fixed journal as a backing; init_sync and last_matching tests.
- [x] journal/authenticated.rs `Journal` (items plus persisted Merkle, recovery, batches,
  proofs) with its ported tests under both families, including the interrupted-destroy
  regression (issue 5668) over both backings and the equal-length-branch crash on
  `runtime.storage.faulty` (unsynced writes kept, unsynced resizes lost).
- [x] metadata (two-blob atomic key-value store).
- [x] metadata: the `metadata_recovery` fuzz target and the overwrite-crash-during-sync test
  on `runtime.storage.faulty` (with storage-archive's `archive/faults.zig` harness).
- [x] metadata: `start_sync` with its tests, and the `MetadataWorkload` conformance hash.
- [x] `queue_recovery` fuzz target on faulty storage.
- [x] `journal_segmented_variable_recovery` fuzz target on faulty storage (raw-image oracle).
- [x] `journal_oversized_recovery` fuzz target on faulty storage (marker-floor oracle).
- [x] `journal_contiguous_recovery` fuzz target on faulty storage (multi-cycle, both kinds).
- [x] queue (durable at-least-once queue over the contiguous variable journal, with its
  cursor) with storage.rs's tests and the `QueueWorkload` round trip.
- [x] queue: the `QueueWorkload` conformance hash.
- [x] Journal conformance hashes: contiguous fixed and variable, segmented fixed, glob,
  variable, and oversized, and authenticated over MMR and MMB, all matching commonware's.
- [x] Conformance workloads run through `runtime.conformance.StorageConformance` (the
  deterministic runner's storage audit), like commonware's; all hashes unchanged.
- [ ] Journal conformance hashes of the compressed (`<true>`) workloads: they need zstd
  output byte-identical to libzstd level 3. Blocked on storage-merkle's compressor
  (`journal/zstd.zig`, theirs since 2026-11-16).
- [x] Metrics: metadata (`sync_rewrites`, `sync_overwrites`, `keys`) and queue (`tip`, `floor`,
  `next`) through `runtime.telemetry.metrics`.
- [x] Metrics: contiguous fixed and variable journals (`size`, `pruning_boundary`, `retained`,
  `tail_items`, call and read counters; the variable journal's offsets under `offsets`).
- [x] Metrics: the blob and section managers (`tracked`, `synced`, `pruned`).
- Handed to storage-merkle (2026-11-16): `src/storage/journal/zstd.zig`'s real compressor and
  the `journal_fixed_operations` and `queue_operations` fuzz targets.

## Public API (on main)
- `storage.journal.Error`: commonware's `journal::Error` variants plus `codec.Error`.
- `storage.journal.frame`: `encode_frame_into(V, gpa, compression, item, *ArrayList(u8))`,
  `UncompressedFrame(V)`, `decode_length_prefix`, `find_frame` (`FrameInfo`
  complete/incomplete), `decode_item(V, gpa, payload, cfg, compressed)`,
  `read_frame_at(V, gpa, reader, offset, cfg, compressed)`.
- `storage.journal.durability.Barrier(Completion)`: durable-boundary tracker.
- `storage.journal.zstd`: `compress_into`, `compress_bound`, `frame_content_size`,
  `decompress`.
- `runtime.buffer.mocks.Storage`: test storage over `runtime.storage.memory`;
  `init(gpa)`, `interface()`, `crash()`, `durable_len`; counters `reads`, `writes`,
  `write_bytes`; faults `allow_mutations`, `remove_failures_after`.
- `runtime.buffer.SyncState`; `runtime.buffer.paged`: `Checksum`, `page_size`, `page_len`,
  `corrupt_page`, `CacheRef` (`init(gpa, page_size, capacity)`, `next_id`, `cache`,
  `read_cached`, `clear`), `Writer` (`init`, `open_recovery`, `truncate`,
  `finish_recovery`, `append`, `try_append`, `try_append_value`, `sync`, `read_into`,
  `read_up_to`, `try_read_sync_into`, `replay`, `recoverable_prefix_len[_at_most]`),
  `Replay` (`ensure`, `bytes`, `advance`, `seek_to`), `read_range` and `read_tail`
  (validated logical reads from a raw paged blob).
- `runtime.buffer.Write`: write-buffered blob (`init(gpa, blob, len, capacity)`, `deinit`,
  `size`, `needs_sync`, `read_at`, `try_write_at`, `write_at`, `resize`, `sync`, `truncate`);
  `runtime.buffer.tip`.
- `storage.journal.segmented.manager`: `Manager(Factory)` (one buffer per section, built by
  `AppendFactory` (paged `Writer`) or `WriteFactory` (plain `Write`):
  `get`, `get_or_create`, `sync`, `sync_all`, `prune`, `remove_section`, `truncate_pending`,
  `clear`, `destroy`), `truncate_paged_tail`, `stored_sections`, `section_name`.
- `storage.journal.segmented.fixed`: `Journal(A)` for fixed-size codec items with
  `init`, `init_at_most`, `preflight_floors`, `preflight_restore` (returning a `Recovery`
  with `next`, `drain`, `finish`, `boundary_items`), `append`, `get`, `get_many`,
  `try_get_sync`, `last`, `sync`, `sync_all`, `prune`, `section_len`, `size`, `clear`,
  `destroy`; `Config`, `Floor`.
- `storage.journal.segmented.variable`: `Journal(V)` for variable-size codec items with
  `init` (returns a `Recovery` yielding `{section, offset, size, item}`; `drain`, `finish`),
  `init_at_most`, `append` (returns `{offset, size}`), `get`, `get_many`, `try_get_sync`,
  `size`, `sync`, `sync_all`, `prune`, `pruned`, `clear`, `destroy`; `Config(V)`. Decoded
  items are owned by the caller (`codec.free`).
- `storage.journal.segmented.glob`: `Glob(V)` (`append` returning `Entry{offset, size}`,
  `get(section, offset, size)`, `sync`, `sync_all`, `size`, `prune`, `pruned`,
  `oldest_section`, `newest_section`, `sections` iterator, `remove_section`, `destroy`,
  test-only `inject`), `Recovery(V)` (`init`, `init_bounded`, `verify`, `truncate`,
  `truncate_sections`, `size`, `sections`, `sync`, `remove_section`, `finish`, `deinit`),
  `Config(V)`, `checksum_size`, and the test helper `corrupt_frame`. The manager gained
  `truncate_pending_sections([]const SectionSize)` and `section_iterator`.
- `storage.journal.contiguous`: `Bounds{start, end}`, `position_to_blob`,
  `blob_first_position`, `blob_end_position`, `batch_count_to_blob_boundary`;
  `checkpoint.Checkpoint`; `blobs` (`Partition`, `select`, `Writable`).
- `storage.journal.contiguous.fixed`: `Journal(A)` with `init`, `init_at_most`,
  `init_at_size`, `deinit`, `size`, `get_bounds`, `pruning_boundary`, `append`, `append_many`,
  `append_many_nested`, `prepare_append`/`append_prepared`, `commit`, `start_sync`, `sync`,
  `prune`, `read`, `read_many`, `try_read_sync`, `try_read_many_sync`, `replay(range,
  buffer)` (a `Replay` yielding `Batch{start, items}`), `clear_to_size`,
  `stage_clear_intent`, `destroy`; the `Backing` entry points `recover`, `clear`, `span`
  returning `Recovery(A)` (`size`, `pruning_boundary`, `recovery_watermark`, `item`,
  `append`, `truncate`, `sync`, `prune`, `clear_to_size`, `publish`, `deinit`); `Config`.
- `storage.journal.contiguous.variable`: `Journal(V)` with the fixed journal's API (items are
  decoded and owned by the caller; replay batches are owned by the replay), `Config(V)`
  (`partition`, `items_per_section`, `compression`, `codec_config`, `cache_ref`,
  `write_buffer`, `replay_buffer`), `PreparedAppend`, and the `Backing` entry points
  `recover`, `clear`, `span` returning `Recovery(V)`. Partitions are `{partition}_data` and
  `{partition}_offsets`. The fixed `Recovery` gained `open_dependent`,
  `open_cleared_dependent`, `clear_to_size_dependent` (remove a dependent partition under a
  staged clear), and the fixed journal `destroy_cleared(dependents)`.
- `storage.journal.segmented.oversized`: `Oversized(I, V)` where `I` is a fixed-size codec
  entry with `value_location() Location` and `with_location(offset, size) I`; `Config(V)`,
  `Checkpoint{section, size}`, `Appended{position, offset, size}`. `init_with_checkpoint`,
  `init_with_markers(marker_partition)` (returns a `Recovery`: `next`, `drain`, `finish`,
  `deinit`), `append(section, entry, value)`, `get`, `last`, `get_value`, `sync`,
  `sync_tracked`, `sync_all`, `prune`, `size`, `value_size`, `pruned`, `oldest_section`,
  `newest_section`, `destroy`, `deinit`.
- `storage.journal.authenticated`: `assert_backing(J)`, `last_matching(recovery, ceiling,
  context, predicate)`, `covers(span, position)`, `Stored(J)` (`open` returns `.opened` or
  `.unopened`), `init_sync(J, gpa, storage, cfg, range)`. A backing journal declares
  `BackingConfig`, `BackingRecovery`, `recover(gpa, storage, cfg, ?max_size)`,
  `clear(gpa, storage, cfg, size)`, `span(gpa, storage, cfg) Bounds`; its recovery declares
  `Item`, `get_bounds`, `read`, `reset`, `finish(size) J` (consumes, also on error), `deinit`.
  `contiguous.fixed.Journal(A)` implements it.
- `storage.journal.authenticated.Journal(F, C, H)` (F a Merkle family, C a backing
  contiguous journal, H a cryptography hasher such as `Sha256`): fields `merkle`
  (`merkle.full.Merkle(F, H.Digest)`), `journal: C`, `hasher` (`merkle.hasher.Standard(H)`).
  Open with `init(gpa, storage, merkle_cfg, journal_cfg, comptime predicate, bagging)`,
  `init_at_most(..., max_size, ...)`, or `prepare(..., ?max_size, predicate, bagging)`
  returning a `Recovery` (`bounds`, `is_fresh`, `read`, `finish`, `deinit`);
  `from_components(gpa, merkle, journal, hasher, batch_size)`; `align_merkle`. Reads:
  `size`, `get_bounds`, `read`, `read_many(positions, out)`, `try_read_sync`, `replay`,
  `root(inactive_peaks)`. Mutators (`*Self`; after an error only `deinit`): `append(item)`
  (borrowed) `u64`, `append_many`, `append_many_nested`, `apply_batch(*const
  MerkleizedBatch)`, `prune(loc) u64` and `prune_reporting(loc) Pruned{boundary, pruned}`,
  `commit`, `start_sync`, `sync`, `destroy`, `deinit`. Batches: `new_batch()`
  `UnmerkleizedBatch` (`add(gpa, item)`, `add_many(gpa, items)`, the batch owns added items;
  `merkleize(gpa, *const journal)`; `size`; `deinit`), `merkleize(&batch, items,
  inactive_peaks) Merkleized{batch, root}`, `to_merkleized_batch()`. `MerkleizedBatch` is
  refcounted (`retain`, `release(gpa)`): `size`, `batch_items`, `root(hasher, inactive)`,
  `get_node`, `proof`, `range_proof`, `new_batch()`, fields `inner` and `ancestor_items`.
  Proofs: `proof(start, max_ops, inactive)` and `historical_proof(leaves, start, max_ops,
  inactive)` return `Proved{proof, items}` (`deinit(gpa)`); `speculative_proof(batch,
  inactive)`, `speculative_pinned_nodes(batch, *[max_pinned_nodes]Digest) []Digest`.
- `storage.queue`: `Queue(V)` with `init(gpa, storage, Config(V), ?metrics.Scope)`, `deinit`,
  `destroy`,
  `append`, `enqueue`, `enqueue_bulk(items) Range`, `commit`, `sync` (prunes below the ack
  floor), `size`, and the reader side `try_recv() ?Received{position, item}`, `ack`,
  `ack_up_to`, `is_acked`, `floor`, `read_position`, `is_empty`, `reset`, `pending`;
  `Config(V)` is `journal.contiguous.variable.Config(V)`; `cursor.Cursor`.
- `storage.metadata`: `Metadata(K, V)` with `init`, `deinit`, `get`, `get_mut`,
  `put`, `put_sync`, `upsert`, `remove`, `clear`, `retain`, `items`, `count`, `sync`, `start_sync`,
  `destroy`; `Config(V)` (its optional `metrics` scope registers `sync_rewrites`,
  `sync_overwrites`, and `keys`).

## Decisions
- Errors: `journal.Error` is an error set without payloads (section, offset, sizes);
  codec failures keep their codec error instead of being wrapped in `Error::Codec`.
- zstd: no C libzstd. Decompression uses `std.compress.zstd` and reads every libzstd frame
  (checked with libzstd 1.5.7 vectors). Compression writes valid frames of raw and RLE blocks
  with libzstd's header choices (single segment up to 128 KiB, content size always declared,
  no checksum); commonware reads them, but compressed bytes differ from libzstd and the
  level is ignored. Uncompressed frames are byte-identical. A frame declaring more than
  `(len / 3 + 1) * 128 KiB` of content is rejected before allocating.
- Decoded items own their memory: compressed or split payloads are staged in scratch buffers
  freed after decoding, so borrowing item types (`codec.Bytes`) only work for whole
  uncompressed reads.
- `read_frame_at` takes a reader with `size`, `read_up_to`, and `read_at`; a frame running
  past `size()` fails with `EndOfBuffer` before its payload is allocated (fuzzing found the
  4 GiB allocation a corrupt prefix otherwise requests).
- `durability.Barrier` is generic over a completion with a non-blocking `poll() ?bool`,
  standing in for commonware's shared sync future until runtime storage lands.
- Rust-only frame tests (`Limited` bulk-copy forwarding, cached zstd contexts, byte equality
  with libzstd's compressor) have no Zig counterpart: codec readers take one slice, and the
  compressor differs by design.

- Storage: journal, metadata, and the buffers take `runtime.storage.Storage` and
  `runtime.storage.Blob` vtable values (no comptime storage parameter). Tests run on
  `runtime.buffer.mocks.Storage`, which wraps the runtime's `storage.memory` backend with what
  commonware's runtime mocks provide (`RecordingContext` read counts and
  `runtime_storage_write_bytes_total`, `MutationFaultContext` faults, plus a removal fault),
  and crash with `crash()` where commonware uses `start_and_recover`. The mocks live in the
  buffer directory until the runtime lane ports `mocks.rs`; they can move there unchanged.
- metadata: keys are fixed-size codec types sorted by encoded bytes (commonware's `Span`
  ordering); values are owned by the store and must not borrow input (`codec.Bytes`).
  Methods that commonware makes consuming (`sync`, `put_sync`) mark the store failed on
  error; only `deinit` may follow. A checksummed copy that fails to decode is `Corruption`
  instead of a panic. Metrics are plain fields (`sync_rewrites`, `sync_overwrites`,
  `count()`). `upsert(key, default)` returns a pointer instead of taking a closure.

- runtime buffer: the tip buffer is one contiguous allocation of `capacity + page_size`
  made at init (appends that would overflow it by a page bypass it), instead of chained
  zero-copy chunks. The page cache evicts with CLOCK instead of Clock2Q+ and does not share
  in-flight reads (single-owner fibers); hit rates differ, contents do not. Blobs sync
  synchronously, so `start_sync` is `sync` and `SyncState` has no pending state. A writer
  takes ownership of its blob on success and closes it in `deinit`; a `Replay` borrows it.
  Large appends write their bulk pages in buffer-capacity chunks rather than one write; the
  bytes on disk are identical. `recoverable_prefix_len` reads one page at a time.

- segmented: `Recovery.next` returns `?Item` with errors through the error union (commonware's
  `Option<Result>`); an error ends that section and makes `finish` fail. `finish` and
  `drain` consume the recovery even on error. commonware passes replay `read_options` as an
  argument to `preflight_floors`, `init`, and `init_with_markers`; here it is the configs'
  `replay_read_options` field with a default, so callers that keep the defaults (every lane
  but tests today) need no change. The replay never fills the page cache. Tests of in-flight `start_sync` handles and of dropping a `next` mid-repair
  have no counterpart: syncs and repairs complete synchronously. Removing a section removes
  its blob name before closing its writer, as commonware does.
- The storage mocks provide `reads` and `dont_cache_reads` (commonware's `RecordingContext`
  read count and recorded options) and
  `allow_mutations`/`mutation_refused` (commonware's `MutationFaults`). A clean replay of
  eight pages takes one read where commonware takes two (larger batches).

- variable: replay checks a frame's declared end against the blob before buffering it, so a
  corrupt length cannot make replay buffer the rest of the blob; a frame running past the end
  is an incomplete trailing item, as in commonware. Appends encode each frame into a reused
  scratch buffer and copy it into the write buffer (commonware encodes in place); the bytes
  are identical.

- glob: decoded values own their memory, so `test_glob_get_view` (two reads share one tip
  buffer) has no counterpart. `truncate_survives_crash` models a crash that retains the
  unsynced replacement by writing its bytes into the durable raw blob before reopening, since
  the memory backend drops every unsynced write at `crash()`.

- queue: commonware's separate `Reader` (watch-channel snapshots, `recv` waiting across
  tasks) becomes the reader side of one `Queue` value reading the live journal up to the
  published size, since nothing runs concurrently with the journal. Metrics `tip`, `next`, and
  the floor are plain fields until the metrics backlog item.

- contiguous variable: commonware's clear callbacks (`init_cleared`, `open_cleared`,
  `clear_to_size_cleared`) only ever remove the data partition, so the fixed recovery takes
  the dependent partition name instead of a closure; `destroy_cleared` takes a value with a
  `clear()` method. `read_many` reads item by item (no batched sync pass), and `start_sync`
  advances the joint watermark to the current size since syncs complete synchronously.

- contiguous fixed: syncs complete synchronously, so `start_sync` advances the watermark to
  the current size (commonware advances it to the last observed sync), sealed blobs are
  fully synced paged writers (no `Sealed` views or snapshots; `snapshot` readers are not
  ported, since nothing runs concurrently with the journal), and `read_many` reads item by item
  through the page cache. Metrics are plain counters (`items_read`, `cache_hits`,
  `cache_misses`, blob `synced`/`pruned`).

- oversized: syncs complete synchronously, so tracked barriers are recorded already
  succeeded and marker generations are never in flight; markers persist with a blocking
  metadata `sync`.

- authenticated: commonware's `Backing`/`BackingRecovery` traits are a comptime contract
  (`assert_backing`) over decl names; contexts become `(gpa, storage)`, and
  `last_matching`'s closure is a `(context, comptime predicate)` pair.
- Recovery fuzz targets decode inputs with 1- to 2-byte fields and bias fault rates toward low
  values (cubically, every rate still reachable), so seeded random inputs reach deep states
  instead of failing within a few operations. `queue_recovery` checks the reader's drain after
  the queue is dropped only without a failed operation: one `Queue` holds both sides here.
- authenticated `Journal`: locations are plain `u64`; errors are the merged
  `merkle.full.Merkle.Error` set (`StaleBatch`, `AncestorDropped`, `RangeOutOfBounds`,
  `ItemPruned`, ...) without payloads. Batches are hand-refcounted like `merkle.batch`:
  `MerkleizedBatch.release` is the `Arc` drop, parent links are weak, and items live in
  refcounted chunks shared with descendants' `ancestor_items`. `merkleize` and `align_merkle`
  hash sequentially (no strategy), `read_many` is not sharded, and `start_sync` completes at
  once. Tests use a fixed stand-in `Op` (tag, key, value) for qmdb's operation, since they
  compare roots between journals only.

- `journal_oversized_recovery` interrupts syncs by reaching into the section buffers: a
  parked barrier is a section buffer whose blob sync fails after its flush is written, and
  abandoned `start_sync` handles are every buffer failing that way. An input bit picks whether
  each section's index or value blob arrives first, since commonware's barriers race; without
  it an index could never outlive its values and value verification went untested.

- Contiguous `replay` reads through `paged.Writer.view_replay`, which reads flushed pages from
  the blob and the buffered tail from memory, as commonware replays through a reader view.
  The flushing `Writer.replay` stays for recovery, where buffers are empty. Before this,
  a replay issued writes, so it failed under write faults and left unsynced bytes for a crash.
- `journal_contiguous_recovery`: a held `start_sync` handle counts as completed at the call
  (syncs are synchronous), `Snapshot` does nothing (no snapshot readers), positions are
  16-bit, appends get 5 of 16 op draws, and `items_per_section` is biased toward small
  sections so seeded runs reach prunes.

- Storage conformance workloads follow storage-archive's harness (`cache/conformance_test.zig`):
  in-memory storage, `TestRng` seeded with the case seed, and the storage audit committed. The
  six large journal workloads (up to 16k items per case) run in Debug only with
  `-Dslow-tests`, like other lanes' large conformance tests.
- Oversized `start_sync` is `sync`, so commonware's dropped-`start_sync`-handle test has no
  counterpart; its sync-failure tests use a test-local partition sync fault (`SyncFault`).
- metadata `start_sync` is `sync`: a failed started sync fails at the call and consumes the
  store, instead of failing the next sync (commonware's dropped-handle and failure tests map
  onto that, on faulty storage).

- Contiguous journal duration histograms (`*_duration`) are not ported: journals hold no clock.
  Their scope is `Config.metrics` (null by default).
- Metrics record through `runtime.telemetry.metrics` handles; without a scope, handles are
  `detached` (recorded, not registered), so tests read them without a registry. Metadata takes
  its scope in `Config`, the queue as an `init` argument (its `Config` is the journal's).
- Blob and section managers register `tracked`, `synced`, and `pruned` under the journal's
  scope, with commonware's child names: contiguous fixed under `blobs`, variable under `data`
  (its offsets journal under `offsets`, then `blobs`); segmented fixed, variable, and glob directly in
  `Config.metrics`; oversized under `index`, `values`, and its markers under `metadata`.

## Log
- 2026-11-13: journal Error, frame encoding/decoding with zstd frames, durability Barrier,
  frame fuzz target.
- 2026-11-13: in-memory Storage/Blob stand-in; metadata with its tests and the
  metadata_operations fuzz target.
- 2026-11-13: moved the memory storage stand-in to `runtime.buffer.memory`; paged buffer
  core (page format, tip, cache, Writer, Replay) with tests and a seeded crash fuzz.
- 2026-11-13: `paged.read_range`/`read_tail`; segmented section manager and fixed segmented
  journal with recovery (floors, restore, torn-page repair) and their ported tests; memory
  storage read counts and mutation faults.
- 2026-11-13: switched metadata, the paged buffer, and the segmented journal onto
  `runtime.storage`; the memory stand-in is now a test backend for its vtable.
- 2026-11-13: segmented variable journal with recovery and its ported tests.
- 2026-11-13: deleted the memory stand-in; tests run on `runtime.storage.memory` through
  `runtime.buffer.mocks` (recording and mutation faults) and crash with `crash()`.
- 2026-11-13: buffer `Write` and tip; `Manager` generic over its buffer factory.
- 2026-11-13: segmented glob with `Recovery` and its ported tests.
- 2026-11-13: contiguous fixed journal with checkpoint and blob partitions; shared suite.
- 2026-11-13: first batch of the fixed contiguous journal's own recovery tests.
- 2026-11-13: segmented oversized journal with its core tests.
- 2026-11-13: authenticated backing contract (`init_sync`, `Stored`, `last_matching`).
- 2026-11-16: contiguous variable journal with the shared suite and core recovery tests.
- 2026-11-16: variable recovery tests (torn interior page, watermark beyond data); queue.
- 2026-11-16: authenticated `Journal` (recovery, batches, proofs) with its ported tests.
- 2026-11-16: authenticated equal-length-branch crash test on faulty storage.
- 2026-11-16: metadata_recovery fuzz target and overwrite-crash test on faulty storage.
- 2026-11-16: queue_recovery fuzz target on faulty storage.
- 2026-11-16: journal_segmented_variable_recovery fuzz target on faulty storage.
- 2026-11-16: journal_oversized_recovery fuzz target on faulty storage.
- 2026-11-16: journal, metadata, and queue conformance hashes (10 workloads, all matching);
  metadata `start_sync` and its tests.
- 2026-11-16: contiguous replay no longer flushes the write buffer (found by the
  journal_contiguous_recovery port, which landed with it).
- 2026-11-16: blob and section manager metrics (contiguous and segmented journals).
- 2026-11-18: queue_recovery fuzz decode overflow at a 0xFF page-size byte (CI soak seed 456);
  44 oversized recovery tests.
- 2026-11-18: oversized `destroy` stops at its first failed or cancelled step, as commonware
  does (reported through marshal: it kept destroying the other journals, which re-parked
  after a cancellation).
