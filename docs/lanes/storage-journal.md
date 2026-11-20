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
- [x] runtime buffer `Write` and its tip (write.rs, tip.rs) with their tests (mod.rs's write
  tests, including the straddle, direct-write, at-size append, and pre-wrapped-mutation
  cases). Its in-flight `start_sync` tests are in runtime/buffer/start_sync_test.zig and its
  range-vs-full sync tests in sync_wait_test.zig (as durability-operation counts).
- [x] runtime buffer `Read` (read.rs) with mod.rs's read tests; `read` copies into the caller's
  buffer (one refill buffer allocated at `init`) and rewinds on failure.
- [x] paged `Writer.read_many_into`/`read_ranges_into`/`try_read_ranges_sync_into` with
  writer.rs's and view.rs's batch-read tests (cache tried for every range before any blob read).
- [x] paged `View` (view.rs) shared by `Writer` and `Sealed`; `Sealed` (sealed.rs) with
  `Writer.seal`/`snapshot`/`try_snapshot` and sealed.rs's tests (paged/sealed_test.zig).
  `test_sealed_read_many_into_rejects_unsorted_offsets` is a death test
  (paged/panic_test.zig). The `SplitWriteBlob` partial-page rewrite race
  (`test_replay_preserves_tail_during_partial_page_rewrite`, all 8 rstest cases) is in
  paged/partial_rewrite_test.zig, with a test-local split-write blob whose paused write
  parks in a spawned task.
- [x] The rest of writer.rs's 94 tests, mod.rs's, and read.rs's portable tests (snapshot,
  replay options, recoverable prefix, CRC slots, read_many, needs_sync, recovery truncate
  with commonware's `PartialWriteBlob` interrupted stages, whose write counts match, large
  appends, replay seeks), plus two hints they check: `seal`'s flush writes with `dont_cache`
  and a recovery shrink reads its retained page with `dont_cache`. The in-flight
  `start_sync` handle and wait tests (and `test_sealed_reads_while_seal_sync_pending`: `seal`
  returns its sync's completion) are in runtime/buffer/start_sync_test.zig, range-vs-full
  sync selection in sync_wait_test.zig. No counterpart: `IoBuf` ownership
  and allocation reuse (`to_physical_pages_preserves_chunk_owners`,
  `append_variable_value_encodes_in_place`, `replay_buf_bytes_share_pages`), delayed,
  cancelled, or read-ahead reads (read.rs's batch pipeline: our replay reads one batch at a
  time), and the torn-extension blob. The should_panic argument checks (mod.rs's
  `corrupt_page` and `validate_read_ranges`, writer.rs's `read_many_into`, tip.rs's six) are
  death tests in paged/panic_test.zig (`utils.death.expect_panic`), except
  `test_validate_read_ranges_rejects_length_overflow`: commonware validates against a
  `u64::MAX` size, and here a range past the writer returns `BlobInsufficientLength`.
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
  oversized_recovery_test.zig), including the value-alignment sync-concurrency and
  dropped-`start_sync`-handle tests on `DelayedSync`. The dropped-replay read-gate test is
  ported as a `Canceled` value read, which ends the replay (`ReplayInterrupted`).
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
- [x] journal/contiguous shared suite (`contiguous/tests.rs`) in-flight sync tests
  `test_{fixed,variable}_start_sync_overlaps_predecessor_and_tail`, `_start_sync_overlaps_work`,
  `_start_sync_waits_for_prior`, `_start_sync_failure_propagates`,
  `_prune_waits_for_pending_sync`, and `_prune_surfaces_failed_sync` (12 tests), in
  `contiguous/start_sync_test.zig` (storage-merkle, async start_sync step 2, 2026-11-19). The
  contiguous blobs keep the sealed predecessor's sync in flight (`tail_predecessor_sync`), and
  fixed/variable `start_sync` return a `runtime.storage.Completion`.
- [x] journal/contiguous: the rest of variable.rs's ~150 tests: handed to storage-merkle
  (2026-11-18), which ports them in new sibling test files.
- [x] journal/authenticated.rs backing contract: `assert_backing`, `last_matching`, `covers`,
  `Stored`, `init_sync`, with the fixed journal as a backing; init_sync and last_matching tests.
- [x] journal/authenticated.rs `Journal` (items plus persisted Merkle, recovery, batches,
  proofs) with its ported tests under both families, including the interrupted-destroy
  regression (issue 5668) over both backings and the equal-length-branch crash on
  `runtime.storage.faulty` (unsynced writes kept, unsynced resizes lost). commonware runs
  each test per family (`_inner`/`_mmr`/`_mmb`); here one test covers both families. The
  contiguous journals and `Journal` gained `replay_options` (commonware's replay
  `read_options` argument; `replay` keeps the defaults), with
  `replay_propagates_read_options_to_backing_journal`. The sync-order, `start_sync` overlap
  and failure-handle, and Merkle-watermark tests are in authenticated_start_sync_test.zig, on
  `DelayedSync`. No counterpart: the strategy-pool `read_many` sharding and parallel-align
  tests and `test_merkleize_retains_ancestors_after_cancellation` (merkleization runs
  sequentially on the caller, so there is no detached job to outlive its waiter).
  `test_read_many_rejects_unsorted_positions` (should_panic) is a death test.
- [x] metadata (two-blob atomic key-value store).
- [x] metadata: the `metadata_recovery` fuzz target and the overwrite-crash-during-sync test
  on `runtime.storage.faulty` (with storage-archive's `archive/faults.zig` harness).
- [x] metadata: `start_sync` with its tests, and the `MetadataWorkload` conformance hash.
  Writes and open reads carry commonware's `DONT_CACHE` hint (`test_io_options_and_durability`
  without its sync-handle counts; durability stays an explicit blob sync, where commonware
  folds a lone write's sync into `WriteOptions::SYNC`). No counterpart: `value_too_big`
  (a should_panic on a 4 GiB value), `determinism` (deterministic-runtime auditor state; the
  conformance hash pins the bytes). The dropped-handle, failed-sync, and delayed-sync tests
  are in metadata/start_sync_test.zig, on `DelayedSync`.
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
- [x] Journal conformance hashes of the compressed (`<true>`) workloads: contiguous variable,
  segmented glob, variable, and oversized, with `compression: 3` and commonware's
  compressible `fill_variable_item::<true>`, all matching on storage-merkle's byte-exact
  libzstd 1.5.7 level-3 compressor (00abad1).
- [x] Metrics: metadata (`sync_rewrites`, `sync_overwrites`, `keys`) and queue (`tip`, `floor`,
  `next`) through `runtime.telemetry.metrics`.
- [x] Metrics: contiguous fixed and variable journals (`size`, `pruning_boundary`, `retained`,
  `tail_items`, call and read counters; the variable journal's offsets under `offsets`).
- [x] Metrics: the blob and section managers (`tracked`, `synced`, `pruned`).
- [x] Benches: the 12 journal benches (`storage/src/journal/benches`, bench `journal`) under
  `src/storage/journal/benches/`, with commonware's names (`journal::<module>/...`).
- [x] Benches: metadata (`metadata::overwrite`, `restart`, `sync`) under
  `src/storage/metadata/benches/`.
- [x] Benches: runtime buffer (`buffer_paged::append`, `read`, `sync`) under
  `src/runtime/buffer/benches/`, run from `src/runtime/benches.zig`.
- [x] Benches: runtime `iobuf::iobuf::decode_fixed` (`src/runtime/iobuf_benches.zig`), modes
  `iobuf_bytes`, `iobuf_native`, their `_ref`s, `vec_slice`, and `slice`. Not ported: `bytes`
  and `bytes_ref` (the `bytes` crate) and `vec` (the same slice decode as `vec_slice`);
  `iobuf_bytes` wraps with `from_static`, since `IoBuf` has no external counted owner.
- [x] Benches: bmt's seven benches were already ported (`src/storage/bmt/benches.zig`) with
  commonware's names and sizes; no gaps.
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
- zstd: no C libzstd. Decompression (`zstd/decode.zig`) reads every single libzstd frame
  with libzstd's checks (exact bitstream ends, offsets within the output, dictionary IDs,
  checksums), regenerating literals into the output's tail as libzstd does. It replaced
  `std.compress.zstd`, which copies matches a byte at a time (0.6 GB/s on 16 KiB records
  against several GB/s for libzstd); std stays as the independent decoder its tests and
  fuzzers compare against (checked with libzstd 1.5.7 vectors). Compression (storage-merkle's, 00abad1) writes
  exactly libzstd 1.5.7's level-3 frames, checked by the compressed journal conformance
  hashes; the configured level is not read, since commonware's workloads use only 3. A frame declaring more than
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
  zero-copy chunks. The page cache evicts with Clock2Q+ (`utils.Cache`) like commonware, but
  has no slot hints and does not share in-flight reads (single-owner fibers). `start_sync`
  returns a `runtime.storage.Completion`, and `SyncState` keeps it pending until a later
  operation waits for it, as commonware's does. A writer
  takes ownership of its blob on success and closes it in `deinit`; a `Replay` borrows it.
  Large appends write their bulk pages in buffer-capacity chunks rather than one write; the
  bytes on disk are identical. The journals' recovery scans read whole pages up to a budget
  per blob read (`recoverable_prefix_len_scan`), as commonware's: the config's
  `replay_buffer` at open, and the replay's buffer and read options during a replay.

- segmented: `Recovery.next` returns `?Item` with errors through the error union (commonware's
  `Option<Result>`); an error ends that section and makes `finish` fail. `finish` and
  `drain` consume the recovery even on error. commonware passes replay `read_options` as an
  argument to `preflight_floors`, `init`, and `init_with_markers`; here it is the configs'
  `replay_read_options` field with a default, so callers that keep the defaults (every lane
  but tests today) need no change. The replay never fills the page cache. Section
  `start_sync`s run concurrently and are joined; a `next` canceled mid-call (commonware's
  dropped replay future) ends the replay, so `next` returns null and `finish` fails, as
  commonware's `ReplayInterrupted` does. Removing a section removes
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
  published size. A canceled or failed mutation publishes nothing and fails the queue, where
  commonware's reader ends once the queue is dropped. Metrics `tip`, `next`, and
  the floor are plain fields until the metrics backlog item.

- contiguous variable: commonware's clear callbacks (`init_cleared`, `open_cleared`,
  `clear_to_size_cleared`) only ever remove the data partition, so the fixed recovery takes
  the dependent partition name instead of a closure; `destroy_cleared` takes a value with a
  `clear()` method. `start_sync` joins the data, offsets, and watermark syncs; the watermark
  advances only to the boundary a completed combined sync proved, as in commonware.

- contiguous fixed: `start_sync` advances the watermark to the last observed sync, as in
  commonware, and a sealed predecessor's sync stays in flight (`tail_predecessor_sync`).
  Sealed blobs are paged writers (no `Sealed` views or snapshots; `snapshot` readers are not
  ported, since nothing runs concurrently with the journal; `runtime.buffer.paged.Sealed`
  exists since 48ec31b if a reader ever needs one), and `read_many` reads item by item
  through the page cache. Metrics are plain counters (`items_read`, `cache_hits`,
  `cache_misses`, blob `synced`/`pruned`).

- oversized: data syncs and one marker generation may be in flight (`start_sync_tracked`),
  as in commonware; a failed generation surfaces at the next request.

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
  hash sequentially (no strategy), `read_many` is not sharded, and `start_sync` joins the
  journal's and the Merkle structure's syncs. Tests use a fixed stand-in `Op` (tag, key, value) for qmdb's operation, since they
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
  `-Dslow-tests`, like other lanes' large conformance tests. The four compressed (`<true>`)
  workloads run only with `-Dslow-tests` in every mode: zstd makes each take about 40 s even in
  ReleaseSafe (154 s of CI's test-storage step); nightly's ReleaseSafe `-Dslow-tests` run keeps
  them covered.
- Oversized's sync-failure tests use a test-local partition sync fault (`SyncFault`). Its
  in-flight `start_sync` tests run on `runtime.storage.mocks.DelayedSync`: a dropped completion
  is driven by the next sync, and recovery's value alignment truncates independent sections
  concurrently (every section's sync starts before any is awaited, as in commonware).
- metadata's failure tests run on faulty storage, which completes a started sync at the call,
  so a failure surfaces on the next durability operation and consumes the store. Its
  second-sync-waits test runs on `DelayedSync`.
- authenticated's in-flight tests (`authenticated_start_sync_test.zig`) include both issue 5668
  destroy regressions and the initialization order (operations sync before Merkle repair); a
  canceled task stands in for commonware's dropped destroy future.

- Journal benches measure on the production storage in a temporary `.zig-cache/tmp` directory
  (commonware's tokio runtime) and smoke-test (`zig build test`) on the in-memory storage, so
  the test suite does not wait on disk syncs. Smoke inputs trim the largest cases commonware
  smoke-tests in full, since unoptimized builds take seconds on them: `fixed_read_sequential`
  and the replays run 1,000 items, `variable_prepare_append` skips 32,768 records and the
  1 MiB size (Debug copies each record by value along the encoding path and overflows the
  stack), and `variable_read_compressed` caps items at 500. Measured inputs are commonware's.
- `fixed_read_random`/`variable_read_random` `mode=concurrent` issues its reads back to back:
  the journals take reads through one handle, so there are no futures to join. Syncs complete
  synchronously, so `append_sync`'s `start_sync` mode has no handle to await.
- `variable_read_compressed` and `variable_prepare_append`'s level-3 cases compress with the
  byte-exact libzstd level-3 encoder (00abad1), so frame sizes match commonware's.
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
- 2026-11-19: ported the 12 journal benches (`src/storage/journal/benches/`).
- 2026-11-19: ported the metadata benches (`src/storage/metadata/benches/`).
- 2026-11-19: ported the runtime buffer benches (`src/runtime/buffer/benches/`).
- 2026-11-19: ported the variable journal start_sync flush and init sync-order fault tests
  (from storage-merkle's backlog) and the iobuf bench.
- 2026-11-19: enabled the four compressed (`<true>`) journal conformance hashes; all match.
- 2026-11-19: not-portable re-audit after async start_sync: segmented replays end when a call
  is canceled (fixed, variable, oversized resume), manager start_sync skips clean sections,
  metadata's dropped-completion and failed-sync tests and pipelined overwrite crash, and the
  queue's reader after an interrupted mutation, each on `DelayedSync` or `ReadGate`; stale
  "no counterpart" and "syncs are synchronous" records updated.
- 2026-11-19: 15 of this lane's 17 should_panic tests ported as death tests
  (`utils.death.expect_panic`, 17 Zig tests counting tip.rs's rstest cases): the paged
  buffer's mod.rs 4, writer.rs 3, sealed.rs 1, tip.rs 6, and the authenticated journal's
  unsorted `read_many`, each with a planted bug. Still not ported:
  `validate_read_ranges_rejects_length_overflow` (returns an error here) and metadata's
  `value_too_big` (a 4 GiB allocation). contiguous fixed.rs/variable.rs's five belong to
  storage-merkle's handed-over test files.
- 2026-11-19: ported sealed.rs's partial-page rewrite replay race on a split-write blob mock.
- 2026-11-20: paused (optimization stop). Landed e96c83ca (one zstd encoder per batch),
  a9cfb330 ([N]u8 compressed in place), f78b7454 (`PREPARED_SPARE_LIMIT`), 20d5e341 (dfast
  search state in locals, new libzstd `sparse` sequence fixture), c6b94823 (BENCHMARKS note).
  Stopped at: the post-c7935b0c re-bench was cut in round 8 of compressed prepare_append;
  fixed_append, segmented append_buffered, append_sync and metadata before/after (05e1ed83)
  were never re-measured, so their BENCHMARKS rows stay provisional. Random 1 MiB
  compressed rows (1.35×, 1.69× before f78b7454 and 20d5e341) are unmeasured since.
- 2026-11-20: resumed for the random compressed rows. Landed 586dd9d8 (dfast candidates
  selected without branching on the window check), 971f6c9d (a matchless block whose sampled
  literals stay raw is stored raw without copying it; new libzstd `alphabet` frame fixtures),
  dd6861c5 (one encoder per journal across batches), bc9ee19b (window indexes continue across
  frames instead of clearing the tables, as `ZSTDirp_continue`), c62364ee (dfast on window
  indexes, one read per position), d2ab82b1 (fixed-size batches reserved up front), b83b4871
  (Huffman literals skipped when their streams cannot pay), 90b38d7c (dfast specialized on
  level 3's table logs), fa916d41 (items borrowed through compressed frame encoding: a 1 MiB
  item was copied twice). Tried and dropped: a four-table histogram (`HIST_count_parallel`,
  slower on this Zen 5) and prefetching the next positions' table entries (slower at every
  size). On identical bytes the encoder now runs a random 1 MiB frame in 185k TSC ticks
  against libzstd 1.5.7's 241k.
