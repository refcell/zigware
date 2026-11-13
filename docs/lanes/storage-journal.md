# Lane: storage-journal

Owns `src/storage/{journal,metadata,queue}` and `src/runtime/buffer/` (commonware's
`runtime/src/utils/buffer`: read/write buffers, tip, and `paged`; handed over from the runtime
lane by the coordinator because the journal is its main user). Add your `pub const` lines to
`src/storage/root.zig` (owned by storage-merkle; additive edits).

Reference: `~/.cache/zigware/commonware-ref/storage/src/{journal,metadata,queue}`. These
persist through the runtime's storage (`Storage` partitions and `Blob` read_at, write_at,
resize, sync). The runtime lane is landing that interface and an in-memory backend first;
build on it. Until then, start with the pure parts (frame.rs, durability, item encodings).

## Backlog
- [x] runtime buffer paged core: page format (two-slot CRC record), tip buffer, page cache,
  `Writer` (append, bulk append, sync, recovery open/truncate with staged shrink), `Replay`,
  `recoverable_prefix_len`; `runtime.buffer`.
- [ ] runtime buffer rest: `Sealed`/`seal`/`snapshot`, `read_many_into`/`read_ranges_into`,
  plain `Read`/`Write` buffers (read.rs, write.rs, tip.rs), and the
  remaining writer tests.
- [x] journal frame format and durability (frame.rs, durability.rs), byte-identical.
- [x] journal/segmented: section manager and fixed segmented journal (append, read, replay,
  prune, bounded init, floors and checkpoint restore), torn-page repair; tests incl.
  corruption and interrupted-open crash tests.
- [x] journal/segmented: variable journal (varint frames, optional zstd) with recovery and
  its ported tests.
- [ ] journal/segmented: glob and oversized journals.
- [ ] journal/contiguous: fixed and variable contiguous journals.
- [ ] journal/authenticated.rs.
- [x] metadata (two-blob atomic key-value store), over the in-lane memory storage.
- [ ] metadata: `start_sync` (pipelined syncs), conformance hash (`MetadataWorkload`), and
  the fault-injection tests (torn writes, failed syncs), once runtime storage lands.
- [ ] queue (persistent queue with cursor).
- [ ] Conformance hashes for every on-disk format, fuzz targets (storage/fuzz).
- [ ] zstd: a real compressor (LZ matches, FSE/Huffman) so compressed journals shrink.

## Public API (on main)
- `storage.journal.Error`: commonware's `journal::Error` variants plus `codec.Error`.
- `storage.journal.frame`: `encode_frame_into(V, gpa, compression, item, *ArrayList(u8))`,
  `UncompressedFrame(V)`, `decode_length_prefix`, `find_frame` (`FrameInfo`
  complete/incomplete), `decode_item(V, gpa, payload, cfg, compressed)`,
  `read_frame_at(V, gpa, reader, offset, cfg, compressed)`.
- `storage.journal.durability.Barrier(Completion)`: durable-boundary tracker.
- `storage.journal.zstd`: `compress_into`, `compress_bound`, `frame_content_size`,
  `decompress`.
- `runtime.buffer.memory` (re-exported as `storage.journal.memory`): in-memory test backend;
  `Storage.init(gpa)`, `interface()` returns a `runtime.storage.Storage`; counters `reads`,
  `writes`, `write_bytes`; faults `remove_failures_after`, `allow_mutations`.
- `runtime.buffer.SyncState`; `runtime.buffer.paged`: `Checksum`, `page_size`, `page_len`,
  `corrupt_page`, `CacheRef` (`init(gpa, page_size, capacity)`, `next_id`, `cache`,
  `read_cached`, `clear`), `Writer` (`init`, `open_recovery`, `truncate`,
  `finish_recovery`, `append`, `try_append`, `try_append_value`, `sync`, `read_into`,
  `read_up_to`, `try_read_sync_into`, `replay`, `recoverable_prefix_len[_at_most]`),
  `Replay` (`ensure`, `bytes`, `advance`, `seek_to`), `read_range` and `read_tail`
  (validated logical reads from a raw paged blob).
- `storage.journal.segmented.manager`: `Manager` (one paged writer per section:
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
- `storage.metadata`: `Metadata(K, V)` with `init`, `deinit`, `get`, `get_mut`,
  `put`, `put_sync`, `upsert`, `remove`, `clear`, `retain`, `items`, `count`, `sync`,
  `destroy`; `Config(V)`.

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
  `runtime.storage.Blob` vtable values (no comptime storage parameter). Until the runtime's
  in-memory backend lands, tests run on `runtime.buffer.memory`, a test backend implementing
  that vtable (live contents published by `sync`; closing without a sync drops unsynced
  writes), with read/write counters and removal and mutation fault knobs. It does not model
  the blob header. Read options are not used.
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
  `drain` consume the recovery even on error. Replay reads options (`DONT_CACHE`) do not
  exist, so `replay_propagates_read_options` has no counterpart; the replay never fills the
  page cache. Tests of in-flight `start_sync` handles and of dropping a `next` mid-repair
  have no counterpart: syncs and repairs complete synchronously. Removing a section removes
  its blob name before closing its writer, as commonware does.
- memory storage gained `reads` (commonware's `RecordingContext` read count) and
  `allow_mutations`/`mutation_refused` (commonware's `MutationFaults`). A clean replay of
  eight pages takes one read where commonware takes two (larger batches).

- variable: replay checks a frame's declared end against the blob before buffering it, so a
  corrupt length cannot make replay buffer the rest of the blob; a frame running past the end
  is an incomplete trailing item, as in commonware. Appends encode each frame into a reused
  scratch buffer and copy it into the write buffer (commonware encodes in place); the bytes
  are identical.

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
