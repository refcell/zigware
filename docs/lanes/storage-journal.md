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
- [ ] runtime buffer: read.rs, write.rs, tip.rs, then paged (CRC'd pages, cache, `Append`,
  `Writer`, `Replay`, `CacheRef`), byte-identical page format, over runtime's `Blob`. Add
  `pub const buffer` to `src/runtime/root.zig` (additive edit).
- [x] journal frame format and durability (frame.rs, durability.rs), byte-identical.
- [ ] journal/segmented: fixed and variable segmented journals (append, read, replay,
  prune, rewind, sync), recovery from torn writes; port the tests incl. corruption tests.
- [ ] journal/contiguous: fixed and variable contiguous journals.
- [ ] journal/authenticated.rs.
- [x] metadata (two-blob atomic key-value store), over the in-lane memory storage.
- [ ] metadata: `start_sync` (pipelined syncs), conformance hash (`MetadataWorkload`), and
  the fault-injection tests (torn writes, failed syncs), once runtime storage lands.
- [ ] runtime/buffer (owned by this lane since 3d5033e): read.rs, write.rs, tip.rs, and paged
  (CRC'd pages, Append/Writer/Replay/CacheRef), over runtime's Blob; `pub const buffer` in
  `src/runtime/root.zig`.
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
- `storage.journal.memory`: in-memory `Storage` (`open`, `remove`, `scan`) and `Blob`
  (`read_at`, `write_at`, `resize`, `sync`, `deinit`), a stand-in for runtime storage.
- `storage.metadata`: `Metadata(Storage, K, V)` with `init`, `deinit`, `get`, `get_mut`,
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

- Storage stand-in: until runtime's storage lands, journal/metadata/queue are comptime
  generic over a `Storage` type, tested with `journal/memory.zig`. Its names match
  commonware's (`open`, `remove`, `scan`, `read_at`, `write_at`, `resize`, `sync`); reads
  fill a caller buffer and writes take one slice instead of `IoBufs`, and read/write options
  are omitted (they change caching and syscalls, not contents). Unsynced writes are lost
  when a handle closes, as in commonware's memory storage.
- metadata: keys are fixed-size codec types sorted by encoded bytes (commonware's `Span`
  ordering); values are owned by the store and must not borrow input (`codec.Bytes`).
  Methods that commonware makes consuming (`sync`, `put_sync`) mark the store failed on
  error; only `deinit` may follow. A checksummed copy that fails to decode is `Corruption`
  instead of a panic. Metrics are plain fields (`sync_rewrites`, `sync_overwrites`,
  `count()`). `upsert(key, default)` returns a pointer instead of taking a closure.

## Log
- 2026-11-13: journal Error, frame encoding/decoding with zstd frames, durability Barrier,
  frame fuzz target.
- 2026-11-13: in-memory Storage/Blob stand-in; metadata with its tests and the
  metadata_operations fuzz target.
