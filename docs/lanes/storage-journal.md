# Lane: storage-journal

Owns `src/storage/{journal,metadata,queue}`. Add your `pub const` lines to
`src/storage/root.zig` (owned by storage-merkle; additive edits).

Reference: `~/.cache/zigware/commonware-ref/storage/src/{journal,metadata,queue}`. These
persist through the runtime's storage (`Storage` partitions and `Blob` read_at, write_at,
resize, sync). The runtime lane is landing that interface and an in-memory backend first;
build on it. Until then, start with the pure parts (frame.rs, durability, item encodings).

## Backlog
- [ ] journal frame format and durability (frame.rs, durability.rs), byte-identical.
- [ ] journal/segmented: fixed and variable segmented journals (append, read, replay,
  prune, rewind, sync), recovery from torn writes; port the tests incl. corruption tests.
- [ ] journal/contiguous: fixed and variable contiguous journals.
- [ ] journal/authenticated.rs.
- [ ] metadata (two-blob atomic key-value store).
- [ ] queue (persistent queue with cursor).
- [ ] Conformance hashes for every on-disk format, fuzz targets (storage/fuzz).

## Log
