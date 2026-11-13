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
- [ ] cache (over the variable segmented journal): put, get, prune, recovery; conformance.
- [ ] freezer: the hash table over fixed + oversized journals, checkpoints, resize, recovery
  after crash, conformance hashes for every on-disk format.
- [ ] ordinal (over contiguous fixed journal + metadata + rmap).
- [ ] archive: the `Archive` interface, prunable (index + journal) and immutable (freezer +
  ordinal + metadata) archives; port their test suites including crash recovery.
- [ ] Fuzz targets (storage/fuzz entries for these modules) and metrics through
  `runtime.telemetry.metrics`.

## Log
