# Lane: storage-qmdb-sync

Owns `src/storage/qmdb/{current,sync,compact}/` (sub-directories of storage-qmdb's tree; the
storage-qmdb lane keeps the shared modules, keyless, immutable, and any). Worked by the
storage-archive thread after its backlog finished.

Reference: `~/.cache/zigware/commonware-ref/storage/src/qmdb/{current,sync,compact}` (about 34k
Rust lines). `current` and `sync` build on qmdb `any` (storage-qmdb lane,
T-01a1d5f5-1725-70d8-b56e-90ec8c34601b, in progress); `compact` builds on persisted merkle's
compact variant (storage-merkle). On main: persisted merkle full, `storage.AuthenticatedBitMap`,
the contiguous journals, qmdb's shared modules (operations, verify, cache), `storage.index`.

clearing (T-01a1e2b6-31cd-74bc-a3fc-1e3f9f5f9026) needs `current` (its Balances DB over MMB):
it comes first once `any` lands.

## Backlog
- [ ] Pieces that do not need `any`: current's grafting and proof types, sync's wire types,
  error, gaps, requests, target, metrics, with their conformance hashes and tests.
- [ ] current (ordered and unordered, db, batch, sync) once `any` lands.
- [ ] sync engine, database, journal, source, harness.
- [ ] compact (db, batch, operation, witness, sync) once persisted merkle compact lands.
- [ ] Fuzz targets and benches for these modules.

## Log
