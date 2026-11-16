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
- [x] sync's wire types (`Target`, `CompactTarget`, `Request`, `Response`,
  `max_response_size`), errors, gaps, and metrics, with their 8 codec conformance hashes and
  commonware's tests. (`requests` tracks in-flight futures, so it lands with the engine.)
- [ ] current's grafting and proof types (`OpsRootWitness`, `RangeProof`, `OperationProof`,
  `KeyValueProof`, `ExclusionProof`) with their conformance hashes and tests.
- [ ] current (ordered and unordered, db, batch, sync) once `any` lands.
- [ ] sync engine (with `requests`), database, journal, source, harness; per-variant sync glue
  (`keyless/sync.zig`, `immutable/sync.zig`, `any/sync/`), which this lane owns.
- [ ] compact (db, batch, operation, witness, sync) once persisted merkle compact lands.
- [ ] Fuzz targets and benches for these modules.

## Agreement with storage-qmdb (2026-11-16)
- `any.Db(F, U, C, H, ...)` (family, update type, contiguous journal, hasher, index or
  translator) is a generic struct with `*Self` methods and public fields named as in
  commonware (`log`, `snapshot`, `bitmap`, `inactivity_floor_loc`, `last_commit_loc`,
  `root_digest`; `root()` is the method). Commonware's `pub(crate)` helpers that current and
  sync use (`update_metrics`, `prune_log`/`prune_bitmap`, `validate_batch`,
  `stage`/`expand`/`resolve_updates`, `Slot`, `StagedLoc`) are `pub`. No `strategy`
  (sequential); `start_sync` returns nothing.
- Batches follow keyless (`keyless/db.zig` is the template): `db.new_batch()` returns a value
  (`deinit` to drop); `batch.merkleize(&db)` consumes it and returns a refcounted
  `*MerkleizedBatch` (`retain`/`release`) with a weak parent link; `merkleized.new_batch()`
  chains with a strong parent ref; `db.apply_batch(merkleized)` validates through
  `chain.Bounds`, and the caller still releases. Batch values are shallow copies (keep
  borrowed slices alive until applied or released); reads return owned values.
- Order on storage-qmdb's side: keyless, then any unordered fixed over MMB (current's first
  need, for clearing's Balances DB), then immutable, then the rest of any.
- The sync glue for keyless, immutable, and any lives in this lane; storage-qmdb exposes the
  hooks it needs (for example opening from a synced journal).

## Public API (on main)
- `storage.qmdb.sync`: `Target(F, D)` (`init(root, start, end)`, `advances`, codec),
  `CompactTarget(F, D)` (`to_target`, codec), `Request(F)` (`operations`/`boundary`, `size`,
  `start`, `max_ops`, `order`, codec, `format`), `Response(F, Op, D)`
  (`operations`/`boundary`, `proof`, `deinit`, codec with `Cfg{max_ops, op}`),
  `max_response_size(F, D, max_ops, op_size)`, `source.arbitrary_proof`, `gaps.find_next`,
  `Metrics`, error sets `ServeError`, `EngineError`, `Error(SourceError)`.

## Decisions
- `Target` keeps its range as `start`/`end` fields (`u64` locations, `start < end`) instead of
  a `NonEmptyRange` of locations; it encodes and decodes exactly as commonware's
  `NonEmptyRange<Location<F>>` (varints, out-of-domain locations refused first, then
  "start must be < end"). `CompactTarget`'s `TryFrom` is `to_target`.
- Errors are payload-free error sets: `EngineError`'s roots and bounds are not carried, and
  the sync error is `qmdb.Error || EngineError || SourceError`.
- `Request` and `Response` are tagged unions; `Response` owns its proof, operations, and
  pinned nodes (`deinit`). `merkle.Proof` has no `arbitrary`, so `source.arbitrary_proof`
  ports its derive for the conformance generators.

## Log
- 2026-11-16: sync wire types, errors, gaps, and metrics with their conformance hashes.
