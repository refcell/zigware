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
- [x] current's proof codecs (`OpsRootWitness`, `RangeProof`, constant and dynamic
  `OperationProof`, ordered and unordered `KeyValueProof`, ordered `ExclusionProof`) with
  their 20 codec conformance hashes and commonware's codec tests.
- [x] current's grafting (`height`, `graftable_chunks`, grafted leaves, position conversions,
  `GraftedHasher`, `Verifier`), canonical-root helpers (graft roots, pending and partial
  chunks, sync boundary, grafted root, ops root witness, grafted tree rebuild), the grafted
  storage view with `build_range_proof`, and range and operation proof verification, with
  commonware's grafting, partial-chunk, and combine-roots golden tests plus build-then-verify
  and tamper tests over MMR and MMB at N = 1 and 32.
- [x] current unordered fixed: `Db` (init with grafted metadata, proofs, prune, sync,
  commit, destroy, apply), batches with activity layers and regrafting, `KeyValueProof.verify`,
  `CurrentMmr/MmbUnorderedFixedConf`, and commonware's small-db, proof, prune-boundary, and
  commit-after-sync tests plus randomized chains checked against the reopened rebuild.
- [x] current staged batches (`stage`/`expand`, `Slot`), with the staged-parity tests.
- [ ] current ordered (exclusion proofs) and variable.
- [ ] current sync glue.
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

- `storage.qmdb.current.proof`: `OpsRootWitness(F, D)` (`root(H, ops_root)`, `verify`,
  codec), `RangeProof(F, D)` (codec `Cfg = max_digests`, owns its Merkle proof),
  `OperationProof(F, D, chunk_size)` with `constant.Operation(F, D, N)` (`[N]u8` chunk,
  `Cfg = max_digests`) and `dynamic.Operation(F, D)` (owned `[]const u8` chunk,
  `Cfg{chunk_size, max_digests}`), `combine_roots(H, ...)`, `chunk_bits`, `Pending(F, D)`.
  `current.ordered.proof`: `KeyValueProof(F, K, D, chunk)`, `ExclusionProof(F, K, E, D,
  chunk)` (`key_value`/`commit`). `current.unordered.proof`: `KeyValueProof(F, D, chunk)`.

- `storage.qmdb.current`: `grafting` (`height(N)`, `graftable_chunks`, `grafted_leaf_digest`,
  `ops_to_grafted_pos`/`grafted_to_ops_pos`, `GraftedHasher(F, H)`, `Verifier(F, H)`),
  `canonical` (`GraftRoots(D)`, `pending_chunk`, `partial_chunk`, `sync_boundary`,
  `compute_grafted_root`, `compute_ops_root_witness`, `build_grafted_tree`), `grafted`
  (`Storage(F, H, Grafted, Ops)`, `build_range_proof`), `verification` (`reconstruct_root`,
  `verify_range(F, H, proof, start, encoded_ops, chunks, chunk_size, root)`,
  `verify_operation(F, H, operation_proof, encoded_op, root)`).

- `storage.qmdb.current.Db(F, U, C, I, H, N)` (`current.unordered` fixed instantiation:
  see `current/test_support.zig` `UnorderedFixed(F)`): `init(gpa, storage, scope,
  Cfg{merkle, log, grafted_metadata_partition, translator, init_cache}, ?max_size)`,
  `deinit`, `root` (canonical), `ops_root`, `ops_root_witness` (field), `get`/`get_many`/
  `get_metadata`, `bounds`, `inactivity_floor`, `sync_boundary`, `is_empty`,
  `key_value_proof(&key) -> ProvedValue{proof, value}`, `verify_key_value_proof(proof, key,
  value, &root)` (also `KeyValueProof.verify(H, U, key, value, &root)`),
  `operation_proof(loc)`, `range_proof(start, max_ops) -> Ranged{proof, operations,
  chunks}`, `ops_historical_proof`, `ops_pinned_nodes_at`, `grafted_storage`, `prune(loc)`
  (≤ `sync_boundary`), `commit`, `start_sync`, `sync` (also persists pruning metadata),
  `destroy`, `new_batch`, `to_batch`, `validate_batch`, `apply_batch(*const
  MerkleizedBatch)`. Batches: `var b = try db.new_batch(); try b.write(k, ?v);
  b.with_metadata(m); const mb = try b.merkleize(&db)` (or `merkleize_with(&db, &policy)`);
  `MerkleizedBatch` is refcounted (`retain`/`release`) with `root`, `ops_root`, `bounds`,
  `operations`, `sync_boundary`, `get(&k, &db)`, and `new_batch()` (child). The public
  field `any` is the underlying `any.Db`. Staged: `var s = try b.stage(keys, &db, out)`,
  `s.expand(keys, &db, out)`, `s.with_metadata`, `s.merkleize(slots, unstaged, &db)` with
  `Db.Slot` (`.keep`, `.put = v`, `.delete`) and `Db.StagedBatch.Mutation`; it consumes the
  staged batch, also on error.

## Decisions
- current's per-batch activity chunks are a refcounted `Layer` chain ending at the
  database's bitmap (commonware's `BitmapBatch`); merkleize and apply cut layers the database
  already holds (`trim_committed`). Staleness is left to `any`'s chain validation instead of
  `ensure_based_on`'s pointer check, since the zigware bitmap is owned, not shared.
- current's init opens `any` normally, then prunes its bitmap to the persisted chunk count,
  checking the floor and pair-absorption constraints that commonware's `init_with_bitmap`
  checks before publishing the journal; it fails the same way (`HistoricalFloorPruned`).
- Proof verification takes operations already encoded (`[]const []const u8`) instead of
  commonware's `impl Encode` iterator, so it needs no codec for the operation type; callers
  encode with `codec.encode`. `verify_range` is commonware's `verify_with_chunk_size` (chunks
  as slices); the const-`N` `verify` is the same call with `N`.
- commonware's `Graftable::PendingChunk<D>` (`Option<D>` for MMB, `Unused` for MMR) is
  `current.proof.Pending(F, D)`: `?D` for MMB and `void` (encoded as nothing) for MMR, so
  merkle needs no family hook. `pending_from` is the `TryFrom<Option<D>>` conversion.
- `constant` and `dynamic` proofs are one `OperationProof(F, D, chunk_size: ?usize)`; both
  encode the chunk without a length prefix, so their bytes are identical.
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
- 2026-11-16: current's proof codecs with their 20 conformance hashes.

- 2026-11-16: current's grafting and canonical-root helpers; grafted range proofs and their
  verification.
- 2026-11-16: current unordered fixed `Db` and batches (clearing's Balances DB) with
  `CurrentMmr/MmbUnorderedFixedConf`.
