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
- [x] `#[should_panic]` (2026-11-19): the lane's only one, grafting's
  `test_graftable_chunks_rejects_height_zero`, is a `utils.death.expect_panic` test (the
  `grafting_height >= 1` assert); removing the assert fails it. Not portable: 1 before, 0 now.
- [x] current unordered fixed: `Db` (init with grafted metadata, proofs, prune, sync,
  commit, destroy, apply), batches with activity layers and regrafting, `KeyValueProof.verify`,
  `CurrentMmr/MmbUnorderedFixedConf`, and commonware's small-db, proof, prune-boundary, and
  commit-after-sync tests plus randomized chains checked against the reopened rebuild.
- [x] current staged batches (`stage`/`expand`, `Slot`), with the staged-parity tests.
- [x] current ordered fixed: `exclusion_proof`, ordered `KeyValueProof` (with next key),
  `KeyValueProof.verify`/`ExclusionProof.verify`, `get_span`/`get_next_key`/`get_prev_key`,
  `CurrentMmr/MmbOrderedFixedConf`, and commonware's exclusion-proof test; the unordered
  proof, prune, staged, and random-chain tests also run over ordered.
- [x] current variable (`Variable(Digest)` values): `CurrentMmr/Mmb{Unordered,Ordered}
  VariableConf`; the db tests run over one database per variant. Values that own memory wait
  on `any`.
- [x] any sync glue (`any.sync.Database(Db, H)` on `sync.database.Persisted`), back from the
  crypto lane (2026-11-19): genesis and sync-boundary syncs, post-sync batches, the four
  `from_sync_result` cases, local pins at the last commit's floor, and a wrong root, over all
  eight any variants.
- [x] current sync glue (`current.sync.Database(Db, H)`, `current.Db.init_from_sync`): syncs
  verify against the ops root; the bitmap is pruned to the chunks below the range start and
  the grafted pins come from the ops tree (zero-chunk identity). Tests: genesis and pruned
  syncs with reopen, post-sync batches, replacing a client's pruned db, local pins. Decision:
  `discard_local_state` also clears grafted metadata as commonware does; no test isolates
  it, since the first `sync` rewrites the metadata and `init` clears it beside an empty log.
- [x] the `qmdb_any_{fixed,variable}_sync` fuzz targets (any/sync_fuzz_test.zig). The fixed
  target syncs a source of digest values (commit-counter metadata, prunes, unclean reopens)
  into a fresh database through one shared page cache, and the synced root must match. The
  variable target drives owned byte values through commits, reads, proofs, and historical
  proofs against recorded roots, with every read checked against a model. Decisions: syncs and
  proofs must succeed where commonware ignores their errors, and historical proofs start at or
  above the sync boundary. Planted bugs (a wrong historical-proof floor, a corrupted sync pin)
  are caught. The sync tests share one page cache between source and target, as commonware's
  do. Keyless and immutable glue, the engine, and the shared harness stay with the crypto lane.
- [x] current over owned byte values (`Vec<u8>`, current/variable_test.zig, unordered and
  ordered, both families): batches, the floor walk, reads, key-value, range, and exclusion
  proofs, prune, and reopen under the leak checker. Fixed leaks of owned values in
  `range_proof` (and its partial reads), `ProvedValue`, and the error paths of
  `key_value_proof`/`exclusion_proof`; `exclusion_proof` compares keys with `value.eql`.
  Decision: verifying an owned value's proof allocates its encoding, so it goes through
  `verify_key_value_proof_alloc`/`verify_exclusion_proof_alloc(gpa, ...)` (commonware's
  `verify` encodes into a `Vec`); the bool-returning verifiers keep their inline encoding
  and assert at comptime that the operation owns no memory.
- [x] qmdb benches, current half (storage-qmdb owns the shared `qmdb/benches` code): the 12
  `current::*` entries of commonware's fixed and vec variant registries (`common.CurrentDb`,
  sharing any's partitions plus `grafted-metadata-<suffix>`), so generate and init measure
  current. Commonware's apply_batch has no current variants.
- [x] qmdb benches: `chained_growth` (current only, `benches/chained_growth.zig`), current's
  16 merkleize variants (chunk 32 and 256), and constantinople's two current databases
  (`Names.grafted_metadata` names their grafted partition). Commonware's cold_read and scale
  harnesses have no current variants.
- [x] sync journal (`journal.init`/`resize`/`append` over contiguous journals, `Memory(Op)`)
  and the request tracker (`requests.Requests(F)`), with their commonware tests.
- [x] sync engine, database, source, harness (crypto lane, T-01a1d57b-08a0-72a4-a12b-10ff47f6049d,
  which owns `qmdb/sync/` and the keyless and immutable glue); any and current glue came back
  to this lane (above).
- [x] any and current on the shared sync harness (`any/sync_harness.zig`, commonware's
  `any/sync/tests.rs` harnesses with `create_*_ops`): `sync_harness.Tests` over any (fixed
  digests and owned bytes) and current (fixed and variable digests), unordered and ordered,
  both families, including the engine retention and issue-5669 tests. Current checks its ops
  root and canonical root. A planted `apply_ops`/`create_ops` mismatch fails all 16.
- [x] current bounded reopen refuses a pruned floor without discarding later commits
  (clearing's d287952; regression test after clearing's
  `test_bounded_reopen_fails_once_the_floor_is_pruned`).
- [x] compact db (witness journal over `merkle.compact`, batches, bounded init, prune,
  `init_from_sync` import, `serve`): `{Keyless,Immutable}{Mmr,Mmb}Compact{Fixed,Variable}Conf`
  and `CodecConformance<StoredWitness>`.
- [x] compact crash-point tests (import replacement under torn writes and failed syncs from
  the faulty storage) and tampered-witness tests.
- [x] compact's 10 in-flight `start_sync` tests (`test_compact_start_sync_*` and
  `test_compact_apply_overlaps_start_sync`) in compact/start_sync_test.zig, on
  `runtime.storage.mocks.DelayedSync`, over the keyless and immutable fixed dbs of both
  families (ported by the glue lane, 2026-11-19).
- [x] `qmdb_current_{unordered,ordered}_batch_root` (current/batch_root_fuzz_test.zig) and
  `qmdb_current_recovery` (current/recovery_fuzz_test.zig), on storage-qmdb's
  `qmdb/fuzz_floor.zig` oracle. Ordered neighbors are checked on every batch (current's
  `MerkleizedBatch.get_prev_key`/`get_next_key`, over any's) and on the database.
- [x] `qmdb_current_{unordered,ordered}_operations` (current/operations_fuzz_test.zig) and
  `qmdb_current_mmb_prune_grow` (current/prune_grow_fuzz_test.zig). Keys come from a
  128-key space or the seeded keys so proofs and deletes hit live keys.
- [x] compact/sync.zig: the sync `Database` interface (plus the engine's `open_journal`
  hook) over `sync.journal.Memory`. `Db.Journal` is now the sync journal; the witness journal
  is `Db.WitnessJournal`.
- [x] Fuzz targets: all six `qmdb_current_*` (commonware has no compact fuzz target; compact
  is covered by its crash-point and tamper tests). Benches: commonware's `qmdb/benches` span
  every variant, current included, so they stay with storage-qmdb's benches item.
- [x] Reshare harness phase 2 (coordinator, split agreed with bls-math): commonware's ten
  state-sync ceremonies from `glue/src/dkg/tests/reshare/mod.rs` in
  src/glue/dkg/tests/reshare/state_sync_{block,app,validator,test}.zig, over a validator
  variant with the probe, QMDB resolver, `Stateful` app, and DKG state-sync plan. Each runs
  under both of commonware's electors, with `with_stale` as a `Swap` probe receiver. The
  ceremonies are `-Dslow-tests`; the block codec test runs per push.
  Done 2026-11-19: all ten pass on both networks under both electors with no leaks
  (ReleaseSafe, a221d476); the nightly glue job runs them (all of test-glue, -Dslow-tests).
- [x] Reshare `Network::Lookup` cases (agreed with bls-math, option b): tests/reshare/lookup.zig
  holds `Network`, `TestDirectory` (`Option<Addresses>`, participant `i` at
  127.0.0.1:(10000 + i)), and `TestManager` (`KeyOnlyManager` or
  `AddressableManager(socket_manager)` over the node's own peer sets). One engine type takes the
  network at runtime (`create_on`, `with_network`; `create`/`with_committees` stay discovery),
  as commonware's single `TestDirectory` type does. `peer_provider` stays the node's
  `Net.Manager` on both networks: the simulated `SocketManager` wraps the same per-node
  tracker, so it reads what either manager tracked. Every mod.rs test with a `case::lookup`
  runs both networks (the shareless-player test is discovery only, as upstream), and so does
  harness_test.zig's manager test.

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
  staged batch, also on error. Ordered (`current/test_support.zig` `OrderedFixed(F)`):
  `KeyValueProof` is `ordered.proof.KeyValueProof(F, K, D, N)` (carries `next_key`),
  `exclusion_proof(&key) -> ExclusionProof` (`KeyExists` if active),
  `verify_exclusion_proof(proof, key, &root)`, `get_span`, `get_next_key`, `get_prev_key`.

## Design: concurrent reads of any and current (2026-11-19)

Implemented: a8d3ecb0, 300b7049, e5941c1f (`any/concurrent_test.zig`).

Commonware shares a database as `Arc<D>` (benches) or `Arc<AsyncRwLock<Option<D>>>`
(`glue::stateful::db::Shared`): `get`, `get_many`, `get_metadata`, and proofs take `&self`,
so any number of tasks read under a read guard, while `apply_batch`, `commit`, `prune`, and
`sync` take the database by value or `&mut` under the write guard. Merkleizing a batch reads
the database (`&self`) and so also runs beside other readers. Below the database, a page-cache
miss (`CacheRef::read_after_miss`) reads into a buffer of its own and joins a fetch of the same
page already in flight, so concurrent readers never share mutable read state.

What zigware reads mutate today, on `any.get` → index lookup → `log.read` → contiguous journal
`read` → paged `View.read_into`:
- metrics counters: atomic, safe;
- the page cache: locked since runtime's 404c831, safe (a page cached twice is overwritten);
- the index, the blob map, the write buffer's tail, the variable journal's offsets: read only;
- `View.read_blob` reads each missed page through the writer's single `page_scratch` buffer
  (`runtime/buffer/paged/{writer,sealed,view}.zig`): two readers missing pages of one blob
  overwrite each other's page before validating it. This is the one data race.

Design:
1. Runtime (runtime lane's files, not additive): `View.read_blob` reads a missed page into a
   buffer of its own, on the stack for physical pages up to `blob_page_size` and from the
   cache's allocator above it, instead of the shared `page_scratch` (which stays for the
   writer's own recovery and flushes). Fetch deduplication is left out; it is a performance
   step, not a safety one.
2. Storage: the read path takes `*const Self` from `any.Db.get`/`get_many`/`get_metadata`/
   `get_with_loc`/`get_span`/neighbors (and `current`'s delegates) down through
   `authenticated_journal.read` and the contiguous fixed and variable journals' `read`,
   `read_item`, `try_read_sync`, `locate`, and the paged `Writer.read_into`/`view`, so the
   compiler proves a reader mutates nothing but atomics and the locked cache. Those are
   signature-only edits in storage-journal's and runtime's files.
3. Sharing: readers hold `utils.sync.UpgradableRwLock(Db)` read guards; `apply_batch`,
   `commit`, `prune`, `sync`, and `destroy` take the write guard. Merkleize stays exclusive
   (write guard) for now: it allocates into the batch but also reads through `*D`, and
   widening it is a later step. glue's `db.Shared` keeps its mutex until its owner switches
   it to the read-write lock.
4. Test: a multi-thread stress test (`io.concurrent` readers on `std.Io.Threaded` doing
   `get`/`get_many` of known keys over a tiny page cache, so most reads miss, beside a writer
   applying batches under the write lock) checks every value read; it fails without step 1.

## Decisions
- Batch reference counts are atomic (`storage.refcount.RefCount`: monotonic retain, acq_rel
  release, a CAS `try_retain` for `Weak::upgrade`), and walks up a weak parent chain hold each
  live ancestor while reading it (`refcount.Ancestors`), as commonware's `Arc`/`Weak` do: forks
  of one parent are merkleized, read, and dropped on several threads under shared read guards.
- compact: `Db(F, O, H)` is generic over the keyless or immutable operation (detected by its
  `append`/`set` variant) instead of commonware's sealed trait; `compact.Keyless` and
  `compact.Immutable` are the aliases, kept under `compact/` so keyless/immutable stay
  storage-qmdb's. `Config` carries `codec_config` beside the witness journal config
  (commonware splits it out of the journal config). Since async start_sync step 5, `Open`
  keeps the last `start_sync`'s completion (`pending_sync`), so a dropped failure resurfaces.
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

- Proof verification encodes the claimed operation on the stack: in place for fixed-size
  operations, else in a `max_inline_operation_bytes` (4 KiB) buffer, which bounded keys and
  values fit. Owned values will need an allocating `verify` when `any` supports them.

## Log
- 2026-11-16: sync wire types, errors, gaps, and metrics with their conformance hashes.
- 2026-11-16: current's proof codecs with their 20 conformance hashes.

- 2026-11-16: current's grafting and canonical-root helpers; grafted range proofs and their
  verification.
- 2026-11-16: current unordered fixed `Db` and batches (clearing's Balances DB) with
  `CurrentMmr/MmbUnorderedFixedConf`; staged batches; ordered fixed current with exclusion
  proofs and `CurrentMmr/MmbOrderedFixedConf`.
- 2026-11-18: compact qmdb (keyless and immutable) with its 10 conformance hashes.
- 2026-11-18: compact crash-point and tampered-witness tests.
- 2026-11-18: current batch-root and recovery fuzz targets (planted bugs caught).
- 2026-11-18: current operations and MMB prune-grow fuzz targets; ordered batch neighbors.
- 2026-11-18: compact sync `Database` interface.
- 2026-11-19: any sync glue.
- 2026-11-19: current sync glue.
- 2026-11-19: any fixed and variable sync fuzz targets.
- 2026-11-19: current over owned byte values.
- 2026-11-19: current variants of the qmdb generate and init benches.
- 2026-11-19: any and current on the shared sync harness.
- 2026-11-19: current merkleize, chained_growth, and constantinople benches.
- 2026-11-19: reshare state-sync harness (block, app, validator, engine) and its ten tests.
- 2026-11-19: reshare phase 2 ceremonies verified on both networks and electors.
- 2026-11-19: `qmdb_sync_codec` fuzz target for the sync wire decoders (`Target`, `Request`,
  `Response`), with a drawn-field validity oracle (planted `start == size` bug caught). A
  30-minute `just fuzz` campaign (-j4) over it, `qmdb_any_{fixed,variable}_sync`, and
  storage-archive's targets found nothing.
- 2026-11-20: qmdb conformance gaps closed: `Current*FloorConf` (8), and the
  `StorageConformance` audits of current (8) and the compact databases (8), each with a planted
  bug caught.
