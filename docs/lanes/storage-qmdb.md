# Lane: storage-qmdb

Owns `src/storage/qmdb/`. Add the `pub const qmdb` line to `src/storage/root.zig` (additive).

Reference: `~/.cache/zigware/commonware-ref/storage/src/qmdb` (about 95k Rust lines). This
lane does the shared modules and the keyless, immutable, and any databases. `current`,
`sync`, and `compact` (about 34k lines) go to a second lane once `any` lands.

Builds on (all on main unless noted): `storage.journal.contiguous.fixed` (9717c08),
`storage.journal.segmented.{variable,glob}`, `storage.index` (unordered, ordered,
partitioned, immutable), `storage.merkle` (MMR and MMB, Mem, proofs, ProofStore),
`storage.AuthenticatedBitMap`, `storage.metadata`, `runtime.storage.memory`,
`runtime.buffer`, `runtime.telemetry.metrics`, and the deterministic runner's storage.
Not yet on main: persisted merkle (storage-merkle lane) and `journal/authenticated.rs`
(storage-journal lane). Both lanes are porting them now; until they land, work on the parts
that don't need them and keep a small interface where you must.

## Backlog
- [x] Shared codecs: value encodings, operation commit codecs, floor policies and `Walk`,
  chain (`Commitment`, `Bounds`, staleness checks), the `qmdb.Error` set, initialization
  validation; keyless, immutable, and any (ordered/unordered, fixed/variable) operations with
  all 21 codec conformance hashes; decoder fuzz over every operation type.
- [x] verify (`ProofExt`: operation range, pinned-node, extract, proof-store, and multi
  proofs) with its tests under both families.
- [x] cache (set-associative `location -> key` cache for snapshot rebuilds) with its tests.
- [x] snapshot: serial rebuild of the key index and activity bitmap from the log, with
  model-checked tests (colliding and collision-free translators, with and without the cache).
- [x] bitmap (`fill_from` floor-walk candidates over the activity bitmap, oracle-checked) and
  metrics (the shared metric set over `runtime.telemetry.metrics`).
- [ ] store (`store/db.rs`, the unauthenticated keyed store) and the `any` traits.
- [x] keyless: `Db` and its batches over the interim authenticated journal, with mod.rs's
  core scenarios under MMR and MMB (fixed values).
- [x] keyless: `KeylessMmrFixedConf`/`KeylessMmbFixedConf` root conformance (matches).
- [ ] keyless: the remaining mod.rs/fixed.rs scenarios, variable values over the contiguous
  variable journal (`Keyless*VariableConf`).
- [ ] Switch `qmdb.authenticated` to storage-journal's `journal.authenticated.Journal` when it
  lands (same method names).
- [ ] any, unordered fixed over MMB first (storage-qmdb-sync needs it for current), ahead of
  immutable.
- [ ] immutable.
- [ ] any (ordered and unordered, fixed and variable).
- [ ] Fuzz targets under storage/fuzz for these databases; benches under `benches.zig`.

## Public API (on main)
- `storage.qmdb.value`: `Fixed(V)`, `Variable(V)` (encodings with `Value`, `fixed`), `check`,
  `eql`, `bytes`, `clone`, `arbitrary`.
- `storage.qmdb.operation`: `Commit(V)` (`metadata: ?V`, `floor: u64`), the fixed and
  variable commit codecs, `write_location`/`read_location(F)`/`location_size`,
  `arbitrary_location(F)`, `format_commit`, `format_encoded`.
- `storage.qmdb.keyless.Operation(F, E)`: `append: V`, `commit: Commit`.
- `storage.qmdb.keyless.Db(F, E, C, H)` (`C` the backing contiguous journal, `H` the hash):
  `init(gpa, storage, scope, Config, ?max_size)`, `deinit`, `get`, `get_many`,
  `get_metadata`, `root`, `bounds`, `inactivity_floor`, `proof`/`historical_proof` (a
  `ProofOps` of proof and operations), `pinned_nodes_at`, `prune`, `commit`, `sync`,
  `start_sync`, `destroy`, `new_batch`, `to_batch`, `validate_batch`, `apply_batch`.
  `UnmerkleizedBatch`: `append`, `with_metadata`, `with_inactivity_floor`, `size`, `get`,
  `get_many`, `merkleize(&db)`, `deinit`. `MerkleizedBatch` (refcounted `retain`/`release`):
  `root`, `bounds`, `operations`, `proof`, `pinned_nodes`, `get`, `get_many`, `new_batch`.
  `keyless.initial_root(F, E, H)`.
- `storage.qmdb.authenticated.Journal(F, C, Hash)`: the interim authenticated journal
  (storage-journal's planned API): `prepare`/`Recovery.finish`, `init`, `size`, `get_bounds`,
  `read`, `read_many`, `root`, `append`, `commit`, `sync`, `start_sync`, `prune`, `destroy`,
  `new_batch` → `Batch.add`/`add_many`/`merkleize` → `MerkleizedBatch` (refcounted, keeps
  live ancestors' items), `apply_batch`, `historical_proof`/`proof`, `speculative_proof`,
  `speculative_pinned_nodes`.
- `storage.qmdb.init_journal(J, gpa, storage, merkle_cfg, journal_cfg, InitOptions)`.
- `storage.qmdb.immutable.Operation(F, K, E)`: `set: {key, value}`, `commit: Commit`.
- `storage.qmdb.any.Operation(F, S)`, `any.Ordered(F, K, E)`, `any.Unordered(F, K, E)`:
  `delete: K`, `update: S`, `commit: Commit`; `any.operation.update.{Ordered,Unordered}(K, E)`
  (`key`, `value`, and `next_key` when ordered).
  Every operation has `key`, `is_update`, `is_delete`, `is_commit`, `inactivity_floor`, `eql`,
  `deinit`, the codec interface, `format` (commonware's `Display`), and `arbitrary`.
- `storage.qmdb.floor`: `Limits`, `Entry(K, V)` (`keep`, `stop`, `replace`, `evict`),
  `Decision(V)`, `Action(V)`, `Walk`, policies `Proportional`, `Hold`, `Bounded`, `check`.
- `storage.qmdb.chain`: `Commitment(F, D)` (codec, `compatible`), `Bounds(F, D)` (`from_db`,
  `compatible`, `validate_apply_to`), `effective_boundary`, `validate_batch_applicable`,
  `validate_merkleize_floor`.
- `storage.qmdb.verify`: `Proof(F, H)`, `ProofStore(F, H)`, `verify`,
  `verify_with_pinned_nodes`, `verify_and_extract_digests`, `to_proof_store`, `verify_multi`
  (each `(F, H, O, gpa, proof, ...)` over operations of codec type `O`), `encode_all`.
- `storage.qmdb.cache.Cache(K)`: `init(gpa, capacity)`, `get`, `put(gpa, location, key)`
  (takes ownership), `remove`, `deinit`.
- `storage.qmdb.snapshot`: `build(Op, gpa, floor, reader, index, cache_size) Build`
  (`active_keys`, `activity` bitmap), `build_from_log(..., context)` (`context.status(is_active,
  superseded)`), `update_key`, `delete_key`. A reader has `get_bounds()` and
  `read(position) !Op`.
- `storage.qmdb.bitmap`: `Shared(N)` (a `utils.bitmap.Prunable(N)`), `fill_from(gpa, bitmap,
  scan_from, tip, limit, out)`.
- `storage.qmdb.metrics.Metrics`: `init(scope)`, `deinit`, `update(size, pruning_boundary,
  inactivity_floor, last_commit)`, the counters, and `Timed` durations (`*_duration.scoped(io)`).
- `storage.qmdb`: `Error`, `root_bagging`, `hasher(H)`, `single_operation_root(F, H, bytes)`,
  `validate_initialization_bound`, `validate_initialization_commit`,
  `find_inactivity_floor_at`, `inactive_peaks_at`.

## Decisions
- Value encodings are comptime structs (`value.Fixed(V)`, `value.Variable(V)`) instead of
  sealed traits; one generic operation type switches on `E.fixed` at comptime, so fixed and
  variable layouts share one implementation. Variable byte values are `[]const u8` (Rust
  `Vec<u8>`), owned by decoded operations (`deinit`).
- Locations are plain `u64` as in the merkle lane; their codec (`UInt` varint, refused above
  `max_leaves`) lives in `qmdb.operation`.
- `qmdb.Error` is a payload-free error set merged with the merkle, journal, and runtime
  storage errors (commonware wraps them). `DataCorrupted` drops its check name.
- chain: `Compatible` borrow witnesses have no counterpart; the checks return `void`.
  `Bounds.ancestors` is an owned slice. Weak-parent ancestor iteration comes with the batches.
- floor: a policy is a duck-typed struct (`evicts`, `limits`, `decide`). Rust's lifetime tie
  between a decision and its entry is a documented contract; `stop` and `replace` return the
  entry's value in `Decision.released` so the walk can free it.
- codec: custom types may declare `owns_memory` (an additive codec edit), so generic
  operations over non-allocating values are usable with `decode_fixed`.
- conformance: the TOML reader now accepts `\n`/`\t`/`\"`/`\\` escapes in section names
  (commonware wraps long type names with `\n`); names are compared unescaped.
- verify: commonware's `ProofExt` trait methods are free functions; `verify_multi` takes
  locations and operations as two parallel slices (mismatched lengths fail), like
  `merkle.Proof.verify_multi_inclusion`. Operations are encoded into scratch from `gpa`.
- snapshot: only the serial build is ported (commonware's `Sequential` path). The parallel
  build over partitioned indices (decoder tasks, worker channels, prefetch pipelining) waits
  for a reason to spawn work during init; its results are identical. The build reads the log
  one position at a time through `read` rather than a replay stream, so any reader (the fixed
  journal, an in-memory log) fits.
- bitmap: no `RwLock` around the activity bitmap; databases are single-owner.
- Display formats an encoding of up to 4096 bytes as hex and prints `<N bytes>` beyond that
  (formatting does not allocate).

- keyless: until storage-journal's authenticated `Journal` lands, `qmdb.authenticated` pairs
  `merkle.full` with the contiguous journal under the same API. Values put in a batch are
  shallow copies (kept alive by the caller until the batch is applied or released); every
  read returns owned values. A merkleized batch holds a weak link to its parent and the item
  chunks of its live ancestors, so reads and applies stay exact after ancestors are released.
  Mutators take `*Self` (commonware threads the database by value); `start_sync` returns no
  handle; there is no `strategy`.

## Log
- 2026-11-13: shared codecs (value, operation, floor, chain, Error, initialization checks),
  keyless/immutable/any operations with all 21 codec conformance hashes, decoder fuzz.
- 2026-11-13: verify (operation proofs) with its tests under MMR and MMB.
- 2026-11-13: snapshot-rebuild key cache.
- 2026-11-16: snapshot rebuild (serial) with model-checked tests.
- 2026-11-16: floor-walk candidates (`bitmap.fill_from`) and the shared metric set.
- 2026-11-16: keyless `Db` and batches over the interim authenticated journal.
- 2026-11-16: keyless fixed root conformance hashes (MMR and MMB) match commonware.
