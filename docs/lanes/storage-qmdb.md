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
Also on main: persisted merkle (`storage.merkle.full`, storage-merkle lane) and the
authenticated journal (`storage.journal.authenticated.Journal`, storage-journal lane, c6b5f78),
which every database here is built on.

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
- [x] store (`store/db.rs`, the unauthenticated keyed store). The `any` traits stay unported:
  Zig dispatches on concrete types, so callers use each database directly.
- [x] keyless: `Db` and its batches over the authenticated journal, with mod.rs's
  core scenarios under MMR and MMB (fixed values).
- [x] keyless: `KeylessMmrFixedConf`/`KeylessMmbFixedConf` root conformance (matches).
- [x] keyless: variable values over the contiguous variable journal; batches own their
  values and reads return owned copies; `KeylessMmr/MmbVariableConf` root conformance
  (matches).
- [x] keyless: empty and non-empty recovery from failed commits, replay with trailing
  appends, comprehensive and post-prune proofs, out-of-bounds and pruned reads, and the
  bounded-initialization scenarios (pruned target, restored floor, durable after reopen).
- [x] keyless: merkleize across prune, stale forks, descendant-stale parent reads, foreign
  databases, stale siblings, and ancestor states.
- [x] keyless: dropped-ancestor, stacked, and chained reads with their bounds, empty and
  large batches, stale fork descendants and child-before-parent, pending child roots, floor
  tracking, floors in the root, the single-commit live set, and chained rising floors.
- [x] Switch the interim `qmdb.authenticated` to storage-journal's
  `journal.authenticated.Journal` (keyless, any, immutable); the interim copy is deleted.
- [x] any, unordered fixed (MMR and MMB): `Db`, batches with chaining, the floor walk under
  non-evicting policies, `AnyMmr/MmbUnorderedFixedConf` root conformance (matches), and
  scenario plus randomized chain tests against a model and the reopened rebuild.
- [x] any: `stage`/`expand`/`Staged.merkleize`/`resolve_updates` with `Slot` and `StagedLoc`
  (resolutions model-checked; commonware's staged-ancestor and explicit-equivalence scenarios).
- [x] any, ordered fixed (MMR and MMB): `next_key` link maintenance (successor and
  predecessor candidates from reads, translated-key neighbors, and ancestor updates),
  `get_span`, `get_next_key`, `get_prev_key`, `get_with_next_key`, and
  `AnyMmr/MmbOrderedFixedConf` root conformance (matches); randomized chains check every link
  against a model.
- [x] any: `AnyMmr/Mmb{Unordered,Ordered}VariableConf` root conformance over the variable
  journal (matches).
- [x] any: owned (variable) values, unordered and ordered: batches own their writes,
  metadata, and staged puts; diffs own their values; reads return owned copies; the floor
  walk borrows log reads and hands the journal batch copies (replacing policies included).
- [x] `init_from_log(gpa, scope, log, ...)` on any, immutable, and keyless: the build half of
  `init` over an opened authenticated log (state sync's `from_sync_result`).
- [x] any, unordered: evicting floor policies (an evicted key is deleted at the tip; the policy
  owns the evicted value), with commonware's created-then-evicted scenario.
- [x] any, ordered: evicting floor policies with link repair of evicted keys' predecessors;
  `Any{Mmr,Mmb}{Unordered,Ordered}{Fixed,Variable}FloorConf` (commonware's `floor_batches`
  workload under Proportional, Hold, Bounded, and a seeded keep/evict/replace/stop rule) match.
- [x] any, ordered: `range(start, end)` (commonware's `stream_range`; `Range.next_key` is
  `keys`), a pull iterator over buckets, checked against a sorted model under every bound pair.
- [x] any: ordered staging (the staged-ancestor scenarios run on ordered databases too).
  Batched `get_many` stays a loop over `get` by decision (coordinator, 2026-11-18): commonware's
  batching only groups reads by position for speed, and the results are identical.
- [x] fuzz targets: keyless, immutable, and any unordered/ordered operations, with the floor
  oracle `qmdb/fuzz_floor.zig` (commonware `storage/fuzz/src/floor.rs`).
- [x] any: ordered `MerkleizedBatch.get_prev_key`/`get_next_key` (strict, non-wrapping, through the
  chain's diffs, then the committed snapshot), checked on every level of the random chains.
- [x] fuzz target `qmdb_verify_proof`, plus a positive control (genuine multi-proofs of a real tree
  verify; tampered operations and roots fail).
- [x] store (`qmdb/store`): the unauthenticated variable-value KV over `any` unordered operations
  (MMR family, 64-byte bitmap chunks), with floor policies, bounded init, and db.rs's core tests
  (exact sizes, floors, and pruning boundaries match commonware's).
- [x] store: the `qmdb_store_operations` fuzz target (floor oracle on every commit, crash reopens).
- [x] fuzz targets: `qmdb_any_{unordered,ordered}_batch_root` (pending, dropped-prefix, and
  chained schedules against committed rebuilds; same roots and floor walks; recovery).
- [x] fuzz target: `qmdb_any_ordered_batching` (metadata across commits, final span links).
  Every qmdb fuzz target in my scope is ported (the any sync targets belong to the crypto lane).
- [x] benches for any, immutable, keyless, and store (coordinator split, 2026-11-19: current and
  compact benches go to storage-qmdb-sync), in `qmdb/benches/` (`common.zig` holds the
  variant registry, configs, storage, and seeding; storage-qmdb-sync adds current there).
  - [x] `qmdb::generate`: the any fixed, variable, and variable-vec variants (MMR and MMB),
    the store, and keyless, with commonware's names and constants.
  - [x] `qmdb::init` (both cache sizes, any and store) and `qmdb::apply_batch` (all eight
    cases, including the p256-partitioned ordered and immutable variants).
  - [x] `qmdb::merkleize`: the main grid (chained, seed sync, cache clear; `blob_reads` metric
    through a storage meter) and the churned case, over the eight any variants.
  - `qmdb::chained_growth` benches only `current` variants, so it goes to storage-qmdb-sync.
  - [x] the opt-in CLI harnesses `cold_read`, `constantinople`, and `scale` in
    `qmdb/benches/{cold_read,constantinople,scale}.zig` (shared pieces in `harness.zig`):
    `zig build qmdb-cold-read|qmdb-constantinople|qmdb-scale -- <commonware's args>`, built
    in ReleaseFast; `zig build test` runs a tiny smoke test of each. Their `any` variants;
    storage-qmdb-sync adds `current` to constantinople's `variants` tuple.
- [x] immutable (fixed, MMR and MMB): `Db`, chained batches, floor-filtered batch reads,
  prune, recovery, `ImmutableMmr/MmbFixedConf` root conformance (matches), mod.rs's core
  scenarios, and a randomized chain check against the reopened rebuild.
- [x] immutable: `ImmutableMmr/MmbVariableConf` root conformance over the variable journal
  (matches).
- [x] immutable: owned (variable) values; batches own their sets and metadata, diffs own
  their values, reads return owned copies.
- [x] immutable: bounded initialization (all six `run_bounded_initialization_*` scenarios),
  recovery from failed Merkle and log syncs, prune after an uncommitted floor, prune limits,
  collision-bucket pruning, and `get_many` (`bounded_test.zig`, `recovery_test.zig`).
- [x] immutable: the mod.rs batch scenarios (stacked apply, speculative roots, many
  sequential, large, sibling-apply proof refusal, operations match the applied log;
  `batch_test.zig`), including its `ElementPruned` tail after a flushing commit.
- immutable audit (2026-11-19) against mod.rs's 59 `run_*` scenarios and the fixed.rs and
  variable.rs tests: 25 covered, 15 partial, 19 missing at the start.
  - [x] batch A, floors: `run_inactivity_floor_tracking`, `run_floor_monotonicity`,
    `run_floor_monotonicity_violation`, `run_chained_floor_beyond_commit`, fixed.rs
    `test_batch_inherits_floor_but_not_metadata` (its compact half is the compact lane's).
  - [x] batch B, staleness (also fixes `get_many` with no keys, which skipped the stale
    check commonware makes): `run_descendant_apply_makes_parent_reads_stale`,
    `run_merkleize_foreign_db`, `run_merkleize_stale_sibling`,
    `run_stale_batch_child_applied_before_parent`, and the `StaleRead` halves of
    `run_stale_fork_refuses`, `run_stale_batch_rejected`, `run_stale_batch_chained`.
  - [x] batch C1, chains: `run_partial_ancestor_commit`,
    `run_delayed_merkleize_after_ancestor_apply`,
    `run_child_root_matches_pending_and_committed`, and the rest of `run_to_batch`.
  - [x] batch C2: `run_merkleize_across_prune`, and the partial `run_batch_chain`,
    `run_batch_chained_merkleized_get`, `run_dropped_ancestor_reads`,
    `run_operations_match_applied_log` (child proof unchanged).
  - [x] batch D1, prune and build (`prune_test.zig`): `run_pruning` (5 items per section),
    `run_prune_retires_pruned_sets`, `run_single_commit_live_set`, `run_build_and_authenticate`.
  - [ ] batch D2: the partial `run_build_basic`, `run_batch_many_sequential`,
    `run_batch_empty_batch`, `run_reads_ignore_inactive_operations` (colliding twin, reopen).
  - [ ] batch E, fixed.rs: `start_sync` recovery and failure (synchronous forms), metrics,
    `bounded_init_then_set_crash_recovers_history`. Not portable while `start_sync` completes
    synchronously: `start_sync_overlaps_work`, `apply_indexes_while_journal_waits`,
    `start_sync_prune_waits`. Compact root compatibility is the compact lane's.
- [x] Fuzz: `qmdb_keyless_operations` (seeded and `std.testing.fuzz`), with a value model.
- [x] store batch 1: shared-prefix snapshot rebuild, floor bound (`churn` and
  `randomized_churn` with commonware's `bounded` replay check), collision reads (floors and
  walk reads match; bucket reads are zigware's per-key resolution), `get_many` duplicates.
- [x] store batch 2 (`store/policy_test.zig`, commonware's `PolicyStore`): replace, evicts
  in location order, unreachable own write, proportional probes the snapshot once, limits read
  once, keep/evict/recover across commit, reopen, and prune, own writes decided like applied
  ones, reads only reached candidates (both layouts), and the full limits grid against a port
  of `walk_model`. Commonware's clone counts are not checked: zigware's policies get owned
  values.
- [x] store batch 3: bitmap activity through every policy action, prune, and reopen; bitmap
  chunk-prune recovery; prune at an unsynced floor then reopen; commit after sync recovers;
  an update persisted without its commit is discarded; start_sync recovery; a failed
  start_sync surfaces its error. Not observable here: commonware's `start_sync_overlaps_work`
  and `start_sync_prune_waits`, because zigware's journal `start_sync` completes before it
  returns (journal lane); they need an asynchronous `start_sync`.
- [x] store: variable-length keys. `Db([]const u8, ...)` works: a batch and a changeset copy
  each key (`value.clone`, a plain copy for fixed arrays, so fixed keys stay allocation-free),
  every emitted operation owns its own copy, and lookups free the keys they decode. Ported
  `test_store_variable_length_keys`, plus a leak-checked churn of owned keys through
  overwrites, deletes, and the floor walk.
- [x] Fuzz targets under storage/fuzz for these databases; benches under `qmdb/benches/`.

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
- `storage.qmdb.init_journal(J, gpa, storage, merkle_cfg, journal_cfg, InitOptions)`.
- `storage.qmdb.immutable.Db(F, K, E, C, H, T)` (`T` the translator of its
  `index.immutable.Index`), with public fields `journal`, `snapshot`, `inactivity_floor_loc`,
  `root_digest`, `metrics`: `init(gpa, storage, scope, Cfg{merkle, log, translator}, ?max_size)`,
  `deinit`, `get`, `get_from(key, floor)`, `get_many`, `get_many_from`, `get_metadata`, `root`,
  `commitment`, `bounds`, `inactivity_floor`, `sync_boundary`, `proof`, `historical_proof`,
  `pinned_nodes_at`, `prune`, `commit`, `sync`, `start_sync`, `destroy`, `new_batch`,
  `to_batch`, `validate_batch`, `apply_batch`. `UnmerkleizedBatch`: `set(key, value)`,
  `with_metadata`, `with_inactivity_floor`, `get`, `get_many`, `merkleize(&db)`, `deinit`.
  `MerkleizedBatch` (refcounted): `root`, `commitment`, `operations`, `proof`, `pinned_nodes`,
  `get`, `get_many`, `new_batch`, and the fields `diff` (key-sorted `BatchDiff`),
  `ancestor_diffs`, `bounds`. `immutable.initial_root(F, K, E, H)`.
- `storage.qmdb.any.Db(F, U, C, I, H, N)` (`U` an `any.operation.update` type, `C` the backing
  contiguous journal, `I` the snapshot index, `H` the hash, `N` the activity bitmap's chunk
  bytes, commonware's `const N`), with public fields `log`, `snapshot`, `bitmap`
  (`bitmap.Shared(N)`), `inactivity_floor_loc`,
  `active_keys`, `root_digest`, `metrics`. `init(gpa, storage, scope, Cfg, ?max_size)`,
  `deinit`, `get`, `get_many`, `get_with_loc`, `read_update`, `get_metadata`, `root`,
  `commitment`, `bounds`, `inactivity_floor`, `sync_boundary`, `is_empty`, `proof`,
  `historical_proof`, `pinned_nodes_at`, `prune` (`prune_log`, `prune_bitmap`), `commit`,
  `sync`, `start_sync`, `destroy`, `update_metrics`, `new_batch`, `to_batch`,
  `validate_batch`, `apply_batch`, `update_known_loc`, `delete_known_loc`.
  `any.Config(Translator, JournalConfig)`: `merkle`, `log`, `translator`, `init_cache`.
  `UnmerkleizedBatch`: `write(key, ?value)`, `with_metadata`, `get`, `merkleize(&db)`,
  `merkleize_with(&db, &policy)`, `deinit`. `MerkleizedBatch` (refcounted `retain`/`release`):
  `root`, `commitment`, `bounds`, `operations`, `proof`, `pinned_nodes`, `get`, `new_batch`,
  `apply_to_index`. `any.diff`: the sorted per-batch `Diff` with `Cursors` and `Merge`.
  `any.initial_root(F, U, H)`. Staging: `UnmerkleizedBatch.stage(keys, &db, out)
  StagedBatch`; `StagedBatch` has `len`, `is_empty`, `with_metadata`, `expand(keys, &db, out)
  Range`, `merkleize(slots, unstaged, &db)`, `merkleize_with(..., &policy)`,
  `resolve_updates(slots, unstaged) UnmerkleizedBatch`, `deinit`, and the fields `keys` and
  `resolutions` (`?StagedLoc` per slot: `committed: loc` or `ancestor: {loc, base_old_loc}`).
  `Db.Slot` is `keep`, `put: V`, or `delete`. Ordered databases (`U` an `update.Ordered`, `I`
  an `index.ordered.Index`) add `get_span`, `get_next_key`, `get_prev_key`, and
  `get_with_next_key`.
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
- cold_read, constantinople, and scale are commonware's opt-in CLI harnesses (`harness =
  false` bench binaries that no-op without arguments), so they are executables with their own
  run steps (`zig build qmdb-<name> -- ...`, build.zig `add_qmdb_harnesses`), outside
  `zig build bench`, with commonware's arguments, defaults, partitions, and output lines.
  zigware's databases are not shared across threads, so modes commonware runs as concurrent
  futures (cold_read's chunked, shared, get_concurrent, pipeline, sustained; scale's readers)
  issue the same reads one after another, `blob_read_many` reads page by page, and the
  `threads`, `workers`, `blocking`, and init `concurrency` arguments are reported only.
  cold_read accepts only the 4096-byte physical page zigware's storage writes. scale's Zipf
  ports `rand_distr` 0.6's sampler and matches its value-stability vector. The `*_gungraun`
  instruction-count benches need valgrind and are not ported.
- Benches run over the production disk storage, as commonware's tokio runtime does. On smoke
  inputs (`zig build test`) they use the in-memory storage and smaller cases (generate: 100
  elements and 1,000 operations; init: 100 and 1,000; apply_batch: 256 keys and 64 updates),
  because on disk every commit's fsync made the smoke run take about 67 s.
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

- keyless: built on `journal.authenticated.Journal`, whose batches own their items. Values may
  own memory: `append` and `with_metadata` hand the value to the batch (freed on `deinit`, or
  moved into the journal batch by `merkleize`), and every read returns an owned copy. A
  merkleized batch holds
  a weak link to its parent; its journal batch keeps the item chunks of its live ancestors
  (contiguous below its own items), so reads and applies stay exact after ancestors are
  released.
  Mutators take `*Self` (commonware threads the database by value); `start_sync` returns no
  handle; there is no `strategy`.

- any: values may own memory, keys may not (a comptime check). A merkleize borrows values from
  the batch, its log reads (kept until the merkleize ends), and its ancestors, then gives the
  journal batch and the new diff their own copies; a diff frees its values with its last
  holder. A staged merkleize's puts and unstaged writes belong to the batch once recorded.
  Batches merkleize with the floor policy passed by pointer. A policy's `Entry` carries a
  value it owns (a copy, as commonware's walk clones it); an ordered evicting walk collects its
  decisions, rewrites each evicted key's predecessor (`ordered.repair_links`), then emits them
  as commonware does. Unordered decisions apply as the
  walk makes them (commonware collects them and emits them after the walk, in the same
  location order, so the operations and root agree). A
  batch keeps sorted diffs of itself and its live ancestors, plus `ancestor_base_locs` for keys
  a dropped ancestor wrote, so a tip applies exactly whether its ancestors were applied,
  pending, or dropped. Merkleizing a child after an unapplied ancestor was dropped is
  `StaleBatch`, as in commonware.
- any staging: resolutions are recorded as commonware does, but a staged merkleize records
  its slots and unstaged writes as ordinary writes (last put or delete per key, unstaged
  last) instead of reusing the resolved locations, so it re-reads the keys' locations. The
  root is the same (commonware asserts staged and explicit roots agree). `resolve_updates`
  returns only the batch, since no staged updates are carried.
- any ordered: emission lives in `any/ordered.zig`; predecessor candidates keep the nearest
  ancestor's update of a key (commonware's `Shadow`), and the floor walk's moves keep each
  update's `next_key`.
- immutable: values may own memory (keys may not). Merkleize keeps each key's last set (the
  superseded values are freed then), moves the values into the batch's diff, and hands the
  journal batch copies; the diff frees its values when its last holder releases it.
- any ordered `range`: Zig has no async streams, so commonware's `stream_range` is a pull
  iterator (`next` returns an owned pair, null at the end; a read error leaves the cursor in
  place).
- immutable: the index rebuild reads the log from the floor one position at a time (no replay
  stream). `get_many` loops over `get` (commonware batches the reads by position).

## Log
- 2026-11-13: shared codecs (value, operation, floor, chain, Error, initialization checks),
  keyless/immutable/any operations with all 21 codec conformance hashes, decoder fuzz.
- 2026-11-13: verify (operation proofs) with its tests under MMR and MMB.
- 2026-11-13: snapshot-rebuild key cache.
- 2026-11-16: snapshot rebuild (serial) with model-checked tests.
- 2026-11-16: floor-walk candidates (`bitmap.fill_from`) and the shared metric set.
- 2026-11-16: keyless `Db` and batches over the interim authenticated journal.
- 2026-11-16: keyless fixed root conformance hashes (MMR and MMB) match commonware.
- 2026-11-16: any (unordered, fixed): Db, chained batches, floor walk, root conformance
  hashes (MMR and MMB) match commonware.
- 2026-11-16: any takes the bitmap chunk size `N` as a parameter (current needs 32).
- 2026-11-16: immutable (fixed): Db, chained batches, root conformance hashes (MMR and MMB)
  match commonware.
- 2026-11-16: keyless, any, and immutable moved onto `journal.authenticated.Journal`; the
  interim `qmdb.authenticated` is gone.
- 2026-11-16: any staging (`stage`, `expand`, `Slot`, `StagedLoc`, `resolve_updates`).
- 2026-11-16: any (ordered, fixed): link maintenance, span and neighbor lookups, root
  conformance hashes (MMR and MMB) match commonware.
- 2026-11-16: keyless variable values; variable root conformance hashes (MMR and MMB) match
  commonware.
- 2026-11-16: immutable and any variable root conformance hashes (MMR and MMB, ordered and
  unordered) match commonware.
- 2026-11-16: immutable owned (variable) values.
- 2026-11-16: any owned (variable) values, unordered and ordered.
- 2026-11-18: `init_from_log` hooks on any, immutable, and keyless for state sync.
- 2026-11-18: any (unordered) evicting floor policies.
- 2026-11-18: any ordered evictions with link repair; all eight floor conformance hashes match.
- 2026-11-18: any ordered range scans (`stream_range`/`keys`).
- 2026-11-18: ordered staging covered by the staged-ancestor scenarios; keyless operations fuzz target.
- 2026-11-18: immutable operations fuzz target (value model, crash reopens, proof checks).
- 2026-11-18: floor oracle (`fuzz_floor.zig`) and the any unordered/ordered operations fuzz targets.
- 2026-11-18: ordered merkleized-batch neighbor lookups (`get_prev_key`/`get_next_key`).
- 2026-11-18: `qmdb_verify_proof` fuzz target.
- 2026-11-18: the store (`qmdb/store`).
- 2026-11-19: `qmdb_store_operations` fuzz target.
- 2026-11-19: any unordered/ordered batch_root fuzz targets.
- 2026-11-19: `qmdb_any_ordered_batching` fuzz target.
- 2026-11-19: `qmdb::generate` benches (any, store, keyless).
- 2026-11-19: `qmdb::init` and `qmdb::apply_batch` benches; split into `qmdb/benches/`.
- 2026-11-19: `qmdb::merkleize` benches (main grid and churned).
- 2026-11-19: immutable bounded-initialization, recovery, prune, get_many, and batch scenarios.
- 2026-11-19: keyless recovery, proof, read, bounded-init, and stale-batch scenarios.
- 2026-11-19: keyless batch-read, stale-chain, and floor scenarios; keyless mod.rs done.
- 2026-11-19: the cold_read, constantinople, and scale CLI harnesses; benches done.
- 2026-11-19: store floor bound, collision reads, shared prefix, and get_many duplicates.
- 2026-11-19: store policy scenarios (batch 2) against `walk_model`.
- 2026-11-19: store batch 3 (bitmap, recovery, start_sync); `read_location` cfg tests.
- 2026-11-19: store variable-length keys and `test_store_variable_length_keys`.
- 2026-11-19: immutable audit; batch A (floor scenarios and batch floor inheritance).
- 2026-11-19: immutable batch B (stale reads and merkleizes); empty `get_many` stale check.
- 2026-11-19: immutable batch C1 (partial-ancestor apply, delayed merkleize, to_batch).
- 2026-11-19: immutable batch C2 (merkleize across prune, chain reads, child proof unchanged).
- 2026-11-19: immutable batch D1 (pruning boundaries, pruned-set retirement, live commit).
