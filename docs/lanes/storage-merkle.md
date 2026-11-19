# Lane: storage-merkle

Owns `src/storage/{merkle,bitmap,index,rmap}` (`bmt` moved to the coding lane), `src/storage/translator.zig`, and
`src/storage/root.zig` (other storage lanes add their `pub const` lines there).

Reference: `~/.cache/zigware/commonware-ref/storage/src`. These modules are mostly pure data
structures over cryptography's hashers; build them against `cryptography`'s `Hasher`
interface (sha256), stubbing with `std.crypto.hash.sha2.Sha256` until it lands. Persisted
variants need `runtime` storage; do them after its interface lands.

## Backlog
- [x] translator.rs (key translators) and rmap (range map).
- [x] merkle/mmr: in-memory MMR (append, root, proofs, range proofs, verification), node
  positions and peaks math identical to commonware, proof codec, and the position codec
  (`merkle.read_position`; qmdb's `operation.read_location` decodes locations). Port its tests
  and vectors.
  (The Proof `CodecConformance` hash still waits on the conformance lane's `arbitrary`
  emulation.)
- [x] merkle/batch: stacked speculative batches (`Mem.new_batch`, `merkleize`,
  `Mem.apply_batch`, `add_many`, leaf updates) with commonware's batch.rs and mem.rs tests.
- [x] merkle/mmb and shared merkle proof types.
- bmt moved to the coding lane (it needs it first).
- [x] bitmap (authenticated bitmap over MMR).
- [x] index (ordered/unordered, partitioned, immutable) over translators. The partitioned
  ranges (`new_range`/`install_range`, crate-private in commonware, for qmdb) are
  `partitioned.{unordered,ordered}.Range`.
- [x] merkle/verification (`ProofStore`, `range_proof`/`historical_range_proof`/`multi_proof`
  over any source) and merkle/storage (the source interface, `get_nodes`).
- [x] merkle/persisted/full core: `storage.merkle.full.Merkle(F, Digest)` over
  `journal.contiguous.fixed.Journal(Digest)` and `storage.metadata` (init, init_at_most,
  Recovery prepare/finish, flush/sync/start_sync, prune/prune_all, get_node(s), proofs,
  historical proofs, append-only batches, destroy) with commonware's empty, basic, get_nodes,
  flush, crash, orphan-leaf recovery, pruning, and recovery-with-pruning tests.
- [x] merkle/persisted/full `init_sync(gpa, storage, SyncConfig{config, range, pinned_nodes})`
  over `journal.authenticated.Stored`, with the init_sync tests: empty, empty-at-start keeps
  journal, exact match, partial overlap, recovered pins reopen and crash, metadata ahead of
  journal, malformed/missing/extra pins, truncation past the range, pruned past the range,
  stale pinned metadata, and pins read before pruning.
- [x] merkle/persisted/full init recovery tests (stale metadata, prune boundary past a reset
  journal, metadata ahead, initialization bounds, recovery prune crash), init_sync over an
  invalid journal size, genesis and lower-range syncs dropping stale pins, stale batch, and
  update_leaf after sync.
- [x] merkle/persisted/full blob-level init_sync tests: ahead skips discarded blobs (clean and
  torn), ahead within the end blob, reset / start below retained / stale below start leave
  blobs unopened (clean and torn), torn tail repair, invalid pins leave the pruned journal
  intact, and the watermark publication. A recording storage wrapper checks which node blobs
  open, standing in for commonware's sync and read counters; a journal `commit` (data durable,
  watermark behind) stands in for commonware's parked `start_sync`.
- [x] merkle/persisted/full interrupted bounded publication (a swept mutation budget reaches
  commonware's parked-sync crash shape; pins the journal probe at the highest missing pin) and
  interrupted clear init_sync tests. Not ported: commonware's start_sync-handle tests (clean
  start_sync failure, destroy observing a failed sync) need delayed sync completion, which
  this synchronous port does not have.
- [x] merkle/persisted/full historical proof tests (basic, with pruning, large, singleton,
  pruned elements, appends while available, after sync, after pruning, edge cases, range
  validation, non-size prune) and interrupted destroy (swept budget, and bounded reopen).
- [x] merkle/persisted/compact: `storage.merkle.compact.Merkle(F, Digest)` (init,
  from_compact_state, prune_to_frontier, append_leaf, root, leaves, snapshot, new_batch,
  to_batch, apply_batch) with compact.rs's tests.
- [x] index/immutable on `utils.handles.Table`, with all of immutable.rs's tests.
- [x] Fuzz targets (storage/fuzz entries for these modules): rmap, bitmap, index (unordered,
  ordered, immutable), merkle_family_operations, merkle_range_proof, merkle_proof_store,
  merkle_batch_operations, merkle_full_operations, merkle_full_recovery, and the Merkle half of
  proofs_malleability (its BMT half goes with bmt, now in the coding lane).
- [x] journal/zstd (handed over from storage-journal): a real compressor for
  `src/storage/journal/zstd.zig` (LZ match finding, FSE-coded sequences, Huffman literals) whose
  frames `std.compress.zstd` reads, with a std-decoder roundtrip fuzz and a ratio/throughput
  bench against the raw-block path. Byte identity with libzstd is not required.
- [x] Storage fuzz targets `journal_fixed_operations` and `queue_operations` (handed over from
  storage-journal).
- [x] Partitioned index `new_range`/`install_range` (clearing lane):
  `partitioned.{unordered,ordered}.new_range(T, V, P, &full, offset, count)` returns a
  `Range` with `get_mut`, `get_mut_or_insert`, `for_each_value`, and `install(&full)`.
  Commonware's ranges update the full index's metrics live; a zigware range keeps its own
  counters and `install` adds them (the full index is not shared across threads).
- [x] Parallel merkleize strategy over the `parallel` package: `merkleize_with` and
  `add_many_with` take any strategy (commonware stores it on the batch; zigware passes it per
  call, so batches stay plain values), and the benches' workers=8 and BatchedParallel cases run
  on an 8-thread `Rayon` pool. Tests: `level_batches_keep_pairs` under `mocks.explore`,
  `batch_parallel_update_leaf`, `test_mem_mmr_batched_root_parallel`, `add_many_mixed_operations`
  on 1/2/3/8 workers, and `add_many_at_limit` split three ways. Bench: add_many of 65536 items
  11.6 ms on one worker, 3.4 ms on eight.
- [x] Contiguous journal duration histograms (append, append_many, append_prepared, read on a
  cache miss, read_many, commit, sync) from commonware's `metrics.rs`, timed on the clock of the
  config's `io: ?std.Io = null` (commonware's context clock); without an io they register but
  never observe. The variable journal passes its io to its offsets journal. Ports
  `read_miss_timed` for both journals.

## Design: asynchronous start_sync (2026-11-19, approved; steps 1-3 in this lane)

Commonware's `Blob::start_sync` returns once the runtime has fixed which completed writes the
sync covers and taken responsibility for it; the returned `Handle<()>` only observes. Dropping
it cancels nothing, and a failure is retained and resurfaces on the owner's next durability or
mutating call. There is no background task anywhere above the runtime: every layer flushes
inline, starts blob syncs, and keeps the in-flight completion in a bounded slot
(`SyncState::Pending`, `tail_predecessor_sync`, `Barrier.pending`, metadata `pending`,
oversized `marker_sync_pending`, archive `requested`, compact `pending_sync`). Commonware's
memory backend (the deterministic runtime's) completes the sync inline (`Handle::ready`); only
the `DelayedSyncContext` test mock (`runtime/src/mocks.rs:869-1190`) holds syncs in flight.

### API
- `runtime.storage.Completion`: a reference-counted completion (commonware's shared
  `Handle<()>`). `poll() ?Error!void` (null while in flight), `wait() Error!void`, `retain()`,
  `release()`. `Completion.ready(result)` costs no allocation; `Completion.join(a, b)`
  completes when both do, reporting the first error (commonware's `try_join`). A pending
  completion carries the `Io` of whoever created it and waits on an `Io.Event`, so journals
  and databases stay free of `Io`; a ready one never waits.
- `Blob.VTable.start_sync: fn (ptr) Error!Completion`. Every backend fixes its coverage at
  the call: memory snapshots inline and returns `ready` (as commonware); faulty rolls its fault
  at start and journals a durability cut that a crash honors only if the completion succeeded;
  audited and metered record at start and forward. Production returns `ready` after an inline
  fsync at first (allowed by the contract); a detached fsync (`Io.concurrent`, or the ring) is
  a later runtime-lane optimization that changes no caller.
- Every `start_sync` above the blob returns `Error!Completion` instead of `Error!void`
  (buffer writers, paged `Writer.start_sync`/`seal`, blobs, fixed/variable/segmented/oversized
  journals, checkpoint, metadata, authenticated journal, merkle full, archive, qmdb, glue).

### Ownership
- A returned completion is one reference owned by the caller; `release` without `wait` is
  commonware's drop: the sync continues and its failure stays retained by the owner.
- Each owner keeps its own reference in its slot (`SyncState.pending`, the blobs' predecessor
  slot, `Barrier`, metadata, archive, compact), so at most one or two completions per owner
  exist: allocation is bounded and happens only for pending syncs.
- Every blob mutation (flush, write, resize, rollover, prune, truncate, clear, destroy) first
  waits for the owner's pending completion; buffer-only appends and reads do not. A failed
  wait marks the owner failed (the existing `failed` flags), as commonware drops the owner.
- `durable_page_state` advances only after a pending sync is observed, as commonware's paged
  writer does, so a tip page is never rewritten under an in-flight sync.
- The journals' `durability.Barrier(Completion)` already ports commonware's barrier; the
  stand-in `Done` completion is replaced by `runtime.storage.Completion`, so the watermark
  trails by one `start_sync` call exactly as commonware's does.

### std.Io and the deterministic runtime
- With stock backends nothing changes in timing: memory completes inline, so every existing
  test and DST keeps its behavior.
- `runtime.storage.mocks.DelayedSync` ports `DelayedSyncContext`/`PendingSyncs`: it parks each
  started sync (counters `starts`, `entered`, `completions`; `next`, `release_next`,
  `release_all`, `fail_all`, `arm_fail`, `unblock`, and the `arm` gate on blocking syncs). A
  release runs the inner blob's `sync` then, so durability is taken at completion, as in the
  mock. The existing `SyncGates`/`SyncGated` mock (the voter tests' sync gate) stays as is.
- Commonware tests assert an operation is blocked with `now_or_never().is_none()`. Here the
  test runs the operation as an `Io.concurrent` task on the deterministic runtime, waits until
  the mock reports the wait entered, asserts the task has not finished, releases, and joins.
  Results returned from concurrent tasks stay free of `Io.Timestamp` (AGENTS.md pitfall).

### Rollout (each step keeps main green; callers that do not overlap call `wait()`)
1. runtime: `Completion`, `Blob.start_sync` on every backend, `DelayedSync` mock; buffer
   `SyncState.pending` and paged `Writer.start_sync`/`seal` handles.
2. journals: contiguous blobs (predecessor slot), fixed, variable, checkpoint, metadata,
   segmented manager and journals, oversized tracked sync.
3. authenticated journal and merkle full (joined handles).
4. archive prunable (`requested` sections, marker publication).
5. qmdb (any, current, keyless, immutable, store, compact `pending_sync`).
6. glue `Barrier` and marshal (replace `store.Durable`'s paced stand-in).

### Progress
- Step 1 (9e1f838, 83d1393): runtime `Completion`, `Blob.start_sync`, `DelayedSync`; buffer
  and paged writers. `Completion.join` holds 8 in-flight leaves and waits for the oldest when
  more are folded, so a fold never overflows (a fold over more than 8 parked syncs blocks
  until the oldest completes; the manager test of 30 and 64 sections runs at 1, 2, and 8).
- Step 2a (eaa11a3): contiguous blobs `tail_predecessor_sync`; fixed/variable `start_sync`
  return a completion recorded in `Barrier(durability.Sync)`; the 12 shared-suite tests.
- Step 2b: segmented manager `start_sync` (joined, reused when in flight), and every section
  removal (prune, remove, truncate, clear, destroy) settles started syncs first, an already
  failed one surfacing at once; segmented fixed/variable/glob and untracked oversized return
  completions; the manager's 7 in-flight tests; segmented fixed's 5 and variable's 1 wait
  tests (`fixed_start_sync_test.zig`, `variable_start_sync_test.zig`). Oversized's tracked
  pipeline is clearing's (data half in d83f96f; `marker_sync_pending` is their backlog 4b).
- Step 2c: metadata `start_sync` writes the next version and starts its blob sync, keeping it
  as `pending` (at most one in flight); `sync`, `start_sync`, and `destroy` observe it first.
  The checkpoint's `start_watermark_sync` returns that completion, and fixed/variable
  `start_sync` join it (data, then the watermark, as commonware). Ports
  `test_start_sync_merkle_failure_fails_handle`. A faulty backend's sync fault now reaches
  the caller through the completion and the next durability operation, as in commonware.
- Step 3: merkle full `start_sync` returns its journal's completion (covering the nodes
  flushed so far) and gains `wait_for_sync`, which `destroy` runs first; the authenticated
  journal's `start_sync` joins the items' and Merkle syncs, and its `destroy` surfaces a failed
  Merkle sync before removing anything. qmdb callers wait on it until step 5. Ports
  `test_start_sync_overlaps_work`, `test_start_sync_failure_propagates`,
  `test_reopen_persists_merkle_watermark`, and merkle full's
  `test_full_sync_observes_clean_start_sync_failure` (`full_start_sync_test.zig`; `start_sync`
  marks the journal dirty so a later `sync` observes an unobserved failed completion).

### Tests this unlocks (commonware file: tests)
- runtime (~40): storage/{audited,faulty,metered,tokio/mod,tokio/blob,iouring}.rs, the 10
  named at runtime.md:608-618 plus faulty's two overlapping-write epoch tests (619-621);
  mocks.rs `delayed_sync_blob_forwards_read_options`; utils/buffer/mod.rs 8
  (runtime.md:377-384); paged/writer.rs 18 (runtime.md:457-473); paged/sealed.rs
  `test_sealed_reads_while_seal_sync_pending`. The io_uring driver/operation/request tests stay
  not portable (zigware's ring is synchronous by design).
- storage-journal (~35): segmented/manager.rs 7 (`test_concurrent_sync_reports_later_error`,
  combined/reused handles, truncate/prune/destroy wait and surface); segmented/fixed.rs 5
  (prune/destroy/clear wait, prune surfaces failure, replay dropped during repair);
  segmented/variable.rs `test_journal_replay_dropped_during_repair_fails_replay`;
  oversized.rs `..._alignment_sync_concurrency`, `..._dropped_handle_driven_by_next_sync`;
  contiguous/tests.rs 12 (overlaps_predecessor_and_tail, overlaps_work, waits_for_prior,
  failure_propagates, prune_waits_for_pending_sync, prune_surfaces_failed_sync, both
  journals; unrecorded today); journal/authenticated.rs 7 (overlaps_work, failure_propagates,
  merkle_failure_fails_handle, two issue_5668 destroy tests, reopen watermark, init ordering);
  metadata/mod.rs `test_start_sync_second_sync_waits_for_first` and the handle counts. Done in
  ef5785ca (storage-journal): metadata's second-sync-waits, oversized's alignment truncation
  and dropped completion, and authenticated's two issue_5668 destroys and init ordering.
- storage-merkle (22, all ported 2026-11-19, see "Start-sync handle tests"): contiguous/fixed.rs
  8 (keeps_predecessor_sync, watermark_lagged,
  failure_blocks_watermark, truncate_drains_parked_watermark_advance, deferred_failure, two
  dropped_failed_start_sync, destroy_observes_failed_watermark_sync); contiguous/variable.rs 11
  (keeps_predecessor_sync, stages_offsets_while_data_waits, offsets_watermark_lagged,
  watermark_requires_joint_proof, truncate_truncates_durable_size, deferred_failure, two
  dropped-failure tests, three destroy_observes_failed_*_sync); persisted/full.rs 3
  (`test_full_sync_observes_clean_start_sync_failure`, issue_5668 destroy mmr/mmb).
- storage-archive (15): archive/prunable/mod.rs, the 12 pipelined put/start_sync tests and the
  3 marker tests (storage-archive.md:131-133), plus the fuzz target's abandoned start_syncs.
- storage-qmdb (~23): immutable/fixed.rs 3 (start_sync_overlaps_work,
  apply_indexes_while_journal_waits, start_sync_prune_waits); store/db.rs 2 (overlaps_work,
  prune_waits); keyless/fixed.rs 5 and any/unordered/fixed.rs 3 (unrecorded today); compact
  db.rs 10 `test_compact_start_sync_*`/`apply_overlaps_start_sync`; and the reduced
  `*_failure_propagates` ports become full ports.
- glue: stateful/db/mod.rs `barrier_waits_for_every_handle`,
  `barrier_cancellation_releases_handles`, `barrier_reports_shutdown_as_not_durable`, and the
  shutdown half of `barrier_panics_on_later_failure`.

## Test tally (2026-11-19, merkle and journal internals)
Commonware's tests in `storage/src/merkle` and the contiguous journals, matched by what they
check. Status after the 24 open ports landed (two `read_location` tests went to storage-qmdb).

| file | tests | ported | open | not portable |
|---|---|---|---|---|
| merkle batch, mem, proof, verification, hasher, storage, position | 219 | 211 | 0 | 8 |
| mmr (mod, mem, full, iterator, proof), mmb, persisted/compact | 87 | 71 | 2 (qmdb) | 14 |
| persisted/full.rs | 121 | 118 | 0 | 3 |
| journal/contiguous/fixed.rs | 136 | 129 | 0 | 7 |
| journal/contiguous/variable.rs | 152 | 136 | 0 | 16 |

The `should_panic` tests are death tests (`utils.death`) in merkle/death_test.zig (mmr
`to_nearest_size` past `MAX_NODES`, mmb `children` of a leaf) and journal/contiguous/death_test.zig
(unsorted and duplicate `read_many` on both journals, a reversed `init_sync` range); removing
each panic fails all 7. The batch `add_many_past_limit` pair stays a deviation: zigware returns
`LocationOverflow` and batch_test.zig checks it.
Not portable: positions are plain `u64` (Display, operator, checked/saturating sub tests),
the batch overflow pair above, `View` sharing,
snapshot readers, decode counts, batched `read_many` internals, Rust type checks, and the
`ExactSizeIterator` length test (Zig takes slices). The parallel-strategy and duration-histogram
tests are ported.

Deviations in the ports:
- Replay read options: commonware replays a tip holding an unwritten full page through the page
  cache, which faults pages with `dont_cache`; zigware replays the tip's flushed pages from the
  blob with the caller's options and its buffered bytes from memory, and the tests assert that.
- A bad page in a read-ahead fill: commonware splits the replay buffer into four read-ahead
  batches; zigware fills the whole buffer at once, so the test corrupts a page of the third
  fill and expects the two fills before it.
- Bounded open below a torn watermark page: there is no `Recovery::unbounded()`, so the test
  drops the capped recovery and reopens without a cap.
- Prepared compressed appends: no spare-capacity bound (prepared buffers are exact-size).

## Test tally (2026-11-19, clearing lane)
Commonware's `#[test]` functions matched to zigware tests by what they check.

| module | tests | ported | partial | open | not portable |
|---|---|---|---|---|---|
| index | 172 | 169 | 0 | 0 | 3 |
| rmap | 39 | 39 | 0 | 0 | 0 |
| bitmap | 15 | 15 | 0 | 0 | 0 |
| translator | 18 | 18 | 0 | 0 | 0 |

The 34 `should_panic` tests are death tests (`utils.death`, by storage-merkle): index's 30 in
index/death_test.zig and the bitmap's 4 in bitmap/death_test.zig, each failing with its panic
removed. Not portable: two worker-metrics tests (a worker publishes metrics to the full index in
registry batches), and the metrics-registry range test (the indices keep plain counters, not
registry metrics). The 3 `cursor_across_threads` tests are ported as `index cursor across threads`
(an index behind a `std.Io.Mutex`, updated through a cursor on a spawned thread). Re-audited
2026-11-19 against start_sync, DelayedSync, the faulty wrap, and parallel conformance: none of the
other not-portable entries depends on them. Not-portable review (2026-11-19, coding lane): rmap's
one (`test_missing_items_zero_n`) became the plain `test_missing_items_zero_limit` upstream
(e7987e8c3), which is ported. By category: design difference 3 (the 2 worker-metrics batch tests and
the registry range test). 3 in all; the 35 panic tests (index 30, bitmap 4, translator 1) are ported
with `utils.death`. The per-partition arrays (2026-11-19, clearing lane) ported the 7 spill tests,
`partitioned_ordered_spilling` (the whole battery at threshold 2), the spilling case of
`soa_get_many_matches_get`, and the 7 `partition.rs` tests (4 on `Partition` directly; navigation,
`set`, and `drain_runs` through the index's navigation, cursor-update, and spill-transition tests).

Open (index):
- [x] `range_for_each_value_visits_all_values_once` and `install_range_nonzero_offset` for
  both partitioned indices, and `worker_prunes_count_live` (prunes counted at install).
- [x] Partitioned ordered: `get_mut_or_insert` (spilled too), `get_many` matches `get`.

Partial:
- [x] index: `cursor_insert_with_next` on the last value (3 indices), deleting the middle of
  three then `next()` twice null (2), partitioned ordered insertion order through the cursor,
  `retain`, and `get_many`.
- [x] translator: `identity_hasher_integer_writes_differ` (0 against 1 at u16/u32/u64),
  `hashed_all_cap_sizes` (EightCap).

## Upstream drift 43b357a41..a9ffc25f3 (2026-11-19, storage outside qmdb and clearing)
Commonware changed 79 storage files in 14 commits; most are qmdb (storage-qmdb's, now glue's
for the async steps). Outside qmdb:
- e7987e8c3 rmap: `missing_items` with a zero limit returns nothing instead of asserting.
  Ported (`rmap missing items zero limit`, commonware `test_missing_items_zero_limit`).
- 33861fb2a queue docs: recovered uncommitted appends are delivered on reopen, and acked
  items can be redelivered unless pruned. zigware's queue already behaves so (`published`
  starts at the recovered size); its docs now say so.
- 5573c2929 variable journal: refactors the batched reader's cached frame extents
  (`cached_frame_extents`, `cached_frame_header`) and strengthens the tampered-offsets test.
  On the coordinator's call, the variable journal's `read_many` now ports commonware's
  batched path (see below) and its tests.

### Variable journal batched read_many (2026-11-19)
`read_many` and `try_read_many_sync` run commonware's two passes: a cached pass interleaves
positions and same-blob successors into one offsets probe, resolves ordered disjoint frame
extents (`cached_frame_extents`, from cached successor offsets or cached length prefixes),
and serves each blob's cached frames with one cache-only ranged read; completion fetches the
missing offsets in one offsets `read_many` and each blob's frames with one ranged read.
Offsets that run backwards, overlap another frame, or point past their blob fail with
`Corruption` (the cached pass serves nothing from such a batch); a frame whose prefix
disagrees with its span fails with `OffsetDataMismatch`. Signatures and counters are
unchanged. Ported tests (`variable_read_many_test.zig`):
`..._rejects_inconsistent_offsets`, `..._rejects_overlapping_prefix_frame`,
`..._cached_frame_with_cold_successor`, `..._last_frame_uses_blob_size` (reopen half). Not
ported: tests counting recorded blob reads or per-batch metrics, `..._buffer_len`.
The first cut (de86473) slowed cold reads, because `paged.View.read_ranges_into` read each
missed range page by page. Now (runtime's go-ahead) it probes the cache for every range, then
coalesces missed ranges whose pages touch into runs and reads each run with one blob read of
at most 8 physical pages (a 32 KiB buffer, the allocator's largest size class), validating,
compacting (`@memmove`), and caching them. Completion merges byte-adjacent frames into one span
(commonware's `spans`). Items decode straight into the caller's slice (a bitset tracks filled
slots), and staging uses a reused per-journal scratch (commonware's per-thread scratch),
borrowed atomically, with a local buffer for a concurrent reader. Deviation: that scratch is
filled at most 256 KiB at a time (a larger frame alone), so staged bytes stay in cache until
decoded; commonware stages a whole blob's frames at once.
Bench (`bench-storage --bench -- mode=read_many`, ReleaseFast, best low bound of alternating
rounds against 64374a2, ms, loaded shared desktop): variable_read_random 100 0.013 -> 0.013,
1k 0.138 -> 0.124, 10k 21.4 -> 20.6, 100k 79.3 -> 76.5; compressed read_many / uncached,
sequential then random: 64 B 4.66 -> 4.39 / 3.03 -> 3.15 and 2.82 -> 2.57 / 1.94 -> 2.02;
1 KiB 21.7 -> 21.0 / 13.7 -> 13.7 and 4.06 -> 3.40 / 5.23 -> 4.79; 16 KiB 30.2 -> 29.2 /
18.9 -> 18.4 and 3.28 -> 2.79 / 4.65 -> 3.67. Every row is within noise or faster.
### Start-sync handle tests (2026-11-19)
The 21 tests the start_sync skip audit found still marked not portable now run on the
Completion API with `runtime.storage.mocks.DelayedSync` (`PendingSyncs`) or
`runtime.storage.faulty`'s sync failure rate (`storage_fault_config().sync_rate`).
`drive_call` runs an operation as a task and releases parked syncs until it returns
(`drive_pending_syncs`); commonware's `test_truncate` is a driven `sync` and an `init_at_most`
reopen.
- `fixed_start_sync_test.zig` (fixed.rs 8): keeps_predecessor_sync, watermark lagged, failure
  blocks the watermark, truncate drains a parked advance, deferred advance failure, destroy
  observes a failed watermark sync, and both dropped-failed-start_sync tests (the rstest runs
  all six tail/predecessor x rollover/clear/destroy cases). Planted bugs: advancing the
  watermark to the tip instead of the proven barrier fails five; `seal_tail` creating the
  successor without observing outstanding syncs fails the dropped-failure test.
- `variable_start_sync_test.zig` (variable.rs 11): keeps_predecessor_sync, stages offsets
  while the data waits (both release orders), offsets watermark lagged, watermark requires a
  joint proof, truncate truncates the durable size, deferred advance failure, both dropped
  failure tests, and the three destroy_observes_failed_* tests. Planted bugs: starting the data
  first always fails the staging test; dropping destroy's data wait fails the data-sync destroy
  test; publishing the tip's watermark fails the joint-proof test.
- `full_start_sync_test.zig`: issue_5668 destroy for mmr and mmb (a pruned tree's dropped,
  failed sync surfaces at destroy and the synced tree reopens with its root). Planted bug:
  skipping `wait_for_sync` in `destroy` fails both.
The ports found four differences from commonware, now fixed:
- `blobs.Writable.destroy` returned early on a failed sync without freeing the blobs, so a
  failed fixed or variable destroy leaked them.
- Fixed `destroy_cleared` staged the clear before observing the blobs' syncs; it now waits
  first (commonware `wait_for_sync` before `stage_clear`), so a failed sync leaves a journal
  that reopens recovered, not cleared.
- Variable `destroy` likewise waits for the data blobs before the offsets stage their clear.
- Variable `start_sync` starts the data and offsets syncs at once in commonware (`try_join`);
  zigware starts the offsets first when the data tail's earlier sync is still in flight
  (`Writable.tail_sync_in_flight`), so the offsets are staged while the data waits.

- 082daecd6 merkle (batch, mem, mmr/mem, verification, benches): test and bench harnesses
  drop async wrappers; only indentation and line wrapping change. Nothing to port.
- 162216038 bmt, merkle proof, merkle full, queue, ordinal fuzz: lint-only test edits
  (`.clone()` removed, `NonZero::get` dropped). Nothing to port.
- conformance.toml: every changed hash is a qmdb entry (a9ffc25f3 op tags, 8bf364011 sync
  targets); none of this lane's or clearing's hashes moved.
- Clearing's crates (archive, freezer, ordinal, cache, index): no source change.

## Log
- translator: Rust's `Translator`/`BuildHasher` traits become a comptime interface
  (`Key`, `ordered`, `transform`, `hash`, `order`, `eql`; `translator.check`). `Hashed`
  uses `std.hash.Wyhash` instead of `ahash`; commonware documents its output as unstable
  and never persisted, so they need not match. Seeds come from a caller's `std.Random`
  (`init_random`) or `from_seed`, never from the OS.
- rmap: a two-level B-tree (sorted chunks of at most 256 ranges, binary-searched by each
  chunk's first start) instead of a `BTreeMap`; same semantics and tests. It replaced one
  sorted array (2026-11-19), which was quadratic under random inserts: 8 GB of moves for
  `rmap::insert/items=100000` (3.7× commonware) and about 800 GB at 1,000,000. `items` and
  `iter_from` still return slices, of a flat copy rebuilt on the first read after a change
  into room the change reserved, so reads never allocate; a map must not be read from two
  threads at once. `missing_items` writes into a caller buffer whose length is `max`.
  Seeded + `std.testing.fuzz` target mirrors `rmap_operations` against a reference set.
- merkle/bmt build on `cryptography`'s real hashers (`Sha256`, `assert_hasher`).
- merkle: positions and locations are plain `u64` (named `position`/`location`, or
  `size`/`leaves` for counts) instead of `Position<F>`/`Location<F>` newtypes; the checked
  conversions are `merkle.position_from_location`/`location_from_position`. A family is a
  comptime type (`merkle.check_family`); a Merkle hasher is a comptime interface
  (`merkle.hasher.check`) with `root`/`root_with_folded_peaks` as free functions over it.
- merkle/mem: `Mem.add` appends one leaf directly (the same as a one-leaf batch); the batch
  API (`new_batch`/`merkleize`/`apply_batch`) comes next on top of it. MMR root
  conformance hash (`MmrRootStability`, 200 cases) matches commonware.
- merkle/proof: commonware's recursive subtree walks (sibling collection, range and multi
  reconstruction, pin reconstruction) are iterative over fixed-capacity stacks
  (`merkle.BoundedList`), sized from the 64-peak / 63-level bound. Proof nodes are read through
  any `source` with `get_node(position) ?Digest` (commonware's `get_node` closure). Elements
  are any slice of byte slices, byte arrays, or digests. `verify_multi_inclusion` takes
  locations and elements as two parallel slices. Mutation checks: reversing sibling DFS order
  fails 11 tests; dropping the multi-proof witness cross-check fails the binding test.
- merkle/mmb: `merkle.mmb.Family` (domain 1) with the same comptime interface as MMR plus
  the graftable functions (`leftmost_leaf`, `subtree_root_position`, `chunk_peaks`, which
  returns a `ChunkPeakIterator` since an MMB chunk can span several peaks). Every generic
  proof and Mem test runs under both families. MMB root conformance hash
  (`MmbRootStability`, 200 cases) matches commonware; a domain-tag mutation fails it.
  `Mem.init(gpa, nodes, boundary, pinned)` ports `Mem::init(Config)`.
- merkle/mem: `update_leaf`/`update_leaf_digest` port the batch leaf update (one leaf at a
  time, ancestors recomputed in place); the mem.rs update tests run under both families.
- bitmap: `storage.bitmap.BitMap(Storage, Digest, N)` (`storage.AuthenticatedBitMap`). The
  Merkleized/Unmerkleized typestate is one type with an asserted `merkleized` flag
  (`into_dirty`, mutate, `merkleize`). Pruning state persists through `storage.metadata` with
  commonware's keys (`PrefixedU64` prefix 0 = pinned nodes, prefix 1 = pruned chunk count).
  The `bitmap_operations` fuzz uses 1-byte chunks and weighted appends, and checks every root
  against a from-scratch rebuild; skipping dirty-chunk rehashing fails it at iteration 3.
  Commonware's `should_panic` tests (bad pushes, pruned/out-of-bounds reads) are panics in
  `utils.bitmap.Prunable` and are not ported as tests.
- index: commonware's `Unordered`/`Ordered`/`Cursor` traits become one type,
  `index.storage.Index(T, V, Heads)`; `unordered.Index` keeps heads in a `std.HashMapUnmanaged`
  (translator hash), `ordered.Index` in a `std.Treap` over a memory pool (commonware's
  `BTreeMap`). Values iterate newest first, exactly as commonware's head + reversed overflow
  chain. The cursor edits the chain in place in the overflow map (never storing an empty chain)
  instead of taking it out and putting it back on drop, so `Cursor.finish` only removes an
  emptied key. Closures are a context value plus a comptime fn. The fuzz drives both indices and
  a reference model with every commonware fuzz operation and checks values and counters after
  each step; inserting after the head at the wrong chain end fails it and 3 ported tests.
- index/partitioned: `partition_index_and_sub_key` and its tests match commonware. A
  partitioned index is a flat index over the composite key `(partition, sub-key)`
  (`partitioned.Translator(T, P)`): the unordered one is `unordered.Index` over it, and the
  ordered one keeps commonware's partitioned semantics (values in insertion order, offset
  cursor) and, since 2026-11-19, its structure: each partition is parallel sorted `keys`/`vals`
  arrays (a run is adjacent equal keys, found by binary search) that spill to an ordered tree
  in a side table at `spill_threshold` (512) entries and revert when the tree drains;
  `IndexSpillAt` sets the threshold for tests. Reversal (clearing lane): the earlier design
  kept every run in one treap over `(partition, sub-key)` for the same results without a
  threshold, but `index::grinding` lookup ran 5.9× slower than commonware's arrays (847 µs
  against 144 µs); with the arrays it is 0.85× (BENCHMARKS.md). Every generic index test runs
  against all five indices, one of them spilling at 2 entries. `absorb` (range install) moves
  the range's partitions slot by slot and adopts its spilled trees and pools, so no run is
  copied, like commonware's `install_range` moving partition maps.
- index/immutable: same ring of translated keys by position and exact prefix retirement.
  Positions live in `utils.handles.Table(u64)` as in commonware: `get` returns an iterator that
  confirms each candidate against its ring slot, and growth rehashes through the ring. Seeded and
  `std.testing.fuzz` targets check it against a model of live (position, key) pairs.
- merkle/persisted/full init_sync: commonware's seeded storage-fault runs (`recovered_pins_crash`)
  become a deterministic sweep: fail every mutation after the first `n`, crash, and reopen,
  for each `n` until the sync completes.
- merkle_full_operations / merkle_full_recovery fuzz: leaf data is capped at 16 bytes and
  proof ranges are drawn within the current leaves, so short inputs reach verification (the
  u8 ranges of commonware's target almost never do). The recovery target replaces sampled
  sync/write/remove fault rates with a mutation budget (every mutation after the first `n`
  fails) plus a removal budget armed around prunes, and one faulted recovery attempt; syncs
  complete synchronously, so `start_sync` is a barrier. Both check the final root against a
  rebuilt reference.
- merkle/persisted/compact: commonware's `Arc<Mem>` with copy-on-write mutators becomes an
  owned `Mem`; `snapshot` returns an owned clone, so it still never observes later mutations.
  Merkleizing is sequential, so there is no strategy parameter.
- merkle/storage + verification: commonware's async `Storage` trait is a comptime interface:
  `size()` and `get_node(position)` returning `?Digest` or `!?Digest`, with an optional
  batched `get_nodes`; `merkle.storage.get_nodes` falls back to one read per position. Proof
  builders take the family first (`verification.range_proof(F, gpa, hasher, source, ..)`).
  `ProofStore` keeps the verified digests in a hash map plus the fold-prefix and backward
  suffix accumulators; `multi_proof` takes supplied peaks as `NodeDigest`s (last one wins, as
  commonware's map collect does). The `merkle_proof_store` fuzz also proves random ranges of
  real trees (commonware's raw-bytes proofs almost never verify) and requires every sub-range to
  re-prove; swapping the suffix fold order fails it at iteration 15. The family-operations fuzz
  also rebuilds the root from the reference leaves.
- merkle/batch: commonware's `Arc`/`Weak` batch chain is hand-counted: `Merkleized.retain`/
  `release` are the strong references (`release` is `drop`), a child's parent link is weak, and
  each batch's changes (`batch.Data`) are reference counted so merkleized descendants can replay
  released-but-unapplied ancestors. Builders mutate in place (`batch.add(gpa, hasher, bytes)`)
  instead of consuming and returning the batch; `merkleize` consumes it on success. `add_many`
  takes a comptime item type and hashes each item's codec encoding. Merkleize and `add_many`
  hash sequentially (commonware's strategy split gives the same digests), so the
  parallel-shape tests (`level_batches_keep_pairs`, worker counts) have no counterpart. The
  `hash_plan` exactness tests live in batch.zig (they call the private plan). The
  `merkle_batch_operations` fuzz catches a skipped add_many update record at iteration 0.
- merkle/persisted/full: mutators take `*Self` instead of consuming the structure; after an
  error only `deinit` may follow. Syncs are synchronous, so `start_sync` returns no handle.
  `Mem` gained `add_pinned_nodes` (room for two boundaries' pins), `nodes_from`, and `clone`.
  Metadata keys match commonware (`PrefixedU64` prefix 0 = pins by position, prefix 1 key 0 =
  pruning boundary as a big-endian leaf location). Mutation checks: dropping the pruning-boundary
  pins after a flush, skipping orphan-leaf replay, and skipping the journal prune on reopen each
  fail a ported test.
- journal/zstd: `compress_into` now writes compressed blocks (`zstd/match.zig`: hash chain four
  deep, repeat offsets, lazy step below 32 bytes; `zstd/block.zig`: predefined, RLE, or fresh
  FSE tables per code by estimated bits; `zstd/huffman.zig`: package-merge codes of at most 11
  bits, direct or FSE weights, one or four streams), falling back to raw or RLE when that is
  smaller. `encode_into(.., .store)` keeps the old raw-block path for the bench. On
  `zstd.corpus` text and records it writes 29.2% and 12.8% where `zstd -1` writes 30.0% and 13.0%
  (`zstd -3`: 28.1%), at about 80 and 190 MB/s on the loaded desktop (libzstd -1: 320 and 900).
  Deeper chains bought under 1% ratio for twice the time. The frames are checked against
  `std.compress.zstd` (round-trip fuzz) and were checked once against libzstd 1.5's `zstd -d`
  on 60 inputs up to 400 KB. Planted bugs (a wrong repeat-offset code, swapped initial FSE
  states) fail the seeded fuzz at iterations 3 and 0.
- journal_fixed_operations / queue_operations fuzz
  (`journal/contiguous/fixed_operations_fuzz_test.zig`, `queue/operations_fuzz_test.zig`): drawn with `codec.fuzz.Draws`, seeded in `zig build test`
  and coverage-guided under `--fuzz` (`codec.fuzz.run` does both). The journal target also keeps
  the digest last appended at each position and checks every read, batch read, synchronous read,
  and replayed batch against it (commonware checks only sizes and read agreement); positions are
  drawn inside the bounds half the time, and `ReopenMatching` draws values that were appended.
  Writing an `append_many` batch reversed fails it at iteration 1; skipping the queue's cursor
  reset fails the queue target at iteration 0. The queue target draws at most 128 operations.
- journal/zstd speed: `zstd/match.zig` is now libzstd's double-fast strategy (repeat offsets, one
  candidate each from 8-byte and 5-byte hash tables, a 4-byte prefix check, a lazy step below 6
  bytes, positions inside matches indexed), replacing the four-deep hash chain; `zstd/bits.zig`
  flushes its 64-bit container only when full (eight bytes at a time), which halved sequence
  encoding. On 4 MB of `zstd.corpus` text plus records, CPU time fell from about 0.23 s to
  0.12-0.14 s (1.7-1.9x) while ratios improved: text 28.2% (was 29.2%), records 12.4% (12.8%);
  the 1 KB text case is 50.4% (libzstd -1: 50.5%). libzstd 1.5's `zstd -d` still decodes all 60
  sample frames byte-exactly.
- journal/zstd speed, second step: `search` hashes each position once for both its lookup and
  its insert, and the lazy step probes only the long table one byte later, as libzstd does.
  Median user CPU over 12 runs on the same 4 MB corpus: 0.113 s against 0.232 s for the
  1c5ddb7 compressor (2.05x); ratios unchanged (text 27.9%, records 12.4%; 1 KB text 50.4%).
- Handed over from storage-journal (agreed with it): the rest of commonware's
  `journal/contiguous/fixed.rs` and `variable.rs` tests, in new sibling files
  (`contiguous/fixed_bounded_test.zig`, ...), so its test files stay untouched.
  - [x] fixed.rs batch 1: overlong blob, zero-extended pages, `init_at_most` (with commit,
    lowered watermark, truncate-append-reopen), and the init-at-most and repair truncation
    crashes on `runtime.storage.faulty`. Planted bug (skip the tail truncate in `repair_to`)
    fails four of them.
  - [x] fixed.rs batch 2 (`fixed_torn_test.zig`): rollovers without commit, partial item
    tails, torn interior, rewrite, and boundary pages, tears below the watermark (adopted),
    gaps between blobs, and the prune crash. commonware's `test_sync_blob` is emulated by
    rollover plus `commit`. Planted bug (skip forward page validation) fails six tests.
  - [x] fixed.rs batch 3 (`fixed_size_test.zig`): single-item blobs, `init_at_size` (zero,
    mid-blob, boundaries, large, near `u64::MAX`), `clear_to_size`, mid-blob hints, prune
    durability, interrupted clears, watermark past an empty tail, `read_many`. The two
    should-panic `read_many` tests are assertions here and are not ported. Planted bug
    (ignore a staged clear intent) fails seven tests.
  - [x] fixed.rs batch 4 (`fixed_bounded_recovery_test.zig`): hole after full capacity,
    bounded recovery read counts (zigware's `Recovery.open` opens the checkpoint itself, so
    the test subtracts its two metadata reads; the remaining counts match commonware's),
    huge capacities, append fallbacks, cached reads at the 128-byte stack boundary, empty
    prefixes, rebuilt gaps and tails, `init_at_most` restart sweeps, and retries after sync,
    remove, and resize faults on `runtime.storage.faulty`. Planted bug (unbounded scan on a
    bounded open) fails the read-count test.
  - [x] fixed.rs batch 5 (`fixed_sync_faults_test.zig`): failed flush in `start_sync`,
    failed watermark advance, failed watermark lowering on a bounded reopen, truncation below
    the durable size. Planted bug (lower the watermark after truncating blobs) fails two.
    Skipping the flush is not caught: the checkpoint write fails with the same error, as in
    commonware's test. The parked and dropped sync-handle tests are in
    `fixed_start_sync_test.zig` (see "Start-sync handle tests" below). Not ported: the
    snapshot and cache-hit accounting tests (no snapshot readers, no per-read hit metrics
    on the fixed journal's reads here).
  - [x] variable.rs batch 1 (`variable_offsets_test.zig`): offsets and data disagreeing
    (prune crash leaving the offsets end behind, several data prunes ahead, empty offsets
    in another blob, offsets ending before the oldest data, bounded and not, mid-blob
    offsets start, stale offsets watermark, offsets rebuilt across blobs, overlong and
    over-capacity data blobs). Planted bug (skip the offsets-end check) fails one test.
  - [x] variable.rs batch 2 (`variable_torn_test.zig`): rollovers without commit, torn
    interior pages in the tail, torn rewrites under a bounded open (data and offsets),
    damage below the offsets watermark (torn or shortened blobs adopted, a torn page below a
    mid-blob watermark rejected), gaps, orphaned newer blobs, and unsynced tails. The lagged
    `start_sync` of the torn-rewrite seed becomes a commit of each journal. Planted bug (skip
    data page validation) fails four tests.
  - [x] variable.rs batch 3 (`variable_size_test.zig`): `init_at_size` and `clear_to_size`
    resets (conflicting offsets partitions, staged-reset crash points, pending targets,
    stale same-blob data, mid-blob starts across blobs, data-only crashes, near
    `u64::MAX`), and resets failing on sync or remove faults on `runtime.storage.faulty`.
    Planted bug (leave the data behind a staged reset) fails two tests.
  - [x] variable.rs batch 4 (`variable_sync_test.zig`): `init_sync` over fresh storage,
    overlapping, matching, exceeding, and stale local data, blob-boundary and same-blob
    ranges, empty journals at a stale position, a stale `clear_to_size`, and the first open
    after a staged clear (starts 7, 50, 60, data kept or removed). Planted bug (a sync clear
    leaves the data partition) fails the interrupted-clear test. An open-ended span for a
    staged clear is not caught by design: `init_sync` resets a recovered prefix short of its
    start. The reversed-range should-panic test is an assertion here and is not ported.
  - [x] variable.rs batch 5 (`variable_bounded_test.zig`): unpublished bounded inspection
    keeps acknowledged offsets and data above the watermark, a failed removal keeps durable
    data, missing acknowledged data and offsets without data are corruption, an empty prefix
    at the maximum position, interrupted empty publications at caps 9/10/11/none, a clean
    cap adds no mutations, offset rebuild with a partial final page (slow), an interrupted
    rebuild under write faults, bounded retries after sync/remove/resize faults, and
    `init_at_most` restarts (compressed too) and discarded torn blobs. Planted bug (bounded
    inspection always truncates the offsets to the ceiling) fails the preserve-offsets test.
    Not ported: the two decode-count tests, which count through a `Read::Cfg` counter.
  - [x] variable.rs batch 6 (`variable_repair_test.zig`): an `init_at_most` truncation that
    survives a crash keeping unsynced writes and dropping resizes, a commit after a bounded
    open, acknowledged data cut to a blob boundary, a short blob after the anchor, durable
    offsets and data trailing-byte repairs, empty offsets after a prune and data-only sync,
    a data-only sync across blobs, a mid-blob durable anchor, a full newest blob without a
    successor, a crash between the offsets and data truncation, and a gap in the retained
    blobs. Planted bug (publication skips data repair) fails four of them. A planted anchor
    that accepts a watermark past the data end is not caught by design: inspection's
    contiguity check rejects the lost blob first.
  - [x] variable.rs batch 7 (`variable_reads_test.zig`): compressed `append_many`,
    compressed frames across pages after a cold reopen (replay, read, `read_many`),
    `append_many` past the write buffer, append and replay at the maximum size, and
    `try_read_many_sync` against `read_many`, probe completion, consecutive, scattered, and
    cold-offset reads, and a blob's last frame after a capped reopen. Also lost offsets
    after a prune, lost data aligned to empty, replay stopping at a corrupt blob, single-item
    prune-all and reuse, a backward `clear_to_size` with no mutation, and journal metrics.
    Planted bug (cached frames decode one byte short) fails three of them. zigware's
    `read_many` reads item by item, so the scattered-read hit/miss split is asserted as a sum
    (a miss can warm its neighbor). Not ported: the batched-read accounting, probe-reuse,
    recorded-read, and tampered-offset tests (they test commonware's batched `read_many`
    pass), replay read options (zigware's replay takes none), `View` ownership, should-panic,
    snapshot, and the parked or dropped sync-handle tests (start_sync staging, deferred
    failures, destroy after an unobserved failed sync).
  - [x] variable.rs: start_sync flush failure and the init data-before-offsets sync check,
    ported by storage-journal in `contiguous/variable_faults_test.zig` (the partition-scoped
    sync fault is `runtime.storage.mocks.SyncFault`, commonware's `SyncFaultContext`).
- [x] journal/zstd: byte-exact libzstd level 3 (coordinator, correcting the earlier "byte
  identity not required"). commonware's storage conformance hashes four `<true>` journal
  workloads written with `compression: Some(3)`, so compressed journals must emit exactly
  what `zstd::bulk::compress(.., 3)` writes: the dfast strategy with level 3's parameters,
  block splitting, Huffman literal tables and their repeat/raw choices, FSE normalization and
  table modes, and the frame header. Check against the local `zstd -3` and the four hashes,
  which storage-journal enables through StorageConformance (fe7bafa). The current fast
  compressor stays only if level 3 turns out slower.
  - Pin: commonware's Cargo.lock has zstd 0.13.3, zstd-safe 7.2.4, and zstd-sys
    2.0.16+zstd.1.5.7, so libzstd 1.5.7 (`lib/compress` of that zstd-sys is the source
    ported). The local `zstd` CLI is v1.5.7 too.
  - Oracle: a scratch Rust program (outside the repo) built offline against exactly those
    crates writes `zstd::bulk::compress(data, level)`. It matches `zstd -3 --no-check`
    byte for byte from 0 B to 3 MB, so either serves as the reference.
  - Path facts: `bulk::compress` is `compress2` with the pledged size equal to the input
    and a `compressBound` output, which takes `ZSTD_compressEnd`'s direct path. Level 3
    rows (W/C/H/S/L/T, dfast): over 256 KiB 21/16/17/1/5/0, up to 256 KiB 18/16/16/1/4/0,
    up to 128 KiB 17/15/16/2/5/0, up to 16 KiB 14/14/15/2/4/0, then
    `ZSTD_adjustCParams_internal` shrinks the window to the source. dfast has no pre-split
    (`splitLevels[dfast]` is 1) and no post-split (btopt and up), so blocks are 128 KiB.
    Blocks under 7 bytes are raw, and the first block is never RLE. Window indices start at
    2 (`ZSTD_WINDOW_START_INDEX`).
  - Pieces: (1) parameters and the frame header; (2) the dfast match finder and seqStore
    (`zstd_double_fast.c`); (3) Huffman literals (`huf_compress.c`,
    `zstd_compress_literals.c`); (4) FSE sequence tables and encoding modes
    (`fse_compress.c`, `zstd_compress_sequences.c`); (5) block entropy and repeat state
    (`ZSTD_entropyCompressSeqStore`, `ZSTD_compressBlock_internal`); (6) compressed journals
    switched to it. Vectors: corpus inputs with the oracle's output length and SHA-256.
  - [x] Piece 1: `zstd/params.zig` (level 3 rows and `adjustCParams` for a pledged size) and
    the frame header: single segment while the window covers the source (up to 2 MiB), else
    a window byte (0x58 above 2 MiB). Header vectors from the oracle; a planted off-by-one
    on the single-segment test fails them.
  - [x] Piece 2: `zstd/dfast.zig`, `ZSTD_compressBlock_doubleFast_noDict_generic` step by step
    (hashes, skip schedule, repeat checks, complementary insertion, `enforceMaxDist`). A second
    scratch oracle prints `ZSTD_generateSequences` at level 3. Sequences matched exactly on 6 MB
    of binary, 5 MB of source, mixed and random data, and every row-boundary size. (The oracle
    cannot report frames whose last block is under 7 bytes, which libzstd stores raw.)
    `dfast_test.zig` pins SHA-256 digests of the oracle's sequences for corpus text, records,
    2.3 MB mixed (past the window), and noise. Planted bugs (a shifted complementary insert, or
    `step < 3`) fail it. Order change: FSE (`fse_compress.c`, `hist.c`) comes next, before
    Huffman, because libzstd FSE-compresses the Huffman weights.
  - [x] Piece 3: `zstd/fse_exact.zig`, libzstd's FSE encoder: `HIST_count_simple`,
    `FSE_optimalTableLog_internal`, `FSE_normalizeCount` with `FSE_normalizeM2`,
    `FSE_writeNCount`, `FSE_buildCTable_wksp` and `buildCTable_rle`, the two-state encoder,
    and `BIT_CStream`'s `capacity - 8` overflow rule. A third scratch oracle compiled from
    libzstd's own `fse_compress.c`/`hist.c` printed the table log, NCount header, and stream
    for 648 generated inputs (60 reach M2): 0 mismatches. `fse_exact_test.zig` pins SHA-256
    digests of 8 oracle lines plus the exact capacity edge. Planted bugs (M2 always failing,
    swapped final states, `>` for `>=` in the overflow check) fail it.
  - [x] Piece 4: `zstd/huf_exact.zig`, libzstd's Huffman literals: `HUF_sort` (buckets, then
    quicksort with its recursion on an explicit stack), `HUF_buildTree`, `HUF_setMaxHeight`,
    canonical codes, `HUF_writeCTable` (FSE weights at log 6, else raw nibbles), 1X and 4X
    streams, `HUF_compress_internal`'s repeat, preferRepeat, and suspect-sample heuristics,
    and `ZSTD_compressLiterals` at dfast (raw below 64 literals, RLE, `minGain`, headers).
    A fourth scratch oracle linked from libzstd's `zstd_compress_literals.c` and
    `huf_compress.c` compresses chunk sequences with tables carried across chunks; 1,400 random
    and targeted chunk sequences matched with 0 mismatches. `huf_exact_test.zig` pins 7
    digests. Planted bugs (no overshoot repayment, quicksort threshold 4, preferRepeat off,
    suspect sample off, `<` for `<=` in the old-table check, single stream below 255) each
    fail it. Raw weights above 128 symbols (libzstd: "should not happen") was never reached.
  - [x] Piece 5: `zstd/seq_exact.zig` (`ZSTD_seqToCodes`, `ZSTD_selectEncodingType` below
    lazy, `ZSTD_buildCTable`, `ZSTD_encodeSequences`, the 1.3.4 small-table workaround) and
    `zstd/block_exact.zig` (`ZSTD_compress_frameChunk`, `ZSTD_compressBlock_internal`,
    `ZSTD_entropyCompressSeqStore`: raw below 7 bytes, RLE except on the first block, `minGain`,
    suspect literals at 20 per sequence, repeat offsets and Huffman tables confirmed only by
    compressed blocks). Correction to the path facts above: dfast does pre-split
    (`splitLevels[dfast]` is 1, so `ZSTD_splitBlock_byChunks` at 43-byte sampling), once a
    frame has saved at least 3 bytes. Without a dictionary no FSE table is ever
    `repeat_valid`, so dfast never picks `set_repeat` and FSE tables never carry over.
    Whole frames matched the `bulk::compress(.., 3)` oracle on 210 files from 0 B to 26 MB
    (text, binaries, records, runs, noise, mixtures). Found on the way: `FSE_writeNCount`'s bit
    count reaches 32 after a long zero run, which overflowed the port's `u5` (now `u6`).
    `block_exact_test.zig` pins 11 frame digests. Planted bugs (splitter penalty, threshold,
    and savings gate; RLE on the first block; `minGain >> 7`; suspect ratio 10; the `u5`
    bit count) each fail it.
  - [x] Piece 6: `zstd.compress_into` (every compressed journal) writes the exact frames
    (`Mode.exact`); the faster encoder stays as `Mode.compress` for comparison, and the round
    trip fuzz and benches cover all three modes. storage-journal wired the four `<true>`
    journal conformance workloads (f664cc4): ContiguousVariable, SegmentedGlob,
    SegmentedVariable, and SegmentedOversized match commonware's hashes, 512 cases each, and
    the same items written uncompressed fail all four.
  - Bench (`zig build bench -Doptimize=ReleaseFast -Dbench-filter=journal::zstd`, 1 MB): text
    exact 4.82 ms vs fast 4.30 ms; records exact 2.06 ms vs fast 2.37 ms. The exact path is
    as fast as the earlier encoder and writes libzstd's level 3 ratio, so journals lose nothing
    by using it; `Mode.compress` stays only for comparison.
- 2026-11-19: test tally of index, rmap, bitmap, and translator against commonware (clearing lane).
- 2026-11-19: tally of merkle and journal internals; ported its 22 open tests in this lane.
- 2026-11-19: partitioned index ranges (`new_range`/`install_range`) and their 5 tests
  (clearing lane).
- 2026-11-19: proposed the asynchronous start_sync design (awaiting the coordinator).
- 2026-11-19: index and translator partials and the last 2 open index tests (clearing lane).
