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
  positions and peaks math identical to commonware, proof codec. Port its tests and vectors.
  (The Proof `CodecConformance` hash still waits on the conformance lane's `arbitrary`
  emulation.)
- [x] merkle/batch: stacked speculative batches (`Mem.new_batch`, `merkleize`,
  `Mem.apply_batch`, `add_many`, leaf updates) with commonware's batch.rs and mem.rs tests.
- [x] merkle/mmb and shared merkle proof types.
- bmt moved to the coding lane (it needs it first).
- [x] bitmap (authenticated bitmap over MMR).
- [x] index (ordered/unordered, partitioned, immutable) over translators. The partitioned
  `new_range`/`install_range` (crate-private, for qmdb) come with qmdb.
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
## Log
- translator: Rust's `Translator`/`BuildHasher` traits become a comptime interface
  (`Key`, `ordered`, `transform`, `hash`, `order`, `eql`; `translator.check`). `Hashed`
  uses `std.hash.Wyhash` instead of `ahash`; commonware documents its output as unstable
  and never persisted, so they need not match. Seeds come from a caller's `std.Random`
  (`init_random`) or `from_seed`, never from the OS.
- rmap: a sorted array of ranges with binary search instead of a `BTreeMap`; same
  semantics and tests. `missing_items` writes into a caller buffer whose length is `max`.
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
  cursor) in one treap instead of per-partition sorted arrays that spill to a `BTreeMap`. Same
  results and O(log n) operations, so the spill threshold and its tests do not apply. Every
  generic index test runs against all four indices.
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
