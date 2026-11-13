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
  (Batch API and the Proof `CodecConformance` hash still to do; the latter waits on the
  conformance lane's `arbitrary` emulation.)
- [x] merkle/mmb and shared merkle proof types.
- bmt moved to the coding lane (it needs it first).
- [x] bitmap (authenticated bitmap over MMR).
- [x] index (ordered/unordered, partitioned, immutable) over translators. The partitioned
  `new_range`/`install_range` (crate-private, for qmdb) come with qmdb.
- [ ] merkle/persisted (journaled MMR) once runtime storage lands.
- [ ] Fuzz targets (storage/fuzz entries for these modules).

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
  Commonware's position-only `utils::handles::Table` belongs to the utils lane; until it lands
  the positions sit in a hash map from translated key to positions (same results). Seeded and
  `std.testing.fuzz` targets check it against a model of live (position, key) pairs.
