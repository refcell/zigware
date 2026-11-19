# Lane: utils

Owns `src/utils` (parallel, allocator, and bench moved to the parallel lane).

Reference: `~/.cache/zigware/commonware-ref/{utils,parallel,allocator,bench}`.
`utils` depends on codec; until codec lands, start with the codec-free modules and build the
encoding parts as soon as `codec` has its core API (see docs/lanes/codec.md).

## Public API (on main)
- `utils.faults`: `N3f1`, `N5f1` (`max_faults`, `quorum`, `m_quorum`, `l_quorum`; any int `n`).
- `utils.rng`: `TestRng` (byte-identical to commonware's `TestRng`, i.e. Rust `rand` 0.10
  `StdRng::seed_from_u64`), `ScriptedRng`, `FuzzRng`, `mix64`, and `rand`-identical samplers
  `range_at_most`, `range_less_than`, `boolean`, `bernoulli`, `ratio`, `float64`;
  `random(&rng)` adapts any generator to `std.Random`. Generators are borrowed-slice, no alloc.
- `utils.rng.Uniform(T)`: `rand`'s precomputed `Uniform<T>` (Lemire), distinct from the
  one-shot `range_*` samplers.
- `utils.range`: `Bound(T)`, `contains_cyclic`, `NonEmptyRange(T)` (codec encoding).
- `utils.time`: `Duration` (Rust `Duration` semantics, `parse`, `from_nanos_saturating`,
  `as_millis_u64`), `SystemTime` (`epoch`, `epoch_millis`, `add_jittered`, `limit`,
  `saturating_add`, `from_timestamp(std.Io.Timestamp)`), `sample_duration` (rand-identical).
- `utils.sequence`: `FixedBytes(N)` (`init`, comptime `from_hex`, `zeroize`), `U32`, `U64`,
  `PrefixedU64` (`prefix`, `value`), `VecU64`, `Unit`; all with codec encodings, `order`,
  `eql`, `as_slice`, `{f}` formatting. `utils.Array(T)`/`utils.Span(T)` are comptime checks.
- `utils.bitmap`: `BitMap(N)` (alias `utils.BitMap`, `DefaultBitMap` = 8-byte chunks):
  allocator-explicit `push`/`pop`/`truncate`/`extend_from_bitmap`/`push_chunk`/`prune_chunks`,
  `get`/`set`/`flip`/`set_all`/`flip_all`, `and`/`or`/`xor`, `count_ones`, `is_unset`,
  `iter`, `ones_iter`/`ones_iter_from`/`ones_iter_range`, codec (`Cfg = RangeCfg(u64)`), `{f}`.
  `bitmap.Prunable(N)`: absolute positions over pruned leading chunks (`init_pruned`,
  `prune_to_bit`, `unprune_chunks`, `set_chunk_by_index`, `get_bit`/`set_bit`, `ones_iter_*`,
  codec: pruned count `u64` + `BitMap`, `Cfg` bounds the retained bits).
  `bitmap.historical.BitMap(N)`: a `Prunable` plus reverse diffs per commit (`into_dirty` ->
  `Dirty` with read-through `get_bit`/`get_chunk`, `set_bit`, `push*`, `pop`, `prune_to_bit`;
  `commit(gpa, n)` / `abort`; `apply_batch`, `get_at_commit`, `prune_commits_before`). A failed
  `commit` leaves the `Dirty` unchanged (Rust consumes it).
  `bitmap.roaring`: `roaring.Bitmap` (u64 roaring bitmap: sorted `codec.Map(u64, Container)`
  entries; `insert`, `insert_range`, `contains`, `iter`, `iter_range`, `min`, `max`, `clear`,
  `truncate_containers_below`, `container_variant_counts`, `eql`; set operations with a result
  limit `union`/`intersection`/`difference(other, gpa, limit)` plus `is_subset`/`intersects`;
  codec with `RangeCfg(usize)` container bound); `roaring.Prunable` (a `Bitmap` with a
  container-aligned `pruned_below` watermark: `prune(gpa, threshold)` returns the applied
  watermark; access below it is an assertion; codec `u64` watermark + `Bitmap`); `roaring.Container` (Array/Bitmap/Run with hysteresis transitions,
  canonical encoding, set operations) and its three kinds; codec + conformance hashes.
  `bitmap.readable` is the `Readable` trait (`len`, `pruned_chunks`, `get_chunk`) + `OnesIter`.
- `utils.handles`: `Table(H)` (`empty`, `init_capacity`, `deinit`, `len` field, `capacity`,
  `reserve(gpa, n, rehash_context)`, `get(hash)` -> `Candidates` iterator (`next() ?H`),
  `insert(gpa, hash, handle, rehash_context)`, `find_or_insert(gpa, hash, matcher, handle,
  rehash_context)` -> `Found{handle, inserted}`, `remove(hash, handle)`, `prefetch`);
  `rehash_context.rehash(H) u64` gives each held handle's hash on growth, `matcher.matches(H)`
  confirms a candidate. `partition(hash, partitions)` picks a shard from the bits below the
  fingerprint.
- `utils.acknowledgement`: `Exact` (`handle(gpa, io)` -> `{ acknowledgement, waiter }`,
  `clone`, `acknowledge` (consumes), `deinit` (drop = cancel)); `Exact.Waiter` (`wait()` ->
  `error.AcknowledgementCanceled` when a handle was dropped, `poll()` = `now_or_never`,
  `deinit`); `assert_acknowledgement(T)` checks the interface. Runs on any `std.Io`.
- `utils.Cache(K, V)` (`utils.cache`): Clock2Q+ cache (`init(gpa, capacity)` allocates
  everything; `get`/`get_at`/`get_mut`/`peek`/`contains`, `put` (returns the replaced value),
  `get_or_insert_with(key, factory)`, `try_get_or_insert_with`, `get_or_insert_mut` ->
  `{ slot, value }`, `remove`, `retain(predicate)`, `clear`, `prefill(factory)`). Factories
  declare `make()`, predicates `keep(key, *const V)`; dropped keys/values go to `discard`.
- `utils.BigRational` (`utils.rational`): exact rationals over `std.math.big.int.Managed`,
  canonical like `num_rational` (`from_u64`, `from_frac_u64`, `from_u128`, `from_frac_u128`,
  `from_usize`, `from_frac_usize`, `from_frac`, `from_integer`, `from_ints`, `zero`, `one`,
  `deinit`, `clone`; `add`, `sub`, `mul`, `div`, `neg`, `pow(i32)`, `order`, `eql`,
  `to_integer`, `is_integer`/`is_zero`/`is_negative`/`is_positive`; `ceil_to_u128`,
  `log2_floor(digits)`, `log2_ceil(digits)` bit-identical to commonware). Results allocate with
  the first operand's allocator; the caller `deinit`s them.
- `utils.Probability` (`utils.probability`): platform-independent probability, a `u64`
  `threshold` (extern struct; `maxInt(u64)` = one). `zero`, `one`, `init(n, d) ?Probability`
  (Rust `new`), `from_f64`, `try_from_f64` (`error.InvalidProbability`), comptime `ratio(n, d)`
  and `literal(f)` (the `probability!` macro), `is_zero`, `is_one`, `as_f64`, `sample(rng)`
  (draws one `next_u64` strictly between zero and one, nothing at the endpoints), `eql`,
  `order`, `{f}`, `arbitrary`. Bit-identical thresholds to commonware.
- `utils.channel` (`channel/`): over `std.Io` primitives, values dropped by a channel go to
  `T.discard` if declared. `mpsc.channel(T, gpa, io, cap)`/`mpsc.unbounded(T, gpa, io)` (tokio
  semantics: Sender `clone`/`send`/`try_send`/`reserve`/`try_reserve` -> `Permit`/`is_closed`/
  `closed`/`capacity`/`same_channel`; Receiver `recv` -> `?T`/`try_recv`/`close`/`len`);
  `ring.channel` (drop-oldest: `send_lossy`, `send`, `recv`, `try_recv`); `reservation.
  send_or_reserve` -> `sent`/`reserved: Reservation`/`closed: T`; `fallible` (`send_lossy`,
  `try_send_lossy`, `send_or_reserve_lossy`, `oneshot_send_lossy`, `request`/`request_or`/
  `request_or_default` with a maker declaring `make(responder)`); `tracked.bounded(T, B, ...)`
  (sequences from 1, `Guard` clone/deinit, `watermark`, `pending(batch)`); `oneshot`
  (broadcast-resolver lane).
- `utils.vec`: `Bounded(T)` (`init(gpa, capacity)` allocates once; `push` returns the evicted
  oldest, `pop_front`, `at`, `iterator`, `into_inner`) and `NonEmptyVec(T)` (`init`,
  `from_unchecked`, `from_list`/`from_slice` -> `error.Empty`, `repeat`; `items`, `first`,
  `last`, `map`, `map_into`, `push`, `insert`, `extend`, `resize`, `resize_with`, `pop`/`remove`
  keep one item, `mutate`, `into_list`, `order`). Encodes as `Vec<T>`; decode rejects empty
  as `Invalid`. Owns its items. Also `utils.NonEmptyVec`.
- `utils.iter`: `NonEmpty(I)` (`init`, `try_init`, `into_parts`, `next`), `zip_eq(a, b)`
  (panics on unequal lengths), `slice(T, items)`; iterators are types with `next() ?Item`.
- `utils.concurrency`: `Limiter.init(max)` (`try_acquire` -> `?Reservation`, `deinit` releases)
  and `KeyedLimiter(K).init(gpa, io, max)` (one reservation per key, at most `max` keys,
  allocation-free after `init`). Limiters must outlive their reservations.
- `utils.prefetch`: `prefetch(ptr)`, `prefetch_lines(T, ptr, len, lines_max)` (`@prefetch`),
  `Lookahead.init(distance).advance(T, remaining)`.
- `utils.NonZeroDuration` (`utils.time`): `init` -> `?NonZeroDuration`, `init_panic`, `get`.
- `utils.bitmap.Atomic`: `zeroes(gpa, len)`, concurrent `set(bit)` (monotonic),
  `into_bitmap(gpa)` -> default `BitMap` (consumes), `deinit`.
- `utils.thread_local`: `threadlocal var slot: Slot(T) = .{}` and `Cached(T).take(&slot,
  maker)` (`maker.create() !T`, `maker.reset(*T) !void`), guard `.value`, `deinit` returns it.
- `utils.amount`: `assert_amount(T)` (unsigned ints, `u256` for `U256`), `zero`,
  `overflowing_add`/`overflowing_sub`, `checked_add`/`checked_sub`.
- `utils.sync.UpgradableRwLock(T)` over `std.Io.RwLock`/`Mutex`: `read`, `write`, `try_write`,
  `upgradable_read` -> `upgrade`, `downgrade_to_upgradable`; guards `get`/`deinit`.
- `utils.futures`: `Pool(T).init(gpa, io, capacity)` (`push(function, args)`,
  `next_completed`, `cancel_all`, `len`), `AbortablePool(T)` (tasks return `Io.Cancelable!T`;
  `push` -> `Aborter`, `abort()`; `next_completed` -> `error.Aborted` for aborted tasks), and
  `try_join_all(T, E, gpa, io, function, arguments)` (input order, first error cancels the rest).
- `utils.Hostname` (`utils.hostname`): validated RFC 1035/1123 hostname stored inline
  (`init`, `literal`, `as_str`, `eql`, `order`, `{f}`, `len_max`, `label_len_max`,
  `max_encode_size` = 258), codec as a `RangeCfg(..=253)` byte string; `hostname.Error`.
- `utils.net`: `is_global` (`is_global_v4`/`is_global_v6`), `subnet(ip, SubnetMask)`,
  `Subnet`, `SubnetMask.init(v4_bits, v6_bits)`, `to_ipv4_mapped`, over codec's `IpAddr`.
- `utils.ordered`: `Set(T)`, `Map(K, V)`, `BiMap(K, V)` (sorted, deduplicated; `init` fails
  with `DuplicateKey`/`DuplicateValue`, `from_dedup` drops duplicates; `get`, `position`,
  `as_slice`, `get_value`, `get_key`, `iter_pairs`, `map_values`, `map_values_into`,
  `from_parts`, `truncate`, `{f}`). `Set` has the `Quorum` helpers `quorum(M)`,
  `max_faults(M)`, `key(Participant)`, `index(item) ?Participant`. Codec: `Set` = `Vec<T>`
  (decode rejects unsorted/duplicate), `Map` = keys then values, `Cfg` = `{ range, key, value }`.
  Items order by their `order(a, b)` decl, else `codec.order`. Collections own their items:
  constructors take ownership (releasing on error); `deinit` releases.
- `utils.rng.ChaChaRng(rounds)`, `ChaCha8Rng` (Rust `rand_chacha` 0.10).
- `utils`: `modulo`, `union`, `union_unique`, `Participant`, `NonZero(T)`/`nz`, `GOLDEN_RATIO`,
  `MAX_ALLOCATION_BYTES`.

## Decisions
- RNG interface is `next_u32`/`next_u64`/`fill_bytes`; ports that draw randomness use the
  samplers in `utils.rng` (not `std.Random`) so values match commonware's tests.
- `union_unique`, `Participant` (`UInt<u32>`), and `NonEmptyRange(T)` (start, end; rejects
  `start >= end` as `Invalid`) encode through `codec`. Their conformance hashes need codec's
  `arbitrary` emulation; they are checked in `conformance_test.zig`.
- Conformance: `src/utils/conformance_test.zig` checks every utils/conformance.toml entry
  (copied unchanged next to it) through the shared `conformance.verify` harness with
  `codec.arbitrary` generators; each type's Rust `Arbitrary` derive is a small generator there.
- `channel.tracked` batch IDs are plain hashable values copied into the tracker (Rust allows any
  `Eq + Hash + Clone`, including `Arc`s with destructors), so commonware's
  `batch_destructor_can_read_watermark` has no counterpart; guards are (tracker, sequence)
  pairs with per-sequence reference counts instead of per-message `Arc`s.
- `sync`: commonware's re-exported `parking_lot`/`tokio` locks are `std.Io.Mutex`/`RwLock`/
  `Condition`; `Exclusive` (a `Sync` marker) and the traced locks (tracing spans) have no Zig
  counterpart. `Widen` is `@as`, and `max` is `@max`.
- `futures`: pools run functions as `std.Io` tasks instead of holding futures; aborting is an
  explicit `Aborter.abort()` (Rust aborts on drop). `OptionFuture`, `rebind`/`rebind_entry`,
  and `Shared` exist for Rust ownership and polling and are not ported.
- `src/utils/fuzz.zig` is the utils fuzz driver: a body over `*FuzzRng`, run seeded in
  `zig build test` and under `std.testing.fuzz`.

## Backlog
- [x] utils basics: faults, modulo, union/union_unique, NZ/NonZeroDuration, Participant, rng,
  range, time, iter, vec, rational, probability, sampling (resolver lane), hostname, net,
  amount, concurrency, prefetch, thread_local, sync, futures (Pool/AbortablePool/try_join_all);
  `Span`/`Array` as comptime checks. Not ported by design: `sys_rng` (library code takes
  randomness from the runtime), `Exclusive`, traced locks, `OptionFuture`, `rebind`, `Shared`.
- [x] utils sequence: fixed_bytes, u32, u64, prefixed_u64, vec_u64, unit — with codec.
- [x] utils bitmap: BitMap, prunable, historical, roaring (containers, Bitmap, Prunable, ops,
  fuzz Plan); codec encodings identical, all bitmap conformance hashes match.
- [x] utils ordered (Set/Map/BiMap/Quorum) with conformance hashes.
- [x] utils priority_set (resolver lane, audited), acknowledgement, cache (unit tests,
  colliding keys, model fuzz), channel mpsc/ring/reservation/fallible/tracked.
- [x] utils handles (`Table`, `partition`), requested by storage-merkle.
- [x] Fuzz targets for every commonware utils/fuzz target.

## Log
- 2026-11-13: faults, rng (TestRng/ScriptedRng/FuzzRng + FuzzRng conformance hash), range,
  lib basics.
- 2026-11-13: switched union_unique to codec; Participant and NonEmptyRange codec encodings.
- 2026-11-13: time (Duration, SystemTime, parse, rand-identical jitter) with seeded and
  std.testing.fuzz targets; rng.Uniform.
- 2026-11-13: sequence (FixedBytes, U32, U64, PrefixedU64, VecU64, Unit) with conformance
  hashes; Participant and NonEmptyRange conformance hashes; ChaCha8Rng; utils fuzz driver.
- 2026-11-13: moved utils conformance onto the shared harness (conformance + codec.arbitrary).
- 2026-11-13: BitMap with all mod.rs tests, conformance hash, and a model-based fuzz target.
- 2026-11-13: Hostname (conformance hash) and net is_global/subnet, for p2p.
- 2026-11-13: Prunable bitmap with its tests, conformance hash, and fuzz target.
- 2026-11-13: ordered Set/Map/BiMap/Quorum with tests, conformance hashes, and a set fuzz.
- 2026-11-13: historical bitmap with its tests, randomized checkpoints, and fuzz target.
- 2026-11-13: roaring containers (Array, Bitmap, Run, Container) with tests and all five
  container conformance hashes, including ContainerTransitionsConformance.
- 2026-11-13: roaring top-level Bitmap with the mod.rs tests and its conformance hash.
- 2026-11-13: roaring Prunable (conformance hash), ops (union/intersection/difference with
  limits, is_subset, intersects), and the roaring fuzz Plan. The fuzz draws overlapping
  sets (shared narrow domains, dense blocks): with commonware's independent full-range
  values, intersections are almost always empty and a broken `difference` went unnoticed.
- 2026-11-13: handles `Table` (Robin Hood multimap of hashes to handles) and `partition`,
  with all handles.rs tests; Rust closures are `rehash_context`/`matcher` parameters.
- 2026-11-13: acknowledgement Exact with its tests, a concurrent waiter test, and the ack fuzz.
- 2026-11-13: Clock2Q+ Cache over handles.Table, with the cache.rs unit tests and invariants.
- 2026-11-16: rational BigRational (BigRationalExt plus the arithmetic bloomfilter uses), all
  mod.rs tests and a fuzz that checks log2 against its defining bounds.
- 2026-11-16: Probability with the probability.rs tests (thresholds, sampling, round trips).
- 2026-11-16: channel mpsc, ring, reservation, fallible, tracked with their tests, an mpsc model
  fuzz, and a tracked model fuzz (watermark and per-batch pending against a model).
- 2026-11-16: cache model fuzz, Ghost collision churn and ownership, colliding resident keys.
- 2026-11-16: vec (Bounded, NonEmptyVec with codec and arbitrary) and iter (NonEmpty, zip_eq).
- 2026-11-16: NonZeroDuration, concurrency limiters, prefetch/Lookahead, and the lib_functions,
  net, and sequence fuzz targets.
- 2026-11-16: bitmap Atomic, thread_local Cached, amount, and sync UpgradableRwLock.
- 2026-11-16: futures Pool, AbortablePool, try_join_all, and the futures fuzz target.

## Test audit (2026-11-19, against main)

Every commonware `#[test]` in this lane's crates (macro and rstest cases expanded where noted), matched by reading both sides: ported (a Zig test checks the behavior, often one consolidated test), open, or not portable with the reason. Written by the consensus-marshal lane; tick a box when its test lands.

### utils (everything but bitmap/)
| File | Tests | Ported | Open | Not portable |
| --- | --- | --- | --- | --- |
| acknowledgement.rs | 5 | 5 | 0 | 0 |
| amount.rs | 2 | 2 | 0 | 0 |
| cache.rs | 50 | 42 | 2 | 6 |
| channel/fallible.rs | 18 | 18 | 0 | 0 |
| channel/reservation.rs | 5 | 5 | 0 | 0 |
| channel/ring.rs | 14 | 11 | 0 | 3 |
| channel/tracked.rs | 7 | 6 | 0 | 1 |
| concurrency.rs | 3 | 3 | 0 | 0 |
| faults.rs | 55 | 45 | 0 | 10 |
| futures.rs | 22 | 12 | 0 | 10 |
| futures/shared.rs | 13 | 0 | 0 | 13 |
| futures/try_join_all.rs | 30 | 5 | 8 | 17 |
| handles.rs | 13 | 12 | 0 | 1 |
| hostname.rs | 12 | 10 | 0 | 2 |
| iter.rs | 9 | 5 | 0 | 4 |
| lib.rs | 15 | 12 | 0 | 3 |
| net.rs | 8 | 8 | 0 | 0 |
| ordered.rs | 48 | 46 | 0 | 2 |
| prefetch.rs | 4 | 4 | 0 | 0 |
| priority_set.rs | 5 | 5 | 0 | 0 |
| probability.rs | 7 | 6 | 0 | 1 |
| range.rs | 12 | 8 | 0 | 4 |
| rational/mod.rs | 28 | 26 | 0 | 2 |
| rng.rs | 12 | 11 | 0 | 1 |
| sampling.rs | 9 | 7 | 0 | 2 |
| sequence/fixed_bytes.rs | 6 | 6 | 0 | 0 |
| sequence/prefixed_u64.rs | 2 | 2 | 0 | 0 |
| sequence/u32.rs | 2 | 2 | 0 | 0 |
| sequence/u64.rs | 2 | 2 | 0 | 0 |
| sequence/unit.rs | 3 | 3 | 0 | 0 |
| sequence/vec_u64.rs | 1 | 1 | 0 | 0 |
| sync/exclusive.rs | 1 | 0 | 0 | 1 |
| sync/mod.rs | 7 | 4 | 0 | 3 |
| thread_local.rs | 8 | 5 | 0 | 3 |
| time.rs | 19 | 16 | 0 | 3 |
| vec.rs | 32 | 26 | 0 | 6 |
| **Total** | **489** | **381** | **10** | **98** |

Counting notes:
- rstest cases are counted one per case. faults.rs `test_bft3f1_quorum_and_max_faults` (21)
  and `test_bft5f1_quorums` (21) are ported by the case tables in
  `src/utils/faults.zig` "faults: N3f1 quorum and max_faults" and "faults: N5f1 quorums".
  ordered.rs: `test_map_from_parts_lengths` (9), `test_map_values_into_reuses_keys` (2),
  `test_try_map_values_error` (6). shared.rs: `test_destroyed_waker_may_drop_a_registered_clone`
  (2). try_join_all.rs: `preserves_order` (5), `later_error_drops_futures_and_values` (8),
  `cancellation_drops_futures_and_values` (8), `completed_future_drop_unblocks_another` (3),
  `later_error_wakes_caller` (3).
- Each proptest fn counts once. cache.rs `cache_invariants_hold{,_with_wide_small}` are ported by
  `cache_test.zig` "fuzz cache" (capacities 1..48, optional prefill). faults.rs proptests are
  ported by "faults: quorum relationships and safety for all n below 10000".
- probability.rs includes `expression_macro_rejects_invalid_probability` (line 326), a
  `#[should_panic]` test that is missing from the input TSV.

Open:
- [ ] `cache.rs:2601` `shared_hashes_without_rehash_steps`: each op hashes a key exactly once
  (hash-call counts)
- [ ] `cache.rs:2868` `non_clone_keys_keep_incoming_metadata_on_ghost_hits`: on a Ghost hit
  the caller's key, not the historical one, is stored
- [ ] `futures/try_join_all.rs:264` `later_error_drops_futures_and_values::case_1::known_1_false`:
  later error returns while first task blocks, cancelling it
- [ ] `futures/try_join_all.rs:264` `later_error_drops_futures_and_values::case_1::known_2_true`:
  same, count 2
- [ ] `futures/try_join_all.rs:264` `later_error_drops_futures_and_values::case_2::known_1_false`:
  same, count 30
- [ ] `futures/try_join_all.rs:264` `later_error_drops_futures_and_values::case_2::known_2_true`:
  same, count 30
- [ ] `futures/try_join_all.rs:264` `later_error_drops_futures_and_values::case_3::known_1_false`:
  same, count 31
- [ ] `futures/try_join_all.rs:264` `later_error_drops_futures_and_values::case_3::known_2_true`:
  same, count 31
- [ ] `futures/try_join_all.rs:264` `later_error_drops_futures_and_values::case_4::known_1_false`:
  same, count 64
- [ ] `futures/try_join_all.rs:264` `later_error_drops_futures_and_values::case_4::known_2_true`:
  same, count 64

Not portable:
- `faults.rs` `test_bft3f1_max_faults_zero_panics`, `test_bft3f1_quorum_zero_panics`,
  `test_bft5f1_max_faults_zero_panics`, `test_bft5f1_quorum_zero_panics`,
  `test_bft5f1_m_quorum_zero_panics`, `test_bft5f1_l_quorum_zero_panics`,
  `test_max_faults_negative_panics`, `test_max_faults_overflow_panics`,
  `test_quorum_negative_panics`, `test_quorum_overflow_panics`: #[should_panic]
- `futures.rs` `test_rebind_empty_slot_panics`, `test_rebind_entry_missing_entry_panics`;
  `handles.rs` `test_partition_rejects_a_count_that_is_not_a_power_of_two`;
  `iter.rs` `zip_eq_panics_when_right_is_shorter`, `zip_eq_panics_when_left_is_shorter`,
  `macro_rejects_empty_iterators`; `lib.rs` `test_modulo_zero_panics`,
  `test_participant_from_usize_overflow`; `probability.rs`
  `expression_macro_rejects_invalid_probability`; `rational/mod.rs` `log2_ceil_negative_panics`,
  `log2_floor_negative_panics`; `time.rs` `test_epoch_panics`, `test_epoch_millis_panics`;
  `vec.rs` `test_from_unchecked_panics_on_empty`, `test_mutate_panics_on_empty`: #[should_panic]
- `time.rs` `test_as_millis_u64_overflow`; `sampling.rs`
  `weighted_index_update_panics_preserve_index`, `without_replacement_restores_weights_on_unwind`;
  `thread_local.rs` `test_nested_guards_rejected`, `test_create_panic_does_not_poison_held_flag`,
  `test_reset_panic_does_not_poison_held_flag`: assert via catch_unwind (panic/unwind)
- `cache.rs` `displaced_key_destructors_follow_replacement_bookkeeping`: panicking key Drop
  under catch_unwind
- `cache.rs` `eviction_does_not_clone_keys`, `canonical_key_move_and_ghost_drop_ownership`:
  key clone counting and Rc/Drop ownership counts
- `cache.rs` `test_ghost_rehash_reads_live_keys`, `collisions_rehash_and_stable_values`,
  `distinct_hashes_rehash_and_stable_values`: force hashbrown lazy growth; Zig indexes are
  preallocated with `init_capacity` (cache.zig:336, 462) and never rehash
- `futures/shared.rs` `test_clones_share_output_and_poll_one_at_a_time`,
  `test_clone_after_completion_resolves`, `test_wake_during_poll_rewakes_clone_polled_meanwhile`,
  `test_clone_finding_future_busy_is_woken_after_poll`,
  `test_dropped_woken_clone_leaves_others_woken`,
  `test_last_clone_drops_future_despite_retained_waker`, `test_panic_poisons_every_clone`,
  `test_clones_poll_inner_future_once_per_wake`,
  `test_panicking_replaced_waker_poisons_every_clone`, `test_output_clone_may_wake_inner_future`,
  `test_destroyed_waker_may_drop_a_registered_clone::case_1_replaced`,
  `test_destroyed_waker_may_drop_a_registered_clone::case_2_dropped`,
  `test_last_drop_with_panicking_waker_releases_future`: `Shared` not ported by design
  (docs/lanes/utils.md Decisions)
- `futures.rs` `test_rebind_restores_value_and_yields_rest`, `test_rebind_error_destroys_value`,
  `test_rebind_entry_restores_value_and_yields_rest`, `test_rebind_entry_error_destroys_value`,
  `test_option_future`: `rebind`/`rebind_entry`/`OptionFuture` not ported by design (utils.md)
- `futures.rs` `test_dummy_future_doesnt_resolve`: Zig `Pool.next_completed` asserts a
  non-empty pool (futures.zig:73); no pending-forever empty pool
- `futures.rs` `test_borrowing_futures`, `test_abortable_pool_borrowing_futures`;
  `futures/try_join_all.rs` `supports_borrowed_non_send_values`: Rust lifetimes/borrowed futures
- `futures/try_join_all.rs` `cancellation_drops_futures_and_values::case_{1..4}::poll_{1_false,
  2_true}` (8), `completed_future_drop_unblocks_another::case_{1,2,3}` (3): outer-future drop
  and Drop side effects/counts
- `futures/try_join_all.rs` `later_error_wakes_caller::case_{1,2,3}` (3): Waker wake counting
- `futures/try_join_all.rs` `consumes_non_send_iterator_before_returning_send_future`: Send
  bound; `size_hint_can_change`: Rust Iterator::size_hint collector choice
- `channel/ring.rs` `test_receiver_drop_releases_waker`, `test_replaced_waker_dropped_outside_lock`:
  Waker registration internals
- `channel/ring.rs` `test_send_all`: futures `Sink::send_all`
- `channel/tracked.rs` `test_batch_destructor_can_read_watermark`: documented, batch IDs are
  plain values (utils.md Decisions)
- `sync/mod.rs` `test_traced_async_mutex`, `test_traced_async_rwlock`; `sync/exclusive.rs`
  `test_exclusive_is_sync_and_grants_exclusive_access`: traced locks and `Exclusive` not ported
  by design (utils.md)
- `sync/mod.rs` `test_async_rwlock`: re-exported tokio `RwLock`; Zig uses `std.Io.RwLock`
  (utils.md)
- `lib.rs` `test_max`: const fn `max` is `@max` by decision (utils.md)
- `hostname.rs` `test_hostname_try_from`, `test_hostname_into_string`: TryFrom/String conversions
- `iter.rs` `macro_ignores_colliding_into_iterator_methods`: Rust macro method resolution
- `ordered.rs` `test_map_deref_to_set`: Deref impl; `test_map_from_set`: FromIterator conversion
- `range.rs` `test_contains_cyclic_current_bounds`: partially consumed RangeInclusive iterator
  state; `test_non_empty_range_into`: From impl; `test_non_empty_range_debug`: Debug impl;
  `test_non_empty_range_iter`: IntoIterator impl
- `rng.rs` `test_try_fill_bytes_consistency_with_fill_bytes`: rand `TryRng::try_fill_bytes`
- `vec.rs` `test_try_from_iterator`: TryCollect trait; `test_from_non_empty_vec`: From impl;
  `test_iterators`: iter/iter_mut/IntoIterator impls; `test_as_ref`: AsRef impls

### utils (bitmap/)
| File | Tests | Ported | Open | Not portable |
| --- | --- | --- | --- | --- |
| bitmap/atomic.rs | 5 | 2 | 0 | 3 |
| bitmap/mod.rs | 74 | 57 | 8 | 9 |
| bitmap/prunable.rs | 54 | 44 | 0 | 10 |
| bitmap/historical/tests.rs | 20 | 17 | 0 | 3 |
| bitmap/roaring/container/array.rs | 25 | 24 | 1 | 0 |
| bitmap/roaring/container/bitmap.rs | 26 | 21 | 5 | 0 |
| bitmap/roaring/container/mod.rs | 27 | 12 | 15 | 0 |
| bitmap/roaring/container/run.rs | 26 | 21 | 3 | 2 |
| bitmap/roaring/fuzz.rs | 1 | 1 | 0 | 0 |
| bitmap/roaring/mod.rs | 32 | 28 | 0 | 4 |
| bitmap/roaring/ops.rs | 43 | 43 | 0 | 0 |
| bitmap/roaring/prunable.rs | 27 | 22 | 0 | 5 |
| **Total** | **360** | **292** | **32** | **36** |

Open:
- [ ] `bitmap/mod.rs:1800` `test_multi_chunk_operations`: and/or/xor over two full 4-byte chunks
- [ ] `bitmap/mod.rs:1843` `test_partial_chunk_operations`: and/or/xor keep length on 35-bit maps
- [ ] `bitmap/mod.rs:2128` `test_ones_iter_empty`: ones_iter of an empty bitmap yields nothing
- [ ] `bitmap/mod.rs:2135` `test_ones_iter_all_zeros`: ones_iter of zeroes(100) yields nothing
- [ ] `bitmap/mod.rs:2162` `test_ones_iter_single_bit`: one-bit bitmap, set and unset
- [ ] `bitmap/mod.rs:2219` `test_ones_iter_matches_count_ones`: ones_iter count equals count_ones
- [ ] `bitmap/mod.rs:2716` `test_from_different_chunk_sizes`: from_bools at N=8 and N=16
- [ ] `bitmap/mod.rs:2960` `is_unset_chunk_boundaries`: is_unset with N=1 (8-bit chunks)
- [ ] `bitmap/roaring/container/array.rs:796` `test_union_disjoint_unlimited`: union copies b's
  tail when b lies entirely after a
- [ ] `bitmap/roaring/container/bitmap.rs:636` `test_iterator_size_hint_after_exhaustion_regression`:
  iter remaining() is 0 after exhaustion
- [ ] `bitmap/roaring/container/bitmap.rs:849` `test_encode_size_independent_of_cardinality`: full
  bitmap encode_size equals empty
- [ ] `bitmap/roaring/container/bitmap.rs:911` `test_run_count_idempotent_on_duplicate`: duplicate
  insert leaves run_count unchanged
- [ ] `bitmap/roaring/container/bitmap.rs:920` `test_run_count_at_boundaries`: run_count at 0 and
  u16 max, extending inward
- [ ] `bitmap/roaring/container/bitmap.rs:964` `test_from_words_run_count_matches_scan`:
  from_words alternating word gives run_count 32
- [ ] `bitmap/roaring/container/mod.rs:742` `test_new_container`: new container is empty, array kind
- [ ] `bitmap/roaring/container/mod.rs:766` `test_equality_ignores_representation`: eql across
  array/bitmap/run kinds
- [ ] `bitmap/roaring/container/mod.rs:786` `test_decode_rejects_noncanonical_sparse_bitmap_container`:
  sparse bitmap payload rejected (only array-as-run tested)
- [ ] `bitmap/roaring/container/mod.rs:807` `test_decode_rejects_noncanonical_full_bitmap_container`:
  full bitmap payload rejected
- [ ] `bitmap/roaring/container/mod.rs:825` `test_encode_canonicalizes_sparse_bitmap_container`:
  sparse bitmap encodes and decodes as array
- [ ] `bitmap/roaring/container/mod.rs:838` `test_encode_canonicalizes_full_bitmap_container`:
  full bitmap encodes and decodes as run
- [ ] `bitmap/roaring/container/mod.rs:848`
  `test_encode_sparse_bitmap_container_spanning_first_to_last_word`: values in first/last words
- [ ] `bitmap/roaring/container/mod.rs:871` `test_encode_sparse_run_container_ending_at_max`:
  sparse run ending at u16 max encodes as array
- [ ] `bitmap/roaring/container/mod.rs:891`
  `test_decode_normalization_is_idempotent_after_run_to_bitmap`: re-encode is stable
- [ ] `bitmap/roaring/container/mod.rs:940` `test_max_cardinality_serializes_as_bitmap`: 4096-value
  array decodes as bitmap
- [ ] `bitmap/roaring/container/mod.rs:980`
  `test_insert_range_overlap_noop_does_not_force_bitmap_conversion`: no-op range keeps array
- [ ] `bitmap/roaring/container/mod.rs:1089` `test_no_thrash_in_hysteresis_band`: bitmap stays
  bitmap inside the threshold band
- [ ] `bitmap/roaring/container/mod.rs:1120` `test_union_bitmap_fast_path_normalizes_to_run`:
  bitmap union result is run kind
- [ ] `bitmap/roaring/container/mod.rs:1132`
  `test_intersection_bitmap_fast_path_normalizes_to_array_when_sparse`: result kind array
- [ ] `bitmap/roaring/container/mod.rs:1150`
  `test_difference_bitmap_fast_path_normalizes_to_array_when_sparse`: result kind array
- [ ] `bitmap/roaring/container/run.rs:771` `test_from_full_bitmap`: full bitmap converts to one run
- [ ] `bitmap/roaring/container/run.rs:796` `test_encode_size_empty`: empty run encode size
- [ ] `bitmap/roaring/container/run.rs:802` `test_encode_size_grows_per_run`: encode size for 5 runs

Not portable:
- `bitmap/atomic.rs` `test_set_past_len_panics`, `test_set_past_len_in_tail_word_panics`,
  `test_set_on_empty_panics`: #[should_panic]
- `bitmap/mod.rs` `test_truncate_larger_size_panics`, `test_pop_chunk_not_aligned`,
  `test_pop_chunk_insufficient_bits`, `test_flip_out_of_bounds`, `test_and_length_mismatch`,
  `test_or_length_mismatch`, `test_xor_length_mismatch`, `test_prune_too_many_chunks`,
  `is_unset_out_of_bounds`: #[should_panic]
- `bitmap/prunable.rs` `test_get_pruned_bit_panics`, `test_get_pruned_chunk_panics`,
  `test_set_pruned_bit_panics`, `test_prune_to_bit_out_of_bounds`,
  `test_truncate_into_pruned_region_panics`, `test_pop_chunk_not_aligned`,
  `test_pop_chunk_insufficient_bits`, `test_set_chunk_by_index_rejects_high_bits_in_last_byte`,
  `test_set_chunk_by_index_rejects_nonzero_trailing_bytes`,
  `test_set_chunk_by_index_rejects_nonzero_final_byte`: #[should_panic]
- `bitmap/historical/tests.rs` `test_read_popped_bit_panics`, `test_prune_beyond_length_panics`,
  `test_pop_into_pruned_region_panics`: #[should_panic]
- `bitmap/roaring/container/run.rs` `test_arbitrary_can_generate_run_starting_at_zero`,
  `test_arbitrary_can_generate_trailing_max_singleton`: Rust Arbitrary impl
- `bitmap/roaring/mod.rs` `test_from_iter_empty`, `test_from_iter_basic`,
  `test_from_iter_range_expression`, `test_extend_into_existing`: Rust FromIterator/Extend impls
- `bitmap/roaring/prunable.rs` `test_panic_on_insert_below_pruned`,
  `test_panic_on_contains_below_pruned`, `test_panic_on_insert_range_below_pruned`,
  `test_panic_on_iter_range_below_pruned`, `test_extend_below_pruned_panics`: #[should_panic]

