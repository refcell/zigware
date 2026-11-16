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
