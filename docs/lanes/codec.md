# Lane: codec

Owns `src/formatting`, `src/conformance`, `src/invariants`, `src/codec`. Everything else
builds on codec, so land the core API first and keep it stable; record each public type
here so other lanes can code against it.

Reference: `~/.cache/zigware/commonware-ref/{formatting,conformance,invariants,codec}`.

## Public API (stable)

### formatting

- `hex(gpa, bytes) ![]u8` lowercase hex (caller frees); `hex_encode(out, bytes) []u8` no alloc.
- `from_hex(gpa, string) !?[]u8`: strips space/tab/CR/LF and one `0x`/`0X` (commonware order);
  null on invalid input.
- `fmt_hex(bytes)` / `Hex{ .bytes }`: `{f}` formatter, no allocation.
- `hex_literal("0x12 34")` comptime `[N]u8` (commonware `hex!`); join literals with `++`.

### codec

Every value goes through comptime dispatch on its type (`src/codec/codec.zig` has the table):

| Zig type | commonware | wire |
| --- | --- | --- |
| `bool` | `bool` | 1 byte, 0/1 (else `InvalidBool`) |
| `u8`..`u128`, `i8`..`i128` | same | fixed big-endian |
| any unsigned `uN` (`u36`, `u256`, ...) | `Uint<BITS, LIMBS>`, `U256` | big-endian in ceil(N/8) bytes; bits beyond N are `Invalid` |
| `f32`, `f64` | same | IEEE bits big-endian |
| `usize` | `usize` | `UInt<u32>` varint; cfg `RangeCfg(usize)` |
| `[N]T` | `[T; N]` | elements, no prefix |
| `?T` | `Option<T>` | bool + value |
| `[]const T` | `Vec<T>` | usize len + elements; decode allocates |
| `codec.Bytes` | `Bytes` | usize len + bytes; decode borrows the input (zero copy) |
| `*const T` | `Arc<T>` | the pointee; decode allocates |
| tuple `struct { A, B }` | `(A, B)` | fields in order; cfg is the tuple of cfgs |
| `enum(u8)` without methods | tag enums | tag; unknown tag is `InvalidEnum` |
| `codec.UInt(T)`, `codec.SInt(S)` | `UInt`, `SInt` | varint / ZigZag varint, any width |
| `codec.Map(K, V)`, `codec.HashMap(K, V)` | `BTreeMap`, `HashMap` | usize count + key/value pairs, keys strictly ascending |
| `codec.Set(K)`, `codec.HashSet(K)` | `BTreeSet`, `HashSet` | usize count + items strictly ascending |
| `codec.Ipv4`, `Ipv6`, `SocketAddrV4`, `SocketAddrV6` | std::net types | octets (+ u16 port) |
| `codec.IpAddr` (union v4/v6), `codec.SocketAddr` | `IpAddr`, `SocketAddr` | version byte 4/6 + addr (+ port) |
| `codec.NonZero(u16/u32/u64)` | `NonZeroU16/32/64` | the integer; zero is `Invalid` |
| `codec.Lazy(T)` | `Lazy<T>` | `T`'s bytes; read defers fixed-size `T`, `get(gpa)` decodes once, returns `?*const T` |
| `codec.Modes(N)` from `[N]u7` (`codec.mode(u8) ?u7`) | `Modes<N>`, `Mode` | continuation-bit packet |

Operations (`T` is always the first, comptime argument):

```zig
codec.encode(T, gpa, value) ![]u8           // exact size, asserts encode_size == written
codec.encode_to(T, value, out) []u8          // into a caller buffer
codec.encode_fixed(T, value) [N]u8           // FixedSize types
codec.encode_size(T, value) usize
codec.write(T, value, *codec.Writer) void
codec.decode_cfg(T, gpa, bytes, cfg) codec.Error!T   // rejects trailing bytes (ExtraData)
codec.decode(T, gpa, bytes)                  // unit cfg (void / tuple of voids)
codec.decode_range(T, gpa, bytes, range)     // slices: cfg = range + unit item cfg
codec.decode_fixed(T, *const [N]u8)          // FixedSize, non-allocating types
codec.decode_reader(T, gpa, *Reader, cfg)    // like decode_cfg, keeps reader.diagnostic
codec.read_cfg(T, gpa, *codec.Reader, cfg) / read / read_range / read_fixed
codec.read_items(T, gpa, reader, len, cfg) ![]T  // Read::read_vec (no prefix)
codec.read_usize(reader, range)              // length prefix + range check
codec.free(T, gpa, value)                    // free whatever decode allocated
codec.Cfg(T), codec.fixed_size(T) ?usize, codec.max_encode_size(T) ?usize,
codec.owns_memory(T) bool, codec.SliceCfg(ItemCfg) = struct { range, item }
codec.util.max_items_size(len, item_size), codec.util.ensure_zeros(reader, n)
codec.varint.{write, read, size, write_signed, read_signed, size_signed, Decoder, max_size}
```

`codec.Reader` (`init(bytes)`, `remaining`, `rest`, `take(n)`, `take_array(n)`, `read_byte`,
`read_int(T)`, `skip`, `at_least`, `at_least_items`, `invalid(ctx, msg)`, `fail(err, value)`,
`diagnostic`) and `codec.Writer` (`init(buf)`, `write_bytes`, `write_byte`, `write_int(T, v)`,
`written`). Writers assert capacity (commonware panics too); readers never panic on input.

`codec.Error` = `EndOfBuffer, ExtraData, InvalidVarint, InvalidUsize, InvalidBool,
InvalidEnum, InvalidLength, Invalid, Wrapped, OutOfMemory`. The Rust payloads (extra byte
count, varint width, enum tag, length, context/message) go to `reader.diagnostic`.

Custom types declare the interface (all methods take `self: Self` or `self: *const Self`):

```zig
pub const Cfg = ...;                  // optional, default void
pub const fixed_size: usize = N;      // optional: FixedSize (then encode_size is optional)
pub const max_encode_size: usize = M; // optional: MaxEncodeSize
pub fn write(self: Self, writer: *codec.Writer) void
pub fn encode_size(self: Self) usize
pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self
pub fn deinit(self: *Self, gpa: Allocator) void   // optional: frees what read allocated
```

Use `reader.invalid("Type", "message")` for `Error::Invalid(ctx, msg)`.

Maps and sets wrap a sorted slice: `M.sort(entries)` then `M.init(entries)` (asserts strictly
ascending keys), `.get(key)` / `.contains(item)` by binary search. Map cfg is
`.{ .range, .key, .value }` (void parts default), set cfg is `.{ .range, .item }`.
Decoded maps/sets own their slice: free with `codec.free(M, gpa, m)` or `m.deinit(gpa)`.
`codec.order(T, a, b)` is Rust's `Ord` (custom types declare `order(a, b) std.math.Order`).

### conformance (for other lanes)

A conformance type declares `pub fn commit(gpa, seed: u64) ![]u8`. Copy the crate's
`conformance.toml` next to the test and call
`conformance.verify(C, gpa, "<rust type path>", conformance.default_cases, @embedFile(...))`.
For codec types, build values with `codec.arbitrary.generate(T, gen, arena, seed)` where `gen`
is `codec.arbitrary.default_generator(T)` or a hand-written port of the Rust `Arbitrary` impl
(see `src/codec/conformance_test.zig`). Pass `std.heap.smp_allocator` for 65536-case runs.

### invariants (minifuzz, for other lanes' property tests)

```zig
const minifuzz = @import("invariants").minifuzz;
try minifuzz.run(testing.allocator, context, body);            // default Builder
try (minifuzz.Builder{}).with_search_limit(1000).with_seed(0)
    .run(testing.allocator, context, body);
// body: fn (@TypeOf(context), u: *minifuzz.Unstructured) !void
```

Builder: `with_seed`, `with_search_limit`, `with_search_time(io, duration)`,
`with_min_iterations`, `with_reproduce("0x...")`; `search(...)` returns
`Outcome{ passed: Branch, failed: Failure{ branch, err, sampling } }` instead of printing.
The body fails by returning an error (use `testing.expect*`, not `assert`);
`error.NotEnoughData` asks for more input and `error.IncorrectFormat` rejects it. A failure
prints `failure (MINIFUZZ_BRANCH = 0x...)`; replay one test with `with_reproduce`, or all with
`zig build test -Dminifuzz-branch=0x...`.
After the search passes, minifuzz runs as many long-input cases (128, 512, and 2048 random
bytes in turn, at most `long_cases_max`) as the search had tries, so bodies whose generators
pad with zeros reach their later actions. A long case's token has `long_input_bit` set in its
size and replays the same way.

`Unstructured` (arbitrary 1.4, same bytes to same values): `arbitrary(T)` for bool, ints,
floats, arrays, optionals, structs/tuples, enums (`derive` scaling), or `T.arbitrary(u)`;
`int_in_range(T, lo, hi)`, `choose(T, items)`, `choose_index(n)`, `ratio(T, num, den)`,
`bytes(n)`, `fill(out)`, `byte_size()`, `arbitrary_len(T)`, `peek_bytes`, `take_rest`,
`len`, `is_empty`. Collections: `for (0..u.arbitrary_len(T))` and append.

### codec.fuzz.Draws (Smith bodies on seeded input)

Smith's typed draws are nearly inert on seeded random input (see AGENTS.md, "Fuzz bodies").
A `fn (ctx, *std.testing.Smith) !void` body draws through
`const draws: codec.fuzz.Draws = .init(smith);` (`utils.fuzz.Draws` re-exports it):
`value(T)` for ints, floats, bool, exhaustive enums, and arrays of them; `range_at_most(T, lo,
hi)`, `range_less_than`, `index(len)`, `bytes(out)`, and `slice(buffer)` (the rest of a seeded
input or corpus entry, as written). Draws past the end of the input read zeros. Bound loops
with a drawn count (`for (0..draws.range_at_most(u32, 0, max))`), never `smith.eos()`.

## Decisions

- Zig errors carry no payload; payloads live in `Reader.diagnostic`.
- Readers take one contiguous slice (no `Chain`/`Take` buffers). `Bytes` borrows (like
  `Viewing`), `[]const u8` copies (like `Vec<u8>`/`Copying`). Same wire format.
- Decoding takes an explicit allocator; non-allocating types ignore it. `read_fixed` and
  `decode_fixed` use `Allocator.failing`.
- `write_bufs`/`BufsMut` (vectored writes) are not ported yet; writes go to one buffer.
- One map and one set implementation serve both BTree and Hash flavors (same wire format);
  the flavor only picks the `Invalid` error context ("BTreeMap" vs "HashMap").
- `**` array repetition is gone in Zig 0.17.1: use `@splat`.
- Variable-size slice decoding reserves `min(len, remaining)` items up front like commonware;
  fixed-size elements check `len * size` bytes remain before allocating.
- formatting/codec/conformance/invariants sit below `utils`, so their tests cannot use
  `utils.rng.TestRng`; the conformance generator ports ChaCha8 `seed_from_u64` itself.
- minifuzz defaults to `default_search_limit` (10000) cases times `-Dfuzz-soak` instead of
  commonware's 10 s (time needs an `std.Io`), seeds from `-Dfuzz-seed` instead of the OS, and
  takes `-Dminifuzz-branch` instead of reading `MINIFUZZ_BRANCH` from the environment.
- conformance does no file I/O: TOML text comes in via `@embedFile`, and a missing entry fails
  and prints the entry to add (commonware writes the file instead).

## Backlog
- [x] formatting: hex encode/decode (`hex`, `from_hex`), display helper (`Hex`), comptime hex
  literal parsing. Tests from formatting/src.
- [x] codec core: comptime `write`/`read`/`encode_size` interface, error set matching
  error.rs, `RangeCfg`, buffer helpers (`Reader`/`Writer`), util.rs.
- [x] codec varint (any unsigned width, ZigZag signed) byte-identical to varint.rs, with tests.
- [x] codec types: primitives, arrays, optional, vec, tuple, bytes, Arc (pointer).
- [x] varint: rest of varint.rs tests (exhaustive u16/i16, bit boundaries, narrow, partial,
  and u256 widths).
- [x] codec fuzz: `codec/fuzz.zig` seeded driver (Smith over a seeded PRNG, `fuzz_soak`,
  `fuzz_seed`, then `std.testing.fuzz`); targets port codec_roundtrip.rs plus a
  decode-canonical target (any successful decode re-encodes to the exact input).
- [x] codec types: maps/sets (sorted, canonical, reject duplicates/unsorted), with tests.
- [x] codec types: net addrs, mode (`Mode`/`Modes`), with tests and fuzz.
- [x] codec types: lazy, uint.rs (any-width unsigned `uN`, incl. `u256`), with tests.
- [x] conformance: hash-of-encodings harness (`conformance.compute_hash`, `find`, `verify`
  over an `@embedFile`d TOML), with the crate's tests.
- [x] codec conformance: `codec.arbitrary` reproduces rand_core `seed_from_u64` + ChaCha8 and
  arbitrary 1.4 bit for bit; all 51 hashes in commonware's codec/conformance.toml match.
- [x] invariants: minifuzz (Builder, Branch tokens, ChaCha8 Sampler and its strategies) plus
  arbitrary 1.4's `Unstructured`, with the crate's tests and a byte-exact sampler vector.
- [x] extend the codec fuzz targets: net, mode, NonZero, and a Lazy property (deferred `get`
  agrees with a direct decode); maps/sets done.
- [x] remaining codec.rs/buf.rs tests: generic FixedArray conversions (`encode_fixed`,
  `decode_fixed`, `decode` cover the derive), Viewing cursor tests on `Reader` + `Bytes`.
  Chained-buffer and `should_panic` tests have no Zig counterpart (contiguous readers;
  programmer errors are assertions).
- [x] benches: formatting (encode/decode/display) and codec (lazy, utils fixtures), ported
  by the coding lane (`src/formatting/benches.zig`, `src/codec/benches.zig`).

Not ported by design: conformance/macros `fixtures` (a nextest-inventory CI tool for stale
TOML entries; here a missing entry fails `verify` and prints the line to add), and the
`conformance_tests!` macro (call `conformance.verify` in a test instead).

## Log
- 2026-11-13: formatting (hex, from_hex, Hex, hex_literal) and codec core (Reader/Writer,
  Error, RangeCfg, varint, primitives, arrays, optional, vec, tuple, Bytes, pointer) landed.
- 2026-11-13: remaining varint tests; codec seeded fuzz driver and roundtrip/canonical targets.
- 2026-11-13: canonical Map/HashMap/Set/HashSet and `codec.order`, with tests and fuzz.
- 2026-11-13: net addresses (Ipv4/Ipv6/SocketAddr*/IpAddr) and Modes, with tests and fuzz.
- 2026-11-13: any-width unsigned integers (Uint/U256) and Lazy, with tests and fuzz.
- 2026-11-13: conformance harness, codec arbitrary/ChaCha8 port, NonZero; all 51 commonware
  codec conformance hashes match.
- 2026-11-13: invariants: minifuzz (Builder, Branch tokens, Sampler) and `Unstructured`
  (arbitrary 1.4); sampler stream matches commonware's byte for byte.
- 2026-11-13: codec fuzz covers NonZero and Lazy; generic FixedArray and Viewing tests.

## Test audit (2026-11-19, against main)

Drift check (commonware 43b357a41 to a9ffc25f3, p2p lane, 2026-11-19): 883eae27e folds
`types/lazy.rs`'s six proptests into one minifuzz `test_lazy_matches_direct` and adds
`codec/src/fuzz.rs` `test_fuzz_plan`, which runs the same Lazy plan. The properties are unchanged,
and `types/lazy.zig`'s exhaustive tests over all 256 bytes already check each one (encoding through
`new` and `deferred`, `new` equal to `deferred`, order and equality, decoding agreement). No code
change.

Every commonware `#[test]` in this lane's crates (macro and rstest cases expanded where noted), matched by reading both sides: ported (a Zig test checks the behavior, often one consolidated test), open, or not portable with the reason. Written by the consensus-marshal lane; tick a box when its test lands.

### codec
| File | Tests | Ported | Open | Not portable |
| --- | --- | --- | --- | --- |
| buf.rs | 16 | 9 | 0 | 7 |
| codec.rs | 13 | 7 | 0 | 6 |
| config.rs | 8 | 7 | 0 | 1 |
| mode.rs | 8 | 5 | 0 | 3 |
| types/btree_map.rs | 7 | 7 | 0 | 0 |
| types/btree_set.rs | 7 | 7 | 0 | 0 |
| types/bytes.rs | 3 | 3 | 0 | 0 |
| types/hash_map.rs | 15 | 13 | 1 | 1 |
| types/hash_set.rs | 14 | 13 | 0 | 1 |
| types/lazy.rs | 9 | 9 | 0 | 0 |
| types/net.rs | 8 | 8 | 0 | 0 |
| types/primitives.rs (18 + 12 from `impl_num_test!`) | 30 | 26 | 0 | 4 |
| types/tuple.rs | 2 | 2 | 0 | 0 |
| types/vec.rs | 6 | 4 | 0 | 2 |
| uint.rs | 4 | 4 | 0 | 0 |
| util.rs | 4 | 2 | 0 | 2 |
| varint.rs | 18 | 15 | 0 | 3 |
| Total | 172 | 141 | 1 | 30 |

Open:
- [x] `types/hash_map.rs:407` `test_hashmap_malicious_allocation`: u32::MAX map length, one entry,
  fails EndOfBuffer unallocated
  (map_test.zig checks this for sets only; `Map.read` is never fed a hostile length)

Not portable:
- `buf.rs` `test_take_owned_claims_matching_views`, `test_take_owned_through_adapters`: custom
  `Buf`/`OwnedBytes` storage types and `Take`/`Chain` adapters; Zig reads one contiguous slice
  (codec.md Decisions)
- `buf.rs` `test_try_take_owned_reports_shortfall`: checks the error's requested/available
  payload and `Take` limits; Zig errors carry no payload and there are no adapters (codec.md).
  A short read leaving the cursor unchanged is in buf.zig "reader reads and bounds"
- `buf.rs` `test_take_owned_past_inner_end`, `test_viewing_advance_past_end`,
  `test_viewing_copy_past_end`, `test_viewing_split_past_end`; `codec.rs` `test_encode_fixed_panic`,
  `test_decode_fixed_panic`; `mode.rs` `mode_macro_rejects_invalid_expressions`;
  `types/primitives.rs` `test_usize_encode_panic`, `test_usize_write_panic`; `util.rs`
  `test_max_items_size_beyond_prefix`: #[should_panic] (Zig asserts or returns EndOfBuffer)
- `codec.rs` `test_fixed_array_infallible`, `test_fixed_array_generic_infallible`,
  `test_fixed_array_bounded_generic`, `test_fixed_array_lifetime`: `FixedArray` derive variants
  (infallible `From`, trait bounds, lifetimes) are Rust derive/trait features; the round trip is
  in codec_test.zig "custom fixed-size type" and "generic fixed array conversions"
- `config.rs` `test_type_inference`: Rust type inference for `RangeCfg::new`
- `mode.rs` `macro_converts_heterogeneous_values`, `mode_macro_constructs_literals_and_expressions`:
  `modes!`/`mode!` macros and `From<_> for Mode`; Zig has plain `mode()` and `Modes(N).init`
- `types/hash_map.rs` `test_hashmap_encoding_matches_ordered_map`, `types/hash_set.rs`
  `test_hashset_encoding_matches_ordered_set`: one implementation serves the BTree and Hash
  flavors, so they cannot differ (codec.md), and the `write_bufs` half is not ported
- `types/primitives.rs` `test_array_specialization_selection`, `types/vec.rs`
  `test_specialization_selection`: count `put_slice`/`put_u8` calls through mock `BufMut`/`Buf`
  trait impls, and `write_bufs`; Zig `Writer` has no such hook
- `types/primitives.rs` `test_array_write_bufs_equivalence`, `types/vec.rs`
  `test_write_bufs_equivalence`: `write_bufs`/`BufsMut` not ported (codec.md Decisions)
- `util.rs` `test_ensure_zeros_across_chunks`, `varint.rs` `test_fragmented_varint`: chained
  (non-contiguous) `Buf`; Zig `Reader` is one contiguous slice (codec.md Decisions)
- `varint.rs` `test_varuint_into`, `test_varsint_into`: `From`/`Into` impls on `UInt`/`SInt`

### formatting
| File | Tests | Ported | Open | Not portable |
| --- | --- | --- | --- | --- |
| hex_literal.rs | 11 | 11 | 0 | 0 |
| lib.rs | 6 | 4 | 0 | 2 |
| Total | 17 | 15 | 0 | 2 |

Open:
- none

Not portable:
- `lib.rs` `test_hex_newtype_debug`, `test_hex_newtype_from`: `Debug` and `From<T> for Hex<T>`
  trait impls; Zig `Hex` only has `format` (its "ff00" output is in root.zig
  "hex formatter display")

