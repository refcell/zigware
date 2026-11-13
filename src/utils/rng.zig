//! Deterministic random number generators for tests and fuzzing (commonware `utils/src/rng.rs`).
//!
//! - `TestRng`: byte-identical to commonware's `TestRng` (Rust `rand` 0.10 `StdRng`, which is
//!   ChaCha12 seeded through `SeedableRng::seed_from_u64`), so tests and conformance hashes
//!   that draw from it reproduce commonware's values exactly.
//! - `ScriptedRng`: returns a caller-supplied sequence of `u64` samples.
//! - `FuzzRng`: expands a fuzzer byte slice into an infinite deterministic stream.
//!
//! Every generator implements the same small comptime interface: `next_u32`, `next_u64`,
//! and `fill_bytes`. The sampling helpers below (`range_less_than`, `range_at_most`,
//! `boolean`, `bernoulli`, `ratio`, `float64`) reproduce `rand` 0.10's algorithms on top of
//! that interface, so a Zig port consumes randomness exactly like the Rust original.
//! `random(rng)` adapts any generator to `std.Random` where parity does not matter.
//!
//! Library code never draws OS entropy; the runtime supplies randomness.

const std = @import("std");
const assert = std.debug.assert;

/// 64-bit golden-ratio-derived odd mixing constant, `floor(2^64 / phi)`.
pub const GOLDEN_RATIO: u64 = 0x9e37_79b9_7f4a_7c15;

/// Comptime check that `Rng` implements the generator interface.
pub fn assert_rng(comptime Rng: type) void {
    comptime {
        assert(@hasDecl(Rng, "next_u32"));
        assert(@hasDecl(Rng, "next_u64"));
        assert(@hasDecl(Rng, "fill_bytes"));
    }
}

/// Applies a SplitMix64-style finalizer to a deterministic input word.
pub fn mix64(input: u64) u64 {
    var word = input;
    word ^= word >> 30;
    word *%= 0xbf58_476d_1ce4_e5b9;
    word ^= word >> 27;
    word *%= 0x94d0_49bb_1331_11eb;
    return word ^ (word >> 31);
}

/// `rand_core`'s PCG32 step used by `SeedableRng::seed_from_u64`.
fn pcg32(state: *u64) [4]u8 {
    const multiplier: u64 = 0x5851_F42D_4C95_7F2D;
    const increment: u64 = 0xA176_54E4_6FBE_17F3;
    state.* = state.* *% multiplier +% increment;
    const current = state.*;
    const xorshifted: u32 = @truncate(((current >> 18) ^ current) >> 27);
    const rotation: u32 = @truncate(current >> 59);
    var out: [4]u8 = undefined;
    std.mem.writeInt(u32, &out, std.math.rotr(u32, xorshifted, rotation), .little);
    return out;
}

/// Deterministic RNG for tests: ChaCha12 with a 64-bit block counter and zero stream id,
/// buffered four blocks at a time, exactly as Rust `rand` 0.10's `StdRng`.
pub const TestRng = struct {
    const ChaCha = std.crypto.stream.chacha.ChaCha12With64BitNonce;
    const block_words = 16;
    const buffer_blocks = 4;
    const buffer_words = block_words * buffer_blocks;

    key: [32]u8,
    /// Block counter of the next buffer to generate.
    block_counter: u64,
    words: [buffer_words]u32,
    /// Next word to return; `buffer_words` means the buffer is exhausted.
    index: usize,

    /// Returns a deterministic RNG seeded with `seed` (Rust `StdRng::seed_from_u64`).
    pub fn init(seed: u64) TestRng {
        var key: [32]u8 = undefined;
        var state = seed;
        var chunk: usize = 0;
        while (chunk < key.len / 4) : (chunk += 1) {
            key[chunk * 4 ..][0..4].* = pcg32(&state);
        }
        return init_key(key);
    }

    /// Returns a deterministic RNG from a 32-byte ChaCha key (Rust `StdRng::from_seed`).
    pub fn init_key(key: [32]u8) TestRng {
        const rng: TestRng = .{
            .key = key,
            .block_counter = 0,
            .words = undefined,
            .index = buffer_words,
        };
        assert(rng.index == buffer_words);
        return rng;
    }

    fn generate(rng: *TestRng) void {
        var bytes: [buffer_words * 4]u8 = undefined;
        ChaCha.stream(&bytes, rng.block_counter, rng.key, @splat(0));
        for (&rng.words, 0..) |*word, i| {
            word.* = std.mem.readInt(u32, bytes[i * 4 ..][0..4], .little);
        }
        rng.block_counter +%= buffer_blocks;
        rng.index = 0;
    }

    pub fn next_u32(rng: *TestRng) u32 {
        assert(rng.index <= buffer_words);
        if (rng.index == buffer_words) rng.generate();
        const value = rng.words[rng.index];
        rng.index += 1;
        assert(rng.index <= buffer_words);
        return value;
    }

    /// Two consecutive words, low then high; mirrors `BlockRng::next_u64_from_u32`, which
    /// straddles a buffer refill when only one word is left.
    pub fn next_u64(rng: *TestRng) u64 {
        assert(rng.index <= buffer_words);
        const low = rng.next_u32();
        const high = rng.next_u32();
        return (@as(u64, high) << 32) | low;
    }

    /// Fills `dest` with little-endian words; a partially used final word is discarded.
    pub fn fill_bytes(rng: *TestRng, dest: []u8) void {
        var written: usize = 0;
        while (written < dest.len) {
            const word = rng.next_u32();
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            const take = @min(bytes.len, dest.len - written);
            @memcpy(dest[written..][0..take], bytes[0..take]);
            written += take;
        }
        assert(written == dest.len);
    }
};

/// Returns `TestRng` seeded with 0 (commonware's `test_rng()`).
pub fn test_rng() TestRng {
    return TestRng.init(0);
}

/// A bounded deterministic RNG that returns a caller-supplied sequence of `u64` samples.
///
/// Each `u32` consumes one sample and returns its low 32 bits. Byte fills encode samples
/// in little-endian order and discard unused bytes of the final sample. Sampling beyond
/// the supplied sequence panics.
pub const ScriptedRng = struct {
    samples: []const u64,
    position: usize,

    pub fn init(samples: []const u64) ScriptedRng {
        return .{ .samples = samples, .position = 0 };
    }

    pub fn next_u64(rng: *ScriptedRng) u64 {
        assert(rng.position <= rng.samples.len);
        if (rng.position == rng.samples.len) {
            @panic("scripted RNG consumed more samples than expected");
        }
        const value = rng.samples[rng.position];
        rng.position += 1;
        return value;
    }

    pub fn next_u32(rng: *ScriptedRng) u32 {
        return @truncate(rng.next_u64());
    }

    pub fn fill_bytes(rng: *ScriptedRng, dest: []u8) void {
        var written: usize = 0;
        while (written < dest.len) {
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, rng.next_u64(), .little);
            const take = @min(bytes.len, dest.len - written);
            @memcpy(dest[written..][0..take], bytes[0..take]);
            written += take;
        }
        assert(written == dest.len);
    }
};

/// Width of each `FuzzRng` source window in bytes.
const block_bytes = 8;

/// An RNG that expands a fuzzer byte slice into an infinite deterministic stream.
///
/// For block counter `i`, the source word is the big-endian `u64` of the wrapping window
/// `bytes[i % n .. (i + 7) % n]`, and the output block is `mix64(word ^ i ^ GOLDEN_RATIO)`.
/// A single input-byte mutation therefore only changes nearby blocks. Output is served
/// from cached block bytes, so `next_u64`, `next_u32`, and `fill_bytes` see one stream.
/// The input slice is borrowed and must outlive the generator.
pub const FuzzRng = struct {
    bytes: []const u8,
    counter: u64,
    cache: [block_bytes]u8,
    cache_position: usize,

    pub fn init(bytes: []const u8) FuzzRng {
        return .{
            .bytes = bytes,
            .counter = 0,
            .cache = @splat(0),
            .cache_position = block_bytes,
        };
    }

    fn next_block(rng: *FuzzRng) u64 {
        var window: [block_bytes]u8 = @splat(0);
        if (rng.bytes.len > 0) {
            const len: u64 = rng.bytes.len;
            for (&window, 0..) |*byte, i| {
                byte.* = rng.bytes[@intCast((rng.counter +% i) % len)];
            }
        }
        const word = std.mem.readInt(u64, &window, .big);
        const counter = rng.counter;
        rng.counter +%= 1;
        return mix64(word ^ counter ^ GOLDEN_RATIO);
    }

    pub fn fill_bytes(rng: *FuzzRng, dest: []u8) void {
        var written: usize = 0;
        while (written < dest.len) {
            assert(rng.cache_position <= block_bytes);
            if (rng.cache_position == block_bytes) {
                std.mem.writeInt(u64, &rng.cache, rng.next_block(), .big);
                rng.cache_position = 0;
            }
            const take = @min(block_bytes - rng.cache_position, dest.len - written);
            @memcpy(dest[written..][0..take], rng.cache[rng.cache_position..][0..take]);
            rng.cache_position += take;
            written += take;
        }
        assert(written == dest.len);
    }

    pub fn next_u32(rng: *FuzzRng) u32 {
        var bytes: [4]u8 = undefined;
        rng.fill_bytes(&bytes);
        return std.mem.readInt(u32, &bytes, .big);
    }

    pub fn next_u64(rng: *FuzzRng) u64 {
        var bytes: [8]u8 = undefined;
        rng.fill_bytes(&bytes);
        return std.mem.readInt(u64, &bytes, .big);
    }
};

comptime {
    assert_rng(TestRng);
    assert_rng(ScriptedRng);
    assert_rng(FuzzRng);
}

/// Adapts any generator to `std.Random` (backed by `fill_bytes`). `std.Random`'s
/// distributions differ from Rust `rand`'s; use the helpers below where parity matters.
pub fn random(rng: anytype) std.Random {
    const Rng = @typeInfo(@TypeOf(rng)).pointer.child;
    assert_rng(Rng);
    return std.Random.init(rng, Rng.fill_bytes);
}

/// Widening multiply: returns `(high, low)` halves of `a * b`.
fn wide_multiply(comptime T: type, a: T, b: T) struct { T, T } {
    const Wide = @Int(.unsigned, @bitSizeOf(T) * 2);
    const product = @as(Wide, a) * @as(Wide, b);
    return .{ @truncate(product >> @bitSizeOf(T)), @truncate(product) };
}

/// Draws a full-width `T` the way `rand` does: `u8`/`u16`/`u32` truncate `next_u32`.
fn draw(rng: anytype, comptime T: type) T {
    comptime assert(@typeInfo(T).int.signedness == .unsigned);
    return switch (@bitSizeOf(T)) {
        0...32 => @truncate(rng.next_u32()),
        33...64 => @truncate(rng.next_u64()),
        else => @compileError("unsupported width"),
    };
}

/// Uniform sample in `[low, high]` with `rand` 0.10's biased Canon method
/// (`UniformInt::sample_single_inclusive`). `T` is an unsigned integer up to 64 bits;
/// `usize` follows `rand`'s `UniformUsize`, which samples 32-bit when `high` fits in `u32`.
pub fn range_at_most(rng: anytype, comptime T: type, low: T, high: T) T {
    assert(low <= high);
    if (T == usize) {
        if (high > std.math.maxInt(u32)) {
            return @intCast(range_at_most(rng, u64, low, high));
        }
        return range_at_most(rng, u32, @intCast(low), @intCast(high));
    }
    // Rust samples u8 and u16 ranges with u32 words.
    const Sample = if (@bitSizeOf(T) <= 32) u32 else u64;
    const range: Sample = @as(Sample, high - low) +% 1;
    if (range == 0) return draw(rng, T);
    var result, const low_order = wide_multiply(Sample, draw(rng, Sample), range);
    if (low_order > 0 -% range) {
        const new_high_order, _ = wide_multiply(Sample, draw(rng, Sample), range);
        if (@addWithOverflow(low_order, new_high_order)[1] == 1) result += 1;
    }
    assert(result < range);
    return low + @as(T, @intCast(result));
}

/// Uniform sample in `[low, high)` (`rand`'s `random_range(low..high)`).
pub fn range_less_than(rng: anytype, comptime T: type, low: T, high: T) T {
    assert(low < high);
    const value = range_at_most(rng, T, low, high - 1);
    assert(value >= low and value < high);
    return value;
}

/// A fair coin: the sign bit of `next_u32` (`rand`'s `random::<bool>()`).
pub fn boolean(rng: anytype) bool {
    return rng.next_u32() >> 31 == 1;
}

/// True with probability `p` in `[0, 1]` (`rand`'s `random_bool`).
pub fn bernoulli(rng: anytype, p: f64) bool {
    assert(p >= 0.0 and p <= 1.0);
    if (p == 1.0) return true;
    const scale: f64 = 18446744073709551616.0; // 2^64
    const threshold: u64 = @intFromFloat(p * scale);
    return rng.next_u64() < threshold;
}

/// True with probability `numerator / denominator` (`rand`'s `random_ratio`).
pub fn ratio(rng: anytype, numerator: u32, denominator: u32) bool {
    assert(denominator > 0);
    assert(numerator <= denominator);
    if (numerator == denominator) return true;
    const p = @as(f64, @floatFromInt(numerator)) / @as(f64, @floatFromInt(denominator));
    const threshold: u64 = @intFromFloat(p * 18446744073709551616.0);
    return rng.next_u64() < threshold;
}

/// Uniform `f64` in `[0, 1)` from the top 53 bits of `next_u64` (`rand`'s `random::<f64>()`).
pub fn float64(rng: anytype) f64 {
    const value = rng.next_u64() >> 11;
    const result = @as(f64, @floatFromInt(value)) * (1.0 / 9007199254740992.0);
    assert(result >= 0.0 and result < 1.0);
    return result;
}

const testing = std.testing;

test "rng: TestRng matches rand 0.10 StdRng::seed_from_u64" {
    // Reference values from Rust `rand` 0.10.2.
    var rng = TestRng.init(0);
    try testing.expectEqual(@as(u32, 3442241407), rng.next_u32());
    try testing.expectEqual(@as(u32, 3140108210), rng.next_u32());
    try testing.expectEqual(@as(u32, 2384947579), rng.next_u32());
    try testing.expectEqual(@as(u64, 14929725332637449364), rng.next_u64());
    try testing.expectEqual(@as(u64, 12386577723477049602), rng.next_u64());
    try testing.expectEqual(@as(u64, 16060253061633504797), rng.next_u64());
    var bytes: [7]u8 = undefined;
    rng.fill_bytes(&bytes);
    try testing.expectEqualSlices(u8, &.{ 84, 157, 29, 67, 34, 196, 113 }, &bytes);

    // A u64 that straddles the buffer refill.
    var straddle = TestRng.init(42);
    for (0..63) |_| _ = straddle.next_u32();
    try testing.expectEqual(@as(u64, 17178619768944704768), straddle.next_u64());

    var long = TestRng.init(7);
    var fill: [300]u8 = undefined;
    long.fill_bytes(&fill);
    const tail = [_]u8{
        30,  132, 81,  224, 94, 118, 10,  118, 151, 43, 203, 135, 183, 244, 174, 177, 2,
        22,  226, 17,  243, 78, 182, 242, 226, 163, 49, 82,  94,  144, 17,  168, 161, 98,
        230, 90,  133, 3,   32, 105, 221, 191, 196, 13, 85,  173, 10,  227, 215, 50,
    };
    try testing.expectEqualSlices(u8, &tail, fill[250..]);
}

test "rng: sampling helpers match rand 0.10" {
    // Reference values from Rust `rand` 0.10.2 drawing from `StdRng::seed_from_u64(1)`.
    var rng = TestRng.init(1);
    for ([_]usize{ 53, 63, 52, 45, 13, 28, 14, 12 }) |expected| {
        try testing.expectEqual(expected, range_at_most(&rng, usize, 1, 64));
    }
    for ([_]u64{
        4695651197854250067, 7168549356730372074, 9598647570783253411, 3725167443292225732,
    }) |expected| {
        try testing.expectEqual(expected, range_less_than(&rng, u64, 0, std.math.maxInt(u64) - 5));
    }
    for ([_]u32{ 811, 936, 806, 438 }) |expected| {
        try testing.expectEqual(expected, range_less_than(&rng, u32, 10, 1000));
    }
    for ([_]usize{ 213621548324, 156243998045, 981082569525, 429379164031 }) |expected| {
        try testing.expectEqual(expected, range_less_than(&rng, usize, 0, 1 << 40));
    }
    for ([_]bool{ false, true, false, false, false, true, false, false }) |expected| {
        try testing.expectEqual(expected, boolean(&rng));
    }
    for ([_]bool{ false, false, false, true, true, true, false, false }) |expected| {
        try testing.expectEqual(expected, bernoulli(&rng, 0.3));
    }
    for ([_]bool{ false, true, false, true, true, false, true, false }) |expected| {
        try testing.expectEqual(expected, ratio(&rng, 2, 7));
    }
    // `random::<[u8; 5]>()` draws one u32 per byte.
    for ([_]u8{ 157, 202, 72, 11, 79 }) |expected| {
        try testing.expectEqual(expected, @as(u8, @truncate(rng.next_u32())));
    }
    try testing.expectEqual(@as(f64, 0.21757424256511837), float64(&rng));
}

test "rng: ScriptedRng output forms" {
    var rng = ScriptedRng.init(&.{
        0x0123_4567_89ab_cdef,
        0xfedc_ba98_7654_3210,
        0x0807_0605_0403_0201,
    });
    try testing.expectEqual(@as(u64, 0x0123_4567_89ab_cdef), rng.next_u64());
    try testing.expectEqual(@as(u32, 0x7654_3210), rng.next_u32());
    var bytes: [5]u8 = undefined;
    rng.fill_bytes(&bytes);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5 }, &bytes);
}

fn expect_not_constant(rng: *FuzzRng) !void {
    var first = rng.next_u64();
    var changed = false;
    for (1..block_bytes) |_| {
        const value = rng.next_u64();
        changed = changed or value != first;
        first = value;
    }
    try testing.expect(changed);
}

test "rng: FuzzRng empty and all-zero inputs are not constant" {
    var empty = FuzzRng.init(&.{});
    try expect_not_constant(&empty);
    const zero_input: [block_bytes]u8 = @splat(0);
    var zeros = FuzzRng.init(&zero_input);
    try expect_not_constant(&zeros);

    var a = FuzzRng.init(&.{});
    var b = FuzzRng.init(&.{});
    for (0..256) |_| try testing.expectEqual(a.next_u64(), b.next_u64());
}

test "rng: FuzzRng short input wraparound" {
    const input: [3]u8 = @splat(0xAB);
    for (1..4) |len| {
        var a = FuzzRng.init(input[0..len]);
        var b = FuzzRng.init(input[0..len]);
        var changed = false;
        var previous = a.next_u64();
        try testing.expectEqual(previous, b.next_u64());
        for (1..32) |_| {
            const value = a.next_u64();
            try testing.expectEqual(value, b.next_u64());
            changed = changed or value != previous;
            previous = value;
        }
        try testing.expect(changed);
    }
}

fn mutation_diff(position: usize, draws: usize, out: []usize) usize {
    var base: [64]u8 = undefined;
    for (&base, 0..) |*byte, i| byte.* = @intCast(i);
    var mutated = base;
    mutated[position] ^= 0x01;
    var a = FuzzRng.init(&base);
    var b = FuzzRng.init(&mutated);
    var count: usize = 0;
    for (0..draws) |i| {
        if (a.next_u64() != b.next_u64()) {
            out[count] = i;
            count += 1;
        }
    }
    return count;
}

test "rng: FuzzRng small mutation locality" {
    var diff: [64]usize = undefined;
    const count = mutation_diff(20, 40, &diff);
    try testing.expectEqualSlices(usize, &.{ 13, 14, 15, 16, 17, 18, 19, 20 }, diff[0..count]);
    const wrapped = mutation_diff(2, 64, &diff);
    try testing.expectEqualSlices(usize, &.{ 0, 1, 2, 59, 60, 61, 62, 63 }, diff[0..wrapped]);
}

test "rng: FuzzRng output shape stability" {
    var input: [32]u8 = undefined;
    for (&input, 0..) |*byte, i| byte.* = @intCast(i);

    var from_u64_rng = FuzzRng.init(&input);
    var from_u64: [128]u8 = undefined;
    for (0..16) |i| std.mem.writeInt(u64, from_u64[i * 8 ..][0..8], from_u64_rng.next_u64(), .big);

    var from_fill_rng = FuzzRng.init(&input);
    var from_fill: [128]u8 = undefined;
    const chunk_sizes = [_]usize{ 3, 1, 7, 2, 11, 5, 13, 17 };
    var offset: usize = 0;
    var index: usize = 0;
    while (offset < from_fill.len) : (index += 1) {
        const chunk = @min(chunk_sizes[index % chunk_sizes.len], from_fill.len - offset);
        from_fill_rng.fill_bytes(from_fill[offset..][0..chunk]);
        offset += chunk;
    }
    try testing.expectEqualSlices(u8, &from_u64, &from_fill);

    var from_u32_rng = FuzzRng.init(input[0..16]);
    var from_u32: [64]u8 = undefined;
    for (0..16) |i| std.mem.writeInt(u32, from_u32[i * 4 ..][0..4], from_u32_rng.next_u32(), .big);
    var whole_rng = FuzzRng.init(input[0..16]);
    var whole: [64]u8 = undefined;
    whole_rng.fill_bytes(&whole);
    try testing.expectEqualSlices(u8, &from_u32, &whole);
}

test "rng: FuzzRng mixes the counter into every block" {
    const input: [block_bytes]u8 = @splat(0xAA);
    var rng = FuzzRng.init(&input);
    const word = std.mem.readInt(u64, &input, .big);
    try testing.expectEqual(mix64(word ^ 0 ^ GOLDEN_RATIO), rng.next_u64());
    try testing.expectEqual(mix64(word ^ 1 ^ GOLDEN_RATIO), rng.next_u64());
}

/// commonware's `FuzzRngConformance::commit`: a seeded input of 1..=64 bytes, then 32
/// big-endian `u64` blocks of output.
fn fuzz_rng_commit(seed: u64, output: *[32 * block_bytes]u8) void {
    var seed_rng = TestRng.init(seed);
    const len = range_at_most(&seed_rng, usize, 1, 64);
    var input: [64]u8 = undefined;
    seed_rng.fill_bytes(input[0..len]);
    var rng = FuzzRng.init(input[0..len]);
    for (0..32) |i| std.mem.writeInt(u64, output[i * 8 ..][0..8], rng.next_u64(), .big);
}

test "rng: FuzzRng conformance hash matches commonware" {
    // utils/conformance.toml: commonware_utils::rng::tests::conformance::FuzzRngConformance.
    // The hash is SHA-256 over `len as u64 LE || commit(seed)` for seeds 0..n_cases.
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (0..1024) |seed| {
        var output: [32 * block_bytes]u8 = undefined;
        fuzz_rng_commit(seed, &output);
        var len_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &len_bytes, output.len, .little);
        hasher.update(&len_bytes);
        hasher.update(&output);
    }
    const digest = hasher.finalResult();
    const hex = std.fmt.bytesToHex(digest, .lower);
    try testing.expectEqualStrings(
        "98c11adc87998940c19bf9c9ce8554ce91409e81375078b99f511fbb64cf3e79",
        &hex,
    );
}

test "rng: std.Random adapter draws from the generator" {
    var a = TestRng.init(9);
    var b = TestRng.init(9);
    var expected: [12]u8 = undefined;
    b.fill_bytes(&expected);
    var actual: [12]u8 = undefined;
    random(&a).bytes(&actual);
    try testing.expectEqualSlices(u8, &expected, &actual);
}
