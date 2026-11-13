//! Bounded deterministic fuzzing for Reed-Solomon (commonware `reed_solomon/fuzz.rs` and the
//! `reed_solomon_engine` / `reed_solomon_rate` fuzz targets).
//!
//! `EnginePlan` compares every engine with `Naive` (multiplication and transforms) and checks
//! the engine-independent kernels (short Walsh locators, the fused formal derivative) against
//! references. `RatePlan` compares rate encoders and decoders with `Naive`, checks roundtrips,
//! reuse, and resets, the public recovery decoder, prepared plans, and shortened locators. The
//! field oracle multiplies in the polynomial basis without the engine tables, so a table bug
//! cannot cancel against the same bug in an engine.
//!
//! Plans draw their choices from `invariants.minifuzz.Unstructured` (arbitrary 1.4) the way
//! commonware's do; shard bytes come from the rest of the input, read cyclically. The tests run
//! them under `minifuzz` with commonware's seeds and search limits.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const testing = std.testing;

const root = @import("root.zig");
const engine = @import("engine.zig");
const rate = @import("rate.zig");
const test_util = @import("test_util.zig");
const minifuzz = @import("invariants").minifuzz;

const Unstructured = minifuzz.Unstructured;

const Chunk = engine.Chunk;
const GfElement = engine.GfElement;
const GF_ORDER = engine.GF_ORDER;
const GF_MODULUS = engine.GF_MODULUS;
const SHARD_CHUNK_BYTES = engine.SHARD_CHUNK_BYTES;
const Naive = engine.Naive;
const Scalar = engine.Scalar;
const ShardsRefMut = engine.ShardsRefMut;
const BitSet = std.DynamicBitSetUnmanaged;
const half = SHARD_CHUNK_BYTES / 2;

/// Engines compared with `Naive` (`DefaultEngine` is `Scalar`).
const engines = .{Scalar};

/// Shard lengths for rate cases: one element, one chunk, and one element either side of one
/// and two chunks.
const shard_sizes = [_]usize{ 2, 62, 64, 66, 126, 130 };

/// Largest input a coverage-guided iteration hands a plan.
const input_bytes_max = 4096;

/// Cyclic byte source over fuzz input; reads zeros when the input is empty.
const Cyclic = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn byte(cyclic: *Cyclic) u8 {
        if (cyclic.bytes.len == 0) return 0;
        const value = cyclic.bytes[cyclic.offset % cyclic.bytes.len];
        cyclic.offset += 1;
        return value;
    }
};

/// Fills every chunk from `input`, adding chunk and lane offsets so the bytes still vary when a
/// short input repeats.
fn fill_chunks(chunks: []Chunk, input: *Cyclic) void {
    for (chunks, 0..) |*chunk, chunk_index| {
        const index: u8 = @truncate(chunk_index);
        for (0..half) |lane_index| {
            const lane: u8 = @intCast(lane_index);
            chunk[lane_index] = input.byte() +% index *% 29 +% lane;
            chunk[half + lane_index] = input.byte() +% index *% 53 -% lane;
        }
    }
}

fn expect_chunks(expected: []const Chunk, actual: []const Chunk) !void {
    const expected_bytes = std.mem.sliceAsBytes(expected);
    try testing.expectEqualSlices(u8, expected_bytes, std.mem.sliceAsBytes(actual));
}

/// Carry-less multiply, then reduce the degree-30 product modulo `GF_POLYNOMIAL`.
fn polynomial_mul(left: GfElement, right: GfElement) GfElement {
    var product: u32 = 0;
    for (0..16) |bit| {
        if (right & (@as(GfElement, 1) << @intCast(bit)) != 0) {
            product ^= @as(u32, left) << @intCast(bit);
        }
    }
    var bit: u5 = 30;
    while (bit >= 16) : (bit -= 1) {
        if (product & (@as(u32, 1) << bit) != 0) {
            product ^= @as(u32, engine.GF_POLYNOMIAL) << (bit - 16);
        }
    }
    assert(product >> 16 == 0);
    return @intCast(product);
}

/// Converts Cantor-basis coordinates to the polynomial basis.
fn cantor_to_polynomial(value: GfElement) GfElement {
    var polynomial: GfElement = 0;
    for (engine.CANTOR_BASIS, 0..) |basis, bit| {
        if (value & (@as(GfElement, 1) << @intCast(bit)) != 0) polynomial ^= basis;
    }
    return polynomial;
}

/// Row `r` holds the Cantor coordinates of `x^r`, by Gauss-Jordan elimination over GF(2). A
/// pivot always exists because the basis is linearly independent.
const cantor_inverse: [16]GfElement = blk: {
    var values = engine.CANTOR_BASIS;
    var coordinates: [16]GfElement = undefined;
    for (&coordinates, 0..) |*coordinate, i| coordinate.* = @as(GfElement, 1) << @intCast(i);
    for (0..16) |pivot| {
        const mask = @as(GfElement, 1) << @intCast(pivot);
        var row = pivot;
        while (values[row] & mask == 0) row += 1;
        std.mem.swap(GfElement, &values[pivot], &values[row]);
        std.mem.swap(GfElement, &coordinates[pivot], &coordinates[row]);
        for (0..16) |other| {
            if (other != pivot and values[other] & mask != 0) {
                values[other] ^= values[pivot];
                coordinates[other] ^= coordinates[pivot];
            }
        }
    }
    for (values, 0..) |value, i| assert(value == @as(GfElement, 1) << @intCast(i));
    break :blk coordinates;
};

/// Converts polynomial-basis `value` to Cantor-basis coordinates.
fn polynomial_to_cantor(value: GfElement) GfElement {
    var coordinates: GfElement = 0;
    for (cantor_inverse, 0..) |coordinate, bit| {
        if (value & (@as(GfElement, 1) << @intCast(bit)) != 0) coordinates ^= coordinate;
    }
    return coordinates;
}

/// Multiplies Cantor-basis `value` by polynomial-basis `coefficient`.
fn independent_mul_coefficient(value: GfElement, coefficient: GfElement) GfElement {
    return polynomial_to_cantor(polynomial_mul(cantor_to_polynomial(value), coefficient));
}

/// Multiplies `value` by the element with logarithm `log_m` without the engine tables, building
/// `x^log_m` by square-and-multiply.
fn independent_mul(value: GfElement, log_m: GfElement) GfElement {
    var coefficient: GfElement = 1;
    var alpha: GfElement = 2;
    var exponent = log_m % GF_MODULUS;
    while (exponent > 0) : (exponent >>= 1) {
        if (exponent & 1 == 1) coefficient = polynomial_mul(coefficient, alpha);
        alpha = polynomial_mul(alpha, alpha);
    }
    assert(coefficient != 0);
    return independent_mul_coefficient(value, coefficient);
}

/// Checks `Naive` multiplication against `independent_mul`, then every engine against `Naive`.
fn compare_mul(gpa: Allocator, input: []const Chunk, log_m: GfElement) !void {
    const expected = try gpa.dupe(Chunk, input);
    defer gpa.free(expected);
    for (expected) |*chunk| {
        for (0..half) |lane| {
            const value = @as(GfElement, chunk[lane]) | (@as(GfElement, chunk[half + lane]) << 8);
            const product = independent_mul(value, log_m);
            chunk[lane] = @truncate(product);
            chunk[half + lane] = @truncate(product >> 8);
        }
    }
    const actual = try gpa.dupe(Chunk, input);
    defer gpa.free(actual);
    Naive.init().mul(actual, log_m);
    try expect_chunks(expected, actual);
    inline for (engines) |E| {
        @memcpy(actual, input);
        E.init().mul(actual, log_m);
        try expect_chunks(expected, actual);
    }
}

/// One FFT or IFFT on shards `pos..pos + size` of `shard_count` shards.
pub const Transform = struct {
    shard_count: usize,
    shard_chunks: usize,
    pos: usize,
    size: usize,
    truncated_size: usize,
    skew_delta: usize,

    fn apply(transform: Transform, eng: anytype, data: []Chunk, inverse: bool) void {
        const shards: ShardsRefMut = .init(transform.shard_count, transform.shard_chunks, data);
        const t = transform;
        if (inverse) {
            eng.ifft(shards, t.pos, t.size, t.truncated_size, t.skew_delta);
        } else {
            eng.fft(shards, t.pos, t.size, t.truncated_size, t.skew_delta);
        }
    }

    fn shard(transform: Transform, data: []Chunk, index: usize) []Chunk {
        return data[index * transform.shard_chunks ..][0..transform.shard_chunks];
    }

    fn in_block(transform: Transform, index: usize) bool {
        return index >= transform.pos and index < transform.pos + transform.size;
    }
};

/// Checks every engine's FFT and IFFT against `Naive`. Shards outside the block must stay
/// unchanged. FFT compares the first `truncated_size` block outputs; IFFT zeroes the block's
/// input shards from `pos + truncated_size`, then compares the whole block.
fn compare_transform(gpa: Allocator, input: []const Chunk, t: Transform) !void {
    assert(std.math.isPowerOfTwo(t.size) and t.size <= GF_ORDER);
    assert(t.truncated_size <= t.size and t.pos + t.size <= t.shard_count);
    assert(t.size == 1 or t.skew_delta <= GF_ORDER - t.size);
    assert(input.len == t.shard_count * t.shard_chunks);
    const original = try gpa.dupe(Chunk, input);
    defer gpa.free(original);
    const operation = try gpa.alloc(Chunk, input.len);
    defer gpa.free(operation);
    const expected = try gpa.alloc(Chunk, input.len);
    defer gpa.free(expected);
    const actual = try gpa.alloc(Chunk, input.len);
    defer gpa.free(actual);

    for ([_]bool{ false, true }) |inverse| {
        @memcpy(operation, input);
        if (inverse) {
            for (t.pos + t.truncated_size..t.pos + t.size) |index| {
                @memset(t.shard(operation, index), @splat(0));
            }
        }
        @memcpy(expected, operation);
        t.apply(Naive.init(), expected, inverse);
        for (0..t.shard_count) |index| {
            if (!t.in_block(index)) {
                try expect_chunks(t.shard(original, index), t.shard(expected, index));
            }
        }
        inline for (engines) |E| {
            @memcpy(actual, operation);
            t.apply(E.init(), actual, inverse);
            try check_transform(t, original, expected, actual, inverse);
        }
    }
}

fn check_transform(
    t: Transform,
    input: []Chunk,
    expected: []Chunk,
    actual: []Chunk,
    inverse: bool,
) !void {
    for (0..t.shard_count) |index| {
        if (!t.in_block(index)) {
            try expect_chunks(t.shard(input, index), t.shard(actual, index));
        } else if (inverse or index < t.pos + t.truncated_size) {
            // FFT specifies a prefix; IFFT specifies the whole block after zeroing its suffix.
            try expect_chunks(t.shard(expected, index), t.shard(actual, index));
        }
    }
}

/// Checks that `eval_poly_short` on `n` entries matches `Naive`'s full-field `eval_poly` modulo
/// `GF_MODULUS` on the first `n` outputs and never writes entry `n`.
fn compare_short_locator(gpa: Allocator, n: usize, end: usize, seed: u16) !void {
    assert(std.math.isPowerOfTwo(n) and n < GF_ORDER and end <= n);
    const short = try gpa.create([GF_ORDER]GfElement);
    defer gpa.destroy(short);
    const full = try gpa.create([GF_ORDER]GfElement);
    defer gpa.destroy(full);
    // The convolution is linear modulo GF_MODULUS, so inputs need not be 0/1 flags. Mix zero,
    // GF_MODULUS (the other encoding of zero), and seeded residues.
    short.* = @splat(0);
    for (short[0..end], 0..) |*value, i| {
        value.* = switch ((i ^ seed) % 5) {
            0 => 0,
            1 => GF_MODULUS,
            else => (@as(GfElement, @truncate(i)) *% 257) ^ seed,
        };
    }
    full.* = short.*;
    engine.eval_poly(Naive, full, end);

    // The sentinel detects a write past the domain.
    short[n] = 0xa5a5;
    engine.utils.eval_poly_short(short[0..n], end);
    for (0..n) |i| try testing.expectEqual(full[i] % GF_MODULUS, short[i] % GF_MODULUS);
    try testing.expectEqual(0xa5a5, short[n]);
}

/// Checks `formal_derivative` on `count` shards of `chunks` chunks against the reference pass
/// schedule over a zero-padded power-of-two block. Padding shards only absorb higher padding
/// shards and stay zero, so the first `count` shards match the clamped schedule.
fn compare_derivative(gpa: Allocator, input: []const Chunk, count: usize, chunks: usize) !void {
    assert(input.len == count * chunks);
    const padded_count = rate.next_power_of_two(@max(count, 1));
    const expected = try gpa.alloc(Chunk, padded_count * chunks);
    defer gpa.free(expected);
    @memset(expected, @splat(0));
    @memcpy(expected[0..input.len], input);
    const actual = try gpa.dupe(Chunk, input);
    defer gpa.free(actual);

    const reference: ShardsRefMut = .init(padded_count, chunks, expected);
    for (1..padded_count) |i| {
        const width = @as(usize, 1) << @intCast(@ctz(i));
        engine.utils.xor_within(reference, i - width, i, width);
    }
    engine.utils.formal_derivative(.init(count, chunks, actual));
    try expect_chunks(expected[0..input.len], actual);
}

/// Checks a rate's shortened erasure locator against `Naive`'s full-field `eval_poly`.
///
/// High rate places recovery shards from 0 and originals from `chunk`, erases the padding
/// between them, and truncates at `end`. Low rate places originals from 0 and recovery shards
/// from `chunk`, keeps the padding known, and erases every position from `end`. Only outputs
/// below `end` are compared, modulo `GF_MODULUS`.
fn compare_rate_locator(
    gpa: Allocator,
    high: bool,
    original_count: usize,
    recovery_count: usize,
    received: *const BitSet,
) !void {
    const first = if (high) recovery_count else original_count;
    const chunk = rate.next_power_of_two(first);
    const end = chunk + (if (high) original_count else recovery_count);
    assert(received.bit_length >= end);
    const expected = try gpa.create([GF_ORDER]GfElement);
    defer gpa.destroy(expected);
    expected.* = @splat(0);
    for (0..first) |i| expected[i] = @intFromBool(!received.isSet(i));
    for (chunk..end) |i| expected[i] = @intFromBool(!received.isSet(i));
    if (high) @memset(expected[recovery_count..chunk], 1) else @memset(expected[end..], 1);
    engine.eval_poly(Naive, expected, if (high) end else GF_ORDER);

    const actual = try gpa.alloc(GfElement, rate.next_power_of_two(end));
    defer gpa.free(actual);
    @memset(actual, 0);
    if (high) {
        rate.high.eval_erasures(Scalar, actual, original_count, recovery_count, received);
    } else {
        rate.low.eval_walsh(Scalar, actual, original_count, recovery_count, received);
    }
    for (0..end) |i| try testing.expectEqual(expected[i] % GF_MODULUS, actual[i] % GF_MODULUS);
}

/// Bounded comparisons of engines and engine-independent kernels against references.
pub const EnginePlan = enum {
    /// Multiplication, including empty and multi-chunk operands.
    mul,
    /// FFT and IFFT with offsets, truncation, and sentinel shards.
    transform,
    /// Short Walsh locator convolution against the full-field evaluator.
    locator,
    /// The fused formal derivative against the unfused pass schedule.
    derivative,

    pub fn run(plan: EnginePlan, gpa: Allocator, u: *Unstructured) !void {
        switch (plan) {
            .mul => try fuzz_mul(gpa, u),
            .transform => try fuzz_transform(gpa, u),
            .locator => try fuzz_locator(gpa, u),
            .derivative => try fuzz_derivative(gpa, u),
        }
    }
};

/// Logarithm edge cases (including `GF_MODULUS`) or a random one; 0 to 3 or 65 chunks, or 4
/// to 16.
fn fuzz_mul(gpa: Allocator, u: *Unstructured) !void {
    const log_m: GfElement = switch (u.int_in_range(usize, 0, 7)) {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => GF_MODULUS / 2,
        4 => GF_MODULUS / 2 + 1,
        5 => GF_MODULUS - 1,
        6 => GF_MODULUS,
        else => try u.arbitrary(GfElement),
    };
    const chunk_count: usize = switch (u.int_in_range(usize, 0, 5)) {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 65,
        else => u.int_in_range(usize, 4, 16),
    };
    const chunks = try gpa.alloc(Chunk, chunk_count);
    defer gpa.free(chunks);
    var cyclic: Cyclic = .{ .bytes = u.take_rest() };
    fill_chunks(chunks, &cyclic);
    try compare_mul(gpa, chunks, log_m);
}

/// A block of `2^k` shards, `k` in `0..=6`, at shard `pos` with up to three suffix shards, and
/// an edge or random `skew_delta`.
fn fuzz_transform(gpa: Allocator, u: *Unstructured) !void {
    const size = @as(usize, 1) << @intCast(u.int_in_range(usize, 0, 6));
    const pos: usize = u.int_in_range(usize, 0, 5);
    const suffix: usize = u.int_in_range(usize, 0, 3);
    const truncated_size: usize = u.int_in_range(usize, 0, size);
    const max_skew = GF_ORDER - size;
    const skew_delta: usize = switch (u.int_in_range(usize, 0, 5)) {
        0 => 0,
        1 => @min(1, max_skew),
        2 => @min(7, max_skew),
        3 => max_skew,
        4 => @min(17, max_skew),
        else => @as(usize, try u.arbitrary(u16)) % (max_skew + 1),
    };
    const shard_chunks: usize = switch (u.int_in_range(usize, 0, 5)) {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 17,
        4 => 65,
        else => u.int_in_range(usize, 3, 8),
    };
    const shard_count = pos + size + suffix;
    const chunks = try gpa.alloc(Chunk, shard_count * shard_chunks);
    defer gpa.free(chunks);
    var cyclic: Cyclic = .{ .bytes = u.take_rest() };
    fill_chunks(chunks, &cyclic);
    try compare_transform(gpa, chunks, .{
        .shard_count = shard_count,
        .shard_chunks = shard_chunks,
        .pos = pos,
        .size = size,
        .truncated_size = truncated_size,
        .skew_delta = skew_delta,
    });
}

/// A power-of-two domain `n <= 2^15` and truncation `end` in `1..=n`.
fn fuzz_locator(gpa: Allocator, u: *Unstructured) !void {
    const n = @as(usize, 1) << @intCast(u.int_in_range(usize, 0, 15));
    const end: usize = u.int_in_range(usize, 1, n);
    const seed = try u.arbitrary(u16);
    try compare_short_locator(gpa, n, end, seed);
}

/// Shard counts bracketing the four- and sixteen-shard leaf blocks and each pass width.
const derivative_counts = [_]usize{
    0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129,
};
/// Chunks per shard bracketing the AVX-512 leaf's 8-chunk minimum and 64-chunk exclusion.
const derivative_chunks = [_]usize{ 0, 1, 3, 7, 8, 9, 17, 63, 64, 65 };

fn fuzz_derivative(gpa: Allocator, u: *Unstructured) !void {
    const count: usize = if (try u.arbitrary(bool))
        derivative_counts[u.int_in_range(usize, 0, derivative_counts.len - 1)]
    else
        u.int_in_range(usize, 0, 129);
    const chunks = derivative_chunks[u.int_in_range(usize, 0, derivative_chunks.len - 1)];
    const data = try gpa.alloc(Chunk, count * chunks);
    defer gpa.free(data);
    var cyclic: Cyclic = .{ .bytes = u.take_rest() };
    fill_chunks(data, &cyclic);
    try compare_derivative(gpa, data, count, chunks);
}

/// Encoding rate exercised by the shared checks.
pub const RateKind = enum { high, low, default };

fn rate_of(comptime kind: RateKind) fn (type) type {
    return switch (kind) {
        .high => rate.HighRate,
        .low => rate.LowRate,
        .default => rate.DefaultRate,
    };
}

/// Bounded rate comparisons and backend-independent encoding and decoding contracts.
pub const RatePlan = union(enum) {
    /// Encode with each engine and with `Naive`, and decode the reference recovery shards.
    matches_naive: RateKind,
    /// Roundtrips, automatic reuse, and reset with the same backend.
    contract: RateKind,
    /// The public recovery decoder's reuse and missing recovery shards.
    recovery,
    /// Prepared recovery against ordinary decoding across sizes, reuse, and mismatches.
    prepared_recovery,
    /// The rate-specific shortened locator against full-field arithmetic.
    locator,

    /// `derive(Arbitrary)`: the variant, then its payload.
    pub fn arbitrary(u: *Unstructured) !RatePlan {
        return switch (try u.arbitrary(std.meta.Tag(RatePlan))) {
            .matches_naive => .{ .matches_naive = try u.arbitrary(RateKind) },
            .contract => .{ .contract = try u.arbitrary(RateKind) },
            .recovery => .recovery,
            .prepared_recovery => .prepared_recovery,
            .locator => .locator,
        };
    }

    pub fn run(plan: RatePlan, gpa: Allocator, u: *Unstructured) !void {
        if (plan == .locator) return fuzz_rate_locator(gpa, u);
        const small: usize = u.int_in_range(usize, 2, 4);
        const large: usize = u.int_in_range(usize, 9, 12);
        const shard_bytes_a = shard_sizes[u.int_in_range(usize, 0, shard_sizes.len - 1)];
        const shard_bytes_b = shard_sizes[u.int_in_range(usize, 0, shard_sizes.len - 1)];
        const counts = plan.shapes(small, large);
        var cyclic: Cyclic = .{ .bytes = u.take_rest() };
        var a = try RateCase.init(gpa, counts[0], shard_bytes_a, &cyclic);
        defer a.deinit(gpa);
        var b = try RateCase.init(gpa, counts[1], shard_bytes_b, &cyclic);
        defer b.deinit(gpa);
        switch (plan) {
            .matches_naive => |kind| {
                inline for (engines) |E| try rate_matches_naive(E, kind, gpa, &a, &b);
            },
            .contract => |kind| {
                try rate_contract(Naive, kind, gpa, &a, &b);
                inline for (engines) |E| try rate_contract(E, kind, gpa, &a, &b);
            },
            .recovery => try exercise_recovery_reuse(gpa, &a, &b),
            .prepared_recovery => try exercise_prepared_reuse(gpa, &a, &b),
            .locator => unreachable, // Returned above.
        }
    }

    /// Original and recovery counts of the two cases: the plan's rate for both, or one high and
    /// one low shape to switch rates.
    fn shapes(plan: RatePlan, small: usize, large: usize) [2][2]usize {
        assert(small < large);
        const switching: [2][2]usize = .{ .{ large, small }, .{ small, large } };
        return switch (plan) {
            .matches_naive, .contract => |kind| switch (kind) {
                .high => .{ .{ large, small }, .{ large - 1, small + 1 } },
                .low => .{ .{ small, large }, .{ small + 1, large - 1 } },
                .default => switching,
            },
            else => switching,
        };
    }
};

/// Fuzzed counts in `1..=64`, a fuzzed rate, and a fuzzed received mask.
fn fuzz_rate_locator(gpa: Allocator, u: *Unstructured) !void {
    const high = try u.arbitrary(bool);
    const original_count: usize = u.int_in_range(usize, 1, 64);
    const recovery_count: usize = u.int_in_range(usize, 1, 64);
    const chunk = rate.next_power_of_two(if (high) recovery_count else original_count);
    const end = chunk + (if (high) original_count else recovery_count);
    var received = try BitSet.initEmpty(gpa, end);
    defer received.deinit(gpa);
    for (0..end) |i| {
        if (try u.arbitrary(bool)) received.set(i);
    }
    try compare_rate_locator(gpa, high, original_count, recovery_count, &received);
}

/// A rate encoding and decoding case with fuzzed shard contents and erasure offsets.
const RateCase = struct {
    original_count: usize,
    recovery_count: usize,
    shard_bytes: usize,
    originals: [][]u8,
    /// First original index dropped in the round with `start_delta` 0.
    original_start: usize,
    /// First recovery index provided in the round with `start_delta` 0.
    recovery_start: usize,

    /// Draws the erasure offsets and then the shard bytes from `input`.
    fn init(gpa: Allocator, counts: [2]usize, shard_bytes: usize, input: *Cyclic) !RateCase {
        const original_count, const recovery_count = counts;
        assert(original_count > 0 and recovery_count > 0);
        const original_start = @as(usize, input.byte()) % original_count;
        const recovery_start = @as(usize, input.byte()) % recovery_count;
        const originals = try gpa.alloc([]u8, original_count);
        var filled: usize = 0;
        errdefer test_util.free_original(gpa, originals[0..filled]);
        while (filled < original_count) : (filled += 1) {
            const shard = try gpa.alloc(u8, shard_bytes);
            originals[filled] = shard;
            const shard_index: u8 = @truncate(filled);
            for (shard, 0..) |*byte, byte_index| {
                const offset: u8 = @truncate(byte_index);
                byte.* = input.byte() +% shard_index *% 31 +% offset *% 17;
            }
        }
        return .{
            .original_count = original_count,
            .recovery_count = recovery_count,
            .shard_bytes = shard_bytes,
            .originals = originals,
            .original_start = original_start,
            .recovery_start = recovery_start,
        };
    }

    fn deinit(case: *RateCase, gpa: Allocator) void {
        test_util.free_original(gpa, case.originals);
        case.* = undefined;
    }

    /// A copy whose originals are truncated to `shard_bytes`.
    fn truncated(case: *const RateCase, gpa: Allocator, shard_bytes: usize) !RateCase {
        assert(shard_bytes <= case.shard_bytes);
        const originals = try gpa.alloc([]u8, case.original_count);
        var copied: usize = 0;
        errdefer test_util.free_original(gpa, originals[0..copied]);
        while (copied < case.original_count) : (copied += 1) {
            originals[copied] = try gpa.dupe(u8, case.originals[copied][0..shard_bytes]);
        }
        var short = case.*;
        short.shard_bytes = shard_bytes;
        short.originals = originals;
        return short;
    }

    /// Originals dropped and recovery shards provided per round, so every decode receives
    /// exactly `original_count` shards; at least one recovery shard stays unprovided when there
    /// are two or more.
    fn missing_count(case: *const RateCase) usize {
        return @max(@min(case.original_count, case.recovery_count - 1), 1);
    }

    /// Whether original `index` is dropped: `missing_count()` consecutive indices from
    /// `original_start + start_delta`, wrapping at `original_count`.
    fn missing(case: *const RateCase, start_delta: usize, index: usize) bool {
        return in_window(index, case.original_start + start_delta, case.original_count, case);
    }

    /// Whether recovery `index` is provided, laid out like `missing`.
    fn provided(case: *const RateCase, start_delta: usize, index: usize) bool {
        return in_window(index, case.recovery_start + start_delta, case.recovery_count, case);
    }

    fn in_window(index: usize, start: usize, count: usize, case: *const RateCase) bool {
        assert(index < count);
        const offset = (index + count - start % count) % count;
        return offset < case.missing_count();
    }
};

fn expect_shards(expected: []const []u8, actual: []const []u8) !void {
    try testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |e, a| try testing.expectEqualSlices(u8, e, a);
}

fn expect_optional(expected: ?[]const u8, actual: ?[]const u8) !void {
    if (expected) |shard| {
        try testing.expectEqualSlices(u8, shard, actual orelse return error.TestExpectedEqual);
    } else {
        try testing.expect(actual == null);
    }
}

fn new_encoder(
    comptime R: type,
    comptime E: type,
    gpa: Allocator,
    case: *const RateCase,
) !R.Encoder {
    return R.Encoder.init(
        gpa,
        case.original_count,
        case.recovery_count,
        case.shard_bytes,
        E.init(),
        null,
    );
}

fn new_decoder(
    comptime R: type,
    comptime E: type,
    gpa: Allocator,
    case: *const RateCase,
) !R.Decoder {
    return R.Decoder.init(
        gpa,
        case.original_count,
        case.recovery_count,
        case.shard_bytes,
        E.init(),
        null,
    );
}

fn reset_to(coder: anytype, gpa: Allocator, case: *const RateCase) !void {
    try coder.reset(gpa, case.original_count, case.recovery_count, case.shard_bytes);
}

/// Adds every original of `case` to `encoder`, encodes, and returns owned recovery shards.
fn encode_with(
    comptime R: type,
    gpa: Allocator,
    encoder: *R.Encoder,
    case: *const RateCase,
) ![][]u8 {
    for (case.originals) |shard| try encoder.add_original_shard(shard);
    var result = try encoder.encode();
    defer result.deinit();
    const recovery = try gpa.alloc([]u8, case.recovery_count);
    var copied: usize = 0;
    errdefer test_util.free_original(gpa, recovery[0..copied]);
    while (copied < case.recovery_count) : (copied += 1) {
        recovery[copied] = try gpa.dupe(u8, result.recovery(copied).?);
    }
    assert(result.recovery(copied) == null);
    return recovery;
}

/// Encodes `case` with a fresh rate `R` encoder on engine `E`.
fn encode(comptime R: type, comptime E: type, gpa: Allocator, case: *const RateCase) ![][]u8 {
    var encoder = try new_encoder(R, E, gpa, case);
    defer encoder.deinit(gpa);
    return encode_with(R, gpa, &encoder, case);
}

/// Hands `decoder` the originals and recovery shards round `start_delta` selects.
fn add_round(
    decoder: anytype,
    case: *const RateCase,
    recovery: []const []u8,
    start_delta: usize,
) !void {
    for (case.originals, 0..) |shard, i| {
        if (!case.missing(start_delta, i)) try decoder.add_original_shard(i, shard);
    }
    for (recovery, 0..) |shard, i| {
        if (case.provided(start_delta, i)) try decoder.add_recovery_shard(i, shard);
    }
}

/// One decode round; the result must hold exactly the missing originals.
fn decode_with(
    comptime R: type,
    decoder: *R.Decoder,
    case: *const RateCase,
    recovery: []const []u8,
    start_delta: usize,
) !void {
    try add_round(decoder, case, recovery, start_delta);
    var result = (try decoder.decode(false)).?;
    defer result.deinit();
    for (case.originals, 0..) |shard, i| {
        const expected: ?[]const u8 = if (case.missing(start_delta, i)) shard else null;
        try expect_optional(expected, result.original(i));
    }
}

/// The encoder encodes `a`, resets, and encodes `b`. The decoder decodes two rounds of `a`
/// without a reset, then resets and decodes two rounds of `b`.
fn check_rate_contract(
    comptime R: type,
    comptime E: type,
    gpa: Allocator,
    a: *const RateCase,
    b: *const RateCase,
) !void {
    var encoder = try new_encoder(R, E, gpa, a);
    defer encoder.deinit(gpa);
    const recovery_a = try encode_with(R, gpa, &encoder, a);
    defer test_util.free_original(gpa, recovery_a);
    try reset_to(&encoder, gpa, b);
    const recovery_b = try encode_with(R, gpa, &encoder, b);
    defer test_util.free_original(gpa, recovery_b);

    var decoder = try new_decoder(R, E, gpa, a);
    defer decoder.deinit(gpa);
    try decode_with(R, &decoder, a, recovery_a, 0);
    try decode_with(R, &decoder, a, recovery_a, 1);
    try reset_to(&decoder, gpa, b);
    try decode_with(R, &decoder, b, recovery_b, 1);
    try decode_with(R, &decoder, b, recovery_b, 0);
}

/// Rate `R` on engine `E` encodes `a` and, after a reset, `b` to the same recovery shards as
/// `Reference` on `Naive`, then decodes both from the reference shards.
fn compare_rate(
    comptime R: type,
    comptime Reference: type,
    comptime E: type,
    gpa: Allocator,
    a: *const RateCase,
    b: *const RateCase,
) !void {
    const expected_a = try encode(Reference, Naive, gpa, a);
    defer test_util.free_original(gpa, expected_a);
    const expected_b = try encode(Reference, Naive, gpa, b);
    defer test_util.free_original(gpa, expected_b);

    var encoder = try new_encoder(R, E, gpa, a);
    defer encoder.deinit(gpa);
    const actual_a = try encode_with(R, gpa, &encoder, a);
    defer test_util.free_original(gpa, actual_a);
    try expect_shards(expected_a, actual_a);
    try reset_to(&encoder, gpa, b);
    const actual_b = try encode_with(R, gpa, &encoder, b);
    defer test_util.free_original(gpa, actual_b);
    try expect_shards(expected_b, actual_b);

    var decoder = try new_decoder(R, E, gpa, a);
    defer decoder.deinit(gpa);
    try decode_with(R, &decoder, a, expected_a, 0);
    try reset_to(&decoder, gpa, b);
    try decode_with(R, &decoder, b, expected_b, 1);
}

fn rate_contract(
    comptime E: type,
    kind: RateKind,
    gpa: Allocator,
    a: *const RateCase,
    b: *const RateCase,
) !void {
    switch (kind) {
        inline else => |k| try check_rate_contract(rate_of(k)(E), E, gpa, a, b),
    }
}

fn rate_matches_naive(
    comptime E: type,
    kind: RateKind,
    gpa: Allocator,
    a: *const RateCase,
    b: *const RateCase,
) !void {
    switch (kind) {
        inline else => |k| try compare_rate(rate_of(k)(E), rate_of(k)(Naive), E, gpa, a, b),
    }
}

/// The restored originals are exactly the missing ones and the restored recovery shards
/// exactly the unprovided ones.
fn expect_recovery_result(
    result: root.RecoveryDecoderResult,
    case: *const RateCase,
    recovery: []const []u8,
    start_delta: usize,
) !void {
    for (case.originals, 0..) |shard, i| {
        const expected: ?[]const u8 = if (case.missing(start_delta, i)) shard else null;
        try expect_optional(expected, result.original(i));
    }
    for (recovery, 0..) |shard, i| {
        const expected: ?[]const u8 = if (case.provided(start_delta, i)) null else shard;
        try expect_optional(expected, result.recovery(i));
    }
}

/// One `decode_with_recovery` round on the public `Decoder`.
fn recovery_round(
    decoder: *root.Decoder,
    case: *const RateCase,
    recovery: []const []u8,
    start_delta: usize,
) !void {
    try add_round(decoder, case, recovery, start_delta);
    var result = (try decoder.decode_with_recovery()).?;
    defer result.deinit();
    try expect_recovery_result(result, case, recovery, start_delta);
}

/// Two rounds of `a` without a reset, then one round of `b` after a reset.
fn exercise_recovery_reuse(gpa: Allocator, a: *const RateCase, b: *const RateCase) !void {
    const expected_a = try encode(rate.DefaultRate(Naive), Naive, gpa, a);
    defer test_util.free_original(gpa, expected_a);
    const expected_b = try encode(rate.DefaultRate(Naive), Naive, gpa, b);
    defer test_util.free_original(gpa, expected_b);
    var decoder = try root.Decoder.init(gpa, a.original_count, a.recovery_count, a.shard_bytes);
    defer decoder.deinit(gpa);
    try recovery_round(&decoder, a, expected_a, 0);
    try recovery_round(&decoder, a, expected_a, 1);
    try reset_to(&decoder, gpa, b);
    try recovery_round(&decoder, b, expected_b, 0);
}

/// Most shard indices a plan built here names.
const index_count_max = 1024;

const IndexList = struct {
    buffer: [index_count_max]usize = undefined,
    len: usize = 0,

    fn push(list: *IndexList, value: usize) void {
        assert(list.len < index_count_max);
        list.buffer[list.len] = value;
        list.len += 1;
    }

    fn slice(list: *const IndexList) []const usize {
        return list.buffer[0..list.len];
    }
};

/// No index: `round_plan` neither adds nor removes a recovery index.
const none = std.math.maxInt(usize);

/// The plan for round `start_delta`'s received indices, with recovery `extra` added and
/// recovery `without` removed.
fn round_plan(
    gpa: Allocator,
    case: *const RateCase,
    start_delta: usize,
    extra: usize,
    without: usize,
) !root.Plan {
    var originals: IndexList = .{};
    for (0..case.original_count) |i| {
        if (!case.missing(start_delta, i)) originals.push(i);
    }
    var recoveries: IndexList = .{};
    for (0..case.recovery_count) |i| {
        if ((case.provided(start_delta, i) and i != without) or i == extra) recoveries.push(i);
    }
    return root.Plan.init(
        gpa,
        case.original_count,
        case.recovery_count,
        originals.slice(),
        recoveries.slice(),
    );
}

/// A plan with a different original count, one with one more recovery index, and one with a
/// provided recovery index swapped for an unprovided one must each mismatch and leave the
/// submitted shards usable.
fn expect_plan_mismatches(
    gpa: Allocator,
    decoder: *root.Decoder,
    case: *const RateCase,
    start_delta: usize,
) !void {
    var all: IndexList = .{};
    for (0..case.original_count + 1) |i| all.push(i);
    var other_counts = try root.Plan.init(
        gpa,
        case.original_count + 1,
        case.recovery_count,
        all.slice(),
        &.{},
    );
    defer other_counts.deinit(gpa);
    try testing.expectError(error.PlanMismatch, decoder.decode_with_plan(&other_counts));

    var additional: usize = 0;
    while (case.provided(start_delta, additional)) additional += 1;
    var swapped: usize = 0;
    while (!case.provided(start_delta, swapped)) swapped += 1;
    var changed = try round_plan(gpa, case, start_delta, additional, none);
    defer changed.deinit(gpa);
    try testing.expectError(error.PlanMismatch, decoder.decode_with_recovery_plan(&changed));
    var exchanged = try round_plan(gpa, case, start_delta, additional, swapped);
    defer exchanged.deinit(gpa);
    try testing.expectError(error.PlanMismatch, decoder.decode_with_recovery_plan(&exchanged));
}

/// One prepared decode round with `plan`, checked against ordinary decoding of the same shards.
/// `case` must have at least two recovery shards.
fn prepared_round_with_plan(
    gpa: Allocator,
    decoder: *root.Decoder,
    case: *const RateCase,
    recovery: []const []u8,
    start_delta: usize,
    plan: *const root.Plan,
) !void {
    assert(case.recovery_count >= 2);
    var reference = try root.Decoder.init(
        gpa,
        case.original_count,
        case.recovery_count,
        case.shard_bytes,
    );
    defer reference.deinit(gpa);
    try add_round(decoder, case, recovery, start_delta);
    try add_round(&reference, case, recovery, start_delta);
    try expect_plan_mismatches(gpa, decoder, case, start_delta);

    var result = (try decoder.decode_with_recovery_plan(plan)).?;
    defer result.deinit();
    var ordinary = (try reference.decode_with_recovery()).?;
    defer ordinary.deinit();
    for (0..case.original_count) |i| try expect_optional(ordinary.original(i), result.original(i));
    for (0..case.recovery_count) |i| try expect_optional(ordinary.recovery(i), result.recovery(i));
    try expect_recovery_result(result, case, recovery, start_delta);
}

fn prepared_round(
    gpa: Allocator,
    decoder: *root.Decoder,
    case: *const RateCase,
    recovery: []const []u8,
    start_delta: usize,
) !void {
    var plan = try round_plan(gpa, case, start_delta, none, none);
    defer plan.deinit(gpa);
    try prepared_round_with_plan(gpa, decoder, case, recovery, start_delta, &plan);
}

/// Prepared recovery across decoder reuse: two rounds of `a`, a plan reused for 2-byte shards,
/// a plan with every original present, and two rounds of `b` after a reset.
fn exercise_prepared_reuse(gpa: Allocator, a: *const RateCase, b: *const RateCase) !void {
    const recovery_a = try encode(rate.DefaultRate(Naive), Naive, gpa, a);
    defer test_util.free_original(gpa, recovery_a);
    const recovery_b = try encode(rate.DefaultRate(Naive), Naive, gpa, b);
    defer test_util.free_original(gpa, recovery_b);
    var decoder = try root.Decoder.init(gpa, a.original_count, a.recovery_count, a.shard_bytes);
    defer decoder.deinit(gpa);
    try prepared_round(gpa, &decoder, a, recovery_a, 0);
    try prepared_round(gpa, &decoder, a, recovery_a, 1);

    // A plan does not depend on shard bytes: reuse the first mask's plan for 2-byte shards.
    var shared = try round_plan(gpa, a, 0, none, none);
    defer shared.deinit(gpa);
    var short = try a.truncated(gpa, 2);
    defer short.deinit(gpa);
    const short_recovery = try encode(rate.DefaultRate(Naive), Naive, gpa, &short);
    defer test_util.free_original(gpa, short_recovery);
    try reset_to(&decoder, gpa, &short);
    try prepared_round_with_plan(gpa, &decoder, &short, short_recovery, 0, &shared);

    // A matching plan with every original present returns null.
    try reset_to(&decoder, gpa, a);
    var originals: IndexList = .{};
    for (0..a.original_count) |i| originals.push(i);
    var all = try root.Plan.init(gpa, a.original_count, a.recovery_count, originals.slice(), &.{});
    defer all.deinit(gpa);
    for (a.originals, 0..) |shard, i| try decoder.add_original_shard(i, shard);
    try testing.expect(try decoder.decode_with_recovery_plan(&all) == null);

    try reset_to(&decoder, gpa, b);
    try prepared_round(gpa, &decoder, b, recovery_b, 0);
    try prepared_round(gpa, &decoder, b, recovery_b, 1);
}

/// Decodes an `EnginePlan` from `bytes` and runs it (the `reed_solomon_engine` fuzz target).
/// Inputs too short to describe a case are skipped; a failed check is an error.
pub fn run_engine_input(gpa: Allocator, bytes: []const u8) !void {
    var u = Unstructured.init(bytes);
    const plan = u.arbitrary(EnginePlan) catch return;
    plan.run(gpa, &u) catch |err| return skip_short_input(err);
}

/// Decodes a `RatePlan` from `bytes` and runs it (the `reed_solomon_rate` fuzz target).
pub fn run_rate_input(gpa: Allocator, bytes: []const u8) !void {
    var u = Unstructured.init(bytes);
    const plan = u.arbitrary(RatePlan) catch return;
    plan.run(gpa, &u) catch |err| return skip_short_input(err);
}

/// Swallows the `Unstructured` errors (commonware ignores `plan.run`'s `arbitrary::Result`)
/// and returns every other error.
fn skip_short_input(err: anyerror) anyerror!void {
    switch (err) {
        error.NotEnoughData, error.IncorrectFormat, error.EmptyChoose => return,
        else => return err,
    }
}

fn run_engine_plan(plan: EnginePlan, u: *Unstructured) !void {
    try plan.run(testing.allocator, u);
}

fn run_rate_plan(plan: RatePlan, u: *Unstructured) !void {
    try plan.run(testing.allocator, u);
}

/// commonware's `minifuzz::Builder::default().with_seed(0).with_search_limit(limit)`.
fn search(limit: u64) minifuzz.Builder {
    return (minifuzz.Builder{}).with_seed(0).with_search_limit(limit);
}

const gpa_test = testing.allocator;

/// A `RateCase` whose shard bytes and erasure offsets derive from `seed`.
fn fixed_case(counts: [2]usize, shard_bytes: usize, seed: u8) !RateCase {
    var cyclic: Cyclic = .{ .bytes = &.{ seed, seed *% 17, seed +% 91 } };
    return RateCase.init(gpa_test, counts, shard_bytes, &cyclic);
}

test "minifuzz derivative" {
    try search(64).run(gpa_test, EnginePlan.derivative, run_engine_plan);
}

test "minifuzz mul" {
    try search(64).run(gpa_test, EnginePlan.mul, run_engine_plan);
}

test "minifuzz transform" {
    try search(64).run(gpa_test, EnginePlan.transform, run_engine_plan);
}

test "minifuzz engine locator" {
    try search(32).run(gpa_test, EnginePlan.locator, run_engine_plan);
}

test "minifuzz rate locator" {
    try search(32).run(gpa_test, @as(RatePlan, .locator), run_rate_plan);
}

test "minifuzz rate matches naive" {
    for ([_]RateKind{ .high, .low, .default }) |kind| {
        try search(32).run(gpa_test, RatePlan{ .matches_naive = kind }, run_rate_plan);
    }
}

test "minifuzz rate contract" {
    for ([_]RateKind{ .high, .low, .default }) |kind| {
        try search(32).run(gpa_test, RatePlan{ .contract = kind }, run_rate_plan);
    }
}

test "minifuzz recovery" {
    try search(32).run(gpa_test, @as(RatePlan, .recovery), run_rate_plan);
}

test "minifuzz prepared recovery" {
    try search(32).run(gpa_test, @as(RatePlan, .prepared_recovery), run_rate_plan);
}

test "fuzz engine plans (coverage-guided)" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var bytes: [input_bytes_max]u8 = undefined;
            const length = smith.slice(&bytes);
            try run_engine_input(testing.allocator, bytes[0..length]);
        }
    }.run, .{});
}

test "fuzz rate plans (coverage-guided)" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var bytes: [input_bytes_max]u8 = undefined;
            const length = smith.slice(&bytes);
            try run_rate_input(testing.allocator, bytes[0..length]);
        }
    }.run, .{});
}

test "derivative boundary schedule" {
    for ([_]usize{ 0, 1, 3, 4, 5, 15, 16, 17, 31, 32, 33, 64, 65 }) |count| {
        for ([_]usize{ 0, 1, 7, 8, 9, 63, 64, 65 }) |chunks| {
            const data = try gpa_test.alloc(Chunk, count * chunks);
            defer gpa_test.free(data);
            var cyclic: Cyclic = .{ .bytes = &.{ 3, 0xff, 19, 0x80 } };
            fill_chunks(data, &cyclic);
            try compare_derivative(gpa_test, data, count, chunks);
        }
    }
}

test "locator every short level" {
    // Builds each short Walsh kernel and checks it at the domain edges.
    for (0..engine.GF_BITS) |bits| {
        const n = @as(usize, 1) << @intCast(bits);
        for ([_]usize{ 1, n / 2 + 1, n }) |end| try compare_short_locator(gpa_test, n, end, 0x5a5a);
    }
}

test "locator domain boundaries" {
    // Straddle several Walsh size changes and the switch to the full field above 32768. The
    // low-rate check calls `eval_walsh` directly, which ignores DIRECT_EVALUATION_LIMIT.
    const ends = [_]usize{
        2, 3, 4, 7, 8, 15, 16, 127, 128, 129, 511, 512, 513, 32767, 32768, 32769, 65535, 65536,
    };
    for ([_]bool{ false, true }) |high| {
        for (ends) |end| {
            // Chunk size one places the other group immediately after it.
            const original_count = if (high) end - 1 else 1;
            const recovery_count = if (high) 1 else end - 1;
            for (0..3) |pattern| {
                var received = try BitSet.initEmpty(gpa_test, end);
                defer received.deinit(gpa_test);
                for (0..end) |i| {
                    if (pattern == 0 or (pattern == 1 and i % 3 != 0)) received.set(i);
                }
                try compare_rate_locator(gpa_test, high, original_count, recovery_count, &received);
            }
        }
    }
}

test "prepared received mask reuse" {
    // Reuse larger masks for both partial and full final words in each rate.
    for ([_][2]usize{ .{ 3, 5 }, .{ 5, 3 }, .{ 16, 48 }, .{ 48, 16 } }) |counts| {
        var large = try fixed_case(.{ counts[0] * 4, counts[1] * 4 }, 2, 21);
        defer large.deinit(gpa_test);
        var small = try fixed_case(counts, 2, 23);
        defer small.deinit(gpa_test);
        try exercise_prepared_reuse(gpa_test, &large, &small);
    }
}

test "prepared low locator boundaries" {
    var high = try fixed_case(.{ 11, 3 }, 2, 23);
    defer high.deinit(gpa_test);
    // Three originals pad to a chunk of 4, so the decoding domain ends at 4 + recovery_count.
    // Straddle DIRECT_EVALUATION_LIMIT, then take the transform path with a larger domain.
    const limit = rate.low.DIRECT_EVALUATION_LIMIT - 4;
    for ([_]usize{ limit - 1, limit, limit + 1, 510 }) |recovery_count| {
        var low = try fixed_case(.{ 3, recovery_count }, 66, 21);
        defer low.deinit(gpa_test);
        try exercise_prepared_reuse(gpa_test, &low, &high);
    }
}

test "engines match naive on field and log edges" {
    var chunks: [3]Chunk = undefined;
    const edges = [_]GfElement{ 0, 1, 0x00ff, 0x0100, 0x7fff, 0x8000, 0xfffe, 0xffff };
    for (&chunks, 0..) |*chunk, chunk_index| {
        for (0..half) |lane| {
            const value = edges[(chunk_index * 32 + lane) % edges.len];
            chunk[lane] = @truncate(value);
            chunk[half + lane] = @truncate(value >> 8);
        }
    }
    for ([_]GfElement{ 0, 1, 2, 0x7fff, 0x8000, 0xfffe, 0xffff }) |log_m| {
        try compare_mul(gpa_test, &.{}, log_m);
        try compare_mul(gpa_test, &chunks, log_m);
    }
    var multi_vector: [65]Chunk = undefined;
    var cyclic: Cyclic = .{ .bytes = &.{ 3, 0xff, 19, 0x80, 0 } };
    fill_chunks(&multi_vector, &cyclic);
    try compare_mul(gpa_test, &multi_vector, 12_345);
}

test "log tables match independent field multiplication" {
    const exp_log = engine.tables.get_exp_log();
    var coefficient: GfElement = 1;
    var log_m: u32 = 0;
    while (log_m <= GF_MODULUS) : (log_m += 1) {
        if (log_m == GF_MODULUS) {
            try testing.expectEqual(1, coefficient); // The generator closes at GF_MODULUS.
        } else if (log_m > 0) {
            try testing.expect(coefficient != 1); // The generator does not cycle early.
        }
        for ([_]u4{ 0, 4, 8, 12 }) |shift| {
            var bit_products: [4]GfElement = undefined;
            for (&bit_products, 0..) |*product, bit| {
                const input = @as(GfElement, 1) << @intCast(shift + bit);
                product.* = independent_mul_coefficient(input, coefficient);
            }
            for (0..16) |nibble| {
                var expected: GfElement = 0;
                for (bit_products, 0..) |product, bit| {
                    if (nibble & (@as(usize, 1) << @intCast(bit)) != 0) expected ^= product;
                }
                const value = @as(GfElement, @intCast(nibble)) << shift;
                const actual = engine.tables.mul(value, @intCast(log_m), exp_log.exp, exp_log.log);
                try testing.expectEqual(expected, actual);
            }
        }
        coefficient = polynomial_mul(coefficient, 2);
    }
}

test "engines match naive on offset, truncated, and skewed transforms" {
    // Size-4 cases pick butterfly branches through `skew_delta`: the transform reads `log_m01`,
    // `log_m02`, and `log_m23` from `skew[skew_delta..skew_delta + 3]`, and `skew` holds
    // GF_MODULUS (a zero coefficient) exactly at indices `2^k - 1`.
    const cases = [_][5]usize{
        .{ 0, 1, 0, GF_ORDER - 1, 1 },    .{ 1, 2, 1, 0, 2 },     .{ 2, 4, 1, 3, 2 },
        .{ 3, 4, 3, 7, 1 },               .{ 2, 8, 5, 31, 3 },    .{ 1, 4, 4, 4, 0 },
        .{ 5, 16, 16, GF_ORDER - 16, 2 }, .{ 1, 4, 0, 4, 1 },     .{ 1, 4, 4, 0, 1 },
        .{ 2, 4, 3, 1, 65 },              .{ 3, 4, 2, 2, 1 },     .{ 2, 4, 4, 4, 65 },
        .{ 1, 16, 13, 0, 1 },             .{ 2, 64, 37, 17, 17 },
    };
    for (cases) |case| {
        const pos, const size, const truncated_size, const skew_delta, const shard_chunks = case;
        const shard_count = pos + size + 2;
        const data = try gpa_test.alloc(Chunk, shard_count * shard_chunks);
        defer gpa_test.free(data);
        var cyclic: Cyclic = .{ .bytes = &.{ 3, 0xff, 19, 0x80, 0 } };
        fill_chunks(data, &cyclic);
        try compare_transform(gpa_test, data, .{
            .shard_count = shard_count,
            .shard_chunks = shard_chunks,
            .pos = pos,
            .size = size,
            .truncated_size = truncated_size,
            .skew_delta = skew_delta,
        });
    }
}

test "maximum domain transform regression" {
    const data = try gpa_test.alloc(Chunk, GF_ORDER);
    defer gpa_test.free(data);
    var cyclic: Cyclic = .{ .bytes = &.{ 3, 0xff, 19, 0x80, 0 } };
    fill_chunks(data, &cyclic);
    try compare_transform(gpa_test, data, .{
        .shard_count = GF_ORDER,
        .shard_chunks = 1,
        .pos = 0,
        .size = GF_ORDER,
        .truncated_size = 1,
        .skew_delta = 0,
    });
}

test "optimized eval_poly matches naive" {
    const input = try gpa_test.create([GF_ORDER]GfElement);
    defer gpa_test.destroy(input);
    const expected = try gpa_test.create([GF_ORDER]GfElement);
    defer gpa_test.destroy(expected);
    const values = [_]GfElement{ 0, 1, 2, 0x7fff, 0x8000, 0xfffe, 0xffff };
    for ([_]usize{ 0, 1, 257 }) |truncated_size| {
        input.* = @splat(0);
        for (input[0..truncated_size], 0..) |*value, i| value.* = values[i % values.len];
        expected.* = input.*;
        engine.eval_poly(Naive, expected, truncated_size);
        inline for (engines) |E| {
            const actual = try gpa_test.create([GF_ORDER]GfElement);
            defer gpa_test.destroy(actual);
            actual.* = input.*;
            engine.eval_poly(E, actual, truncated_size);
            try testing.expectEqualSlices(GfElement, expected, actual);
        }
    }
}

test "rate engines match naive with partial chunks and mixed erasures" {
    var high_a = try fixed_case(.{ 11, 3 }, 66, 3);
    defer high_a.deinit(gpa_test);
    var high_b = try fixed_case(.{ 9, 4 }, 130, 5);
    defer high_b.deinit(gpa_test);
    inline for (engines) |E| try rate_matches_naive(E, .high, gpa_test, &high_a, &high_b);

    var low_a = try fixed_case(.{ 3, 11 }, 126, 7);
    defer low_a.deinit(gpa_test);
    var low_b = try fixed_case(.{ 4, 9 }, 62, 11);
    defer low_b.deinit(gpa_test);
    inline for (engines) |E| try rate_matches_naive(E, .low, gpa_test, &low_a, &low_b);
}

test "default rate switches and recovery decoder reuses work" {
    var high = try fixed_case(.{ 11, 3 }, 66, 13);
    defer high.deinit(gpa_test);
    var low = try fixed_case(.{ 3, 11 }, 130, 17);
    defer low.deinit(gpa_test);
    inline for (engines) |E| try rate_matches_naive(E, .default, gpa_test, &high, &low);
    try exercise_recovery_reuse(gpa_test, &high, &low);
}
