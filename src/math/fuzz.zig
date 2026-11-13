//! A small structured-input source for property and fuzz tests, plus two drivers.
//!
//! `Unstructured` turns raw bytes into values, like Rust's `arbitrary::Unstructured`: when the
//! bytes run out it yields zeros (and the low end of ranges), so every input is valid.
//!
//! - `run_seeded` runs a test body on random inputs from a seeded PRNG inside the normal
//!   `zig build test` (iterations scale with `build_options.fuzz_soak`, and the seed mixes in
//!   `build_options.fuzz_seed`), like commonware's `minifuzz::test`.
//! - `run_smith` adapts `std.testing.fuzz` so the coverage-guided fuzzer drives the same body.
//!
//! This stands in for `invariants.minifuzz` until that package lands.

const std = @import("std");
const build_options = @import("build_options");
const assert = std.debug.assert;

pub const Unstructured = struct {
    data: []const u8,
    position: usize = 0,

    pub fn init(data: []const u8) Unstructured {
        return .{ .data = data };
    }

    pub fn remaining(u: *const Unstructured) usize {
        assert(u.position <= u.data.len);
        return u.data.len - u.position;
    }

    pub fn is_empty(u: *const Unstructured) bool {
        return u.remaining() == 0;
    }

    /// Fill `out` with input bytes, then zeros once the input is exhausted.
    pub fn bytes(u: *Unstructured, out: []u8) void {
        const take = @min(out.len, u.remaining());
        @memcpy(out[0..take], u.data[u.position..][0..take]);
        @memset(out[take..], 0);
        u.position += take;
        assert(u.position <= u.data.len);
    }

    /// An integer from little-endian input bytes.
    pub fn int(u: *Unstructured, comptime T: type) T {
        comptime assert(@typeInfo(T) == .int);
        const Unsigned = @Int(.unsigned, @bitSizeOf(T));
        var buffer: [(@bitSizeOf(T) + 7) / 8]u8 = undefined;
        u.bytes(&buffer);
        var value: Unsigned = 0;
        for (buffer, 0..) |byte, position| {
            value |= @as(Unsigned, byte) << @intCast(8 * position);
        }
        return @bitCast(value);
    }

    pub fn boolean(u: *Unstructured) bool {
        return u.int(u8) & 1 == 1;
    }

    /// An integer in `[low, high]`.
    pub fn int_in_range(u: *Unstructured, comptime T: type, low: T, high: T) T {
        assert(low <= high);
        const Unsigned = @Int(.unsigned, @bitSizeOf(T));
        const span: Unsigned = @bitCast(high -% low);
        const raw: Unsigned = @bitCast(u.int(T));
        const offset = if (span == std.math.maxInt(Unsigned)) raw else raw % (span + 1);
        const result = low +% @as(T, @bitCast(offset));
        assert(result >= low and result <= high);
        return result;
    }

    /// An index into a collection of `count` items (`count > 0`).
    pub fn index(u: *Unstructured, count: usize) usize {
        assert(count > 0);
        return @intCast(u.int_in_range(u64, 0, count - 1));
    }

    /// A collection length, at most `max`.
    pub fn length(u: *Unstructured, max: usize) usize {
        return @intCast(u.int_in_range(u64, 0, max));
    }

    /// One variant of an enum, chosen uniformly.
    pub fn choose(u: *Unstructured, comptime E: type) E {
        const fields = @typeInfo(E).@"enum".field_names;
        comptime assert(fields.len > 0);
        const choice = u.index(fields.len);
        inline for (0..fields.len) |field_index| {
            if (choice == field_index) return @field(E, fields[field_index]);
        }
        unreachable;
    }
};

/// Largest input a seeded iteration generates.
pub const input_size_max = 4096;

/// Run `body` on `iterations * fuzz_soak` seeded random inputs.
pub fn run_seeded(
    seed: u64,
    iterations: u32,
    context: anytype,
    comptime body: fn (@TypeOf(context), *Unstructured) anyerror!void,
) !void {
    assert(iterations > 0);
    const total = @as(u64, iterations) * build_options.fuzz_soak;
    var prng = std.Random.DefaultPrng.init(seed ^ build_options.fuzz_seed);
    const random = prng.random();
    var buffer: [input_size_max]u8 = undefined;
    var iteration: u64 = 0;
    while (iteration < total) : (iteration += 1) {
        // Bias towards short inputs so the zero-fill path is covered too.
        const size_max: usize = if (random.boolean()) 64 else input_size_max;
        const size = random.uintAtMost(usize, size_max);
        random.bytes(buffer[0..size]);
        var u = Unstructured.init(buffer[0..size]);
        body(context, &u) catch |err| {
            std.debug.print("fuzz: seed {d} iteration {d} failed\n", .{ seed, iteration });
            return err;
        };
    }
    assert(iteration == total);
}

/// Adapter for `std.testing.fuzz`: the fuzzer's bytes become one `Unstructured` input.
pub fn run_smith(
    context: anytype,
    smith: *std.testing.Smith,
    comptime body: fn (@TypeOf(context), *Unstructured) anyerror!void,
) !void {
    var buffer: [input_size_max]u8 = undefined;
    const size = smith.slice(&buffer);
    assert(size <= buffer.len);
    var u = Unstructured.init(buffer[0..size]);
    try body(context, &u);
}

test "unstructured yields zeros when exhausted" {
    var u = Unstructured.init(&.{ 1, 2 });
    try std.testing.expectEqual(@as(u16, 0x0201), u.int(u16));
    try std.testing.expect(u.is_empty());
    try std.testing.expectEqual(@as(u64, 0), u.int(u64));
    try std.testing.expectEqual(@as(u8, 5), u.int_in_range(u8, 5, 9));
}

test "unstructured ranges stay in bounds" {
    var prng = std.Random.DefaultPrng.init(1);
    var buffer: [256]u8 = undefined;
    prng.random().bytes(&buffer);
    var u = Unstructured.init(&buffer);
    for (0..32) |_| {
        const value = u.int_in_range(i32, -3, 3);
        try std.testing.expect(value >= -3 and value <= 3);
        const full = u.int_in_range(u64, 0, std.math.maxInt(u64));
        _ = full;
    }
}
