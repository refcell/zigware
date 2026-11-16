//! Deterministic seeded fuzzing for codec tests, and `Draws`, the way every seeded fuzz body
//! draws values from its input.
//!
//! A fuzz test body takes a `*std.testing.Smith`, so the same body runs under coverage-guided
//! fuzzing (`std.testing.fuzz`, `zig build test --fuzz`) and here, where `zig build test`
//! feeds it pseudo-random inputs from a fixed seed. Iterations scale with
//! `build_options.fuzz_soak`; `build_options.fuzz_seed` is mixed into every seed.
//! (codec sits below `invariants` in the package graph, so it carries this small driver
//! itself; other packages use `invariants.minifuzz`.)
//!
//! On a fixed input (`smith.in`, the seeded path) Smith's typed draws are nearly inert:
//! `value(T)` and the range and index draws read an 8-byte word and return the minimum when
//! it falls outside the range, which random bytes almost always do for types narrower than
//! 64 bits; `eos` is true for any nonzero byte, so `while (!smith.eos())` runs about one step;
//! and `slice` returns nothing when the rest of the input is longer than its buffer. No
//! driver can lay out input bytes to avoid this, because what a draw consumes depends on the
//! draw. `Draws` reads raw bytes with `smith.bytes`, which passes them through unchanged, and
//! derives every value from them, so seeded inputs give uniform values (the package
//! `utils.fuzz` re-exports it for packages above utils).

const std = @import("std");
const assert = std.debug.assert;
const build_options = @import("build_options");
const Smith = std.testing.Smith;

/// Largest input handed to one iteration.
pub const input_size_max = 4096;

/// Runs `body` on `iterations * fuzz_soak` seeded random inputs, then under
/// `std.testing.fuzz` for coverage-guided runs.
pub fn run(
    context: anytype,
    comptime body: fn (@TypeOf(context), *Smith) anyerror!void,
    seed: u64,
    iterations: u32,
) !void {
    assert(iterations > 0);
    var prng = std.Random.DefaultPrng.init(seed ^ build_options.fuzz_seed);
    const random = prng.random();
    var input: [input_size_max]u8 = undefined;
    const total: u64 = @as(u64, iterations) * build_options.fuzz_soak;
    var iteration: u64 = 0;
    while (iteration < total) : (iteration += 1) {
        // Bias toward short inputs, where most decoder edge cases live.
        const len_max: usize = if (random.boolean()) 64 else input.len;
        const len = random.uintAtMost(usize, len_max);
        random.bytes(input[0..len]);
        var smith: Smith = .{ .in = input[0..len] };
        body(context, &smith) catch |err| {
            std.debug.print("fuzz: seed {d} iteration {d} failed: {t}\n", .{
                seed ^ build_options.fuzz_seed, iteration, err,
            });
            return err;
        };
    }
    assert(iteration == total);
    try std.testing.fuzz(context, body, .{});
}

/// Uniform draws from a `Smith` for fuzz bodies: `const draws: Draws = .init(smith);`.
///
/// Every value comes from raw input bytes (from the fuzzer under coverage-guided fuzzing).
/// Draws past the end of a seeded input read zero bytes, so they return zero or the low end of
/// the range. Bound loops by a drawn step count, not by `smith.eos()`. The methods are
/// `inline` so each call site keeps its own fuzzer id.
pub const Draws = struct {
    smith: *Smith,

    pub fn init(smith: *Smith) Draws {
        return .{ .smith = smith };
    }

    /// A uniform `T`: an integer, float, bool, or exhaustive enum, or an array of them.
    pub inline fn value(draws: Draws, comptime T: type) T {
        switch (@typeInfo(T)) {
            .array => |array| {
                var result: T = undefined;
                if (array.child == u8) {
                    draws.smith.bytes(&result);
                } else {
                    for (&result) |*item| item.* = draws.scalar(array.child);
                }
                return result;
            },
            else => return draws.scalar(T),
        }
    }

    inline fn scalar(draws: Draws, comptime T: type) T {
        switch (@typeInfo(T)) {
            .bool => {
                var raw: [1]u8 = undefined;
                draws.smith.bytes(&raw);
                return raw[0] & 1 == 1;
            },
            .@"enum" => |info| {
                comptime assert(info.mode == .exhaustive and info.field_names.len > 0);
                const values = comptime std.enums.values(T);
                return values[draws.index(values.len)];
            },
            .int, .float => {
                const Raw = @Int(.unsigned, 8 * @sizeOf(T));
                var raw: [@sizeOf(T)]u8 = undefined;
                draws.smith.bytes(&raw);
                const bits: @Int(.unsigned, @bitSizeOf(T)) =
                    @truncate(std.mem.readInt(Raw, &raw, .little));
                return @bitCast(bits);
            },
            else => @compileError("Draws cannot draw " ++ @typeName(T)),
        }
    }

    /// A uniform integer in `[at_least, at_most]`, from as few bytes as the range needs (for
    /// ranges that are not a power of two the low values are slightly more likely).
    pub inline fn range_at_most(draws: Draws, comptime T: type, at_least: T, at_most: T) T {
        comptime assert(@typeInfo(T) == .int and @bitSizeOf(T) <= 64);
        assert(at_least <= at_most);
        const U = @Int(.unsigned, @bitSizeOf(T));
        const signed = @typeInfo(T).int.signedness == .signed;
        const sign: U = if (signed) 1 << (@bitSizeOf(T) - 1) else 0;
        // Map to unsigned keeping the order, so signed ranges work the same way.
        const low: u64 = @as(U, @bitCast(at_least)) ^ sign;
        const span: u64 = (@as(U, @bitCast(at_most)) ^ sign) - low;
        const width: usize = (64 - @clz(span) + 7) / 8;
        var raw: [8]u8 = @splat(0);
        draws.smith.bytes(raw[0..width]);
        const word = std.mem.readInt(u64, &raw, .little);
        const offset = if (span == std.math.maxInt(u64)) word else word % (span + 1);
        const result: T = @bitCast(@as(U, @intCast(low + offset)) ^ sign);
        assert(at_least <= result and result <= at_most);
        return result;
    }

    /// A uniform integer in `[at_least, less_than)`.
    pub inline fn range_less_than(draws: Draws, comptime T: type, at_least: T, less_than: T) T {
        assert(at_least < less_than);
        return draws.range_at_most(T, at_least, less_than - 1);
    }

    /// A uniform index below `len`.
    pub inline fn index(draws: Draws, len: usize) usize {
        assert(len > 0);
        return draws.range_less_than(usize, 0, len);
    }

    /// Fills `out` with input bytes.
    pub inline fn bytes(draws: Draws, out: []u8) void {
        draws.smith.bytes(out);
    }

    /// The rest of a seeded input, up to `buffer.len` bytes, copied into `buffer` (under
    /// coverage-guided fuzzing, `smith.slice`). For bodies that treat the input as one byte
    /// string; the driver already varies its length.
    pub inline fn slice(draws: Draws, buffer: []u8) []u8 {
        if (draws.smith.in) |in| {
            const len = @min(in.len, buffer.len);
            draws.smith.bytes(buffer[0..len]);
            assert(draws.smith.in.?.len == in.len - len);
            return buffer[0..len];
        }
        const len = draws.smith.slice(buffer);
        assert(len <= buffer.len);
        return buffer[0..len];
    }
};

const testing = std.testing;

test "draws are uniform on random seeded input" {
    var prng = std.Random.DefaultPrng.init(0x6472617773);
    var input: [64]u8 = undefined;
    var seen_u8: [256]bool = @splat(false);
    var seen_range: [7]bool = @splat(false);
    var seen_signed: [5]bool = @splat(false);
    var seen_bool: [2]bool = @splat(false);
    for (0..2000) |_| {
        prng.random().bytes(&input);
        var smith: Smith = .{ .in = &input };
        const draws: Draws = .init(&smith);
        seen_u8[draws.value(u8)] = true;
        seen_range[draws.range_at_most(u32, 3, 9) - 3] = true;
        seen_signed[@intCast(draws.range_at_most(i16, -2, 2) + 2)] = true;
        seen_bool[@intFromBool(draws.value(bool))] = true;
        const ordering = draws.value(std.math.Order);
        try testing.expect(ordering == .lt or ordering == .eq or ordering == .gt);
        try testing.expect(draws.index(1000) < 1000);
    }
    for (seen_u8) |seen| try testing.expect(seen);
    for (seen_range ++ seen_signed ++ seen_bool) |seen| try testing.expect(seen);
}

test "draws read the input in order and zeros past its end" {
    const input = [_]u8{ 0x34, 0x12, 5, 0xaa, 0xbb, 0xcc };
    var smith: Smith = .{ .in = &input };
    const draws: Draws = .init(&smith);
    try testing.expectEqual(@as(u16, 0x1234), draws.value(u16));
    // A span below 256 takes one byte: 5 % 7.
    try testing.expectEqual(@as(u8, 15), draws.range_at_most(u8, 10, 16));
    var buffer: [8]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc }, draws.slice(&buffer));
    try testing.expectEqual(@as(u32, 0), draws.value(u32));
    try testing.expectEqual(@as(i8, -3), draws.range_at_most(i8, -3, 4));
    try testing.expectEqual(@as(u64, 0), draws.range_at_most(u64, 0, std.math.maxInt(u64)));
    try testing.expectEqualSlices(u8, &.{}, draws.slice(&buffer));
}
