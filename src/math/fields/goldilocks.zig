//! The Goldilocks field, integers modulo P = 2^64 - 2^32 + 1 (commonware
//! `math::fields::goldilocks`).
//!
//! The codec encoding is the canonical value as a big-endian u64; decoding rejects
//! values >= P.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const algebra = @import("../algebra.zig");
const minifuzz = @import("invariants").minifuzz;
const Unstructured = minifuzz.Unstructured;
const testing_types = @import("../testing.zig");

/// The modulus P := 2^64 - 2^32 + 1.
pub const P: u64 = 0xffff_ffff_0000_0001;

/// An element of the Goldilocks field, always reduced (< P).
pub const F = struct {
    value: u64,

    comptime {
        assert(@sizeOf(F) == 8);
        assert(P == (0 -% (@as(u64, 1) << 32)) + 1);
    }

    pub const fixed_size = 8;

    pub const zero: F = .{ .value = 0 };
    pub const one: F = .{ .value = 1 };

    /// Any non-zero element is GENERATOR^k for some k; GENERATOR^((P - 1) / 64) = 8.
    pub const generator: F = .{ .value = 0xd64f951101aff9bf };
    /// An element of order 2^32, chosen so that ROOT_OF_UNITY^(2^26) = 8.
    pub const root_of_unity_max: F = .{ .value = 0xee41f5320c4ea145 };
    /// An element guaranteed not to be any power of `root_of_unity_max`.
    pub const not_root_of_unity: F = .{ .value = 0x79bc2f50acd74161 };
    /// The inverse of `not_root_of_unity`.
    pub const not_root_of_unity_inv: F = .{ .value = 0x1036c4023580ce8d };

    pub const max_lg_root_order: u8 = 32;

    /// Reduce any u64 into the field.
    pub fn from_u64(x: u64) F {
        // 2P > 2^64 - 1, so one subtraction suffices.
        const result: F = .{ .value = if (x >= P) x - P else x };
        assert(result.value < P);
        return result;
    }

    pub fn add(a: F, b: F) F {
        assert(a.value < P);
        // a + b <= 2P - 2, so subtract P at most once. On overflow the true sum exceeds
        // 2^64 > P, and the wrapped subtraction is the reduced result.
        const sum = @addWithOverflow(a.value, b.value);
        const difference = @subWithOverflow(sum[0], P);
        const result: F = .{
            .value = if (sum[1] == 1 or difference[1] == 0) difference[0] else sum[0],
        };
        assert(result.value < P);
        return result;
    }

    /// Addition on possibly unreduced inputs (any u64 values); still correct because a
    /// single subtraction of P suffices for any two u64 values.
    fn add_unreduced(a: u64, b: u64) F {
        const sum = @addWithOverflow(a, b);
        const difference = @subWithOverflow(sum[0], P);
        const value = if (sum[1] == 1 or difference[1] == 0) difference[0] else sum[0];
        return from_u64(value);
    }

    pub fn sub(a: F, b: F) F {
        assert(a.value < P);
        const difference = @subWithOverflow(a.value, b.value);
        const result: F = .{
            .value = if (difference[1] == 1) difference[0] +% P else difference[0],
        };
        assert(result.value < P);
        return result;
    }

    pub fn neg(a: F) F {
        return zero.sub(a);
    }

    pub fn double(a: F) F {
        return a.add(a);
    }

    /// Reduce a 128-bit integer, using 2^64 = 2^32 - 1 and 2^96 = -1 (mod P):
    /// x = c 2^96 + b 2^64 + a = b (2^32 - 1) + (a - c).
    pub fn reduce_128(x: u128) F {
        const low: u64 = @truncate(x);
        const middle: u64 = @truncate((x >> 64) & 0xffff_ffff);
        const high: u64 = @truncate(x >> 96);
        // low - high wraps into any u64; middle * (2^32 - 1) < 2^64.
        const difference = @subWithOverflow(low, high);
        const low_minus_high = if (difference[1] == 1) difference[0] +% P else difference[0];
        const result = add_unreduced(low_minus_high, (middle << 32) - middle);
        assert(result.value < P);
        return result;
    }

    pub fn mul(a: F, b: F) F {
        assert(a.value < P and b.value < P);
        return reduce_128(@as(u128, a.value) * b.value);
    }

    pub fn square(a: F) F {
        return a.mul(a);
    }

    /// Multiplicative inverse; zero maps to zero.
    pub fn inv(a: F) F {
        const result = algebra.exp(F, a, &.{P - 2});
        assert(a.value == 0 or result.mul(a).value == 1);
        return result;
    }

    pub fn eql(a: F, b: F) bool {
        return a.value == b.value;
    }

    pub fn root_of_unity(lg: u8) ?F {
        if (lg > max_lg_root_order) return null;
        var out = root_of_unity_max;
        var step: u8 = 0;
        while (step < max_lg_root_order - lg) : (step += 1) out = out.square();
        return out;
    }

    pub fn coset_shift() F {
        return not_root_of_unity;
    }

    pub fn coset_shift_inv() F {
        return not_root_of_unity_inv;
    }

    pub fn div_2(a: F) F {
        assert(a.value < P);
        if (a.value & 1 == 0) return .{ .value = a.value >> 1 };
        const sum = @addWithOverflow(a.value, P);
        const result: F = .{ .value = (@as(u64, sum[1]) << 63) | (sum[0] >> 1) };
        assert(result.value < P);
        return result;
    }

    /// Uniform sampling by rejection; fails about once every 2^32 draws.
    /// `rng` is a `utils.rng` generator (`next_u64`), so draws match commonware's.
    pub fn random(rng: anytype) F {
        while (true) {
            const x = rng.next_u64();
            if (x < P) return .{ .value = x };
        }
    }

    pub fn arbitrary(u: *Unstructured) minifuzz.Error!F {
        return from_u64(try u.arbitrary(u64));
    }

    pub fn to_le_bytes(a: F) [8]u8 {
        var out: [8]u8 = undefined;
        std.mem.writeInt(u64, &out, a.value, .little);
        return out;
    }

    pub fn write(a: F, writer: *codec.Writer) void {
        assert(a.value < P);
        writer.write_int(u64, a.value);
    }

    pub fn read(_: std.mem.Allocator, reader: *codec.Reader, _: void) codec.Error!F {
        const x = try reader.read_int(u64);
        if (x >= P) return reader.invalid("F", "out of range");
        return .{ .value = x };
    }

    /// How many elements `stream_from_u64s` uses for `bits` bits.
    pub fn bits_to_elements(bits: usize) usize {
        return std.math.divCeil(usize, bits, 63) catch unreachable; // 63 != 0.
    }

    pub fn format(a: F, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{X:0>16}", .{a.value});
    }
};

/// Packs a stream of u64s into field elements of 63 bits each.
pub const StreamFromU64s = struct {
    inner: []const u64,
    position: usize = 0,
    accumulator: u128 = 0,
    accumulator_bits: u32 = 0,

    pub fn next(self: *StreamFromU64s) ?F {
        while (self.accumulator_bits < 63 and self.position < self.inner.len) {
            const word: u128 = self.inner[self.position];
            self.accumulator |= word << @intCast(self.accumulator_bits);
            self.position += 1;
            self.accumulator_bits += 64;
        }
        assert(self.accumulator_bits <= 126);
        if (self.accumulator_bits == 0) return null;
        self.accumulator_bits -|= 63;
        const out: F = .{ .value = @as(u64, @truncate(self.accumulator)) & ((1 << 63) - 1) };
        self.accumulator >>= 63;
        return out;
    }
};

/// Inverts `StreamFromU64s`; may produce one extra zero word.
pub const StreamToU64s = struct {
    inner: []const F,
    position: usize = 0,
    accumulator: u128 = 0,
    accumulator_bits: u32 = 0,

    pub fn next(self: *StreamToU64s) ?u64 {
        while (self.accumulator_bits < 64 and self.position < self.inner.len) {
            const x = self.inner[self.position].value & ((1 << 63) - 1);
            self.accumulator |= @as(u128, x) << @intCast(self.accumulator_bits);
            self.position += 1;
            self.accumulator_bits += 63;
        }
        assert(self.accumulator_bits <= 126);
        if (self.accumulator_bits == 0) return null;
        self.accumulator_bits -|= 64;
        const out: u64 = @truncate(self.accumulator);
        self.accumulator >>= 64;
        return out;
    }
};

pub fn stream_from_u64s(inner: []const u64) StreamFromU64s {
    return .{ .inner = inner };
}

pub fn stream_to_u64s(inner: []const F) StreamToU64s {
    return .{ .inner = inner };
}

comptime {
    algebra.assert_field_ntt(F);
}

/// Most words `stream_roundtrip` collects; a longer arbitrary `Vec<u64>` is truncated.
const stream_words_max = 1024;

/// The goldilocks fuzz plan (commonware `fields::goldilocks::fuzz::Plan`).
pub fn fuzz_plan(_: void, u: *Unstructured) !void {
    switch (try u.arbitrary(enum { stream_roundtrip, read_rejects_out_of_range, fuzz_field })) {
        .stream_roundtrip => {
            // arbitrary's Vec<u64>: a continue flag before each element.
            var data: [stream_words_max]u64 = undefined;
            var count: usize = 0;
            while (count < data.len and try u.arbitrary(bool)) : (count += 1) {
                data[count] = try u.arbitrary(u64);
            }
            var from = stream_from_u64s(data[0..count]);
            var to_buffer: [F.bits_to_elements(64 * stream_words_max)]F = undefined;
            var element_count: usize = 0;
            while (from.next()) |element| : (element_count += 1) {
                to_buffer[element_count] = element;
            }
            assert(element_count == F.bits_to_elements(64 * count));
            var to = stream_to_u64s(to_buffer[0..element_count]);
            for (data[0..count]) |word| {
                if (to.next() != word) return error.StreamMismatch;
            }
        },
        .read_rejects_out_of_range => {
            try check_read_rejects(u.int_in_range(u64, P, std.math.maxInt(u64)));
        },
        .fuzz_field => try algebra.test_suites.fuzz_field_ntt(F, u),
    }
}

fn check_read_rejects(x: u64) !void {
    assert(x >= P);
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, x, .big);
    var reader = codec.Reader.init(&bytes);
    if (F.read(std.testing.allocator, &reader, {})) |_| {
        return error.AcceptedOutOfRange;
    } else |err| if (err != error.Invalid) return err;
}

const testing = std.testing;

test "goldilocks fuzz plan" {
    try minifuzz.run(testing.allocator, {}, fuzz_plan);
}

test "goldilocks fuzz plan (coverage-guided)" {
    try testing.fuzz({}, testing_types.smith_body(void, fuzz_plan), .{});
}

test "read rejects the modulus (regression)" {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, P, .big);
    try testing.expectError(error.Invalid, codec.decode_fixed(F, &bytes));
    std.mem.writeInt(u64, &bytes, P - 1, .big);
    try testing.expectEqual(P - 1, (try codec.decode_fixed(F, &bytes)).value);
}

test "generator calculation" {
    try testing.expect(F.generator.eql(algebra.exp(F, F.from_u64(7), &.{133})));
}

test "root of unity calculation" {
    try testing.expect(F.root_of_unity_max.eql(algebra.exp(F, F.generator, &.{(P - 1) >> 32})));
}

test "not root of unity calculation" {
    try testing.expect(F.not_root_of_unity.eql(algebra.exp(F, F.generator, &.{1 << 32})));
}

test "not root of unity inverse calculation" {
    try testing.expect(F.not_root_of_unity.mul(F.not_root_of_unity_inv).eql(F.one));
}

test "root of unity exp" {
    try testing.expect(algebra.exp(F, F.root_of_unity_max, &.{1 << 26}).eql(F.from_u64(8)));
}

test "reduce_128 matches u128 modulo" {
    var prng = std.Random.DefaultPrng.init(42);
    const random = prng.random();
    for (0..10_000) |_| {
        const x = random.int(u128);
        try testing.expectEqual(@as(u64, @intCast(x % P)), F.reduce_128(x).value);
    }
    const max: u128 = std.math.maxInt(u128);
    try testing.expectEqual(@as(u64, @intCast(max % P)), F.reduce_128(max).value);
}

test "encode is big-endian" {
    const bytes = codec.encode_fixed(F, F.from_u64(0x0102030405060708));
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, &bytes);
}
