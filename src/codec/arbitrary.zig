//! Deterministic value generation for conformance tests (codec/src/conformance.rs).
//!
//! commonware builds each conformance value with the `arbitrary` crate (1.4) from the
//! keystream of `ChaCha8Rng::seed_from_u64(seed)`. This module reproduces both bit for bit, so
//! zigware's encodings hash to the values committed in commonware's `conformance.toml`:
//!
//! - `Keystream`: rand_core 0.10 `seed_from_u64` (PCG32 key expansion) feeding ChaCha8 with a
//!   64-bit block counter and a zero 64-bit stream id, generated one block at a time on demand.
//! - `Unstructured`: arbitrary's byte consumer (`fill_buffer`, `int_in_range`, `bytes`,
//!   `arbitrary_byte_size`, and iterator continuation bytes).
//! - `value(T, ...)`: arbitrary's `Arbitrary` impls for the Rust type each Zig type stands
//!   for. Custom types declare `pub fn arbitrary(gpa, *Unstructured) Error!Self`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const ChaCha8 = std.crypto.stream.chacha.ChaCha8With64BitNonce;

pub const Error = error{ NotEnoughData, IncorrectFormat, OutOfMemory };

/// Initial size of the random buffer behind each value.
pub const buffer_size_initial = 4096;
/// Largest buffer tried before giving up (16 MiB).
pub const buffer_size_max = 16 * 1024 * 1024;

/// One output of rand_core's PCG32 key expansion.
fn pcg32(state: *u64) [4]u8 {
    const multiplier: u64 = 0x5851_f42d_4c95_7f2d;
    const increment: u64 = 0xa176_54e4_6fbe_17f3;
    state.* = state.* *% multiplier +% increment;
    const current = state.*;
    const xorshifted: u32 = @truncate(((current >> 18) ^ current) >> 27);
    const rotation: u5 = @intCast(current >> 59);
    var out: [4]u8 = undefined;
    std.mem.writeInt(u32, &out, std.math.rotr(u32, xorshifted, rotation), .little);
    return out;
}

/// The ChaCha8 key `SeedableRng::seed_from_u64(seed)` produces.
pub fn seed_key(seed: u64) [32]u8 {
    var state = seed;
    var key: [32]u8 = undefined;
    var index: usize = 0;
    while (index < key.len) : (index += 4) key[index..][0..4].* = pcg32(&state);
    assert(index == key.len);
    return key;
}

/// The first `len` bytes of a seeded ChaCha8 keystream, generated block by block on demand.
pub const Keystream = struct {
    key: [32]u8,
    len: usize,
    block_index: u64 = std.math.maxInt(u64),
    block: [64]u8 = undefined,

    pub fn init(seed: u64, len: usize) Keystream {
        return .{ .key = seed_key(seed), .len = len };
    }

    pub fn byte(self: *Keystream, index: usize) u8 {
        assert(index < self.len);
        const block_index: u64 = index / 64;
        if (block_index != self.block_index) {
            ChaCha8.stream(&self.block, block_index, self.key, @splat(0));
            self.block_index = block_index;
        }
        return self.block[index % 64];
    }
};

/// arbitrary's `Unstructured`: consumes bytes from the front, and lengths from the back.
pub const Unstructured = struct {
    stream: *Keystream,
    start: usize,
    end: usize,

    pub fn init(stream: *Keystream) Unstructured {
        return .{ .stream = stream, .start = 0, .end = stream.len };
    }

    pub fn remaining(self: *const Unstructured) usize {
        assert(self.start <= self.end);
        return self.end - self.start;
    }

    /// Copies the next bytes into `out`, zero-filling past the end of the data.
    pub fn fill(self: *Unstructured, out: []u8) void {
        const count = @min(out.len, self.remaining());
        for (out[0..count], self.start..) |*byte, index| byte.* = self.stream.byte(index);
        @memset(out[count..], 0);
        self.start += count;
    }

    /// Takes exactly `out.len` bytes, or fails with `NotEnoughData`.
    pub fn bytes(self: *Unstructured, out: []u8) Error!void {
        if (self.remaining() < out.len) return error.NotEnoughData;
        self.fill(out);
    }

    /// A primitive integer read little-endian (`impl Arbitrary for uN/iN`).
    pub fn int(self: *Unstructured, comptime T: type) T {
        var buffer: [@sizeOf(T)]u8 = undefined;
        self.fill(&buffer);
        return std.mem.readInt(T, &buffer, .little);
    }

    /// `bool::arbitrary`: the low bit of one byte.
    pub fn boolean(self: *Unstructured) bool {
        return self.int(u8) & 1 == 1;
    }

    /// `int_in_range(start..=end)` for unsigned `T`: up to `@sizeOf(T)` bytes, big-endian,
    /// only as many as the range needs, reduced modulo its size.
    pub fn int_in_range(self: *Unstructured, comptime T: type, start: T, end: T) T {
        const result, const consumed = int_in_range_from(T, start, end, self, next_front);
        self.start += consumed;
        return result;
    }

    fn next_front(self: *Unstructured, index: usize) ?u8 {
        const position = self.start + index;
        return if (position < self.end) self.stream.byte(position) else null;
    }

    fn next_back(self: *Unstructured, index: usize) ?u8 {
        return self.stream.byte(self.end + index);
    }

    /// `arbitrary_byte_size`: a length read from the back of the data.
    pub fn byte_size(self: *Unstructured) usize {
        const len = self.remaining();
        if (len <= 1) {
            self.end = self.start;
            return 0;
        }
        inline for (.{ u8, u16, u32, u64 }) |T| {
            if (len <= @as(u128, std.math.maxInt(T)) + @sizeOf(T)) {
                const max_size = len - @sizeOf(T);
                self.end -= @sizeOf(T);
                const result, _ = int_in_range_from(T, 0, @intCast(max_size), self, next_back);
                return result;
            }
        }
        unreachable; // Proof: every usize length fits the u64 case.
    }

    /// The continuation byte before each element of `arbitrary_iter`.
    pub fn keep_going(self: *Unstructured) bool {
        return self.boolean();
    }
};

fn int_in_range_from(
    comptime T: type,
    start: T,
    end: T,
    source: *Unstructured,
    comptime next: fn (*Unstructured, usize) ?u8,
) struct { T, usize } {
    comptime assert(@typeInfo(T).int.signedness == .unsigned);
    assert(start <= end);
    if (start == end) return .{ start, 0 };
    const delta = end - start;
    var raw: T = 0;
    var consumed: usize = 0;
    while (consumed < @sizeOf(T) and (delta >> @intCast(consumed * 8)) > 0) {
        const byte = next(source, consumed) orelse break;
        consumed += 1;
        raw = if (@sizeOf(T) == 1) byte else (raw << 8) | byte;
    }
    const offset = if (delta == std.math.maxInt(T)) raw else raw % (delta + 1);
    return .{ start + offset, consumed };
}

/// Generates a value the way the `Arbitrary` impl of the matching Rust type does.
pub fn value(comptime T: type, gpa: Allocator, u: *Unstructured) Error!T {
    if (T == usize) return @intCast(u.int(u64));
    switch (@typeInfo(T)) {
        .bool => return u.boolean(),
        .int => {
            const bits = @typeInfo(T).int.bits;
            if (comptime bits >= 8 and bits <= 128 and std.math.isPowerOfTwo(bits)) {
                return u.int(T);
            }
            comptime assert(@typeInfo(T).int.signedness == .unsigned);
            return wide_uint(T, u);
        },
        .float => return @bitCast(u.int(@Int(.unsigned, @bitSizeOf(T)))),
        .optional => |info| return if (u.boolean()) try value(info.child, gpa, u) else null,
        .array => |info| {
            var result: T = undefined;
            for (&result) |*item| item.* = try value(info.child, gpa, u);
            return result;
        },
        .pointer => |info| switch (info.size) {
            .slice => return try collect(info.child, gpa, u),
            .one => {
                const pointer = try gpa.create(info.child);
                pointer.* = try value(info.child, gpa, u);
                return pointer;
            },
            else => @compileError("arbitrary: unsupported pointer: " ++ @typeName(T)),
        },
        .@"struct" => |info| {
            if (!info.is_tuple) return T.arbitrary(gpa, u);
            var result: T = undefined;
            inline for (info.field_types, 0..) |field_type, index| {
                result[index] = try value(field_type, gpa, u);
            }
            return result;
        },
        .@"union", .@"enum" => return T.arbitrary(gpa, u),
        else => @compileError("arbitrary: unsupported type: " ++ @typeName(T)),
    }
}

/// ruint's `Uint<BITS, LIMBS>`: low limbs as little-endian u64s, then the top limb from
/// `int_in_range(0..=MASK)`.
fn wide_uint(comptime T: type, u: *Unstructured) T {
    const bits = @bitSizeOf(T);
    if (bits == 0) return 0;
    const limbs = (bits + 63) / 64;
    const top_bits = bits - 64 * (limbs - 1);
    const mask: u64 = std.math.maxInt(@Int(.unsigned, top_bits));
    var result: @Int(.unsigned, limbs * 64) = 0;
    inline for (0..limbs - 1) |index| {
        result |= @as(@TypeOf(result), u.int(u64)) << (64 * index);
    }
    const top = u.int_in_range(u64, 0, mask);
    result |= @as(@TypeOf(result), top) << (64 * (limbs - 1));
    return @intCast(result);
}

/// `arbitrary_iter().collect()`: a continuation bit before each element.
pub fn collect(comptime T: type, gpa: Allocator, u: *Unstructured) Error![]T {
    var list: std.ArrayList(T) = .empty;
    // Each continuation consumes a byte until the data runs out, then reads zero: bounded.
    while (u.keep_going()) try list.append(gpa, try value(T, gpa, u));
    return list.toOwnedSlice(gpa);
}

/// A generator for `T`: `value(T, ...)` or a hand-written equivalent of a Rust impl.
pub fn Generator(comptime T: type) type {
    return fn (Allocator, *Unstructured) Error!T;
}

/// The generator that uses `value(T, ...)`.
pub fn default_generator(comptime T: type) Generator(T) {
    return struct {
        fn generate(gpa: Allocator, u: *Unstructured) Error!T {
            return value(T, gpa, u);
        }
    }.generate;
}

/// `generate_value`: retries `IncorrectFormat` on the same data and doubles the buffer on
/// `NotEnoughData`. Allocate with an arena; values are not freed individually.
pub fn generate(comptime T: type, comptime gen: Generator(T), gpa: Allocator, seed: u64) Error!T {
    var size: usize = buffer_size_initial;
    while (true) {
        var stream = Keystream.init(seed, size);
        var u = Unstructured.init(&stream);
        while (true) {
            if (gen(gpa, &u)) |result| return result else |err| switch (err) {
                // Rust retries forever here; once the data is exhausted every retry reads
                // the same zeros, so treat that as running out of data.
                error.IncorrectFormat => if (u.remaining() == 0) break,
                error.NotEnoughData => break,
                error.OutOfMemory => return err,
            }
        }
        if (size >= buffer_size_max) return error.NotEnoughData;
        size = @min(size * 2, buffer_size_max);
    }
}

const testing = std.testing;

test "pcg32 seed expansion" {
    // seed_from_u64(0): the first PCG32 output, computed from its definition.
    var state: u64 = 0;
    const first = pcg32(&state);
    const next: u64 = 0xa176_54e4_6fbe_17f3;
    const xorshifted: u32 = @truncate(((next >> 18) ^ next) >> 27);
    const expected = std.math.rotr(u32, xorshifted, @as(u5, @intCast(next >> 59)));
    try testing.expectEqual(expected, std.mem.readInt(u32, &first, .little));
    try testing.expectEqual(next, state);
}

test "int_in_range matches arbitrary" {
    var stream = Keystream.init(1, 64);
    var u = Unstructured.init(&stream);
    const first = stream.byte(0);
    try testing.expectEqual(@as(u64, 5), u.int_in_range(u64, 5, 5));
    try testing.expectEqual(@as(usize, 0), u.start);
    try testing.expectEqual(@as(u8, first % 128), u.int_in_range(u8, 0, 127));
    try testing.expectEqual(@as(usize, 1), u.start);
}

test "fill zero-pads past the end" {
    var stream = Keystream.init(7, 2);
    var u = Unstructured.init(&stream);
    const expected = [_]u8{ stream.byte(0), stream.byte(1), 0, 0 };
    var out: [4]u8 = undefined;
    u.fill(&out);
    try testing.expectEqualSlices(u8, &expected, &out);
    try testing.expectEqual(@as(usize, 0), u.remaining());
    try testing.expectError(error.NotEnoughData, u.bytes(out[0..1]));
}

test "byte size reads from the back" {
    var stream = Keystream.init(3, 300);
    var u = Unstructured.init(&stream);
    const high: u16 = stream.byte(298);
    const low: u16 = stream.byte(299);
    const expected = ((high << 8) | low) % 299;
    try testing.expectEqual(@as(usize, expected), u.byte_size());
    try testing.expectEqual(@as(usize, 298), u.end);
}
