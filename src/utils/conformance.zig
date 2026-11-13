//! Conformance hashes for utils tests (commonware `conformance` and codec's
//! `CodecConformance`), so encodings are checked against `utils/conformance.toml`.
//!
//! A conformance hash is SHA-256 over `len as u64 LE || commit(seed)` for seeds
//! `0..n_cases`. `CodecConformance<T>` commits `T::arbitrary(u).encode()`, where `u` is an
//! `arbitrary::Unstructured` over a 4096-byte buffer filled by `ChaCha8Rng::seed_from_u64`
//! (doubling up to 16 MiB on `NotEnoughData`, retrying on `IncorrectFormat`).
//!
//! `Unstructured` here emulates `arbitrary` 1.4 over that buffer without materializing it:
//! the buffer is the ChaCha8 keystream, so any byte is computed at its block position.
//! Callers write each type's `Arbitrary` derive by hand against it.
//!
//! (The conformance package will own a shared harness; this is the utils-local piece.)

const std = @import("std");
const codec = @import("codec");
const rng = @import("rng.zig");
const assert = std.debug.assert;

pub const Error = error{ NotEnoughData, IncorrectFormat };

const ChaCha8 = std.crypto.stream.chacha.ChaCha8With64BitNonce;
const block_bytes = 64;
const initial_buffer_size = 4096;
const max_buffer_size = 16 * 1024 * 1024;

/// `arbitrary::Unstructured` over the first `len` keystream bytes of a ChaCha8 key.
pub const Unstructured = struct {
    key: [32]u8,
    /// Index of the next unread byte from the front.
    front: usize,
    /// One past the last unread byte (`arbitrary_len` consumes from the back).
    back: usize,

    pub fn init(seed: u64, len: usize) Unstructured {
        return .{ .key = rng.ChaCha8Rng.init(seed).key, .front = 0, .back = len };
    }

    pub fn remaining(u: *const Unstructured) usize {
        assert(u.front <= u.back);
        return u.back - u.front;
    }

    pub fn is_empty(u: *const Unstructured) bool {
        return u.remaining() == 0;
    }

    /// Copies keystream bytes `[offset, offset + out.len)` into `out`.
    fn read_at(u: *const Unstructured, offset: usize, out: []u8) void {
        var written: usize = 0;
        while (written < out.len) {
            const position = offset + written;
            var block: [block_bytes]u8 = undefined;
            ChaCha8.stream(&block, position / block_bytes, u.key, @splat(0));
            const skip = position % block_bytes;
            const take = @min(block_bytes - skip, out.len - written);
            @memcpy(out[written..][0..take], block[skip..][0..take]);
            written += take;
        }
        assert(written == out.len);
    }

    /// `fill_buffer`: copies what is left (up to `out.len`) and zero-fills the rest.
    pub fn fill_buffer(u: *Unstructured, out: []u8) void {
        const take = @min(out.len, u.remaining());
        u.read_at(u.front, out[0..take]);
        @memset(out[take..], 0);
        u.front += take;
        assert(u.front <= u.back);
    }

    /// `<int>::arbitrary`: little-endian from `fill_buffer`.
    pub fn int(u: *Unstructured, comptime T: type) T {
        var bytes: [@sizeOf(T)]u8 = undefined;
        u.fill_buffer(&bytes);
        return std.mem.readInt(T, &bytes, .little);
    }

    /// `bool::arbitrary`: the low bit of a `u8`.
    pub fn boolean(u: *Unstructured) bool {
        return u.int(u8) & 1 == 1;
    }

    /// `int_in_range`: big-endian bytes, only as many as the span needs, then modulo.
    pub fn int_in_range(u: *Unstructured, comptime T: type, low: T, high: T) T {
        var bytes: [@sizeOf(T)]u8 = undefined;
        const available = @min(bytes.len, u.remaining());
        u.read_at(u.front, bytes[0..available]);
        const result = int_in_range_bytes(T, low, high, bytes[0..available]);
        u.front += result.consumed;
        return result.value;
    }

    /// `arbitrary_byte_size`: a length taken from the back of the data, using 1, 2, 4, or 8
    /// bytes depending on how much data is left.
    pub fn arbitrary_byte_size(u: *Unstructured) usize {
        const len = u.remaining();
        if (len <= 1) {
            u.back = u.front;
            return 0;
        }
        const width: usize = if (len <= 256) 1 else if (len <= 65_537) 2 else 4;
        var bytes: [4]u8 = undefined;
        u.back -= width;
        u.read_at(u.back, bytes[0..width]);
        const max = u.remaining();
        const result = switch (width) {
            1 => int_in_range_bytes(u8, 0, @intCast(max), bytes[0..1]).value,
            2 => int_in_range_bytes(u16, 0, @intCast(max), bytes[0..2]).value,
            else => int_in_range_bytes(u32, 0, @intCast(max), bytes[0..4]).value,
        };
        assert(result <= max);
        return result;
    }

    /// `arbitrary_len::<E>()` where `E`'s size hint upper bound is `element_size`.
    pub fn arbitrary_len(u: *Unstructured, element_size: usize) usize {
        return u.arbitrary_byte_size() / @max(1, element_size);
    }
};

/// `int_in_range_impl`: folds bytes big-endian while the span still has higher bits, then
/// reduces modulo the span. Returns the value and how many bytes it consumed.
fn int_in_range_bytes(
    comptime T: type,
    low: T,
    high: T,
    bytes: []const u8,
) struct { value: T, consumed: usize } {
    comptime assert(@typeInfo(T).int.signedness == .unsigned);
    assert(low <= high);
    if (low == high) return .{ .value = low, .consumed = 0 };
    const delta = high - low;
    var value: T = 0;
    var consumed: usize = 0;
    while (consumed < @sizeOf(T) and std.math.shr(T, delta, consumed * 8) > 0) {
        if (consumed == bytes.len) break;
        const shifted = if (@sizeOf(T) == 1) 0 else std.math.shl(T, value, 8);
        value = shifted | bytes[consumed];
        consumed += 1;
    }
    const offset = if (delta == std.math.maxInt(T)) value else value % (delta + 1);
    return .{ .value = low + offset, .consumed = consumed };
}

/// The type of a hand-written `Arbitrary` derive for `T`.
pub fn Arbitrary(comptime T: type) type {
    return fn (void, *Unstructured) Error!T;
}

/// commonware's `generate_value`: retries with bigger buffers until `arbitrary` succeeds.
pub fn generate(
    comptime T: type,
    seed: u64,
    context: anytype,
    comptime arbitrary: fn (@TypeOf(context), *Unstructured) Error!T,
) T {
    var buffer_size: usize = initial_buffer_size;
    while (true) {
        var u = Unstructured.init(seed, buffer_size);
        while (true) {
            if (arbitrary(context, &u)) |value| {
                return value;
            } else |err| switch (err) {
                error.IncorrectFormat => continue,
                error.NotEnoughData => break,
            }
        }
        if (buffer_size >= max_buffer_size) @panic("failed to generate arbitrary value");
        buffer_size = @min(buffer_size * 2, max_buffer_size);
    }
}

/// Lowercase hex SHA-256 of `commit(seed)` for `seed` in `0..n_cases`, framed like
/// commonware's `compute_conformance_hash`.
pub fn hash(
    gpa: std.mem.Allocator,
    n_cases: u64,
    context: anytype,
    comptime commit: fn (@TypeOf(context), std.mem.Allocator, u64) anyerror![]u8,
) ![64]u8 {
    assert(n_cases > 0);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var seed: u64 = 0;
    while (seed < n_cases) : (seed += 1) {
        const committed = try commit(context, gpa, seed);
        defer gpa.free(committed);
        var len_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &len_bytes, committed.len, .little);
        hasher.update(&len_bytes);
        hasher.update(committed);
    }
    return std.fmt.bytesToHex(hasher.finalResult(), .lower);
}

/// `CodecConformance<T>`: the hash of `encode(arbitrary(seed))` over `n_cases` seeds.
/// `arbitrary` emulates `T`'s `Arbitrary` derive; decoded values must own no memory.
pub fn codec_hash(
    comptime T: type,
    gpa: std.mem.Allocator,
    n_cases: u64,
    comptime arbitrary: fn (void, *Unstructured) Error!T,
) ![64]u8 {
    return hash(gpa, n_cases, {}, struct {
        fn commit(_: void, allocator: std.mem.Allocator, seed: u64) anyerror![]u8 {
            const value = generate(T, seed, {}, arbitrary);
            return codec.encode(T, allocator, value);
        }
    }.commit);
}

/// Checks a codec conformance hash; `expected` is the `hash` line of conformance.toml.
pub fn expect_codec_hash(
    comptime T: type,
    n_cases: u64,
    comptime arbitrary: fn (void, *Unstructured) Error!T,
    expected: []const u8,
) !void {
    const actual = try codec_hash(T, std.testing.allocator, n_cases, arbitrary);
    try std.testing.expectEqualStrings(expected, &actual);
}

test "conformance: Unstructured reads the ChaCha8 keystream" {
    var expected: [100]u8 = undefined;
    var generator = rng.ChaCha8Rng.init(5);
    generator.fill_bytes(&expected);
    var u = Unstructured.init(5, 100);
    var front: [70]u8 = undefined;
    u.fill_buffer(&front);
    try std.testing.expectEqualSlices(u8, expected[0..70], &front);
    try std.testing.expectEqual(std.mem.readInt(u16, expected[70..72], .little), u.int(u16));
    try std.testing.expectEqual(@as(usize, 28), u.remaining());
}
