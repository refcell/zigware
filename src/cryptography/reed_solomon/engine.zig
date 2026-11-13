//! Low-level building blocks for Reed-Solomon encoding and decoding
//! (commonware `reed_solomon/engine.rs`).
//!
//! An engine implements the compute-intensive algorithms. Rust's `Engine` trait is a comptime
//! interface here (`assert_engine`): a type with
//!
//! ```zig
//! pub fn fft(self, data: ShardsRefMut, pos, size, truncated_size, skew_delta: usize) void
//! pub fn ifft(self, data: ShardsRefMut, pos, size, truncated_size, skew_delta: usize) void
//! pub fn mul(self, x: []Chunk, log_m: GfElement) void
//! pub fn eval_poly(erasures: *[GF_ORDER]GfElement, truncated_size: usize) void // optional
//! ```
//!
//! - `Naive`: simple reference implementation.
//! - `Scalar`: portable engine without SIMD.
//! - `DefaultEngine`: the engine `Encoder` and `Decoder` use; chosen at compile time.
//!
//! `fft` transforms `data[pos..pos + size]`, producing the requested output prefix in
//! `data[pos..pos + truncated_size]`; the rest of the block is unspecified and shards outside
//! it are unchanged. `ifft` requires `data[pos + truncated_size..pos + size]` to be zero and
//! leaves the full inverse in the block. A transform of size one is the identity.

const std = @import("std");
const assert = std.debug.assert;

pub const tables = @import("engine/tables.zig");
pub const utils = @import("engine/utils.zig");
pub const fwht = @import("engine/fwht.zig");
pub const shards = @import("engine/shards.zig");
pub const Naive = @import("engine/naive.zig").Naive;
pub const Scalar = @import("engine/scalar.zig").Scalar;
pub const Shards = shards.Shards;
pub const ShardsRefMut = shards.ShardsRefMut;

/// The engine `Encoder` and `Decoder` use.
pub const DefaultEngine = Scalar;

/// Size of a Galois field element in bits.
pub const GF_BITS = 16;
/// Galois field order, i.e. number of elements.
pub const GF_ORDER = 65536;
/// `GF_ORDER - 1`.
pub const GF_MODULUS: GfElement = 65535;
/// Galois field polynomial.
pub const GF_POLYNOMIAL = 0x1002D;
/// Byte width of a shard chunk. Engines process shard buffers as arrays of chunks; a partial
/// final chunk is padded during processing and returned at the original shard length.
pub const SHARD_CHUNK_BYTES = 64;

/// Galois field element expressed in the `CANTOR_BASIS`.
pub const GfElement = u16;
/// One shard chunk: 32 low bytes followed by the 32 matching high bytes.
pub const Chunk = [SHARD_CHUNK_BYTES]u8;

/// Cantor basis used by the additive FFT over GF(2^16).
pub const CANTOR_BASIS = [GF_BITS]GfElement{
    0x0001, 0xACCA, 0x3C0E, 0x163E, 0xC582, 0xED2E, 0x914C, 0x4012,
    0x6C98, 0x10D8, 0x6A72, 0xB900, 0xFDB8, 0xFB34, 0xFF38, 0x991E,
};

comptime {
    assert(GF_ORDER == 1 << GF_BITS);
    assert(GF_MODULUS == GF_ORDER - 1);
    assert(SHARD_CHUNK_BYTES % 2 == 0);
}

/// Checks at compile time that `E` implements the engine interface.
pub fn assert_engine(comptime E: type) void {
    comptime {
        assert(@hasDecl(E, "fft"));
        assert(@hasDecl(E, "ifft"));
        assert(@hasDecl(E, "mul"));
        assert(@hasDecl(E, "init"));
    }
}

/// `E.eval_poly` when the engine provides one, else the portable `utils.eval_poly`.
///
/// Replaces `erasures` with its XOR convolution against the field logarithm table: on return,
/// `erasures[i]` is congruent modulo `GF_MODULUS` to the sum over `j != i` of
/// `erasures[j] * log(i ^ j)`. Entries at and after `truncated_size` must be zero.
pub fn eval_poly(comptime E: type, erasures: *[GF_ORDER]GfElement, truncated_size: usize) void {
    assert_engine(E);
    assert(truncated_size <= GF_ORDER);
    if (@hasDecl(E, "eval_poly")) E.eval_poly(erasures, truncated_size) else {
        utils.eval_poly(erasures, truncated_size);
    }
}

/// Asserts the `fft` and `ifft` preconditions.
pub fn validate_transform(
    data: ShardsRefMut,
    pos: usize,
    size: usize,
    truncated_size: usize,
    skew_delta: usize,
) void {
    assert(std.math.isPowerOfTwo(size) and size <= GF_ORDER);
    assert(truncated_size <= size);
    assert(pos <= data.len() and size <= data.len() - pos);
    // Butterflies read skew entries up to `size + skew_delta - 2`, and `Skew` has
    // `GF_ORDER - 1` entries. A size-one transform has no butterflies.
    assert(size == 1 or skew_delta <= GF_ORDER - size);
}

const testing = std.testing;

fn expect_identity_transforms(comptime E: type) !void {
    const eng: E = .init();
    const empty: ShardsRefMut = .init(GF_ORDER + 3, 0, &.{});
    eng.fft(empty, 3, GF_ORDER, 0, 0);
    eng.ifft(empty, 3, GF_ORDER, 0, 0);

    for ([_]usize{ 0, 1 }) |truncated_size| {
        var data: [3]Chunk = @splat(@splat(17));
        const view: ShardsRefMut = .init(3, 1, &data);
        eng.fft(view, 1, 1, truncated_size, std.math.maxInt(usize));
        eng.ifft(view, 1, 1, 1, std.math.maxInt(usize));
        for (data) |chunk| try testing.expectEqual(@as(Chunk, @splat(17)), chunk);
    }
}

test "transform empty shards and identity" {
    try expect_identity_transforms(Naive);
    try expect_identity_transforms(Scalar);
}

test "eval_poly matches across engines" {
    const input = try testing.allocator.create([GF_ORDER]GfElement);
    defer testing.allocator.destroy(input);
    const expected = try testing.allocator.create([GF_ORDER]GfElement);
    defer testing.allocator.destroy(expected);
    input.* = @splat(0);
    input[0..4].* = .{ 1, 0, 1, 1 };
    expected.* = input.*;
    eval_poly(Scalar, expected, 4);
    inline for (.{ DefaultEngine, Naive }) |E| {
        input.* = @splat(0);
        input[0..4].* = .{ 1, 0, 1, 1 };
        eval_poly(E, input, 4);
        try testing.expectEqualSlices(GfElement, expected, input);
    }
}

test {
    _ = tables;
    _ = utils;
    _ = fwht;
    _ = shards;
    _ = @import("engine/scalar.zig");
}
