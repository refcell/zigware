//! Helpers for implementing engines (commonware `reed_solomon/engine/utils.rs`).

const std = @import("std");
const assert = std.debug.assert;

const engine = @import("../engine.zig");
const fwht = @import("fwht.zig");
const tables = @import("tables.zig");
const ShardsRefMut = @import("shards.zig").ShardsRefMut;

const GF_BITS = engine.GF_BITS;
const GF_ORDER = engine.GF_ORDER;
const GfElement = engine.GfElement;
const Chunk = engine.Chunk;
const ChunkVector = @Vector(engine.SHARD_CHUNK_BYTES, u8);

/// Evaluate a polynomial with the Fast Walsh-Hadamard Transform: replace `erasures` with its
/// XOR convolution against the field logarithm table. Entries at and after `truncated_size`
/// must be zero.
pub fn eval_poly(erasures: *[GF_ORDER]GfElement, truncated_size: usize) void {
    assert(truncated_size <= GF_ORDER);
    const log_walsh = tables.get_log_walsh();
    fwht.fwht(erasures, truncated_size);
    for (erasures, log_walsh) |*value, factor| value.* = mul_mod(value.*, factor);
    fwht.fwht(erasures, GF_ORDER);
}

/// XOR-convolve `data` with the field logarithm table over its first `data.len` positions.
///
/// Matches the first `data.len` outputs of `eval_poly` on `data` zero-extended, modulo
/// `GF_MODULUS`, because `i ^ j < data.len` for all `i, j < data.len`. Entries at and after
/// `truncated_size` must be zero.
pub fn eval_poly_short(data: []GfElement, truncated_size: usize) void {
    const n = data.len;
    assert(std.math.isPowerOfTwo(n) and n < GF_ORDER and truncated_size <= n);
    const kernel = tables.get_short_log_walsh(n);
    assert(kernel.len == n);
    fwht.fwht(data, truncated_size);
    for (data, kernel) |*value, factor| value.* = mul_mod(value.*, factor);
    fwht.fwht(data, n);
}

/// `value * factor` modulo `GF_MODULUS`, allowing both 0 and 65535 to represent zero.
inline fn mul_mod(value: GfElement, factor: GfElement) GfElement {
    const product = @as(u32, value) * @as(u32, factor);
    return add_mod(@truncate(product), @truncate(product >> GF_BITS));
}

/// `xs[] ^= ys[]`.
pub fn xor(xs: []Chunk, ys: []const Chunk) void {
    assert(xs.len == ys.len);
    for (xs, ys) |*x, y| {
        const result: ChunkVector = @as(ChunkVector, x.*) ^ @as(ChunkVector, y);
        x.* = result;
    }
}

/// `data[x .. x + count] ^= data[y .. y + count]`; the ranges must not overlap.
pub fn xor_within(data: ShardsRefMut, x: usize, y: usize, count: usize) void {
    const xs, const ys = data.flat2(x, y, count);
    xor(xs, ys);
}

/// Addition modulo 65535, allowing both 0 and 65535 to represent zero.
pub inline fn add_mod(x: GfElement, y: GfElement) GfElement {
    const sum = @as(u32, x) + @as(u32, y);
    return @truncate(sum + (sum >> GF_BITS));
}

/// Subtraction modulo 65535, allowing both 0 and 65535 to represent zero.
pub inline fn sub_mod(x: GfElement, y: GfElement) GfElement {
    const difference = @as(u32, x) -% @as(u32, y);
    return @truncate(difference +% (difference >> GF_BITS));
}

/// FFT with `skew_delta = pos + size`.
pub fn fft_skew_end(
    eng: anytype,
    data: ShardsRefMut,
    pos: usize,
    size: usize,
    truncated_size: usize,
) void {
    eng.fft(data, pos, size, truncated_size, pos + size);
}

/// IFFT with `skew_delta = pos + size`.
pub fn ifft_skew_end(
    eng: anytype,
    data: ShardsRefMut,
    pos: usize,
    size: usize,
    truncated_size: usize,
) void {
    eng.ifft(data, pos, size, truncated_size, pos + size);
}

/// Formal derivative, in place.
///
/// The reference schedule runs `data[i - w..i] ^= data[i..i + w]` for each `i` in
/// `1..data.len()` in ascending order, where `w = 1 << ctz(i)`. Pass `i` reads only shards at
/// or above `i`, which no earlier pass writes, so output `k` is input `k` XOR input `k + 2^b`
/// for each clear bit `b` of `k` with `k + 2^b < data.len()`. Clamping each pass at
/// `data.len()` matches zero-extending `data` to a power of two, so any shard count works.
///
/// Passes with `w < 4` stay inside one aligned block of four shards, so each block computes
/// them together from its loaded inputs. The pass at `i = base` reads the whole block, so it
/// runs before the block's leaf passes. Shards after the last full block take the reference
/// passes. (Commonware also fuses blocks of 16 with AVX-512; the output is identical.)
pub fn formal_derivative(data: ShardsRefMut) void {
    const count = data.len();
    const fused4_end = count / 4 * 4;
    var base: usize = 0;
    while (base < fused4_end) : (base += 4) {
        if (base != 0) derivative_pass(data, base);
        // Leaf passes `base + 1..base + 4` give `a ^= b ^ c`, `b ^= d`, and `c ^= d`.
        const a, const b, const c, const d = data.dist4(base, 1);
        for (a, b, c, d) |*a_chunk, *b_chunk, *c_chunk, d_chunk| {
            const bv: ChunkVector = b_chunk.*;
            const cv: ChunkVector = c_chunk.*;
            const dv: ChunkVector = d_chunk;
            a_chunk.* = @as(ChunkVector, a_chunk.*) ^ bv ^ cv;
            b_chunk.* = bv ^ dv;
            c_chunk.* = cv ^ dv;
        }
    }
    // There is no pass at 0, and no pass at all for zero or one shard.
    const tail_start = @max(fused4_end, 1);
    if (tail_start < count) {
        for (tail_start..count) |i| derivative_pass(data, i);
    }
}

/// The reference pass at `i`: `data[i - w..i] ^= data[i..i + w]`, clamped at `data.len()`.
fn derivative_pass(data: ShardsRefMut, i: usize) void {
    assert(i > 0 and i < data.len());
    const width = @as(usize, 1) << @intCast(@ctz(i));
    const count = @min(width, data.len() - i);
    xor_within(data, i - width, i, count);
}

test "add_mod and sub_mod" {
    try std.testing.expectEqual(@as(GfElement, 0), add_mod(1, 65534) % engine.GF_MODULUS);
    try std.testing.expectEqual(@as(GfElement, 5), add_mod(2, 3));
    try std.testing.expectEqual(@as(GfElement, 65534), sub_mod(0, 1));
    try std.testing.expectEqual(@as(GfElement, 1), sub_mod(3, 2));
}
