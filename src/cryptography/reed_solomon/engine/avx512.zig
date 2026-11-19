//! `Avx512`: the `Scalar` transforms with a GFNI multiply on 512-bit vectors (commonware
//! `reed_solomon/engine/engine_avx512.rs`), one chunk per vector.
//!
//! A chunk holds 32 low bytes and then the 32 matching high bytes. GF2P8AFFINEQB applies an
//! 8 by 8 bit matrix to every byte of a 64-bit lane, so one instruction maps each half through
//! its matrix: `direct` maps each half into the same output half (`low_from_low`,
//! `high_from_high`), `cross` maps the swapped halves into the other one (`low_from_high`,
//! `high_from_low`), and their XOR is the product. Two butterfly layers over four shards run in
//! one pass that loads and stores each chunk once.
//!
//! The engine is chosen at compile time: `available` needs AVX-512F and GFNI on the target and
//! the LLVM backend (ReleaseSafe and ReleaseFast; Debug builds fall back to `Simd`).

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

const engine = @import("../engine.zig");
const scalar = @import("scalar.zig");
const tables = @import("tables.zig");

const Chunk = engine.Chunk;
const Vector = @Vector(engine.SHARD_CHUNK_BYTES, u8);
const Matrices = @Vector(8, u64);

/// Whether the target has AVX-512F and GFNI, and the build runs on LLVM: Zig's own x86
/// backend (Debug builds) cannot pass 512-bit vectors to inline assembly, so those use `Simd`.
pub const available = builtin.zig_backend == .stage2_llvm and builtin.cpu.arch == .x86_64 and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx512f) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .gfni);

comptime {
    assert(@sizeOf(Vector) == @sizeOf(Chunk));
    assert(@sizeOf(Matrices) == @sizeOf(Chunk));
}

/// One multiplier's matrices, broadcast for a chunk: low half's 64-bit lanes first.
const Lut = struct {
    direct: Vector,
    cross: Vector,

    fn init(m: *const tables.MultiplyGfni) Lut {
        const direct: Matrices = .{
            m.low_from_low,   m.low_from_low,   m.low_from_low,   m.low_from_low,
            m.high_from_high, m.high_from_high, m.high_from_high, m.high_from_high,
        };
        const cross: Matrices = .{
            m.low_from_high, m.low_from_high, m.low_from_high, m.low_from_high,
            m.high_from_low, m.high_from_low, m.high_from_low, m.high_from_low,
        };
        return .{ .direct = @bitCast(direct), .cross = @bitCast(cross) };
    }
};

/// GF2P8AFFINEQB with a zero constant: each byte of `x` times its lane's matrix in `matrices`.
inline fn affine(x: Vector, matrices: Vector) Vector {
    return asm ("vgf2p8affineqb $0, %[matrices], %[x], %[out]"
        : [out] "=x" (-> Vector),
        : [x] "x" (x),
          [matrices] "x" (matrices),
    );
}

/// The 32 field elements of `x` times the multiplier of `lut`.
inline fn multiply(x: Vector, lut: Lut) Vector {
    // Swap the 256-bit halves, so the high bytes meet the low half's matrices and back.
    const swap = comptime blk: {
        var mask: [engine.SHARD_CHUNK_BYTES]i32 = undefined;
        for (&mask, 0..) |*index, i| index.* = @intCast((i + 32) % 64);
        break :blk mask;
    };
    const swapped = @shuffle(u8, x, undefined, swap);
    return affine(x, lut.direct) ^ affine(swapped, lut.cross);
}

inline fn load(chunk: *const Chunk) Vector {
    return chunk.*;
}

inline fn store(chunk: *Chunk, value: Vector) void {
    chunk.* = value;
}

/// The GFNI kernel of `scalar.Engine`.
pub const GfniKernel = struct {
    pub const Table = tables.MulGfni;
    pub const table = tables.get_mul_gfni;

    pub fn mul(m: *const tables.MultiplyGfni, x: []Chunk) void {
        const lut: Lut = .init(m);
        for (x) |*chunk| store(chunk, multiply(load(chunk), lut));
    }

    pub fn mul_add(m: *const tables.MultiplyGfni, x: []Chunk, y: []const Chunk) void {
        assert(x.len == y.len);
        const lut: Lut = .init(m);
        for (x, y) |*x_chunk, *y_chunk| {
            store(x_chunk, load(x_chunk) ^ multiply(load(y_chunk), lut));
        }
    }

    /// Two FFT layers: (s0, s2) and (s1, s3) by `m02`, then (s0, s1) by `m01` and (s2, s3) by
    /// `m23`, each a butterfly `x ^= y * m; y ^= x`.
    pub fn fft4(
        m01: *const tables.MultiplyGfni,
        m23: *const tables.MultiplyGfni,
        m02: *const tables.MultiplyGfni,
        shards: [4][]Chunk,
    ) void {
        const lut01: Lut = .init(m01);
        const lut23: Lut = .init(m23);
        const lut02: Lut = .init(m02);
        const len = shards[0].len;
        for (shards[1..]) |shard| assert(shard.len == len);
        for (0..len) |i| {
            var s0 = load(&shards[0][i]);
            var s1 = load(&shards[1][i]);
            var s2 = load(&shards[2][i]);
            var s3 = load(&shards[3][i]);
            s0 ^= multiply(s2, lut02);
            s2 ^= s0;
            s1 ^= multiply(s3, lut02);
            s3 ^= s1;
            s0 ^= multiply(s1, lut01);
            s1 ^= s0;
            s2 ^= multiply(s3, lut23);
            s3 ^= s2;
            store(&shards[0][i], s0);
            store(&shards[1][i], s1);
            store(&shards[2][i], s2);
            store(&shards[3][i], s3);
        }
    }

    /// Two IFFT layers: (s0, s1) by `m01` and (s2, s3) by `m23`, then (s0, s2) and (s1, s3)
    /// by `m02`, each a butterfly `y ^= x; x ^= y * m`.
    pub fn ifft4(
        m01: *const tables.MultiplyGfni,
        m23: *const tables.MultiplyGfni,
        m02: *const tables.MultiplyGfni,
        shards: [4][]Chunk,
    ) void {
        const lut01: Lut = .init(m01);
        const lut23: Lut = .init(m23);
        const lut02: Lut = .init(m02);
        const len = shards[0].len;
        for (shards[1..]) |shard| assert(shard.len == len);
        for (0..len) |i| {
            var s0 = load(&shards[0][i]);
            var s1 = load(&shards[1][i]);
            var s2 = load(&shards[2][i]);
            var s3 = load(&shards[3][i]);
            s1 ^= s0;
            s0 ^= multiply(s1, lut01);
            s3 ^= s2;
            s2 ^= multiply(s3, lut23);
            s2 ^= s0;
            s0 ^= multiply(s2, lut02);
            s3 ^= s1;
            s1 ^= multiply(s3, lut02);
            store(&shards[0][i], s0);
            store(&shards[1][i], s1);
            store(&shards[2][i], s2);
            store(&shards[3][i], s3);
        }
    }
};

/// The AVX-512 GFNI engine where the target has it, else `Simd`.
pub const Avx512 = if (available) scalar.Engine(GfniKernel) else @import("simd.zig").Simd;

const testing = std.testing;

test "avx512 multiplies every basis element by every multiplier" {
    // commonware `gfni_all_multipliers_basis`: element `bit` of the chunk is `1 << bit`.
    if (comptime !available) return error.SkipZigTest;
    const gfni: Avx512 = .init();
    const exp_log = tables.get_exp_log();
    var basis: [1]Chunk = @splat(@splat(0));
    for (0..16) |bit| {
        const value = @as(u16, 1) << @intCast(bit);
        basis[0][bit] = @truncate(value);
        basis[0][32 + bit] = @truncate(value >> 8);
    }
    for (0..@as(usize, engine.GF_MODULUS) + 1) |log_m| {
        var actual = basis;
        gfni.mul(&actual, @intCast(log_m));
        for (0..16) |bit| {
            const product = @as(u16, actual[0][bit]) | @as(u16, actual[0][32 + bit]) << 8;
            const input = @as(u16, 1) << @intCast(bit);
            const expected = tables.mul(input, @intCast(log_m), exp_log.exp, exp_log.log);
            try testing.expectEqual(expected, product);
        }
    }
}

test "avx512 transforms match scalar" {
    // Every FFT and IFFT shape on random shards, so a wrong fused layer order or butterfly
    // direction differs from `Scalar`, which writes the same bytes.
    if (comptime !available) return error.SkipZigTest;
    const ChaCha8Rng = @import("../test_util.zig").ChaCha8Rng;
    const ShardsRefMut = @import("shards.zig").ShardsRefMut;
    const gfni: Avx512 = .init();
    const reference: scalar.Scalar = .init();
    var rng = ChaCha8Rng.init_key(@splat(7));
    const chunks = 3;
    var a: [128 * chunks]Chunk = undefined;
    var b: [128 * chunks]Chunk = undefined;
    var log_size: u6 = 0;
    while (log_size <= 7) : (log_size += 1) {
        const size = @as(usize, 1) << log_size;
        const view_a = ShardsRefMut.init(size, chunks, a[0 .. size * chunks]);
        const view_b = ShardsRefMut.init(size, chunks, b[0 .. size * chunks]);
        for ([_]usize{ 0, 1, 37, 300 }) |skew| {
            rng.fill_bytes(std.mem.sliceAsBytes(a[0 .. size * chunks]));
            b = a;
            gfni.fft(view_a, 0, size, size, skew);
            reference.fft(view_b, 0, size, size, skew);
            try testing.expectEqualSlices(Chunk, b[0 .. size * chunks], a[0 .. size * chunks]);
            gfni.ifft(view_a, 0, size, size, skew);
            reference.ifft(view_b, 0, size, size, skew);
            try testing.expectEqualSlices(Chunk, b[0 .. size * chunks], a[0 .. size * chunks]);
        }
    }
}
