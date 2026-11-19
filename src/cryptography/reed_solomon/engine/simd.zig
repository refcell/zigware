//! `Simd`: the `Scalar` transforms over a vector multiply kernel (commonware's AVX2 and NEON
//! engines, `engine_avx2.rs` and `engine_neon.rs`, use the same nibble-shuffle multiply).
//!
//! A chunk is 32 low bytes then 32 high bytes, so one `@Vector(32, u8)` holds the low or high
//! halves of 32 field elements. Multiplying by `m` looks up each 4-bit nibble of every element
//! in a 16-entry table with a byte shuffle (`vpshufb` on x86-64 AVX2, `tbl` on aarch64 NEON)
//! and XORs the four results, for the low and high output bytes. Zig has no portable runtime
//! byte shuffle, so the kernel exists only where one of those does; `available` says whether
//! it does, and `DefaultEngine` uses it then.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

const engine = @import("../engine.zig");
const scalar = @import("scalar.zig");

const GfElement = engine.GfElement;
const Chunk = engine.Chunk;
const half = engine.SHARD_CHUNK_BYTES / 2;
const Bytes = @Vector(half, u8);
const Lane = @Vector(16, u8);

const avx2 = builtin.cpu.arch == .x86_64 and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx2);
const neon = builtin.cpu.arch == .aarch64 and
    std.Target.aarch64.featureSetHas(builtin.cpu.features, .neon);

/// Whether the target has the byte shuffle the kernel needs.
pub const available = avx2 or neon;

/// The name of the vector engine on this target, as commonware's benchmarks label it.
pub const name = if (avx2) "avx2" else if (neon) "neon" else "scalar";

/// Shuffles each 128-bit lane of `table` by the low four bits of `index` (both lanes of
/// `table` hold the same 16 entries, and every index is below 16).
inline fn shuffle(table: Bytes, index: Bytes) Bytes {
    comptime assert(available);
    if (avx2) {
        return asm ("vpshufb %[index], %[table], %[out]"
            : [out] "=x" (-> Bytes),
            : [table] "x" (table),
              [index] "x" (index),
        );
    }
    const low = lookup(
        @shuffle(u8, table, undefined, masks.low),
        @shuffle(u8, index, undefined, masks.low),
    );
    const high = lookup(
        @shuffle(u8, table, undefined, masks.high),
        @shuffle(u8, index, undefined, masks.high),
    );
    return @shuffle(u8, low, high, masks.concat);
}

/// `@shuffle` masks that split a `Bytes` into its 128-bit lanes and join two lanes back (a
/// mask selects from the second vector with `~i`).
const masks = struct {
    const low: @Vector(16, i32) = std.simd.iota(i32, 16);
    const high: @Vector(16, i32) = low + @as(@Vector(16, i32), @splat(16));
    const concat: [32]i32 = @as([16]i32, low) ++ @as([16]i32, ~low);
};

/// NEON `tbl`: the bytes of `table` at `index` (every index is below 16).
inline fn lookup(table: Lane, index: Lane) Lane {
    comptime assert(neon);
    return asm ("tbl %[out].16b, {%[table].16b}, %[index].16b"
        : [out] "=w" (-> Lane),
        : [table] "w" (table),
          [index] "w" (index),
    );
}

/// The nibble tables of one multiplier as vectors: `lo[i]` and `hi[i]` hold the low and high
/// bytes of the products for nibble position `i`, each 16-entry table repeated in both lanes.
const Tables = struct {
    lo: [4]Bytes,
    hi: [4]Bytes,

    fn init(lut: *const [4][16]GfElement) Tables {
        var tables: Tables = undefined;
        for (lut, &tables.lo, &tables.hi) |row, *lo, *hi| {
            var lo_bytes: [half]u8 = undefined;
            var hi_bytes: [half]u8 = undefined;
            for (0..half) |i| {
                lo_bytes[i] = @truncate(row[i % 16]);
                hi_bytes[i] = @truncate(row[i % 16] >> 8);
            }
            lo.* = lo_bytes;
            hi.* = hi_bytes;
        }
        return tables;
    }

    /// The low and high product bytes of the 32 elements whose bytes are `lo` and `hi`.
    inline fn product(tables: *const Tables, lo: Bytes, hi: Bytes) [2]Bytes {
        const mask: Bytes = @splat(0x0f);
        const four: @Vector(half, u3) = @splat(4);
        const nibbles = [4]Bytes{ lo & mask, lo >> four, hi & mask, hi >> four };
        var out_lo: Bytes = @splat(0);
        var out_hi: Bytes = @splat(0);
        inline for (0..4) |i| {
            out_lo ^= shuffle(tables.lo[i], nibbles[i]);
            out_hi ^= shuffle(tables.hi[i], nibbles[i]);
        }
        return .{ out_lo, out_hi };
    }
};

pub const VectorKernel = struct {
    pub const Table = @import("tables.zig").Mul16;
    pub const table = @import("tables.zig").get_mul16;

    pub fn mul(lut: *const [4][16]GfElement, x: []Chunk) void {
        comptime assert(available);
        const tables: Tables = .init(lut);
        for (x) |*chunk| {
            const lo: Bytes = chunk[0..half].*;
            const hi: Bytes = chunk[half..].*;
            const product = tables.product(lo, hi);
            chunk[0..half].* = product[0];
            chunk[half..].* = product[1];
        }
    }

    pub fn mul_add(lut: *const [4][16]GfElement, x: []Chunk, y: []const Chunk) void {
        comptime assert(available);
        assert(x.len == y.len);
        const tables: Tables = .init(lut);
        for (x, y) |*x_chunk, *y_chunk| {
            const product = tables.product(y_chunk[0..half].*, y_chunk[half..].*);
            const x_lo: Bytes = x_chunk[0..half].*;
            const x_hi: Bytes = x_chunk[half..].*;
            x_chunk[0..half].* = x_lo ^ product[0];
            x_chunk[half..].* = x_hi ^ product[1];
        }
    }
};

/// The vector engine, or `Scalar` where the target lacks the shuffle.
pub const Simd = if (available) scalar.Engine(VectorKernel) else scalar.Scalar;

const testing = std.testing;
const Naive = @import("naive.zig").Naive;
const ChaCha8Rng = @import("../test_util.zig").ChaCha8Rng;

test "simd mul and mul_add match scalar" {
    if (!available) return error.SkipZigTest;
    const lut_source = @import("tables.zig").get_mul16();
    var rng = ChaCha8Rng.init_key(@splat(7));
    var x: [5]Chunk = undefined;
    var y: [5]Chunk = undefined;
    for (0..200) |_| {
        const n = rng.next_u32() % 6;
        rng.fill_bytes(std.mem.sliceAsBytes(x[0..n]));
        rng.fill_bytes(std.mem.sliceAsBytes(y[0..n]));
        const lut = &lut_source[@as(GfElement, @truncate(rng.next_u32()))];
        var x_scalar = x;
        var x_vector = x;
        scalar.ScalarKernel.mul_add(lut, x_scalar[0..n], y[0..n]);
        VectorKernel.mul_add(lut, x_vector[0..n], y[0..n]);
        try testing.expectEqualSlices(Chunk, x_scalar[0..n], x_vector[0..n]);
        scalar.ScalarKernel.mul(lut, x_scalar[0..n]);
        VectorKernel.mul(lut, x_vector[0..n]);
        try testing.expectEqualSlices(Chunk, x_scalar[0..n], x_vector[0..n]);
    }
}

test "simd mul matches naive" {
    const naive: Naive = .init();
    const simd: Simd = .init();
    var rng = ChaCha8Rng.init_key(@splat(0));
    var data_simd: [5]Chunk = undefined;
    var data_naive: [5]Chunk = undefined;
    for (0..6) |shard_chunks| {
        rng.fill_bytes(std.mem.sliceAsBytes(data_simd[0..shard_chunks]));
        @memcpy(data_naive[0..shard_chunks], data_simd[0..shard_chunks]);
        const log_m: GfElement = @truncate(rng.next_u32());
        simd.mul(data_simd[0..shard_chunks], log_m);
        naive.mul(data_naive[0..shard_chunks], log_m);
        try testing.expectEqualSlices(
            Chunk,
            data_naive[0..shard_chunks],
            data_simd[0..shard_chunks],
        );
    }
}
