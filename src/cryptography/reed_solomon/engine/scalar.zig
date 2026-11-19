//! `Scalar`: portable engine without SIMD (commonware `reed_solomon/engine/engine_scalar.rs`).
//!
//! Multiplies one field element at a time with four lookups in the nibble tables of `Mul16`,
//! and applies two butterfly layers per pass.

const std = @import("std");
const assert = std.debug.assert;

const engine = @import("../engine.zig");
const tables = @import("tables.zig");
const utils = @import("utils.zig");
const ShardsRefMut = @import("shards.zig").ShardsRefMut;

const GF_MODULUS = engine.GF_MODULUS;
const GfElement = engine.GfElement;
const Chunk = engine.Chunk;
const half = engine.SHARD_CHUNK_BYTES / 2;

/// The transforms of `Scalar` over a multiply kernel. `Kernel.Table` is indexed by a
/// multiplier's logarithm and built by `Kernel.table()`; `Kernel.mul_add(lut, x, y)` computes
/// `x ^= y * m` for the entry `lut` of `m`, and `Kernel.mul(lut, x)` computes `x *= m`. A kernel
/// may also fuse two butterfly layers over four shards (`fft4`, `ifft4`, with the entries of
/// `m01`, `m23`, and `m02`), used when no coefficient is zero. Every kernel must produce the
/// same bytes.
pub fn Engine(comptime Kernel: type) type {
    comptime assert(@hasDecl(Kernel, "Table") and @hasDecl(Kernel, "table"));
    comptime assert(@hasDecl(Kernel, "fft4") == @hasDecl(Kernel, "ifft4"));
    return struct {
        const Self = @This();
        const fused = @hasDecl(Kernel, "fft4");

        mul16: *const Kernel.Table,
        skew: *const tables.Skew,

        /// Creates a `Scalar` engine and initializes its multiplication and skew tables.
        pub fn init() Self {
            return .{ .mul16 = Kernel.table(), .skew = tables.get_skew() };
        }

        /// In-place decimation-in-time FFT of `data[pos..pos + size]` (see `engine.zig`).
        pub fn fft(
            scalar: Self,
            data: ShardsRefMut,
            pos: usize,
            size: usize,
            truncated_size: usize,
            skew_delta: usize,
        ) void {
            engine.validate_transform(data, pos, size, truncated_size, skew_delta);
            // Apply two butterfly layers per pass.
            var dist4 = size;
            var dist = size >> 2;
            while (dist != 0) {
                var r: usize = 0;
                while (r < truncated_size) : (r += dist4) {
                    const base = r + dist + skew_delta - 1;
                    const log_m01 = scalar.skew[base];
                    const log_m02 = scalar.skew[base + dist];
                    const log_m23 = scalar.skew[base + dist * 2];
                    for (r..r + dist) |i| {
                        scalar.fft_two_layers(data, pos + i, dist, log_m01, log_m23, log_m02);
                    }
                }
                dist4 = dist;
                dist >>= 2;
            }

            // An odd log2(size) leaves one final layer.
            if (dist4 == 2) {
                var r: usize = 0;
                while (r < truncated_size) : (r += 2) {
                    const log_m = scalar.skew[r + skew_delta];
                    const x, const y = data.dist2(pos + r, 1);
                    if (log_m == GF_MODULUS) utils.xor(y, x) else scalar.fft_partial(x, y, log_m);
                }
            }
        }

        /// In-place decimation-in-time IFFT of `data[pos..pos + size]` (see `engine.zig`).
        pub fn ifft(
            scalar: Self,
            data: ShardsRefMut,
            pos: usize,
            size: usize,
            truncated_size: usize,
            skew_delta: usize,
        ) void {
            engine.validate_transform(data, pos, size, truncated_size, skew_delta);
            // Apply two butterfly layers per pass.
            var dist: usize = 1;
            var dist4: usize = 4;
            while (dist4 <= size) {
                var r: usize = 0;
                while (r < truncated_size) : (r += dist4) {
                    const base = r + dist + skew_delta - 1;
                    const log_m01 = scalar.skew[base];
                    const log_m02 = scalar.skew[base + dist];
                    const log_m23 = scalar.skew[base + dist * 2];
                    for (r..r + dist) |i| {
                        scalar.ifft_two_layers(data, pos + i, dist, log_m01, log_m23, log_m02);
                    }
                }
                dist = dist4;
                dist4 <<= 2;
            }

            // An odd log2(size) leaves one final layer.
            if (dist < size) {
                const log_m = scalar.skew[dist + skew_delta - 1];
                if (log_m == GF_MODULUS) {
                    utils.xor_within(data, pos + dist, pos, dist);
                } else {
                    for (0..dist) |i| {
                        const x, const y = data.dist2(pos + i, dist);
                        scalar.ifft_partial(x, y, log_m);
                    }
                }
            }
        }

        /// Multiply every field element in `x` by the element with logarithm `log_m`.
        pub fn mul(scalar: Self, x: []Chunk, log_m: GfElement) void {
            Kernel.mul(&scalar.mul16[log_m], x);
        }

        /// `x ^= y * m` for each chunk, where `m` has logarithm `log_m`.
        fn mul_add(scalar: Self, x: []Chunk, y: []const Chunk, log_m: GfElement) void {
            assert(x.len == y.len);
            Kernel.mul_add(&scalar.mul16[log_m], x, y);
        }

        /// Partial FFT butterfly; the caller handles a `GF_MODULUS` coefficient with `xor`.
        inline fn fft_partial(scalar: Self, x: []Chunk, y: []Chunk, log_m: GfElement) void {
            scalar.mul_add(x, y, log_m);
            utils.xor(y, x);
        }

        /// Partial IFFT butterfly; the caller handles a `GF_MODULUS` coefficient with `xor`.
        inline fn ifft_partial(scalar: Self, x: []Chunk, y: []Chunk, log_m: GfElement) void {
            utils.xor(y, x);
            scalar.mul_add(x, y, log_m);
        }

        /// FFT butterfly, or the XOR it reduces to when the coefficient is zero.
        inline fn fft_butterfly(scalar: Self, x: []Chunk, y: []Chunk, log_m: GfElement) void {
            if (log_m == GF_MODULUS) utils.xor(y, x) else scalar.fft_partial(x, y, log_m);
        }

        /// IFFT butterfly, or the XOR it reduces to when the coefficient is zero.
        inline fn ifft_butterfly(scalar: Self, x: []Chunk, y: []Chunk, log_m: GfElement) void {
            if (log_m == GF_MODULUS) utils.xor(y, x) else scalar.ifft_partial(x, y, log_m);
        }

        /// Two FFT layers on shards `pos + k * dist` for `k` in `0..4`.
        inline fn fft_two_layers(
            scalar: Self,
            data: ShardsRefMut,
            pos: usize,
            dist: usize,
            log_m01: GfElement,
            log_m23: GfElement,
            log_m02: GfElement,
        ) void {
            const s0, const s1, const s2, const s3 = data.dist4(pos, dist);
            if (fused and log_m01 != GF_MODULUS and log_m23 != GF_MODULUS and
                log_m02 != GF_MODULUS)
            {
                const luts = .{ &scalar.mul16[log_m01], &scalar.mul16[log_m23] };
                return Kernel.fft4(luts[0], luts[1], &scalar.mul16[log_m02], .{ s0, s1, s2, s3 });
            }
            // First layer: (s0, s2) and (s1, s3). Second layer: (s0, s1) and (s2, s3).
            scalar.fft_butterfly(s0, s2, log_m02);
            scalar.fft_butterfly(s1, s3, log_m02);
            scalar.fft_butterfly(s0, s1, log_m01);
            scalar.fft_butterfly(s2, s3, log_m23);
        }

        /// Two IFFT layers on shards `pos + k * dist` for `k` in `0..4`.
        inline fn ifft_two_layers(
            scalar: Self,
            data: ShardsRefMut,
            pos: usize,
            dist: usize,
            log_m01: GfElement,
            log_m23: GfElement,
            log_m02: GfElement,
        ) void {
            const s0, const s1, const s2, const s3 = data.dist4(pos, dist);
            if (fused and log_m01 != GF_MODULUS and log_m23 != GF_MODULUS and
                log_m02 != GF_MODULUS)
            {
                const luts = .{ &scalar.mul16[log_m01], &scalar.mul16[log_m23] };
                return Kernel.ifft4(luts[0], luts[1], &scalar.mul16[log_m02], .{ s0, s1, s2, s3 });
            }
            // First layer: (s0, s1) and (s2, s3). Second layer: (s0, s2) and (s1, s3).
            scalar.ifft_butterfly(s0, s1, log_m01);
            scalar.ifft_butterfly(s2, s3, log_m23);
            scalar.ifft_butterfly(s0, s2, log_m02);
            scalar.ifft_butterfly(s1, s3, log_m02);
        }
    };
}

/// Multiplies one field element at a time with four nibble-table lookups.
pub const ScalarKernel = struct {
    pub const Table = tables.Mul16;
    pub const table = tables.get_mul16;

    pub fn mul(lut: *const [4][16]GfElement, x: []Chunk) void {
        for (x) |*chunk| {
            for (0..half) |i| {
                const product = lookup(lut, chunk[i], chunk[i + half]);
                chunk[i] = @truncate(product);
                chunk[i + half] = @truncate(product >> 8);
            }
        }
    }

    pub fn mul_add(lut: *const [4][16]GfElement, x: []Chunk, y: []const Chunk) void {
        assert(x.len == y.len);
        for (x, y) |*x_chunk, *y_chunk| {
            for (0..half) |i| {
                const product = lookup(lut, y_chunk[i], y_chunk[i + half]);
                x_chunk[i] ^= @truncate(product);
                x_chunk[i + half] ^= @truncate(product >> 8);
            }
        }
    }

    inline fn lookup(lut: *const [4][16]GfElement, lo: u8, hi: u8) GfElement {
        return lut[0][lo & 15] ^ lut[1][lo >> 4] ^ lut[2][hi & 15] ^ lut[3][hi >> 4];
    }
};

/// Portable engine without SIMD that works on all CPUs.
pub const Scalar = Engine(ScalarKernel);

test "scalar mul matches naive" {
    const ChaCha8Rng = @import("../test_util.zig").ChaCha8Rng;
    const Naive = @import("naive.zig").Naive;
    const naive: Naive = .init();
    const scalar: Scalar = .init();
    var rng = ChaCha8Rng.init_key(@splat(0));
    var data_scalar: [5]Chunk = undefined;
    var data_naive: [5]Chunk = undefined;
    for (0..6) |shard_chunks| {
        rng.fill_bytes(std.mem.sliceAsBytes(data_scalar[0..shard_chunks]));
        @memcpy(data_naive[0..shard_chunks], data_scalar[0..shard_chunks]);
        const log_m: GfElement = @truncate(rng.next_u32());
        scalar.mul(data_scalar[0..shard_chunks], log_m);
        naive.mul(data_naive[0..shard_chunks], log_m);
        try std.testing.expectEqualSlices(
            Chunk,
            data_naive[0..shard_chunks],
            data_scalar[0..shard_chunks],
        );
    }
}
