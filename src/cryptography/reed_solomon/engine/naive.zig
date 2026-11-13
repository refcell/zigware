//! `Naive`: simple reference engine (commonware `reed_solomon/engine/engine_naive.rs`).
//!
//! Meant for studying the algorithms and as the differential-testing oracle for faster engines.

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

/// Simple reference implementation of the engine interface.
pub const Naive = struct {
    exp: *const tables.Exp,
    log: *const tables.Log,
    skew: *const tables.Skew,

    /// Creates a `Naive` engine and initializes its multiplication and skew tables.
    pub fn init() Naive {
        const exp_log = tables.get_exp_log();
        return .{ .exp = exp_log.exp, .log = exp_log.log, .skew = tables.get_skew() };
    }

    /// In-place decimation-in-time FFT of `data[pos..pos + size]` (see `engine.zig`).
    pub fn fft(
        naive: Naive,
        data: ShardsRefMut,
        pos: usize,
        size: usize,
        truncated_size: usize,
        skew_delta: usize,
    ) void {
        engine.validate_transform(data, pos, size, truncated_size, skew_delta);
        var dist = size / 2;
        while (dist > 0) : (dist /= 2) {
            var r: usize = 0;
            while (r < truncated_size) : (r += dist * 2) {
                const log_m = naive.skew[r + dist + skew_delta - 1];
                for (r..r + dist) |i| {
                    const a, const b = data.dist2(pos + i, dist);
                    if (log_m != GF_MODULUS) naive.mul_add(a, b, log_m);
                    utils.xor(b, a);
                }
            }
        }
    }

    /// In-place decimation-in-time IFFT of `data[pos..pos + size]` (see `engine.zig`).
    pub fn ifft(
        naive: Naive,
        data: ShardsRefMut,
        pos: usize,
        size: usize,
        truncated_size: usize,
        skew_delta: usize,
    ) void {
        engine.validate_transform(data, pos, size, truncated_size, skew_delta);
        var dist: usize = 1;
        while (dist < size) : (dist *= 2) {
            var r: usize = 0;
            while (r < truncated_size) : (r += dist * 2) {
                const log_m = naive.skew[r + dist + skew_delta - 1];
                for (r..r + dist) |i| {
                    const a, const b = data.dist2(pos + i, dist);
                    utils.xor(b, a);
                    if (log_m != GF_MODULUS) naive.mul_add(a, b, log_m);
                }
            }
        }
    }

    /// Multiply every field element in `x` by the element with logarithm `log_m`.
    pub fn mul(naive: Naive, x: []Chunk, log_m: GfElement) void {
        for (x) |*chunk| {
            for (0..half) |i| {
                const value = @as(GfElement, chunk[i]) | (@as(GfElement, chunk[i + half]) << 8);
                const product = tables.mul(value, log_m, naive.exp, naive.log);
                chunk[i] = @truncate(product);
                chunk[i + half] = @truncate(product >> 8);
            }
        }
    }

    /// `x ^= y * m` for each chunk, where `m` has logarithm `log_m`.
    fn mul_add(naive: Naive, x: []Chunk, y: []const Chunk, log_m: GfElement) void {
        assert(x.len == y.len);
        for (x, y) |*x_chunk, y_chunk| {
            for (0..half) |i| {
                const value = @as(GfElement, y_chunk[i]) |
                    (@as(GfElement, y_chunk[i + half]) << 8);
                const product = tables.mul(value, log_m, naive.exp, naive.log);
                x_chunk[i] ^= @truncate(product);
                x_chunk[i + half] ^= @truncate(product >> 8);
            }
        }
    }
};
