//! Advanced encoding and decoding with a chosen engine and rate
//! (commonware `reed_solomon/rate.rs`). Not needed for basic usage: `Encoder` and `Decoder`
//! wrap `DefaultRate` over `DefaultEngine`.
//!
//! - `DefaultRate`, `DefaultRateEncoder`, `DefaultRateDecoder`: high or low rate as appropriate.
//! - `HighRate`, `HighRateEncoder`, `HighRateDecoder`: only high rate.
//! - `LowRate`, `LowRateEncoder`, `LowRateDecoder`: only low rate.
//!
//! Rust's `Rate`, `RateEncoder`, and `RateDecoder` traits are comptime interfaces: each rate is
//! a function of the engine type returning a namespace with `supports`, `validate`, `Encoder`,
//! and `Decoder`; every encoder and decoder has `init`, `deinit`, `reset`, `validate`,
//! `supports`, `into_parts`, and its coding methods. Working space (`EncoderWork`,
//! `DecoderWork`) can move between coders with `into_parts` and `init(..., work)`.

const std = @import("std");
const assert = std.debug.assert;
const utils_package = @import("utils");

const root = @import("root.zig");
const engine = @import("engine.zig");

pub const EncoderWork = @import("rate/encoder_work.zig").EncoderWork;
pub const DecoderWork = @import("rate/decoder_work.zig").DecoderWork;
pub const high = @import("rate/high.zig");
pub const low = @import("rate/low.zig");
pub const default = @import("rate/default.zig");

pub const HighRate = high.HighRate;
pub const HighRateEncoder = high.HighRateEncoder;
pub const HighRateDecoder = high.HighRateDecoder;
pub const LowRate = low.LowRate;
pub const LowRateEncoder = low.LowRateEncoder;
pub const LowRateDecoder = low.LowRateDecoder;
pub const DefaultRate = default.DefaultRate;
pub const DefaultRateEncoder = default.DefaultRateEncoder;
pub const DefaultRateDecoder = default.DefaultRateDecoder;

const Error = root.Error;
const GfElement = engine.GfElement;
const ShardsRefMut = engine.ShardsRefMut;
const BitSet = std.DynamicBitSetUnmanaged;
const GF_MODULUS = engine.GF_MODULUS;
const GF_ORDER = engine.GF_ORDER;
const SHARD_CHUNK_BYTES = engine.SHARD_CHUNK_BYTES;

/// Shared part of `Rate::validate`: the shard counts are supported and the shard size is
/// nonzero and even.
pub fn validate_counts(supported: bool, shard_bytes: usize) Error!void {
    if (!supported) return error.UnsupportedShardCount;
    if (shard_bytes == 0 or shard_bytes & 1 != 0) return error.InvalidShardSize;
}

/// `error.InvalidShardSize` if `work_count` shards of `shard_bytes` bytes, each rounded up to
/// whole chunks, exceed `MAX_ALLOCATION_BYTES` in total.
pub fn validate_work_size(shard_bytes: usize, work_count: usize) Error!void {
    assert(work_count > 0);
    const max_chunks = utils_package.MAX_ALLOCATION_BYTES / SHARD_CHUNK_BYTES;
    const chunks = std.math.divCeil(usize, shard_bytes, SHARD_CHUNK_BYTES) catch
        unreachable; // The divisor is a nonzero constant.
    if (chunks > max_chunks / work_count) return error.InvalidShardSize;
}

/// `value.next_power_of_two()` for a value at most `GF_ORDER`.
pub fn next_power_of_two(value: usize) usize {
    assert(value <= GF_ORDER);
    if (value <= 1) return 1;
    return std.math.ceilPowerOfTwoAssert(usize, value);
}

/// XOR-convolve `erasures` with the field logarithm table. `erasures` holds
/// `n = end.next_power_of_two()` entries, and entries at and after `end` must be zero. Because
/// `i ^ j < n` for all `i, j < n`, the `n`-point transform matches the full-field one.
pub fn eval_locator(comptime E: type, erasures: []GfElement, end: usize) void {
    const n = erasures.len;
    assert(n == next_power_of_two(end));
    if (n == GF_ORDER) {
        engine.eval_poly(E, erasures[0..GF_ORDER], end);
    } else {
        engine.utils.eval_poly_short(erasures, end);
    }
}

/// The decoding transform shared by both rates. The work holds two blocks: `first_count`
/// shards at `0` padded to `chunk_size`, then shards `chunk_size..end`. Received shards are
/// multiplied by their erasure locators, everything else is zeroed, and the formal derivative
/// is taken between an IFFT and an FFT.
pub fn decode_transform(
    eng: anytype,
    work: ShardsRefMut,
    received: *const BitSet,
    erasures: []const GfElement,
    first_count: usize,
    chunk_size: usize,
    end: usize,
) void {
    assert(first_count <= chunk_size and chunk_size <= end and end <= work.len());
    assert(erasures.len >= end);
    for (0..first_count) |i| scale_or_zero(eng, work, received, erasures, i);
    work.zero(first_count, chunk_size);
    for (chunk_size..end) |i| scale_or_zero(eng, work, received, erasures, i);
    work.zero(end, work.len());

    eng.ifft(work, 0, work.len(), end, 0);
    engine.utils.formal_derivative(work);
    eng.fft(work, 0, work.len(), end, 0);
}

inline fn scale_or_zero(
    eng: anytype,
    work: ShardsRefMut,
    received: *const BitSet,
    erasures: []const GfElement,
    i: usize,
) void {
    if (received.isSet(i)) eng.mul(work.get(i), erasures[i]) else @memset(work.get(i), @splat(0));
}

/// Reveals the missing shards in `start..end` by scaling them by the inverse locator.
pub fn reveal(
    eng: anytype,
    work: ShardsRefMut,
    received: *const BitSet,
    erasures: []const GfElement,
    start: usize,
    end: usize,
) void {
    assert(start <= end and end <= work.len());
    for (start..end) |i| {
        if (!received.isSet(i)) eng.mul(work.get(i), GF_MODULUS - erasures[i]);
    }
}

test {
    _ = high;
    _ = low;
    _ = default;
    _ = @import("rate/tests.zig");
}
