//! Encode and reconstruct shards using Reed-Solomon erasure coding over GF(2^16)
//! (commonware `cryptography/src/reed_solomon`, a vendored `reed-solomon-simd`).
//!
//! `Encoder` and `Decoder` select a rate automatically. Every shard must have the same
//! nonzero, even byte length. `Encoder.supports` checks a pair of original and recovery shard
//! counts. Decoding needs at least as many distinct shards as there were originals, all from
//! the same codeword: this module reconstructs missing shards and does not authenticate them.
//! `Plan` prepares erasure coefficients once for decoders that share shard counts and
//! received indices, even when their shard byte lengths differ.
//!
//! ```zig
//! var encoder = try Encoder.init(gpa, 2, 1, 6);
//! defer encoder.deinit(gpa);
//! for (originals) |shard| try encoder.add_original_shard(shard);
//! var encoded = try encoder.encode();
//! defer encoded.deinit();
//!
//! var decoder = try Decoder.init(gpa, 2, 1, 6);
//! defer decoder.deinit(gpa);
//! try decoder.add_original_shard(0, originals[0]);
//! try decoder.add_recovery_shard(0, encoded.recovery(0).?);
//! var decoded = (try decoder.decode()).?;
//! defer decoded.deinit();
//! // decoded.original(1) == originals[1]
//! ```
//!
//! Results borrow the coder's working buffers; `deinit` on a result resets its coder for
//! another round with the same configuration (Rust does this on drop).
//!
//! # Working space
//!
//! A coder sizes its working space when it is created or reset: up to
//! `2 * (original_count + recovery_count).next_power_of_two()` shards of `shard_bytes` bytes,
//! each rounded up to whole `SHARD_CHUNK_BYTES` blocks. The space grows on reset and never
//! shrinks. Callers taking shard counts or widths from an untrusted source must bound them
//! against their own memory budget first.
//!
//! # Differences from commonware
//!
//! - Errors carry no payload (Zig errors cannot); the variant names match `Error`'s.
//! - Allocation is explicit: coders take an allocator and can fail with `OutOfMemory`.
//!   Decoding allocates nothing; erasure scratch lives in the working space.
//! - The engine is chosen at compile time (`engine.DefaultEngine`), not by CPU detection.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

pub const engine = @import("engine.zig");
pub const rate = @import("rate.zig");
pub const results = @import("results.zig");
pub const plan = @import("plan.zig");

pub const Plan = plan.Plan;
pub const EncoderResult = results.EncoderResult;
pub const DecoderResult = results.DecoderResult;
pub const RecoveryDecoderResult = results.RecoveryDecoderResult;
pub const Recovery = results.Recovery;
pub const Restored = results.Restored;
pub const SHARD_CHUNK_BYTES = engine.SHARD_CHUNK_BYTES;

/// Every error this module reports (commonware `reed_solomon::Error`).
pub const Error = error{
    /// Given shard has a different size than the configured shard size.
    DifferentShardSize,
    /// Decoder or `Plan` was given the same original shard index twice.
    DuplicateOriginalShardIndex,
    /// Decoder or `Plan` was given the same recovery shard index twice.
    DuplicateRecoveryShardIndex,
    /// Decoder or `Plan` was given an original index `>= original_count`.
    InvalidOriginalShardIndex,
    /// Decoder or `Plan` was given a recovery index `>= recovery_count`.
    InvalidRecoveryShardIndex,
    /// Shard size is zero, odd, or needs more working space than one allocation can hold.
    InvalidShardSize,
    /// Fewer shards than `original_count` in total were given.
    NotEnoughShards,
    /// Decoder was given a `Plan` built for different counts or received indices.
    PlanMismatch,
    /// Encoder was given fewer than `original_count` original shards.
    TooFewOriginalShards,
    /// Encoder was given more than `original_count` original shards.
    TooManyOriginalShards,
    /// The `original_count` / `recovery_count` combination is not supported.
    UnsupportedShardCount,
};

/// Errors of operations that size the working space.
pub const InitError = Error || Allocator.Error;

const E = engine.DefaultEngine;

/// Reed-Solomon encoder using `DefaultEngine` and `DefaultRate`.
pub const Encoder = struct {
    inner: rate.DefaultRateEncoder(E),

    /// Creates an encoder and allocates its working space.
    pub fn init(
        gpa: Allocator,
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
    ) InitError!Encoder {
        const inner = try rate.DefaultRateEncoder(E).init(
            gpa,
            original_count,
            recovery_count,
            shard_bytes,
            .init(),
            null,
        );
        return .{ .inner = inner };
    }

    pub fn deinit(encoder: *Encoder, gpa: Allocator) void {
        encoder.inner.deinit(gpa);
        encoder.* = undefined;
    }

    /// Adds the next original shard. Originals have indexes `0..original_count` in the order
    /// they are added, and the same indexes must be used when decoding.
    pub fn add_original_shard(encoder: *Encoder, original_shard: []const u8) Error!void {
        try encoder.inner.add_original_shard(original_shard);
    }

    /// Encodes the added originals into recovery shards. `deinit` the result before the next
    /// round; until then the encoder reports a complete round.
    pub fn encode(encoder: *Encoder) Error!EncoderResult {
        return encoder.inner.encode();
    }

    /// Resets to a new configuration, forgetting added shards and reusing the working space
    /// when large enough. On failure the encoder keeps its previous state.
    pub fn reset(
        encoder: *Encoder,
        gpa: Allocator,
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
    ) InitError!void {
        try encoder.inner.reset(gpa, original_count, recovery_count, shard_bytes);
    }

    /// Whether the `original_count` / `recovery_count` combination is supported.
    pub fn supports(original_count: usize, recovery_count: usize) bool {
        return rate.DefaultRate(E).supports(original_count, recovery_count);
    }
};

/// Reed-Solomon decoder using `DefaultEngine` and `DefaultRate`.
pub const Decoder = struct {
    inner: rate.DefaultRateDecoder(E),

    /// Creates a decoder and allocates its working space.
    pub fn init(
        gpa: Allocator,
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
    ) InitError!Decoder {
        const inner = try rate.DefaultRateDecoder(E).init(
            gpa,
            original_count,
            recovery_count,
            shard_bytes,
            .init(),
            null,
        );
        return .{ .inner = inner };
    }

    pub fn deinit(decoder: *Decoder, gpa: Allocator) void {
        decoder.inner.deinit(gpa);
        decoder.* = undefined;
    }

    /// Adds original shard `index` (in any order; the index used when encoding).
    pub fn add_original_shard(decoder: *Decoder, index: usize, shard: []const u8) Error!void {
        try decoder.inner.add_original_shard(index, shard);
    }

    /// Adds recovery shard `index` (in any order; the index the encoder gave it).
    pub fn add_recovery_shard(decoder: *Decoder, index: usize, shard: []const u8) Error!void {
        try decoder.inner.add_recovery_shard(index, shard);
    }

    /// Restores the missing originals, or returns null (and clears the received shards) when
    /// every original was provided. `deinit` the result before the next round.
    pub fn decode(decoder: *Decoder) Error!?DecoderResult {
        return decoder.inner.decode(false);
    }

    /// Like `decode`, reading erasure coefficients from `p`. A mismatched plan returns
    /// `error.PlanMismatch` and leaves the added shards in place.
    pub fn decode_with_plan(decoder: *Decoder, p: *const Plan) Error!?DecoderResult {
        return decoder.inner.decode_with_plan(false, p);
    }

    /// Like `decode`, and also reconstructs the missing recovery shards.
    pub fn decode_with_recovery(decoder: *Decoder) Error!?RecoveryDecoderResult {
        const inner = try decoder.inner.decode(true) orelse return null;
        return .{ .inner = inner };
    }

    /// Like `decode_with_recovery`, reading erasure coefficients from `p`.
    pub fn decode_with_recovery_plan(
        decoder: *Decoder,
        p: *const Plan,
    ) Error!?RecoveryDecoderResult {
        const inner = try decoder.inner.decode_with_plan(true, p) orelse return null;
        return .{ .inner = inner };
    }

    /// Resets to a new configuration, forgetting added shards and reusing the working space
    /// when large enough. On failure the decoder keeps its previous state.
    pub fn reset(
        decoder: *Decoder,
        gpa: Allocator,
        original_count: usize,
        recovery_count: usize,
        shard_bytes: usize,
    ) InitError!void {
        try decoder.inner.reset(gpa, original_count, recovery_count, shard_bytes);
    }

    /// Whether the `original_count` / `recovery_count` combination is supported.
    pub fn supports(original_count: usize, recovery_count: usize) bool {
        return rate.DefaultRate(E).supports(original_count, recovery_count);
    }
};

test {
    _ = engine;
    _ = rate;
    _ = @import("tests.zig");
}
