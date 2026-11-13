//! Low rate: more recovery shards than original shards
//! (commonware `reed_solomon/rate/rate_low.rs`).
//!
//! Encoding works in chunks of `original_count.next_power_of_two()` shards:
//! `recovery_chunk_i = FFT(IFFT(original_chunk), skew_i)`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const root = @import("../root.zig");
const engine = @import("../engine.zig");
const rate = @import("../rate.zig");
const results = @import("../results.zig");
const Plan = @import("../plan.zig").Plan;
const EncoderWork = @import("encoder_work.zig").EncoderWork;
const DecoderWork = @import("decoder_work.zig").DecoderWork;

const Error = root.Error;
const InitError = root.InitError;
const GfElement = engine.GfElement;
const GF_MODULUS = engine.GF_MODULUS;
const GF_ORDER = engine.GF_ORDER;
const BitSet = std.DynamicBitSetUnmanaged;

/// Largest decoding domain that `eval_erasures` evaluates directly, bounding the quadratic
/// calculation and its stack storage.
pub const DIRECT_EVALUATION_LIMIT = 32;

/// Writes the log erasure locator for each position in `erasures[..end]`, where
/// `end = original_count.next_power_of_two() + recovery_count`. `erasures` must hold
/// `end.next_power_of_two()` zeroed entries; entries at and after `end` are unspecified.
/// Small domains are evaluated directly, larger ones with Walsh transforms.
pub fn eval_erasures(
    comptime E: type,
    erasures: []GfElement,
    original_count: usize,
    recovery_count: usize,
    received: *const BitSet,
) void {
    const end = rate.next_power_of_two(original_count) + recovery_count;
    assert(erasures.len == rate.next_power_of_two(end));
    if (end <= DIRECT_EVALUATION_LIMIT) {
        eval_direct(erasures[0..end], original_count, received);
    } else {
        eval_walsh(E, erasures, original_count, recovery_count, received);
    }
}

/// Whether position `i` is known: received, or a padded original that is a known zero.
inline fn known(i: usize, original_count: usize, chunk_size: usize, received: *const BitSet) bool {
    return (i < received.bit_length and received.isSet(i)) or
        (i >= original_count and i < chunk_size);
}

/// Computes log erasure factors directly from the known positions in a small domain, avoiding
/// the Walsh transforms. `erasures.len` is the domain end and at most `DIRECT_EVALUATION_LIMIT`.
pub fn eval_direct(erasures: []GfElement, original_count: usize, received: *const BitSet) void {
    assert(erasures.len <= DIRECT_EVALUATION_LIMIT);
    const chunk_size = rate.next_power_of_two(original_count);
    var known_positions: [DIRECT_EVALUATION_LIMIT]usize = undefined;
    var count: usize = 0;
    for (0..erasures.len) |i| {
        if (known(i, original_count, chunk_size, received)) {
            known_positions[count] = i;
            count += 1;
        }
    }
    assert(count <= erasures.len);

    // The product over the nonzero field elements is one, so the erased-position product is the
    // reciprocal of the known-position product.
    const log = engine.tables.get_exp_log().log;
    for (erasures, 0..) |*erasure, i| {
        // At most DIRECT_EVALUATION_LIMIT terms fit comfortably in u32.
        var sum: u32 = 0;
        // log[0] is GF_MODULUS, so the self term vanishes modulo GF_MODULUS.
        for (known_positions[0..count]) |j| sum += log[i ^ j];
        erasure.* = GF_MODULUS - @as(GfElement, @intCast(sum % GF_MODULUS));
    }
}

/// Writes the log erasure locators with Walsh transforms. Missing shards and every position at
/// and after `end` are erased. `erasures` must hold `end.next_power_of_two()` zeroed entries.
pub fn eval_walsh(
    comptime E: type,
    erasures: []GfElement,
    original_count: usize,
    recovery_count: usize,
    received: *const BitSet,
) void {
    const chunk_size = rate.next_power_of_two(original_count);
    const end = chunk_size + recovery_count;
    assert(erasures.len == rate.next_power_of_two(end));
    // For each `i`, the values `i ^ j` with `j != i` cover every nonzero field element, whose
    // product is one. So evaluate the known positions, which lie below `end`, and negate.
    for (0..end) |i| {
        if (known(i, original_count, chunk_size, received)) erasures[i] = 1;
    }
    rate.eval_locator(E, erasures, end);
    for (erasures[0..end]) |*value| value.* = GF_MODULUS - value.*;
}

/// Encoder/decoder generator using only low rate.
pub fn LowRate(comptime E: type) type {
    engine.assert_engine(E);
    return struct {
        pub const Encoder = LowRateEncoder(E);
        pub const Decoder = LowRateDecoder(E);

        /// Whether the `original_count` / `recovery_count` combination is supported.
        pub fn supports(original_count: usize, recovery_count: usize) bool {
            return original_count > 0 and recovery_count > 0 and
                original_count < GF_ORDER and recovery_count < GF_ORDER and
                rate.next_power_of_two(original_count) + recovery_count <= GF_ORDER;
        }

        /// The counts are supported and the shard size is nonzero and even.
        pub fn validate(
            original_count: usize,
            recovery_count: usize,
            shard_bytes: usize,
        ) Error!void {
            try rate.validate_counts(supports(original_count, recovery_count), shard_bytes);
        }
    };
}

/// Encoder using only low rate.
pub fn LowRateEncoder(comptime E: type) type {
    return struct {
        const Self = @This();
        const Rate = LowRate(E);

        engine: E,
        /// Originals at `0..original_count`; encoding leaves the recovery shards at
        /// `0..recovery_count`.
        work: EncoderWork,

        pub const Parts = struct { engine: E, work: EncoderWork };

        pub fn supports(original_count: usize, recovery_count: usize) bool {
            return Rate.supports(original_count, recovery_count);
        }

        /// The counts are supported, the shard size is nonzero and even, and the working space
        /// fits in a single allocation.
        pub fn validate(
            original_count: usize,
            recovery_count: usize,
            shard_bytes: usize,
        ) Error!void {
            try Rate.validate(original_count, recovery_count, shard_bytes);
            try rate.validate_work_size(shard_bytes, work_count(original_count, recovery_count));
        }

        /// `recovery_count` rounded up to a multiple of the chunk size: room for the padded
        /// originals in the first chunk and the FFT of every recovery chunk.
        pub fn work_count(original_count: usize, recovery_count: usize) usize {
            assert(supports(original_count, recovery_count));
            const chunk_size = rate.next_power_of_two(original_count);
            return std.mem.alignForward(usize, recovery_count, chunk_size);
        }

        /// Creates an encoder, reusing `work` when given. On failure `work` is freed.
        pub fn init(
            gpa: Allocator,
            original_count: usize,
            recovery_count: usize,
            shard_bytes: usize,
            eng: E,
            work: ?EncoderWork,
        ) InitError!Self {
            var self: Self = .{ .engine = eng, .work = work orelse .empty };
            errdefer self.work.deinit(gpa);
            try self.reset(gpa, original_count, recovery_count, shard_bytes);
            return self;
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.work.deinit(gpa);
        }

        /// Validates, then resets the work. On failure the encoder is unchanged.
        pub fn reset(
            self: *Self,
            gpa: Allocator,
            original_count: usize,
            recovery_count: usize,
            shard_bytes: usize,
        ) InitError!void {
            try validate(original_count, recovery_count, shard_bytes);
            const count = work_count(original_count, recovery_count);
            try self.work.reset(gpa, original_count, recovery_count, shard_bytes, count);
        }

        pub fn add_original_shard(self: *Self, original_shard: []const u8) Error!void {
            try self.work.add_original_shard(original_shard);
        }

        /// Encodes the added originals. Call `deinit` on the result to start a new round.
        pub fn encode(self: *Self) Error!results.EncoderResult {
            const begin = try self.work.encode_begin();
            const work = begin.work;
            const recovery_count = begin.recovery_count;
            const chunk_size = rate.next_power_of_two(begin.original_count);
            const eng = self.engine;

            // Zero-pad the originals to `chunk_size` and IFFT them.
            work.zero(begin.original_count, chunk_size);
            eng.ifft(work, 0, chunk_size, begin.original_count, 0);

            // Copy the IFFT result into each remaining chunk.
            var chunk_start = chunk_size;
            while (chunk_start < recovery_count) : (chunk_start += chunk_size) {
                work.copy_within(0, chunk_start, chunk_size);
            }

            // FFT each full chunk, then the final partial chunk.
            chunk_start = 0;
            while (chunk_start + chunk_size <= recovery_count) : (chunk_start += chunk_size) {
                engine.utils.fft_skew_end(eng, work, chunk_start, chunk_size, chunk_size);
            }
            const last_count = recovery_count % chunk_size;
            if (last_count > 0) {
                engine.utils.fft_skew_end(eng, work, chunk_start, chunk_size, last_count);
            }

            self.work.undo_last_chunk_encoding();
            return .{ .work = &self.work };
        }

        /// Gives up the engine and working space so another encoder can reuse them.
        pub fn into_parts(self: Self) Parts {
            return .{ .engine = self.engine, .work = self.work };
        }
    };
}

/// Decoder using only low rate.
pub fn LowRateDecoder(comptime E: type) type {
    return struct {
        const Self = @This();
        const Rate = LowRate(E);

        engine: E,
        /// Originals at `0..original_count`; recovery shards start at
        /// `original_count.next_power_of_two()`.
        work: DecoderWork,

        pub const Parts = struct { engine: E, work: DecoderWork };

        pub fn supports(original_count: usize, recovery_count: usize) bool {
            return Rate.supports(original_count, recovery_count);
        }

        /// The counts are supported, the shard size is nonzero and even, and the working space
        /// fits in a single allocation.
        pub fn validate(
            original_count: usize,
            recovery_count: usize,
            shard_bytes: usize,
        ) Error!void {
            try Rate.validate(original_count, recovery_count, shard_bytes);
            try rate.validate_work_size(shard_bytes, work_count(original_count, recovery_count));
        }

        /// `original_count.next_power_of_two() + recovery_count` rounded up to a power of two,
        /// the size of the decoding transforms.
        pub fn work_count(original_count: usize, recovery_count: usize) usize {
            assert(supports(original_count, recovery_count));
            return rate.next_power_of_two(rate.next_power_of_two(original_count) + recovery_count);
        }

        /// Creates a decoder, reusing `work` when given. On failure `work` is freed.
        pub fn init(
            gpa: Allocator,
            original_count: usize,
            recovery_count: usize,
            shard_bytes: usize,
            eng: E,
            work: ?DecoderWork,
        ) InitError!Self {
            var self: Self = .{ .engine = eng, .work = work orelse .empty };
            errdefer self.work.deinit(gpa);
            try self.reset(gpa, original_count, recovery_count, shard_bytes);
            return self;
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.work.deinit(gpa);
        }

        /// Validates, then resets the work. On failure the decoder is unchanged.
        pub fn reset(
            self: *Self,
            gpa: Allocator,
            original_count: usize,
            recovery_count: usize,
            shard_bytes: usize,
        ) InitError!void {
            try validate(original_count, recovery_count, shard_bytes);
            try self.work.reset(
                gpa,
                .{
                    .original = original_count,
                    .recovery = recovery_count,
                    .shard_bytes = shard_bytes,
                },
                0,
                rate.next_power_of_two(original_count),
                work_count(original_count, recovery_count),
            );
        }

        pub fn add_original_shard(self: *Self, index: usize, shard: []const u8) Error!void {
            try self.work.add_original_shard(index, shard);
        }

        pub fn add_recovery_shard(self: *Self, index: usize, shard: []const u8) Error!void {
            try self.work.add_recovery_shard(index, shard);
        }

        /// Reconstructs the missing originals, and the missing recovery shards when
        /// `compute_recovery` is set. Returns null, clearing the received state, when every
        /// original was provided. Call `deinit` on the result to start a new round.
        pub fn decode(self: *Self, compute_recovery: bool) Error!?results.DecoderResult {
            return self.decode_impl(compute_recovery, null);
        }

        /// Like `decode`, taking the erasure locators from `plan`.
        pub fn decode_with_plan(
            self: *Self,
            compute_recovery: bool,
            plan: *const Plan,
        ) Error!?results.DecoderResult {
            return self.decode_impl(compute_recovery, plan);
        }

        fn decode_impl(
            self: *Self,
            compute_recovery: bool,
            plan: ?*const Plan,
        ) Error!?results.DecoderResult {
            if (plan) |p| try self.work.validate_plan(p, false);
            const begin = try self.work.decode_begin() orelse {
                self.work.reset_received();
                return null;
            };
            const chunk_size = rate.next_power_of_two(begin.original_count);
            const recovery_end = chunk_size + begin.recovery_count;

            const erasures: []const GfElement = if (plan) |p| p.coefficients else blk: {
                eval_erasures(
                    E,
                    begin.erasures,
                    begin.original_count,
                    begin.recovery_count,
                    begin.received,
                );
                break :blk begin.erasures;
            };

            const work = begin.work;
            const received = begin.received;
            rate.decode_transform(
                self.engine,
                work,
                received,
                erasures,
                begin.original_count,
                chunk_size,
                recovery_end,
            );
            rate.reveal(self.engine, work, received, erasures, 0, begin.original_count);
            if (compute_recovery) {
                rate.reveal(self.engine, work, received, erasures, chunk_size, recovery_end);
            }

            self.work.undo_last_chunk_encoding();
            if (compute_recovery) self.work.undo_last_chunk_encoding_recovery();
            return .{ .work = &self.work };
        }

        /// Gives up the engine and working space so another decoder can reuse them.
        pub fn into_parts(self: Self) Parts {
            return .{ .engine = self.engine, .work = self.work };
        }
    };
}
