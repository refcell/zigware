//! High rate: more original shards than recovery shards
//! (commonware `reed_solomon/rate/rate_high.rs`).
//!
//! Encoding works in chunks of `recovery_count.next_power_of_two()` shards:
//! `recovery = FFT(IFFT(original_chunk_0, skew_0) ^ IFFT(original_chunk_1, skew_1) ^ ...)`.

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
const GF_ORDER = engine.GF_ORDER;
const BitSet = std.DynamicBitSetUnmanaged;

/// Writes the log erasure locator for each position in `erasures[..end]`, where
/// `end = recovery_count.next_power_of_two() + original_count`.
///
/// Missing recovery shards, the padding in `recovery_count..chunk_size`, and missing originals
/// are erased. `erasures` must hold `end.next_power_of_two()` zeroed entries.
pub fn eval_erasures(
    comptime E: type,
    erasures: []GfElement,
    original_count: usize,
    recovery_count: usize,
    received: *const BitSet,
) void {
    const chunk_size = rate.next_power_of_two(recovery_count);
    const end = chunk_size + original_count;
    assert(erasures.len == rate.next_power_of_two(end));
    for (0..recovery_count) |i| {
        if (!received.isSet(i)) erasures[i] = 1;
    }
    @memset(erasures[recovery_count..chunk_size], 1);
    for (chunk_size..end) |i| {
        if (!received.isSet(i)) erasures[i] = 1;
    }
    rate.eval_locator(E, erasures, end);
}

/// Encoder/decoder generator using only high rate.
pub fn HighRate(comptime E: type) type {
    engine.assert_engine(E);
    return struct {
        pub const Encoder = HighRateEncoder(E);
        pub const Decoder = HighRateDecoder(E);

        /// Whether the `original_count` / `recovery_count` combination is supported.
        pub fn supports(original_count: usize, recovery_count: usize) bool {
            return original_count > 0 and recovery_count > 0 and
                original_count < GF_ORDER and recovery_count < GF_ORDER and
                rate.next_power_of_two(recovery_count) + original_count <= GF_ORDER;
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

/// Encoder using only high rate.
pub fn HighRateEncoder(comptime E: type) type {
    return struct {
        const Self = @This();
        const Rate = HighRate(E);

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

        /// `original_count` rounded up to a multiple of the chunk size, so every chunk of
        /// originals, including a zero-padded final chunk, has room for its IFFT.
        pub fn work_count(original_count: usize, recovery_count: usize) usize {
            assert(supports(original_count, recovery_count));
            const chunk_size = rate.next_power_of_two(recovery_count);
            return std.mem.alignForward(usize, original_count, chunk_size);
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
            const original_count = begin.original_count;
            const chunk_size = rate.next_power_of_two(begin.recovery_count);
            const eng = self.engine;

            // Zero-pad the first chunk past `first_count` and IFFT it.
            const first_count = @min(original_count, chunk_size);
            work.zero(first_count, chunk_size);
            engine.utils.ifft_skew_end(eng, work, 0, chunk_size, first_count);

            if (original_count > chunk_size) {
                // IFFT each full chunk and XOR it into the first chunk.
                var chunk_start = chunk_size;
                while (chunk_start + chunk_size <= original_count) : (chunk_start += chunk_size) {
                    engine.utils.ifft_skew_end(eng, work, chunk_start, chunk_size, chunk_size);
                    engine.utils.xor_within(work, 0, chunk_start, chunk_size);
                }
                // Zero-pad the final partial chunk, IFFT it, and XOR it into the first chunk.
                const last_count = original_count % chunk_size;
                if (last_count > 0) {
                    work.zero(chunk_start + last_count, work.len());
                    engine.utils.ifft_skew_end(eng, work, chunk_start, chunk_size, last_count);
                    engine.utils.xor_within(work, 0, chunk_start, chunk_size);
                }
            }

            eng.fft(work, 0, chunk_size, begin.recovery_count, 0);
            self.work.undo_last_chunk_encoding();
            return .{ .work = &self.work };
        }

        /// Gives up the engine and working space so another encoder can reuse them.
        pub fn into_parts(self: Self) Parts {
            return .{ .engine = self.engine, .work = self.work };
        }
    };
}

/// Decoder using only high rate.
pub fn HighRateDecoder(comptime E: type) type {
    return struct {
        const Self = @This();
        const Rate = HighRate(E);

        engine: E,
        /// Recovery shards at `0..recovery_count`; originals start at
        /// `recovery_count.next_power_of_two()`.
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

        /// `recovery_count.next_power_of_two() + original_count` rounded up to a power of two,
        /// the size of the decoding transforms.
        pub fn work_count(original_count: usize, recovery_count: usize) usize {
            assert(supports(original_count, recovery_count));
            return rate.next_power_of_two(rate.next_power_of_two(recovery_count) + original_count);
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
                rate.next_power_of_two(recovery_count),
                0,
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
            if (plan) |p| try self.work.validate_plan(p, true);
            const begin = try self.work.decode_begin() orelse {
                self.work.reset_received();
                return null;
            };
            const chunk_size = rate.next_power_of_two(begin.recovery_count);
            const original_end = chunk_size + begin.original_count;

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
                begin.recovery_count,
                chunk_size,
                original_end,
            );
            rate.reveal(self.engine, work, received, erasures, chunk_size, original_end);
            if (compute_recovery) {
                rate.reveal(self.engine, work, received, erasures, 0, begin.recovery_count);
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
