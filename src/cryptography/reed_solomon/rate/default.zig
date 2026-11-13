//! High or low rate as appropriate (commonware `reed_solomon/rate/rate_default.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const root = @import("../root.zig");
const engine = @import("../engine.zig");
const rate = @import("../rate.zig");
const results = @import("../results.zig");
const high = @import("high.zig");
const low = @import("low.zig");
const Plan = @import("../plan.zig").Plan;
const EncoderWork = @import("encoder_work.zig").EncoderWork;
const DecoderWork = @import("decoder_work.zig").DecoderWork;

const Error = root.Error;
const InitError = root.InitError;
const GF_ORDER = engine.GF_ORDER;

/// Whether high rate should code these shard counts (false: low rate).
///
/// When the counts round up to different powers of two, picks high rate if `original_count` has
/// the larger one. When they round up to the same power of two, picks high rate if
/// `original_count <= recovery_count` (the "wrong" rate decodes faster there).
///
/// `error.UnsupportedShardCount` if either count is zero, or if the smaller count rounded up to
/// a power of two plus the larger count exceeds `GF_ORDER`.
pub fn use_high_rate(original_count: usize, recovery_count: usize) Error!bool {
    // Oversized counts fail before rounding up to a power of two can overflow.
    if (original_count > GF_ORDER or recovery_count > GF_ORDER) {
        return error.UnsupportedShardCount;
    }
    if (original_count == 0 or recovery_count == 0) return error.UnsupportedShardCount;
    const original_pow2 = rate.next_power_of_two(original_count);
    const recovery_pow2 = rate.next_power_of_two(recovery_count);
    const smaller_pow2 = @min(original_pow2, recovery_pow2);
    const larger = @max(original_count, recovery_count);
    if (smaller_pow2 + larger > GF_ORDER) return error.UnsupportedShardCount;

    if (original_pow2 < recovery_pow2) return false;
    if (original_pow2 > recovery_pow2) return true;
    return original_count <= recovery_count;
}

/// Encoder/decoder generator using high or low rate as appropriate.
pub fn DefaultRate(comptime E: type) type {
    engine.assert_engine(E);
    return struct {
        pub const Encoder = DefaultRateEncoder(E);
        pub const Decoder = DefaultRateDecoder(E);

        pub fn supports(original_count: usize, recovery_count: usize) bool {
            _ = use_high_rate(original_count, recovery_count) catch return false;
            return true;
        }

        pub fn validate(
            original_count: usize,
            recovery_count: usize,
            shard_bytes: usize,
        ) Error!void {
            try rate.validate_counts(supports(original_count, recovery_count), shard_bytes);
        }
    };
}

/// Encoder using high or low rate as appropriate (`Encoder` with a chosen engine and work).
pub fn DefaultRateEncoder(comptime E: type) type {
    return union(enum) {
        const Self = @This();
        const High = high.HighRateEncoder(E);
        const Low = low.LowRateEncoder(E);

        high: High,
        low: Low,

        pub const Parts = struct { engine: E, work: EncoderWork };

        pub fn supports(original_count: usize, recovery_count: usize) bool {
            return DefaultRate(E).supports(original_count, recovery_count);
        }

        pub fn validate(
            original_count: usize,
            recovery_count: usize,
            shard_bytes: usize,
        ) Error!void {
            if (try use_high_rate(original_count, recovery_count)) {
                try High.validate(original_count, recovery_count, shard_bytes);
            } else {
                try Low.validate(original_count, recovery_count, shard_bytes);
            }
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
            const is_high = use_high_rate(original_count, recovery_count) catch |err| {
                if (work) |w| {
                    var owned = w;
                    owned.deinit(gpa);
                }
                return err;
            };
            if (is_high) {
                return .{ .high = try .init(
                    gpa,
                    original_count,
                    recovery_count,
                    shard_bytes,
                    eng,
                    work,
                ) };
            }
            return .{ .low = try .init(
                gpa,
                original_count,
                recovery_count,
                shard_bytes,
                eng,
                work,
            ) };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            switch (self.*) {
                inline else => |*inner| inner.deinit(gpa),
            }
        }

        /// Validates, then resets, switching rates when needed. On failure nothing changes.
        pub fn reset(
            self: *Self,
            gpa: Allocator,
            original_count: usize,
            recovery_count: usize,
            shard_bytes: usize,
        ) InitError!void {
            try validate(original_count, recovery_count, shard_bytes);
            const is_high = try use_high_rate(original_count, recovery_count);
            if (is_high == (self.* == .high)) {
                return switch (self.*) {
                    inline else => |*inner| inner.reset(
                        gpa,
                        original_count,
                        recovery_count,
                        shard_bytes,
                    ),
                };
            }
            const parts = self.into_parts();
            // Validation passed, so only allocation can fail; the work is then freed and the
            // encoder is left empty, ready for another reset.
            self.* = init(
                gpa,
                original_count,
                recovery_count,
                shard_bytes,
                parts.engine,
                parts.work,
            ) catch |err| {
                self.* = .{ .low = .{ .engine = parts.engine, .work = .empty } };
                return err;
            };
        }

        pub fn add_original_shard(self: *Self, original_shard: []const u8) Error!void {
            switch (self.*) {
                inline else => |*inner| try inner.add_original_shard(original_shard),
            }
        }

        pub fn encode(self: *Self) Error!results.EncoderResult {
            return switch (self.*) {
                inline else => |*inner| inner.encode(),
            };
        }

        pub fn into_parts(self: Self) Parts {
            return switch (self) {
                inline else => |inner| blk: {
                    const parts = inner.into_parts();
                    break :blk .{ .engine = parts.engine, .work = parts.work };
                },
            };
        }
    };
}

/// Decoder using high or low rate as appropriate (`Decoder` with a chosen engine and work).
pub fn DefaultRateDecoder(comptime E: type) type {
    return union(enum) {
        const Self = @This();
        const High = high.HighRateDecoder(E);
        const Low = low.LowRateDecoder(E);

        high: High,
        low: Low,

        pub const Parts = struct { engine: E, work: DecoderWork };

        pub fn supports(original_count: usize, recovery_count: usize) bool {
            return DefaultRate(E).supports(original_count, recovery_count);
        }

        pub fn validate(
            original_count: usize,
            recovery_count: usize,
            shard_bytes: usize,
        ) Error!void {
            if (try use_high_rate(original_count, recovery_count)) {
                try High.validate(original_count, recovery_count, shard_bytes);
            } else {
                try Low.validate(original_count, recovery_count, shard_bytes);
            }
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
            const is_high = use_high_rate(original_count, recovery_count) catch |err| {
                if (work) |w| {
                    var owned = w;
                    owned.deinit(gpa);
                }
                return err;
            };
            if (is_high) {
                return .{ .high = try .init(
                    gpa,
                    original_count,
                    recovery_count,
                    shard_bytes,
                    eng,
                    work,
                ) };
            }
            return .{ .low = try .init(
                gpa,
                original_count,
                recovery_count,
                shard_bytes,
                eng,
                work,
            ) };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            switch (self.*) {
                inline else => |*inner| inner.deinit(gpa),
            }
        }

        /// Validates, then resets, switching rates when needed. On failure nothing changes.
        pub fn reset(
            self: *Self,
            gpa: Allocator,
            original_count: usize,
            recovery_count: usize,
            shard_bytes: usize,
        ) InitError!void {
            try validate(original_count, recovery_count, shard_bytes);
            const is_high = try use_high_rate(original_count, recovery_count);
            if (is_high == (self.* == .high)) {
                return switch (self.*) {
                    inline else => |*inner| inner.reset(
                        gpa,
                        original_count,
                        recovery_count,
                        shard_bytes,
                    ),
                };
            }
            const parts = self.into_parts();
            self.* = init(
                gpa,
                original_count,
                recovery_count,
                shard_bytes,
                parts.engine,
                parts.work,
            ) catch |err| {
                self.* = .{ .low = .{ .engine = parts.engine, .work = .empty } };
                return err;
            };
        }

        pub fn add_original_shard(self: *Self, index: usize, shard: []const u8) Error!void {
            switch (self.*) {
                inline else => |*inner| try inner.add_original_shard(index, shard),
            }
        }

        pub fn add_recovery_shard(self: *Self, index: usize, shard: []const u8) Error!void {
            switch (self.*) {
                inline else => |*inner| try inner.add_recovery_shard(index, shard),
            }
        }

        pub fn decode(self: *Self, compute_recovery: bool) Error!?results.DecoderResult {
            return switch (self.*) {
                inline else => |*inner| inner.decode(compute_recovery),
            };
        }

        pub fn decode_with_plan(
            self: *Self,
            compute_recovery: bool,
            plan: *const Plan,
        ) Error!?results.DecoderResult {
            return switch (self.*) {
                inline else => |*inner| inner.decode_with_plan(compute_recovery, plan),
            };
        }

        pub fn into_parts(self: Self) Parts {
            return switch (self) {
                inline else => |inner| blk: {
                    const parts = inner.into_parts();
                    break :blk .{ .engine = parts.engine, .work = parts.work };
                },
            };
        }
    };
}

test "use_high_rate" {
    const Case = struct { original: usize, recovery: usize, expected: Error!bool };
    const cases = [_]Case{
        .{ .original = 0, .recovery = 1, .expected = error.UnsupportedShardCount },
        .{ .original = 1, .recovery = 0, .expected = error.UnsupportedShardCount },
        // Unequal powers of two pick the "correct" rate, equal ones the "wrong" rate.
        .{ .original = 3, .recovery = 3, .expected = true },
        .{ .original = 3, .recovery = 4, .expected = true },
        .{ .original = 3, .recovery = 5, .expected = false },
        .{ .original = 4, .recovery = 3, .expected = false },
        .{ .original = 5, .recovery = 3, .expected = true },
        // Low rate limit.
        .{ .original = 4096, .recovery = 61440, .expected = false },
        .{ .original = 4096, .recovery = 61441, .expected = error.UnsupportedShardCount },
        .{ .original = 4097, .recovery = 61440, .expected = error.UnsupportedShardCount },
        // High rate limit.
        .{ .original = 61440, .recovery = 4096, .expected = true },
        .{ .original = 61440, .recovery = 4097, .expected = error.UnsupportedShardCount },
        .{ .original = 61441, .recovery = 4096, .expected = error.UnsupportedShardCount },
        .{
            .original = std.math.maxInt(usize),
            .recovery = std.math.maxInt(usize),
            .expected = error.UnsupportedShardCount,
        },
    };
    for (cases) |case| {
        const actual = use_high_rate(case.original, case.recovery);
        if (case.expected) |expected| {
            try std.testing.expectEqual(expected, try actual);
        } else |expected_err| {
            try std.testing.expectError(expected_err, actual);
        }
    }
}
