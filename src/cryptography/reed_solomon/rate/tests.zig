//! Rate tests (commonware `reed_solomon/{rate,rate/rate_high,rate/rate_low,rate/rate_default}.rs`
//! tests and the `test_util.rs` roundtrip macros). Recovery hashes pin the output byte for byte.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const build_options = @import("build_options");
const utils_package = @import("utils");

const root = @import("../root.zig");
const engine = @import("../engine.zig");
const rate = @import("../rate.zig");
const test_util = @import("../test_util.zig");

const Error = root.Error;
const Naive = engine.Naive;
const Scalar = engine.Scalar;
const GfElement = engine.GfElement;
const GF_ORDER = engine.GF_ORDER;
const GF_MODULUS = engine.GF_MODULUS;
const SHARD_CHUNK_BYTES = engine.SHARD_CHUNK_BYTES;
const BitSet = std.DynamicBitSetUnmanaged;
const gpa = testing.allocator;

/// A half-open range of shard indices; indices past the shard count are ignored and an empty
/// or reversed range selects nothing.
const Selection = struct { start: usize, end: usize };

fn index(i: usize) Selection {
    return .{ .start = i, .end = i + 1 };
}

fn range(start: usize, end: usize) Selection {
    return .{ .start = start, .end = end };
}

const Roundtrip = struct {
    original_count: usize,
    recovery_count: usize,
    shard_bytes: usize,
    recovery_hash: []const u8,
    decoder_original: []const Selection,
    decoder_recovery: []const Selection,
    seed: u8,
};

/// The indices of `selection` below `count`.
fn clamp(selection: Selection, count: usize) Selection {
    const end = @min(selection.end, count);
    return .{ .start = @min(selection.start, end), .end = end };
}

/// Encodes `generate_original` shards, checks the recovery hash, decodes from the selected
/// shards, and checks every original the decoder did not receive.
fn roundtrip(comptime R: type, encoder: *R.Encoder, decoder: *R.Decoder, cfg: Roundtrip) !void {
    const original = try test_util.generate_original(
        gpa,
        cfg.original_count,
        cfg.shard_bytes,
        cfg.seed,
    );
    defer test_util.free_original(gpa, original);
    for (original) |shard| try encoder.add_original_shard(shard);
    var result = try encoder.encode();
    defer result.deinit();
    const recovery = try gpa.alloc([]const u8, cfg.recovery_count);
    defer gpa.free(recovery);
    var iterator = result.recovery_iter();
    for (recovery) |*shard| shard.* = iterator.next().?;
    try testing.expect(iterator.next() == null);
    try test_util.expect_hash(recovery, cfg.recovery_hash);

    var received = try BitSet.initEmpty(gpa, cfg.original_count);
    defer received.deinit(gpa);
    for (cfg.decoder_original) |selection| {
        const clamped = clamp(selection, cfg.original_count);
        for (clamped.start..clamped.end) |i| {
            try decoder.add_original_shard(i, original[i]);
            received.set(i);
        }
    }
    for (cfg.decoder_recovery) |selection| {
        const clamped = clamp(selection, cfg.recovery_count);
        for (clamped.start..clamped.end) |i| try decoder.add_recovery_shard(i, recovery[i]);
    }

    var decoded = try decoder.decode(false) orelse {
        // Nothing to reconstruct: every original was given.
        try testing.expectEqual(cfg.original_count, received.count());
        return;
    };
    defer decoded.deinit();
    for (0..cfg.original_count) |i| {
        if (!received.isSet(i)) try testing.expectEqualSlices(
            u8,
            original[i],
            decoded.original(i).?,
        );
    }
}

/// `roundtrip` once on a fresh encoder and decoder of rate `R`.
fn roundtrip_single(comptime R: type, comptime E: type, cfg: Roundtrip) !void {
    var encoder = try R.Encoder.init(
        gpa,
        cfg.original_count,
        cfg.recovery_count,
        cfg.shard_bytes,
        E.init(),
        null,
    );
    defer encoder.deinit(gpa);
    var decoder = try R.Decoder.init(
        gpa,
        cfg.original_count,
        cfg.recovery_count,
        cfg.shard_bytes,
        E.init(),
        null,
    );
    defer decoder.deinit(gpa);
    try roundtrip(R, &encoder, &decoder, cfg);
}

/// `roundtrip_single` with the `Naive` and `Scalar` engines (`DefaultEngine` is `Scalar`).
fn roundtrip_engines(comptime Rate: fn (type) type, cfg: Roundtrip) !void {
    try roundtrip_single(Rate(Naive), Naive, cfg);
    try roundtrip_single(Rate(Scalar), Scalar, cfg);
}

/// `roundtrip_single` with only the `Scalar` engine, for large shard counts.
fn roundtrip_scalar(comptime Rate: fn (type) type, cfg: Roundtrip) !void {
    try roundtrip_single(Rate(Scalar), Scalar, cfg);
}

/// Two `roundtrip` rounds on one encoder and decoder, resetting to round B's configuration
/// in between when `explicit_reset` is set.
fn roundtrip_two_rounds(
    comptime Rate: fn (type) type,
    explicit_reset: bool,
    a: Roundtrip,
    b: Roundtrip,
) !void {
    inline for (.{ Naive, Scalar }) |E| {
        const R = Rate(E);
        var encoder = try R.Encoder.init(
            gpa,
            a.original_count,
            a.recovery_count,
            a.shard_bytes,
            E.init(),
            null,
        );
        defer encoder.deinit(gpa);
        var decoder = try R.Decoder.init(
            gpa,
            a.original_count,
            a.recovery_count,
            a.shard_bytes,
            E.init(),
            null,
        );
        defer decoder.deinit(gpa);
        try roundtrip(R, &encoder, &decoder, a);
        if (explicit_reset) {
            try encoder.reset(gpa, b.original_count, b.recovery_count, b.shard_bytes);
            try decoder.reset(gpa, b.original_count, b.recovery_count, b.shard_bytes);
        }
        try roundtrip(R, &encoder, &decoder, b);
    }
}

/// A roundtrip of 1024-byte shards.
fn kib(
    original_count: usize,
    recovery_count: usize,
    recovery_hash: []const u8,
    decoder_original: []const Selection,
    decoder_recovery: []const Selection,
    seed: u8,
) Roundtrip {
    return .{
        .original_count = original_count,
        .recovery_count = recovery_count,
        .shard_bytes = 1024,
        .recovery_hash = recovery_hash,
        .decoder_original = decoder_original,
        .decoder_recovery = decoder_recovery,
        .seed = seed,
    };
}

/// The tiny-count rows: decode from originals `recovery_count..` and recoveries
/// `0..min(original_count, recovery_count)`.
fn roundtrips_tiny(comptime Rate: fn (type) type, rows: []const test_util.Tiny) !void {
    for (rows) |row| {
        const original_count, const recovery_count, const seed, const hash = row;
        try roundtrip_engines(Rate, kib(
            original_count,
            recovery_count,
            hash,
            &.{range(recovery_count, original_count)},
            &.{range(0, @min(original_count, recovery_count))},
            seed,
        ));
    }
}

test "high rate roundtrips" {
    const H = rate.HighRate;
    try roundtrip_engines(H, kib(3, 3, test_util.EITHER_3_3, &.{}, &.{range(0, 3)}, 133));
    try roundtrip_engines(H, kib(3, 2, test_util.HIGH_3_2, &.{range(0, 3)}, &.{}, 132));
    try roundtrips_tiny(H, &test_util.high_tiny);
    try roundtrip_scalar(H, .{
        .original_count = 34000,
        .recovery_count = 2000,
        .shard_bytes = 8,
        .recovery_hash = test_util.HIGH_34000_2000_123_8,
        .decoder_original = &.{range(0, 32000)},
        .decoder_recovery = &.{range(0, 2000)},
        .seed = 123,
    });
}

test "low rate roundtrips" {
    const L = rate.LowRate;
    try roundtrip_engines(L, kib(3, 3, test_util.EITHER_3_3, &.{}, &.{range(0, 3)}, 133));
    try roundtrip_engines(L, kib(2, 3, test_util.LOW_2_3, &.{ index(0), index(1) }, &.{}, 123));
    try roundtrips_tiny(L, &test_util.low_tiny);
    try roundtrip_scalar(L, .{
        .original_count = 2000,
        .recovery_count = 34000,
        .shard_bytes = 8,
        .recovery_hash = test_util.LOW_2000_34000_123_8,
        .decoder_original = &.{range(0, 2000)},
        .decoder_recovery = &.{range(0, 32000)},
        .seed = 123,
    });
}

test "default rate roundtrips" {
    try roundtrips_tiny(rate.DefaultRate, &test_util.default_tiny);
}

/// One large roundtrip of `SHARD_CHUNK_BYTES`-byte shards (commonware `test_group("slow")`).
fn roundtrip_large(
    comptime Rate: fn (type) type,
    counts: [2]usize,
    hash: []const u8,
    decoder_original: []const Selection,
    decoder_recovery: []const Selection,
    seed: u8,
) !void {
    try roundtrip_scalar(Rate, .{
        .original_count = counts[0],
        .recovery_count = counts[1],
        .shard_bytes = SHARD_CHUNK_BYTES,
        .recovery_hash = hash,
        .decoder_original = decoder_original,
        .decoder_recovery = decoder_recovery,
        .seed = seed,
    });
}

test "large roundtrips (slow)" {
    if (!build_options.slow_tests) return error.SkipZigTest;
    const H = rate.HighRate;
    const L = rate.LowRate;
    try roundtrip_large(
        H,
        .{ 3000, 30000 },
        test_util.HIGH_3000_30000_14,
        &.{},
        &.{range(0, 3000)},
        14,
    );
    try roundtrip_large(
        H,
        .{ 32768, 32768 },
        test_util.EITHER_32768_32768_11,
        &.{},
        &.{range(0, 32768)},
        11,
    );
    try roundtrip_large(
        H,
        .{ 60000, 3000 },
        test_util.HIGH_60000_3000_12,
        &.{range(3000, 60000)},
        &.{range(0, 3000)},
        12,
    );
    try roundtrip_large(
        L,
        .{ 3000, 60000 },
        test_util.LOW_3000_60000_13,
        &.{},
        &.{range(0, 3000)},
        13,
    );
    try roundtrip_large(
        L,
        .{ 30000, 3000 },
        test_util.LOW_30000_3000_15,
        &.{range(3000, 30000)},
        &.{range(0, 3000)},
        15,
    );
    try roundtrip_large(
        L,
        .{ 32768, 32768 },
        test_util.EITHER_32768_32768_11,
        &.{},
        &.{range(0, 32768)},
        11,
    );
}

test "high rate two rounds" {
    const H = rate.HighRate;
    const first = kib(3, 2, test_util.HIGH_3_2, &.{index(1)}, &.{ index(0), index(1) }, 132);
    try roundtrip_two_rounds(H, false, first, kib(
        3,
        2,
        test_util.HIGH_3_2_232,
        &.{index(0)},
        &.{ index(0), index(1) },
        232,
    ));
    try roundtrip_two_rounds(H, true, first, kib(
        5,
        2,
        test_util.HIGH_5_2,
        &.{ index(0), index(2), index(4) },
        &.{ index(0), index(1) },
        152,
    ));
}

test "low rate two rounds" {
    const L = rate.LowRate;
    const first = kib(2, 3, test_util.LOW_2_3, &.{}, &.{ index(0), index(2) }, 123);
    try roundtrip_two_rounds(L, false, first, kib(
        2,
        3,
        test_util.LOW_2_3_223,
        &.{},
        &.{ index(1), index(2) },
        223,
    ));
    try roundtrip_two_rounds(L, true, first, kib(
        2,
        5,
        test_util.LOW_2_5,
        &.{},
        &.{ index(0), index(4) },
        125,
    ));
}

test "default rate two rounds" {
    const D = rate.DefaultRate;
    const low_2_3 = kib(2, 3, test_util.LOW_2_3, &.{}, &.{ index(0), index(2) }, 123);
    const high_3_2 = kib(3, 2, test_util.HIGH_3_2, &.{index(1)}, &.{ index(0), index(1) }, 132);
    // Implicit reset.
    try roundtrip_two_rounds(D, false, low_2_3, kib(
        2,
        3,
        test_util.LOW_2_3_223,
        &.{index(0)},
        &.{index(1)},
        223,
    ));
    // High to high.
    try roundtrip_two_rounds(D, true, high_3_2, kib(
        5,
        3,
        test_util.HIGH_5_3,
        &.{ index(1), index(3) },
        &.{ index(0), index(1), index(2) },
        153,
    ));
    // High to low, low to high.
    try roundtrip_two_rounds(D, true, high_3_2, low_2_3);
    const low_2_3_b = kib(2, 3, test_util.LOW_2_3, &.{}, &.{ index(0), index(1) }, 123);
    try roundtrip_two_rounds(D, true, low_2_3_b, high_3_2);
    // Low to low.
    try roundtrip_two_rounds(D, true, low_2_3, kib(
        3,
        5,
        test_util.LOW_3_5,
        &.{},
        &.{ index(0), index(2), index(4) },
        135,
    ));
}

/// The errors `init`, `add_original_shard`, `encode`, and `reset` report (commonware
/// `test_rate_encoder_errors!`).
fn expect_encoder_errors(comptime Encoder: type) !void {
    const chunk = SHARD_CHUNK_BYTES;
    const zeros: [chunk]u8 = @splat(0);
    const wide: [chunk * 2]u8 = @splat(0);
    var encoder = try Encoder.init(gpa, 1, 1, chunk, Scalar.init(), null);
    defer encoder.deinit(gpa);
    try testing.expectError(error.DifferentShardSize, encoder.add_original_shard(&wide));
    try testing.expectError(
        error.InvalidShardSize,
        Encoder.init(gpa, 1, 1, 123, Scalar.init(), null),
    );
    try testing.expectError(error.InvalidShardSize, encoder.reset(gpa, 1, 1, 123));
    try testing.expectError(error.TooFewOriginalShards, encoder.encode());
    try encoder.add_original_shard(&zeros);
    try testing.expectError(error.TooManyOriginalShards, encoder.add_original_shard(&zeros));
    try testing.expectError(
        error.UnsupportedShardCount,
        Encoder.init(gpa, 0, 1, chunk, Scalar.init(), null),
    );
    try testing.expectError(error.UnsupportedShardCount, encoder.reset(gpa, 0, 1, chunk));
}

/// The errors `init`, `add_*_shard`, `decode`, and `reset` report (commonware
/// `test_rate_decoder_errors!`).
fn expect_decoder_errors(comptime Decoder: type) !void {
    const chunk = SHARD_CHUNK_BYTES;
    const zeros: [chunk]u8 = @splat(0);
    const wide: [chunk * 2]u8 = @splat(0);
    var decoder = try Decoder.init(gpa, 1, 1, chunk, Scalar.init(), null);
    defer decoder.deinit(gpa);
    try testing.expectError(error.DifferentShardSize, decoder.add_original_shard(0, &wide));
    try testing.expectError(error.DifferentShardSize, decoder.add_recovery_shard(0, &wide));
    try testing.expectError(error.InvalidOriginalShardIndex, decoder.add_original_shard(1, &zeros));
    try testing.expectError(error.InvalidRecoveryShardIndex, decoder.add_recovery_shard(1, &zeros));
    try testing.expectError(error.NotEnoughShards, decoder.decode(false));
    try decoder.add_original_shard(0, &zeros);
    try testing.expectError(
        error.DuplicateOriginalShardIndex,
        decoder.add_original_shard(0, &zeros),
    );
    try decoder.add_recovery_shard(0, &zeros);
    try testing.expectError(
        error.DuplicateRecoveryShardIndex,
        decoder.add_recovery_shard(0, &zeros),
    );
    try testing.expectError(
        error.InvalidShardSize,
        Decoder.init(gpa, 1, 1, 123, Scalar.init(), null),
    );
    try testing.expectError(error.InvalidShardSize, decoder.reset(gpa, 1, 1, 123));
    try testing.expectError(
        error.UnsupportedShardCount,
        Decoder.init(gpa, 0, 1, chunk, Scalar.init(), null),
    );
    try testing.expectError(error.UnsupportedShardCount, decoder.reset(gpa, 0, 1, chunk));
}

test "rate encoder and decoder errors" {
    try expect_encoder_errors(rate.HighRateEncoder(Scalar));
    try expect_encoder_errors(rate.LowRateEncoder(Scalar));
    try expect_encoder_errors(rate.DefaultRateEncoder(Scalar));
    try expect_decoder_errors(rate.HighRateDecoder(Scalar));
    try expect_decoder_errors(rate.LowRateDecoder(Scalar));
    try expect_decoder_errors(rate.DefaultRateDecoder(Scalar));
}

test "high and low rate limits" {
    const H = rate.HighRate(Scalar);
    const L = rate.LowRate(Scalar);
    const max = std.math.maxInt(usize);
    try testing.expect(!H.supports(0, 1) and !H.supports(1, 0) and !H.supports(4096, 61440));
    try testing.expect(
        H.supports(61440, 4096) and !H.supports(61440, 4097) and !H.supports(61441, 4096),
    );
    try testing.expect(!H.supports(max, max));
    try testing.expect(!L.supports(0, 1) and !L.supports(1, 0) and !L.supports(61440, 4096));
    try testing.expect(
        L.supports(4096, 61440) and !L.supports(4096, 61441) and !L.supports(4097, 61440),
    );
    try testing.expect(!L.supports(max, max));

    try testing.expectError(error.InvalidShardSize, H.validate(1, 1, 123));
    try testing.expectError(
        error.UnsupportedShardCount,
        H.validate(4096, 61440, SHARD_CHUNK_BYTES),
    );
    try H.validate(61440, 4096, SHARD_CHUNK_BYTES);
    try testing.expectError(error.InvalidShardSize, L.validate(1, 1, 123));
    try testing.expectError(
        error.UnsupportedShardCount,
        L.validate(61440, 4096, SHARD_CHUNK_BYTES),
    );
    try L.validate(4096, 61440, SHARD_CHUNK_BYTES);

    inline for (.{ H.Encoder, H.Decoder }) |Coder| {
        try testing.expectError(
            error.UnsupportedShardCount,
            Coder.validate(4096, 61440, SHARD_CHUNK_BYTES),
        );
        try testing.expectError(error.InvalidShardSize, Coder.validate(1, 1, 123));
        var coder = try Coder.init(gpa, 61440, 4096, SHARD_CHUNK_BYTES, Scalar.init(), null);
        coder.deinit(gpa);
        try testing.expectError(
            error.UnsupportedShardCount,
            Coder.init(gpa, 4096, 61440, 64, Scalar.init(), null),
        );
    }
    inline for (.{ L.Encoder, L.Decoder }) |Coder| {
        try testing.expectError(
            error.UnsupportedShardCount,
            Coder.validate(61440, 4096, SHARD_CHUNK_BYTES),
        );
        try testing.expectError(error.InvalidShardSize, Coder.validate(1, 1, 123));
        var coder = try Coder.init(gpa, 4096, 61440, SHARD_CHUNK_BYTES, Scalar.init(), null);
        coder.deinit(gpa);
        try testing.expectError(
            error.UnsupportedShardCount,
            Coder.init(gpa, 61440, 4096, 64, Scalar.init(), null),
        );
    }
}

test "work counts" {
    const HE = rate.HighRateEncoder(Scalar);
    const HD = rate.HighRateDecoder(Scalar);
    const LE = rate.LowRateEncoder(Scalar);
    const LD = rate.LowRateDecoder(Scalar);
    const Case = struct { usize, usize, usize };
    const cases = .{
        .{ HE, [_]Case{
            .{ 1, 1, 1 },
            .{ 4096, 1024, 4096 },
            .{ 4097, 1024, 5120 },
            .{ 4097, 1025, 6144 },
            .{ 32768, 32768, 32768 },
        } },
        .{ LE, [_]Case{
            .{ 1, 1, 1 },
            .{ 1024, 4096, 4096 },
            .{ 1024, 4097, 5120 },
            .{ 1025, 4097, 6144 },
            .{ 32768, 32768, 32768 },
        } },
        .{ HD, [_]Case{
            .{ 1, 1, 2 },
            .{ 2048, 1025, 4096 },
            .{ 2049, 1025, 8192 },
            .{ 3072, 1024, 4096 },
            .{ 3073, 1024, 8192 },
            .{ 32768, 32768, 65536 },
        } },
        .{ LD, [_]Case{
            .{ 1, 1, 2 },
            .{ 1024, 3072, 4096 },
            .{ 1024, 3073, 8192 },
            .{ 1025, 2048, 4096 },
            .{ 1025, 2049, 8192 },
            .{ 32768, 32768, 65536 },
        } },
    };
    inline for (cases) |case| {
        for (case[1]) |row| try testing.expectEqual(row[2], case[0].work_count(row[0], row[1]));
    }
}

/// `validate` accepts the largest whole-chunk shard size for `work_count` work shards and
/// rejects that size plus 2 bytes, which needs one more chunk per shard.
fn expect_capacity(comptime Coder: type, counts: [2]usize, work_count: usize) !void {
    const max = utils_package.MAX_ALLOCATION_BYTES;
    const shard_bytes = (max / SHARD_CHUNK_BYTES / work_count) * SHARD_CHUNK_BYTES;
    try Coder.validate(counts[0], counts[1], shard_bytes);
    try testing.expectError(
        error.InvalidShardSize,
        Coder.validate(counts[0], counts[1], shard_bytes + 2),
    );
}

test "working space capacity" {
    // (9, 3) and (3, 9) encode with 12 work shards and decode with 16.
    inline for (.{
        .{ rate.HighRate(Scalar), [2]usize{ 9, 3 } },
        .{ rate.LowRate(Scalar), [2]usize{ 3, 9 } },
        .{ rate.DefaultRate(Scalar), [2]usize{ 9, 3 } },
        .{ rate.DefaultRate(Scalar), [2]usize{ 3, 9 } },
    }) |case| {
        try expect_capacity(case[0].Encoder, case[1], 12);
        try expect_capacity(case[0].Decoder, case[1], 16);
    }
}

test "direct erasure evaluation matches the transform" {
    var rng = utils_package.rng.test_rng();
    const limit = rate.low.DIRECT_EVALUATION_LIMIT;
    // `chunk - 1` and `chunk` originals both pad to `chunk`, so the last two domains end one
    // short of and exactly at the limit.
    const quarter = limit / 4;
    const chunk = rate.next_power_of_two(quarter);
    const recovery = limit - chunk;
    const expected = try gpa.create([GF_ORDER]GfElement);
    defer gpa.destroy(expected);
    const cases = [_][2]usize{
        .{ 1, 1 },
        .{ 3, 5 },
        .{ 7, 13 },
        .{ quarter / 2, quarter },
        .{ chunk - 1, recovery - 1 },
        .{ chunk, recovery },
    };
    for (cases) |case| {
        const original_count, const recovery_count = case;
        const chunk_size = rate.next_power_of_two(original_count);
        const end = chunk_size + recovery_count;
        for (0..18) |pattern| {
            var received = try BitSet.initEmpty(gpa, rate.next_power_of_two(end));
            defer received.deinit(gpa);
            expected.* = @splat(1);
            @memset(expected[original_count..chunk_size], 0);
            for (0..end) |i| {
                if (i >= original_count and i < chunk_size) continue;
                // Include both extremes as well as mixed and surplus shard sets.
                if (pattern == 0 or (pattern > 1 and utils_package.rng.boolean(&rng))) {
                    received.set(i);
                    expected[i] = 0;
                }
            }
            engine.eval_poly(Scalar, expected, GF_ORDER);
            var actual: [limit]GfElement = @splat(0);
            rate.low.eval_direct(actual[0..end], original_count, &received);
            for (0..end) |i| {
                // Zero and GF_MODULUS represent the same logarithmic exponent.
                try testing.expectEqual(expected[i] % GF_MODULUS, actual[i] % GF_MODULUS);
            }
        }
    }
}

test "work and result reuse" {
    const D = rate.DefaultRate(Scalar);
    var encoder_work: ?rate.EncoderWork = null;
    var decoder_work: ?rate.DecoderWork = null;
    const phases = [_][3]usize{ .{ 3, 2, 66 }, .{ 2, 3, 34 }, .{ 5, 3, 130 }, .{ 4, 6, 2 } };
    for (phases, 0..) |phase, phase_index| {
        const original_count, const recovery_count, const shard_bytes = phase;
        var encoder = try D.Encoder.init(
            gpa,
            original_count,
            recovery_count,
            shard_bytes,
            .init(),
            encoder_work,
        );
        encoder_work = null;
        var decoder = try D.Decoder.init(
            gpa,
            original_count,
            recovery_count,
            shard_bytes,
            .init(),
            decoder_work,
        );
        decoder_work = null;
        for (0..2) |round| {
            const seed: u8 = @intCast(phase_index * 2 + round);
            try reuse_round(D, &encoder, &decoder, phase, seed, round == 0);
        }
        // Hand the next phase work with a shard still pending. Reuse must drop the stale
        // received state and keep the stale bytes out of its results.
        const pending = try gpa.alloc(u8, shard_bytes);
        defer gpa.free(pending);
        @memset(pending, 255);
        try encoder.add_original_shard(pending);
        try decoder.add_original_shard(0, pending);
        encoder_work = encoder.into_parts().work;
        decoder_work = decoder.into_parts().work;
    }
    encoder_work.?.deinit(gpa);
    decoder_work.?.deinit(gpa);
}

fn reuse_round(
    comptime D: type,
    encoder: *D.Encoder,
    decoder: *D.Decoder,
    phase: [3]usize,
    seed: u8,
    compute_recovery_first: bool,
) !void {
    const original_count, const recovery_count, const shard_bytes = phase;
    const original = try test_util.generate_original(gpa, original_count, shard_bytes, seed);
    defer test_util.free_original(gpa, original);
    var fresh = try D.Encoder.init(gpa, original_count, recovery_count, shard_bytes, .init(), null);
    defer fresh.deinit(gpa);
    for (original) |shard| {
        try encoder.add_original_shard(shard);
        try fresh.add_original_shard(shard);
    }
    var expected = try fresh.encode();
    defer expected.deinit();
    {
        var encoded = try encoder.encode();
        defer encoded.deinit();
        for (0..recovery_count) |i| {
            try testing.expectEqualSlices(u8, expected.recovery(i).?, encoded.recovery(i).?);
        }
        var iterator = encoded.recovery_iter();
        try testing.expectEqualSlices(u8, expected.recovery(0).?, iterator.next().?);
        try testing.expectEqual(recovery_count - 1, iterator.len());
    }
    try testing.expectError(error.TooFewOriginalShards, encoder.encode());

    for (original, 0..) |shard, i| try decoder.add_original_shard(i, shard);
    try testing.expect(try decoder.decode(compute_recovery_first) == null);
    try testing.expectError(error.NotEnoughShards, decoder.decode(false));
    for (original[2..], 2..) |shard, i| try decoder.add_original_shard(i, shard);
    for (0..2) |i| try decoder.add_recovery_shard(i, expected.recovery(i).?);
    {
        var decoded = (try decoder.decode(true)).?;
        defer decoded.deinit();
        var iterator = decoded.original_iter();
        const first = iterator.next().?;
        try testing.expectEqual(0, first.index);
        try testing.expectEqualSlices(u8, original[0], first.shard);
        try testing.expectEqual(1, iterator.len());
        try testing.expectEqualSlices(u8, original[1], decoded.original(1).?);
    }
    try testing.expectError(error.NotEnoughShards, decoder.decode(false));
}
