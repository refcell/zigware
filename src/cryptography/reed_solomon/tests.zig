//! Wrapper, result, and plan tests (commonware `reed_solomon/{mod,wrappers,encoder_result,
//! decoder_result,plan}.rs` tests).

const std = @import("std");
const testing = std.testing;
const utils_package = @import("utils");

const root = @import("root.zig");
const test_util = @import("test_util.zig");

const Encoder = root.Encoder;
const Decoder = root.Decoder;
const Plan = root.Plan;
const SHARD_CHUNK_BYTES = root.SHARD_CHUNK_BYTES;
const DIRECT_EVALUATION_LIMIT = root.rate.low.DIRECT_EVALUATION_LIMIT;
const gpa = testing.allocator;

/// Original shards plus their encoding, kept as owned copies.
const Codeword = struct {
    original: [][]u8,
    recovery: [][]u8,

    fn init(original_count: usize, recovery_count: usize, shard_bytes: usize, seed: u8) !Codeword {
        const original = try test_util.generate_original(gpa, original_count, shard_bytes, seed);
        errdefer test_util.free_original(gpa, original);
        var encoder = try Encoder.init(gpa, original_count, recovery_count, shard_bytes);
        defer encoder.deinit(gpa);
        for (original) |shard| try encoder.add_original_shard(shard);
        var encoded = try encoder.encode();
        defer encoded.deinit();
        const recovery = try gpa.alloc([]u8, recovery_count);
        var copied: usize = 0;
        errdefer {
            for (recovery[0..copied]) |shard| gpa.free(shard);
            gpa.free(recovery);
        }
        while (copied < recovery_count) : (copied += 1) {
            recovery[copied] = try gpa.dupe(u8, encoded.recovery(copied).?);
        }
        return .{ .original = original, .recovery = recovery };
    }

    fn deinit(codeword: Codeword) void {
        test_util.free_original(gpa, codeword.original);
        test_util.free_original(gpa, codeword.recovery);
    }
};

test "roundtrip" {
    const codeword = try Codeword.init(2, 3, 1024, 123);
    defer codeword.deinit();
    try test_util.expect_hash(@ptrCast(codeword.recovery), test_util.LOW_2_3);

    var decoder = try Decoder.init(gpa, 2, 3, 1024);
    defer decoder.deinit(gpa);
    try decoder.add_recovery_shard(0, codeword.recovery[0]);
    try decoder.add_recovery_shard(1, codeword.recovery[1]);
    var decoded = (try decoder.decode()).?;
    defer decoded.deinit();
    var restored = decoded.original_iter();
    for (0..2) |i| {
        const item = restored.next().?;
        try testing.expectEqual(i, item.index);
        try testing.expectEqualSlices(u8, codeword.original[i], item.shard);
    }
    try testing.expect(restored.next() == null);
}

test "basic usage" {
    const originals = [2][6]u8{ .{ 1, 2, 3, 4, 5, 6 }, .{ 7, 8, 9, 10, 11, 12 } };
    var encoder = try Encoder.init(gpa, 2, 1, 6);
    defer encoder.deinit(gpa);
    for (&originals) |*shard| try encoder.add_original_shard(shard);
    var encoded = try encoder.encode();
    defer encoded.deinit();

    var decoder = try Decoder.init(gpa, 2, 1, 6);
    defer decoder.deinit(gpa);
    try decoder.add_original_shard(0, &originals[0]);
    try decoder.add_recovery_shard(0, encoded.recovery(0).?);
    var decoded = (try decoder.decode()).?;
    defer decoded.deinit();
    try testing.expectEqualSlices(u8, &originals[1], decoded.original(1).?);
}

test "encoder result" {
    const original = try test_util.generate_original(gpa, 2, 1024, 123);
    defer test_util.free_original(gpa, original);
    var encoder = try Encoder.init(gpa, 2, 3, 1024);
    defer encoder.deinit(gpa);
    for (original) |shard| try encoder.add_original_shard(shard);
    var result = try encoder.encode();
    defer result.deinit();

    const all = [_][]const u8{ result.recovery(0).?, result.recovery(1).?, result.recovery(2).? };
    try testing.expect(result.recovery(3) == null);
    try test_util.expect_hash(&all, test_util.LOW_2_3);

    var iterator = result.recovery_iter();
    try testing.expectEqual(3, iterator.len());
    var collected: [3][]const u8 = undefined;
    for (&collected, 0..) |*shard, i| {
        shard.* = iterator.next().?;
        try testing.expectEqual(2 - i, iterator.len());
    }
    try testing.expect(iterator.next() == null);
    try testing.expectEqual(0, iterator.len());
    try test_util.expect_hash(&collected, test_util.LOW_2_3);
}

/// Encodes three originals into two recovery shards, decodes from original 1 and both
/// recovery shards, and checks the restored originals 0 and 2.
fn simple_roundtrip(shard_size: usize) !void {
    const codeword = try Codeword.init(3, 2, shard_size, 0);
    defer codeword.deinit();
    for (codeword.recovery) |shard| try testing.expectEqual(shard_size, shard.len);

    var decoder = try Decoder.init(gpa, 3, 2, shard_size);
    defer decoder.deinit(gpa);
    try decoder.add_original_shard(1, codeword.original[1]);
    try decoder.add_recovery_shard(0, codeword.recovery[0]);
    try decoder.add_recovery_shard(1, codeword.recovery[1]);
    var result = (try decoder.decode()).?;
    defer result.deinit();

    try testing.expectEqualSlices(u8, codeword.original[0], result.original(0).?);
    try testing.expect(result.original(1) == null);
    try testing.expectEqualSlices(u8, codeword.original[2], result.original(2).?);
    try testing.expect(result.original(3) == null);

    var iterator = result.original_iter();
    try testing.expectEqual(2, iterator.len());
    for ([_]usize{ 0, 2 }, 0..) |index, returned| {
        const item = iterator.next().?;
        try testing.expectEqual(index, item.index);
        try testing.expectEqualSlices(u8, codeword.original[index], item.shard);
        try testing.expectEqual(1 - returned, iterator.len());
    }
    try testing.expect(iterator.next() == null);
    try testing.expect(iterator.next() == null);
    try testing.expectEqual(0, iterator.len());
}

test "decoder result and shard sizes not divisible by the chunk size" {
    const sizes = [_]usize{ 1024, 2, 4, 6, 30, 32, 34, 62, SHARD_CHUNK_BYTES, 66, 126, 128, 130 };
    for (sizes) |shard_size| try simple_roundtrip(shard_size);
}

/// Decodes from originals `1..` plus recovery 1 and checks every reconstructed recovery shard
/// is byte-identical to the encoder's, including partial final chunks.
fn recovery_roundtrip(original_count: usize, recovery_count: usize, shard_size: usize) !void {
    const codeword = try Codeword.init(original_count, recovery_count, shard_size, 0);
    defer codeword.deinit();
    var decoder = try Decoder.init(gpa, original_count, recovery_count, shard_size);
    defer decoder.deinit(gpa);
    for (codeword.original[1..], 1..) |shard, i| try decoder.add_original_shard(i, shard);
    try decoder.add_recovery_shard(1, codeword.recovery[1]);
    var decoding = (try decoder.decode_with_recovery()).?;
    defer decoding.deinit();

    try testing.expectEqualSlices(u8, codeword.original[0], decoding.original(0).?);
    for (codeword.recovery, 0..) |shard, i| {
        if (i == 1) {
            try testing.expect(decoding.recovery(i) == null);
        } else {
            try testing.expectEqualSlices(u8, shard, decoding.recovery(i).?);
        }
    }
    var iterator = decoding.recovery_iter();
    for (0..recovery_count) |i| {
        if (i == 1) continue;
        const item = iterator.next().?;
        try testing.expectEqual(i, item.index);
        try testing.expectEqualSlices(u8, codeword.recovery[i], item.shard);
    }
    try testing.expect(iterator.next() == null);
}

test "recovery matches encoder" {
    // Shard sizes span the partial-final-chunk boundary.
    for ([_]usize{ 2, 34, 62, SHARD_CHUNK_BYTES, 66, 130, 1024 }) |shard_size| {
        // High rate selections.
        try recovery_roundtrip(3, 2, shard_size);
        try recovery_roundtrip(16, 4, shard_size);
        // Low rate selections, including the 250-shard k=83, m=167 shape coding uses.
        try recovery_roundtrip(4, 8, shard_size);
        try recovery_roundtrip(83, 167, shard_size);
    }
}

test "direct recovery matches encoder" {
    var rng = utils_package.rng.test_rng();
    // `quarter` originals pad to a chunk of `quarter.next_power_of_two()`, so the last two
    // cases end exactly at and one past DIRECT_EVALUATION_LIMIT.
    const quarter = DIRECT_EVALUATION_LIMIT / 4;
    const recovery = DIRECT_EVALUATION_LIMIT - root.rate.next_power_of_two(quarter);
    const cases = [_][2]usize{
        .{ 7, 13 },
        .{ 84, 166 },
        .{ quarter, recovery },
        .{ quarter, recovery + 1 },
    };
    for (cases) |case| {
        for ([_]usize{ 2, 66, 1024 }) |shard_size| {
            try direct_recovery_case(&rng, case[0], case[1], shard_size);
        }
    }
}

fn direct_recovery_case(
    rng: *utils_package.rng.TestRng,
    k: usize,
    m: usize,
    shard_size: usize,
) !void {
    const codeword = try Codeword.init(k, m, shard_size, 0);
    defer codeword.deinit();
    var decoder = try Decoder.init(gpa, k, m, shard_size);
    defer decoder.deinit(gpa);
    // Always omit original 0 so recovery runs, even with surplus shards.
    const indices = try gpa.alloc(usize, k + m - 1);
    defer gpa.free(indices);
    for (indices, 1..) |*value, i| value.* = i;
    var selected_set = try std.DynamicBitSetUnmanaged.initEmpty(gpa, k + m);
    defer selected_set.deinit(gpa);
    for ([_]usize{ k, k + 3, k + m - 1 }) |provided| {
        utils_package.rng.random(rng).shuffle(usize, indices);
        selected_set.unsetAll();
        for (indices[0..provided]) |i| {
            selected_set.set(i);
            if (i < k) {
                try decoder.add_original_shard(i, codeword.original[i]);
            } else {
                try decoder.add_recovery_shard(i - k, codeword.recovery[i - k]);
            }
        }
        var result = (try decoder.decode_with_recovery()).?;
        defer result.deinit();
        for (codeword.original, 0..) |shard, i| {
            if (!selected_set.isSet(i)) try testing.expectEqualSlices(
                u8,
                shard,
                result.original(i).?,
            );
        }
        for (codeword.recovery, 0..) |shard, i| {
            if (!selected_set.isSet(k + i)) {
                try testing.expectEqualSlices(u8, shard, result.recovery(i).?);
            }
        }
    }
}

test "decode returns null when every original is present" {
    for ([_][2]usize{ .{ 3, 2 }, .{ 4, 8 } }) |counts| {
        const original = try test_util.generate_original(gpa, counts[0], SHARD_CHUNK_BYTES, 0);
        defer test_util.free_original(gpa, original);
        var decoder = try Decoder.init(gpa, counts[0], counts[1], SHARD_CHUNK_BYTES);
        defer decoder.deinit(gpa);
        for (original, 0..) |shard, i| try decoder.add_original_shard(i, shard);
        try testing.expect(try decoder.decode() == null);
        for (original, 0..) |shard, i| try decoder.add_original_shard(i, shard);
        try testing.expect(try decoder.decode_with_recovery() == null);
    }
}

test "maximum decoder indices" {
    const max = std.math.maxInt(usize);
    for ([_][2]usize{ .{ 3, 2 }, .{ 2, 3 } }) |counts| {
        const original_count, const recovery_count = counts;
        const codeword = try Codeword.init(original_count, recovery_count, 2, 123);
        defer codeword.deinit();
        var decoder = try Decoder.init(gpa, original_count, recovery_count, 2);
        defer decoder.deinit(gpa);
        try testing.expectError(
            error.InvalidOriginalShardIndex,
            decoder.add_original_shard(max, &.{ 0, 0 }),
        );
        try testing.expectError(
            error.InvalidRecoveryShardIndex,
            decoder.add_recovery_shard(max, &.{ 0, 0 }),
        );
        for (codeword.original[1..], 1..) |shard, i| try decoder.add_original_shard(i, shard);
        try decoder.add_recovery_shard(0, codeword.recovery[0]);
        var decoded = (try decoder.decode_with_recovery()).?;
        defer decoded.deinit();
        try testing.expectEqualSlices(u8, codeword.original[0], decoded.original(0).?);
        try testing.expect(decoded.original(max) == null);
        try testing.expect(decoded.recovery(max) == null);
    }
}

test "unrepresentable working space" {
    const sizes = [_]usize{ std.math.maxInt(usize) - 1, @as(usize, 1) << (@bitSizeOf(usize) - 2) };
    for ([_][2]usize{ .{ 3, 2 }, .{ 2, 3 } }) |counts| {
        for (sizes) |shard_bytes| {
            try testing.expectError(
                error.InvalidShardSize,
                Encoder.init(gpa, counts[0], counts[1], shard_bytes),
            );
            try testing.expectError(
                error.InvalidShardSize,
                Decoder.init(gpa, counts[0], counts[1], shard_bytes),
            );
        }
    }
}

test "two rounds reset low to high" {
    var encoder = try Encoder.init(gpa, 2, 3, 1024);
    defer encoder.deinit(gpa);
    var decoder = try Decoder.init(gpa, 2, 3, 1024);
    defer decoder.deinit(gpa);
    try wrapper_roundtrip(&encoder, &decoder, 2, test_util.LOW_2_3, &.{}, &.{ 0, 1 }, 123);
    try encoder.reset(gpa, 3, 2, 1024);
    try decoder.reset(gpa, 3, 2, 1024);
    try wrapper_roundtrip(&encoder, &decoder, 3, test_util.HIGH_3_2, &.{1}, &.{ 0, 1 }, 132);
}

/// Encodes `original_count` 1024-byte originals, checks the recovery hash, decodes from the
/// given indices, and checks every original not given to the decoder.
fn wrapper_roundtrip(
    encoder: *Encoder,
    decoder: *Decoder,
    original_count: usize,
    recovery_hash: []const u8,
    decoder_original: []const usize,
    decoder_recovery: []const usize,
    seed: u8,
) !void {
    const original = try test_util.generate_original(gpa, original_count, 1024, seed);
    defer test_util.free_original(gpa, original);
    for (original) |shard| try encoder.add_original_shard(shard);
    var result = try encoder.encode();
    defer result.deinit();
    var recovery: [8][]const u8 = undefined;
    var recovery_count: usize = 0;
    var iterator = result.recovery_iter();
    while (iterator.next()) |shard| : (recovery_count += 1) recovery[recovery_count] = shard;
    try test_util.expect_hash(recovery[0..recovery_count], recovery_hash);

    for (decoder_original) |i| try decoder.add_original_shard(i, original[i]);
    for (decoder_recovery) |i| try decoder.add_recovery_shard(i, recovery[i]);
    var decoded = (try decoder.decode()).?;
    defer decoded.deinit();
    for (0..original_count) |i| {
        if (std.mem.indexOfScalar(usize, decoder_original, i) == null) {
            try testing.expectEqualSlices(u8, original[i], decoded.original(i).?);
        }
    }
}

test "failed encoder reset preserves state" {
    const original = try test_util.generate_original(gpa, 2, 1024, 123);
    defer test_util.free_original(gpa, original);
    var encoder = try Encoder.init(gpa, 2, 3, 1024);
    defer encoder.deinit(gpa);
    try encoder.add_original_shard(original[0]);
    for ([_][2]usize{ .{ 2, 3 }, .{ 3, 2 } }) |counts| {
        for ([_]usize{ 0, 3, std.math.maxInt(usize) - 1 }) |shard_bytes| {
            try testing.expectError(
                error.InvalidShardSize,
                encoder.reset(gpa, counts[0], counts[1], shard_bytes),
            );
        }
    }
    try encoder.add_original_shard(original[1]);
    var result = try encoder.encode();
    defer result.deinit();
    const recovery = [_][]const u8{
        result.recovery(0).?,
        result.recovery(1).?,
        result.recovery(2).?,
    };
    try test_util.expect_hash(&recovery, test_util.LOW_2_3);
}

test "failed decoder reset preserves state" {
    const codeword = try Codeword.init(2, 3, 1024, 123);
    defer codeword.deinit();
    var decoder = try Decoder.init(gpa, 2, 3, 1024);
    defer decoder.deinit(gpa);
    try decoder.add_recovery_shard(0, codeword.recovery[0]);
    for ([_][2]usize{ .{ 2, 3 }, .{ 3, 2 } }) |counts| {
        for ([_]usize{ 0, 3, std.math.maxInt(usize) - 1 }) |shard_bytes| {
            try testing.expectError(
                error.InvalidShardSize,
                decoder.reset(gpa, counts[0], counts[1], shard_bytes),
            );
        }
    }
    try decoder.add_recovery_shard(1, codeword.recovery[1]);
    var decoded = (try decoder.decode()).?;
    defer decoded.deinit();
    try testing.expectEqualSlices(u8, codeword.original[0], decoded.original(0).?);
    try testing.expectEqualSlices(u8, codeword.original[1], decoded.original(1).?);
}

test "supports" {
    try testing.expect(Encoder.supports(4096, 61440) and Encoder.supports(61440, 4096));
    try testing.expect(Decoder.supports(4096, 61440) and Decoder.supports(61440, 4096));
    try testing.expect(Encoder.supports(60_000, 4_000) and !Encoder.supports(60_000, 5_000));
}

test "plan rejects invalid received indices" {
    for ([_][2]usize{ .{ 3, 5 }, .{ 5, 3 } }) |counts| {
        const k, const m = counts;
        try testing.expectError(error.InvalidOriginalShardIndex, Plan.init(gpa, k, m, &.{k}, &.{}));
        try testing.expectError(error.InvalidRecoveryShardIndex, Plan.init(gpa, k, m, &.{}, &.{m}));
        try testing.expectError(
            error.DuplicateOriginalShardIndex,
            Plan.init(gpa, k, m, &.{ 0, 0 }, &.{}),
        );
        try testing.expectError(
            error.DuplicateRecoveryShardIndex,
            Plan.init(gpa, k, m, &.{}, &.{ 0, 0 }),
        );
        try testing.expectError(error.NotEnoughShards, Plan.init(gpa, k, m, &.{0}, &.{0}));
    }
}

test "plan example" {
    // Original 0 and recovery 0 arrive for both codewords; original 1 is missing.
    var plan = try Plan.init(gpa, 2, 1, &.{0}, &.{0});
    defer plan.deinit(gpa);
    const codewords = [2][2][]const u8{
        .{ &.{ 1, 2 }, &.{ 3, 4 } },
        .{ &.{ 5, 6, 7, 8 }, &.{ 9, 10, 11, 12 } },
    };
    for (codewords) |pair| {
        var encoder = try Encoder.init(gpa, 2, 1, pair[0].len);
        defer encoder.deinit(gpa);
        for (pair) |shard| try encoder.add_original_shard(shard);
        var encoded = try encoder.encode();
        defer encoded.deinit();
        var decoder = try Decoder.init(gpa, 2, 1, pair[0].len);
        defer decoder.deinit(gpa);
        try decoder.add_original_shard(0, pair[0]);
        try decoder.add_recovery_shard(0, encoded.recovery(0).?);
        var decoded = (try decoder.decode_with_plan(&plan)).?;
        defer decoded.deinit();
        try testing.expectEqualSlices(u8, pair[1], decoded.original(1).?);
    }
}

const Shape = struct { usize, usize, []const usize, []const usize };

test "decoders reject mismatched plans" {
    // Each case pairs a decoder's counts and received indices with a plan's.
    const cases = [_][2]Shape{
        // Only the recovery count differs, and both set the same work positions.
        .{ .{ 5, 1, &.{ 0, 1, 3, 4 }, &.{0} }, .{ 5, 3, &.{ 0, 1 }, &.{ 0, 1, 2 } } },
        .{ .{ 2, 4, &.{0}, &.{0} }, .{ 2, 3, &.{0}, &.{0} } },
        // Only the original count differs, and both set the same work positions.
        .{ .{ 4, 5, &.{ 0, 1 }, &.{ 0, 1 } }, .{ 3, 5, &.{ 0, 1 }, &.{ 0, 1 } } },
        .{ .{ 4, 2, &.{ 0, 1 }, &.{ 0, 1 } }, .{ 3, 2, &.{ 0, 1 }, &.{ 0, 1 } } },
        // The decoder received one more recovery shard than the plan names.
        .{ .{ 2, 4, &.{0}, &.{ 0, 1 } }, .{ 2, 4, &.{0}, &.{0} } },
        .{ .{ 5, 3, &.{ 0, 1, 2, 3 }, &.{ 0, 1 } }, .{ 5, 3, &.{ 0, 1, 2, 3 }, &.{0} } },
    };
    for (cases) |case| try mismatched_plan_case(case[0], case[1]);
}

fn mismatched_plan_case(shape: Shape, plan_shape: Shape) !void {
    const k, const m, const originals, const recoveries = shape;
    const codeword = try Codeword.init(k, m, 64, 0);
    defer codeword.deinit();
    var decoder = try Decoder.init(gpa, k, m, 64);
    defer decoder.deinit(gpa);
    for (originals) |i| try decoder.add_original_shard(i, codeword.original[i]);
    for (recoveries) |i| try decoder.add_recovery_shard(i, codeword.recovery[i]);

    var plan = try Plan.init(gpa, plan_shape[0], plan_shape[1], plan_shape[2], plan_shape[3]);
    defer plan.deinit(gpa);
    try testing.expectError(error.PlanMismatch, decoder.decode_with_plan(&plan));
    try testing.expectError(error.PlanMismatch, decoder.decode_with_recovery_plan(&plan));

    // The decoder's own plan still recovers the missing originals.
    var own = try Plan.init(gpa, k, m, originals, recoveries);
    defer own.deinit(gpa);
    var decoded = (try decoder.decode_with_plan(&own)).?;
    defer decoded.deinit();
    for (codeword.original, 0..) |shard, i| {
        if (std.mem.indexOfScalar(usize, originals, i) == null) {
            try testing.expectEqualSlices(u8, shard, decoded.original(i).?);
        }
    }
}
