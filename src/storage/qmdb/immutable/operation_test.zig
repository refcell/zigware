//! Tests for immutable operations (immutable/operation/{mod,fixed,variable}.rs) and their
//! codec conformance hashes.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const utils = @import("utils");
const merkle = @import("../../merkle/mod.zig");
const value = @import("../value.zig");
const immutable = @import("operation.zig");
const support = @import("../test_support.zig");

const U64 = utils.sequence.U64;
const Mmr = merkle.mmr.Family;
const VarOp = immutable.Operation(Mmr, U64, value.Variable(U64));
const FixedOp = immutable.Operation(Mmr, U64, value.Fixed(U64));
const VarKeyOp = immutable.Operation(Mmr, []const u8, value.Variable(U64));

fn u64v(n: u64) U64 {
    return U64.init(n);
}

fn roundtrip(comptime Op: type, op: Op, cfg: Op.Cfg) !void {
    const gpa = testing.allocator;
    const encoded = try codec.encode(Op, gpa, op);
    defer gpa.free(encoded);
    try testing.expectEqual(op.encode_size(), encoded.len);
    var decoded = try codec.decode_cfg(Op, gpa, encoded, cfg);
    defer decoded.deinit(gpa);
    try testing.expect(op.eql(decoded));
}

test "operation key, is_commit, and inactivity floor" {
    const set: VarOp = .{ .set = .{ .key = u64v(1234), .value = u64v(56789) } };
    try testing.expect(set.key().?.eql(u64v(1234)));
    try testing.expect(!set.is_commit());
    try testing.expectEqual(@as(?u64, null), set.inactivity_floor());
    const commit: VarOp = .{ .commit = .{ .metadata = u64v(56789), .floor = 42 } };
    try testing.expectEqual(@as(?*const U64, null), commit.key());
    try testing.expect(commit.is_commit());
    try testing.expectEqual(@as(?u64, 42), commit.inactivity_floor());
    const commit_none: VarOp = .{ .commit = .{ .metadata = null, .floor = 0 } };
    try testing.expectEqual(@as(?*const U64, null), commit_none.key());
    try testing.expect(commit_none.is_commit());
    try testing.expectEqual(@as(?u64, 0), commit_none.inactivity_floor());
}

test "operation display" {
    var buffer: [128]u8 = undefined;
    const set: VarOp = .{ .set = .{ .key = u64v(1234), .value = u64v(56789) } };
    try testing.expectEqualStrings(
        "[key:00000000000004d2 value:000000000000ddd5]",
        try std.fmt.bufPrint(&buffer, "{f}", .{set}),
    );
    const commit: VarOp = .{ .commit = .{ .metadata = u64v(56789), .floor = 10 } };
    try testing.expectEqualStrings(
        "[commit 000000000000ddd5 floor:10]",
        try std.fmt.bufPrint(&buffer, "{f}", .{commit}),
    );
    const none: VarOp = .{ .commit = .{ .metadata = null, .floor = 0 } };
    const text = try std.fmt.bufPrint(&buffer, "{f}", .{none});
    try testing.expectEqualStrings("[commit floor:0]", text);
}

test "fixed: size, uniform encoding, roundtrip" {
    // Set: 1 + 8 + 8 = 17; commit: 1 + 1 + 8 + 8 = 18.
    try testing.expectEqual(@as(?usize, 18), codec.fixed_size(FixedOp));
    const ops = [_]FixedOp{
        .{ .set = .{ .key = u64v(1234), .value = u64v(56789) } },
        .{ .commit = .{ .metadata = u64v(42), .floor = 100 } },
        .{ .commit = .{ .metadata = null, .floor = 0 } },
    };
    for (ops) |op| {
        try testing.expectEqual(@as(usize, 18), codec.encode_fixed(FixedOp, op).len);
        try roundtrip(FixedOp, op, {});
    }
}

test "fixed: invalid context, insufficient buffer, non-zero padding" {
    var invalid: [18]u8 = @splat(0);
    invalid[0] = 0xFF;
    try testing.expectError(error.InvalidEnum, codec.decode_fixed(FixedOp, &invalid));
    try testing.expectError(
        error.EndOfBuffer,
        codec.decode(FixedOp, testing.allocator, &.{immutable.set_context}),
    );
    var encoded = codec.encode_fixed(FixedOp, .{ .set = .{ .key = u64v(1), .value = u64v(2) } });
    encoded[encoded.len - 1] = 0xFF;
    try testing.expectError(error.Invalid, codec.decode_fixed(FixedOp, &encoded));
}

test "variable: encode, decode, and encode_size" {
    const ops = [_]VarOp{
        .{ .set = .{ .key = u64v(1234), .value = u64v(56789) } },
        .{ .commit = .{ .metadata = u64v(56789), .floor = 100 } },
        .{ .commit = .{ .metadata = null, .floor = 0 } },
        .{ .set = .{ .key = u64v(100), .value = u64v(1000) } },
        .{ .commit = .{ .metadata = u64v(1000), .floor = 50 } },
    };
    for (ops) |op| try roundtrip(VarOp, op, .{ {}, {} });
    const set: VarOp = .{ .set = .{ .key = u64v(1234), .value = u64v(56789) } };
    try testing.expectEqual(@as(usize, 1 + 8 + 8), set.encode_size());
    const commit: VarOp = .{ .commit = .{ .metadata = u64v(1), .floor = 100 } };
    try testing.expectEqual(@as(usize, 1 + 9 + 1), commit.encode_size());
    const none: VarOp = .{ .commit = .{ .metadata = null, .floor = 0 } };
    try testing.expectEqual(@as(usize, 1 + 1 + 1), none.encode_size());
}

test "variable: invalid context and insufficient buffer" {
    const gpa = testing.allocator;
    const invalid = [_]u8{ 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    try testing.expectError(error.InvalidEnum, codec.decode(VarOp, gpa, &invalid));
    try testing.expectError(error.EndOfBuffer, codec.decode(VarOp, gpa, &.{immutable.set_context}));
    try testing.expectError(
        error.EndOfBuffer,
        codec.decode(VarOp, gpa, &.{immutable.commit_context}),
    );
}

test "variable: variable-length key roundtrip" {
    const cfg: VarKeyOp.Cfg = .{ .{ .range = .range(0, 101) }, {} };
    try roundtrip(VarKeyOp, .{ .set = .{ .key = &.{ 1, 2, 3, 4, 5 }, .value = u64v(42) } }, cfg);
    try roundtrip(VarKeyOp, .{ .commit = .{ .metadata = u64v(42), .floor = 10 } }, cfg);
    try roundtrip(VarKeyOp, .{ .set = .{ .key = &.{}, .value = u64v(99) } }, cfg);
}

test "conformance CodecConformance<FixedOp>" {
    try support.verify_codec(FixedOp, "commonware_storage::qmdb::immutable::operation::fixed::" ++
        "tests::conformance::CodecConformance<FixedOp>");
}

test "conformance CodecConformance<VarOp>" {
    try support.verify_codec(VarOp, "commonware_storage::qmdb::immutable::operation::" ++
        "variable::tests::conformance::CodecConformance<VarOp>");
}

test "conformance CodecConformance<VarKeyOp>" {
    try support.verify_codec(VarKeyOp, "commonware_storage::qmdb::immutable::operation::" ++
        "variable::tests::conformance::CodecConformance<VarKeyOp>");
}
