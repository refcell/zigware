//! Tests for `any` operations and updates (any/operation/{mod,update/mod}.rs) and their codec
//! conformance hashes.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const utils = @import("utils");
const merkle = @import("../../merkle/mod.zig");
const value = @import("../value.zig");
const any = @import("operation.zig");
const support = @import("../test_support.zig");

const U64 = utils.sequence.U64;
const K4 = utils.sequence.FixedBytes(4);
const K8 = utils.sequence.FixedBytes(8);
const Mmr = merkle.mmr.Family;
const Mmb = merkle.mmb.Family;
const Bytes = []const u8;

fn k4(bytes: [4]u8) K4 {
    return K4.init(bytes);
}

fn roundtrip(comptime T: type, item: T, cfg: codec.Cfg(T)) !void {
    const gpa = testing.allocator;
    const encoded = try codec.encode(T, gpa, item);
    defer gpa.free(encoded);
    try testing.expectEqual(codec.encode_size(T, item), encoded.len);
    var decoded = try codec.decode_cfg(T, gpa, encoded, cfg);
    defer decoded.deinit(gpa);
    try testing.expect(item.eql(decoded));
    const again = try codec.encode(T, gpa, decoded);
    defer gpa.free(again);
    try testing.expectEqualSlices(u8, encoded, again);
}

const bytes_cfg: codec.Cfg(Bytes) = .{ .range = .full() };

test "ordered fixed roundtrip" {
    const Op = any.Ordered(Mmr, K4, value.Fixed(u64));
    try roundtrip(Op, .{ .delete = k4(.{ 1, 2, 3, 4 }) }, {});
    try roundtrip(Op, .{ .update = .{
        .key = k4(.{ 4, 3, 2, 1 }),
        .value = 0xdead_beef,
        .next_key = k4(.{ 9, 9, 9, 9 }),
    } }, {});
    try roundtrip(Op, .{ .commit = .{ .metadata = 123, .floor = 5 } }, {});
    try roundtrip(Op, .{ .commit = .{ .metadata = null, .floor = 7 } }, {});
}

test "unordered fixed roundtrip" {
    const Op = any.Unordered(Mmr, K4, value.Fixed(u64));
    try roundtrip(Op, .{ .delete = k4(.{ 0, 0, 0, 1 }) }, {});
    try roundtrip(Op, .{ .update = .{ .key = k4(.{ 9, 8, 7, 6 }), .value = 77 } }, {});
    try roundtrip(Op, .{ .commit = .{ .metadata = 555, .floor = 3 } }, {});
}

test "commit display" {
    const Op = any.Unordered(Mmr, K4, value.Fixed(u64));
    var buffer: [128]u8 = undefined;
    const some: Op = .{ .commit = .{ .metadata = 555, .floor = 3 } };
    try testing.expectEqualStrings(
        "[commit 000000000000022b floor:3]",
        try std.fmt.bufPrint(&buffer, "{f}", .{some}),
    );
    const none: Op = .{ .commit = .{ .metadata = null, .floor = 7 } };
    const text = try std.fmt.bufPrint(&buffer, "{f}", .{none});
    try testing.expectEqualStrings("[commit floor:7]", text);
}

test "update and delete display" {
    const Op = any.Ordered(Mmr, K4, value.Fixed(u64));
    var buffer: [128]u8 = undefined;
    const upd: Op = .{ .update = .{
        .key = k4(.{ 1, 2, 3, 4 }),
        .value = 1,
        .next_key = k4(.{ 5, 6, 7, 8 }),
    } };
    try testing.expectEqualStrings(
        "[key:01020304 next_key:05060708 value:0000000000000001]",
        try std.fmt.bufPrint(&buffer, "{f}", .{upd}),
    );
    const del: Op = .{ .delete = k4(.{ 0xa, 0xb, 0xc, 0xd }) };
    try testing.expectEqualStrings(
        "[key:0a0b0c0d <deleted>]",
        try std.fmt.bufPrint(&buffer, "{f}", .{del}),
    );
}

test "fixed commit non-zero trailing padding rejected" {
    const Op = any.Ordered(Mmr, K8, value.Fixed(u64));
    // With 8-byte keys the update variant is the largest, so commit records carry trailing
    // padding beyond the commit payload.
    var encoded = codec.encode_fixed(Op, .{ .commit = .{ .metadata = null, .floor = 7 } });
    try testing.expect(encoded.len > 1 + 1 + 8 + 8);
    encoded[encoded.len - 1] = 0x01;
    try testing.expectError(error.Invalid, codec.decode_fixed(Op, &encoded));
}

test "fixed operation sizes" {
    // Ordered: update 1 + 4 + 8 + 4 = 17, commit 18, delete 5.
    const size = codec.fixed_size;
    try testing.expectEqual(@as(?usize, 18), size(any.Ordered(Mmr, K4, value.Fixed(u64))));
    // Ordered with 8-byte keys: update 1 + 8 + 8 + 8 = 25.
    try testing.expectEqual(@as(?usize, 25), size(any.Ordered(Mmr, K8, value.Fixed(u64))));
    try testing.expectEqual(@as(?usize, 18), size(any.Unordered(Mmr, K8, value.Fixed(u64))));
}

test "fixed invalid context rejected" {
    const Op = any.Unordered(Mmr, K4, value.Fixed(u64));
    var bytes: [18]u8 = @splat(0);
    bytes[0] = 0xD4;
    try testing.expectError(error.InvalidEnum, codec.decode_fixed(Op, &bytes));
}

test "ordered variable roundtrip" {
    const Op = any.Ordered(Mmr, K4, value.Variable(Bytes));
    const cfg: Op.Cfg = .{ {}, bytes_cfg };
    try roundtrip(Op, .{ .delete = k4(.{ 1, 1, 1, 1 }) }, cfg);
    try roundtrip(Op, .{ .update = .{
        .key = k4(.{ 2, 2, 2, 2 }),
        .value = &.{ 1, 2, 3, 4, 5 },
        .next_key = k4(.{ 3, 3, 3, 3 }),
    } }, cfg);
    try roundtrip(Op, .{ .commit = .{ .metadata = &.{ 9, 9, 9 }, .floor = 9 } }, cfg);
    try roundtrip(Op, .{ .commit = .{ .metadata = null, .floor = 10 } }, cfg);
}

test "unordered variable roundtrip" {
    const Op = any.Unordered(Mmr, K4, value.Variable(Bytes));
    const cfg: Op.Cfg = .{ {}, bytes_cfg };
    try roundtrip(Op, .{ .delete = k4(.{ 4, 4, 4, 4 }) }, cfg);
    const upd: Op = .{ .update = .{ .key = k4(.{ 5, 5, 5, 5 }), .value = &.{ 7, 7, 7, 7 } } };
    try roundtrip(Op, upd, cfg);
    try roundtrip(Op, .{ .commit = .{ .metadata = &.{ 8, 8 }, .floor = 12 } }, cfg);
}

test "update roundtrips" {
    const OrderedFixed = any.update.Ordered(K4, value.Fixed(u64));
    try roundtrip(OrderedFixed, .{
        .key = k4(.{ 1, 2, 3, 4 }),
        .value = 0xdead_beef,
        .next_key = k4(.{ 4, 3, 2, 1 }),
    }, {});
    const OrderedVariable = any.update.Ordered(K4, value.Variable(Bytes));
    try roundtrip(OrderedVariable, .{
        .key = k4(.{ 1, 2, 3, 4 }),
        .value = &.{ 1, 2, 3, 4, 5 },
        .next_key = k4(.{ 4, 3, 2, 1 }),
    }, .{ {}, bytes_cfg });
    const UnorderedFixed = any.update.Unordered(K4, value.Fixed(u64));
    try roundtrip(UnorderedFixed, .{ .key = k4(.{ 7, 7, 7, 7 }), .value = 42 }, {});
    const UnorderedVariable = any.update.Unordered(K4, value.Variable(Bytes));
    try roundtrip(UnorderedVariable, .{
        .key = k4(.{ 0, 1, 2, 3 }),
        .value = &.{ 10, 11, 12, 13 },
    }, .{ {}, bytes_cfg });
}

const operation_prefix = "commonware_storage::qmdb::any::operation::tests::conformance::";
const update_prefix = "commonware_storage::qmdb::any::operation::update::tests::conformance::";

fn verify_operation(comptime F: type, comptime ordered: bool, comptime fixed: bool) !void {
    const E = if (fixed) value.Fixed(U64) else value.Variable(Bytes);
    const Op = if (ordered) any.Ordered(F, U64, E) else any.Unordered(F, U64, E);
    const kind = if (ordered) "OrderedOperation<" else "UnorderedOperation<";
    const family = if (F == Mmr) "mmr" else "mmb";
    // commonware's conformance file wraps these names at column 132 with a newline.
    const name = comptime switch (@as(u2, @intFromBool(ordered)) * 2 + @intFromBool(fixed)) {
        0 => kind ++ family ++ "::Family,U64,VariableEncoding<\nVec<u8>>>>",
        1 => kind ++ family ++ "::Family,U64,FixedEncoding<\nU64>>>",
        2 => kind ++ family ++ "::Family,U64,VariableEncoding<\nVec<u8>>>>",
        3 => kind ++ family ++ "::Family,U64,FixedEncoding<U64\n>>>",
    };
    try support.verify_codec(Op, operation_prefix ++ "CodecConformance<" ++ name);
}

test "conformance CodecConformance<OrderedOperation<..>>" {
    try verify_operation(Mmr, true, true);
    try verify_operation(Mmr, true, false);
    try verify_operation(Mmb, true, true);
    try verify_operation(Mmb, true, false);
}

test "conformance CodecConformance<UnorderedOperation<..>>" {
    try verify_operation(Mmr, false, true);
    try verify_operation(Mmr, false, false);
    try verify_operation(Mmb, false, true);
    try verify_operation(Mmb, false, false);
}

test "conformance CodecConformance<OrderedUpdate<..>> and <UnorderedUpdate<..>>" {
    try support.verify_codec(
        any.update.Ordered(U64, value.Fixed(U64)),
        update_prefix ++ "CodecConformance<OrderedUpdate<U64,FixedEncoding<U64>>>",
    );
    try support.verify_codec(
        any.update.Ordered(U64, value.Variable(Bytes)),
        update_prefix ++ "CodecConformance<OrderedUpdate<U64,VariableEncoding<Vec<u8>>>>",
    );
    try support.verify_codec(
        any.update.Unordered(U64, value.Fixed(U64)),
        update_prefix ++ "CodecConformance<UnorderedUpdate<U64,FixedEncoding<U64>>>",
    );
    try support.verify_codec(
        any.update.Unordered(U64, value.Variable(Bytes)),
        update_prefix ++ "CodecConformance<UnorderedUpdate<U64,VariableEncoding<Vec<u8>>>>",
    );
}
