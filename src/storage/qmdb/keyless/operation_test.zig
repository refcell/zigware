//! Tests for keyless operations (keyless/operation/{mod,fixed,variable}.rs) and their codec
//! conformance hashes.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const conformance = @import("conformance");
const utils = @import("utils");
const merkle = @import("../../merkle/mod.zig");
const value = @import("../value.zig");
const keyless = @import("operation.zig");
const support = @import("../test_support.zig");

const U64 = utils.sequence.U64;
const Mmr = merkle.mmr.Family;
const FixedOp = keyless.Operation(Mmr, value.Fixed(U64));
const VarOp = keyless.Operation(Mmr, value.Variable(U64));

fn u64v(n: u64) U64 {
    return U64.init(n);
}

fn roundtrip(comptime Op: type, op: Op) !void {
    const gpa = testing.allocator;
    const encoded = try codec.encode(Op, gpa, op);
    defer gpa.free(encoded);
    try testing.expectEqual(op.encode_size(), encoded.len);
    var decoded = try codec.decode_cfg(Op, gpa, encoded, codec.unit_cfg(Op.Cfg));
    defer decoded.deinit(gpa);
    try testing.expect(op.eql(decoded));
}

test "display append" {
    var buffer: [128]u8 = undefined;
    const text = try std.fmt.bufPrint(&buffer, "{f}", .{VarOp{ .append = u64v(12345) }});
    try testing.expectEqualStrings("[append value:0000000000003039]", text);
}

test "display commit some" {
    var buffer: [128]u8 = undefined;
    const op: VarOp = .{ .commit = .{ .metadata = u64v(42), .floor = 7 } };
    const text = try std.fmt.bufPrint(&buffer, "{f}", .{op});
    try testing.expectEqualStrings("[commit 000000000000002a floor:7]", text);
}

test "display commit none" {
    var buffer: [128]u8 = undefined;
    const op: VarOp = .{ .commit = .{ .metadata = null, .floor = 3 } };
    const text = try std.fmt.bufPrint(&buffer, "{f}", .{op});
    try testing.expectEqualStrings("[commit floor:3]", text);
}

test "fixed: all variants have same encoded size" {
    try testing.expectEqual(@as(?usize, 2 + 8 + 8), codec.fixed_size(FixedOp));
    const ops = [_]FixedOp{
        .{ .append = u64v(42) },
        .{ .commit = .{ .metadata = u64v(99), .floor = 5 } },
        .{ .commit = .{ .metadata = null, .floor = 0 } },
    };
    for (ops) |op| {
        const encoded = codec.encode_fixed(FixedOp, op);
        try testing.expectEqual(@as(usize, 18), encoded.len);
        try roundtrip(FixedOp, op);
    }
}

test "fixed: invalid context byte rejected" {
    var bytes: [18]u8 = @splat(0);
    bytes[0] = 0xFF;
    try testing.expectError(error.InvalidEnum, codec.decode_fixed(FixedOp, &bytes));
}

test "fixed: non-zero padding rejected" {
    var bytes = codec.encode_fixed(FixedOp, .{ .append = u64v(1) });
    bytes[bytes.len - 1] = 0x01;
    try testing.expectError(error.Invalid, codec.decode_fixed(FixedOp, &bytes));
}

test "fixed: truncated input rejected" {
    const bytes = codec.encode_fixed(FixedOp, .{ .append = u64v(1) });
    try testing.expectError(
        error.EndOfBuffer,
        codec.decode(FixedOp, testing.allocator, bytes[0 .. bytes.len - 1]),
    );
}

test "fixed: commit none has zero value bytes" {
    const bytes = codec.encode_fixed(FixedOp, .{ .commit = .{ .metadata = null, .floor = 0 } });
    for (bytes[2..]) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "fixed: commit floor overflow rejected" {
    var bytes: [18]u8 = @splat(0);
    bytes[0] = keyless.commit_context;
    std.mem.writeInt(u64, bytes[10..18], std.math.maxInt(u64), .big);
    try testing.expectError(error.Invalid, codec.decode_fixed(FixedOp, &bytes));
}

test "fixed: commit non-zero metadata bytes rejected" {
    var bytes: [18]u8 = @splat(0);
    bytes[0] = keyless.commit_context;
    bytes[2] = 0x01;
    try testing.expectError(error.Invalid, codec.decode_fixed(FixedOp, &bytes));
}

test "variable: roundtrips and encode_size" {
    const ops = [_]VarOp{
        .{ .append = u64v(0) },
        .{ .append = u64v(std.math.maxInt(u64)) },
        .{ .append = u64v(12345) },
        .{ .commit = .{ .metadata = null, .floor = 0 } },
        .{ .commit = .{ .metadata = null, .floor = 42 } },
        .{ .commit = .{ .metadata = u64v(999), .floor = 77 } },
        .{ .commit = .{ .metadata = u64v(42), .floor = 1234 } },
    };
    for (ops) |op| try roundtrip(VarOp, op);
}

test "variable: invalid context byte rejected" {
    const gpa = testing.allocator;
    const encoded = try codec.encode(VarOp, gpa, .{ .append = u64v(1) });
    defer gpa.free(encoded);
    encoded[0] = 0xFF;
    try testing.expectError(error.InvalidEnum, codec.decode(VarOp, gpa, encoded));
}

test "variable: empty input rejected" {
    try testing.expectError(error.EndOfBuffer, codec.decode(VarOp, testing.allocator, &.{}));
}

test "variable: append and commit encode differently, context byte first" {
    const gpa = testing.allocator;
    const append = try codec.encode(VarOp, gpa, .{ .append = u64v(1) });
    defer gpa.free(append);
    const commit_op: VarOp = .{ .commit = .{ .metadata = u64v(1), .floor = 0 } };
    const commit = try codec.encode(VarOp, gpa, commit_op);
    defer gpa.free(commit);
    try testing.expect(!std.mem.eql(u8, append, commit));
    try testing.expectEqual(keyless.append_context, append[0]);
    try testing.expectEqual(keyless.commit_context, commit[0]);
}

test "variable: commit floor overflow rejected" {
    var bytes: [16]u8 = undefined;
    var writer = codec.Writer.init(&bytes);
    writer.write_byte(keyless.commit_context);
    codec.write(?U64, null, &writer);
    codec.varint.write(u64, std.math.maxInt(u64), &writer);
    const decoded = codec.decode(VarOp, testing.allocator, writer.written());
    try testing.expectError(error.Invalid, decoded);
}

const prefix = "commonware_storage::qmdb::keyless::operation::tests::conformance::";

test "conformance CodecConformance<Operation<mmr::Family,FixedEncoding<U64>>>" {
    try support.verify_codec(FixedOp, prefix ++ "CodecConformance<Operation<mmr::Family," ++
        "FixedEncoding<U64>>>");
}

test "conformance CodecConformance<Operation<mmr::Family,VariableEncoding<U64>>>" {
    try support.verify_codec(VarOp, prefix ++ "CodecConformance<Operation<mmr::Family," ++
        "VariableEncoding<U64>>>");
}
