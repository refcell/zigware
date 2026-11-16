//! Tests for the sync wire types: commonware's `qmdb/sync/target.rs` tests, `Request` and
//! `Response` round trips and rejections, and the codec conformance hashes of `target.rs` and
//! `source.rs`.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const merkle = @import("../../merkle/mod.zig");
const operation = @import("../operation.zig");
const support = @import("../test_support.zig");
const sync = @import("mod.zig");

const gpa = testing.allocator;
const Mmr = merkle.mmr.Family;
const Mmb = merkle.mmb.Family;
const D = cryptography.Sha256.Digest;
const Target = sync.Target(Mmr, D);
const CompactTarget = sync.CompactTarget(Mmr, D);

fn target(root: D, start: u64, end: u64) Target {
    return Target.init(root, start, end);
}

test "target serialization" {
    const original = target(D.fill(42), 100, 500);
    const encoded = try codec.encode(Target, gpa, original);
    defer gpa.free(encoded);
    try testing.expectEqual(original.encode_size(), encoded.len);
    try testing.expect(original.eql(try codec.decode(Target, gpa, encoded)));
}

/// `root || start || end` with arbitrary bounds.
fn encode_raw(buffer: []u8, root: D, start: u64, end: u64) []const u8 {
    var writer = codec.Writer.init(buffer);
    codec.write(D, root, &writer);
    operation.write_location(start, &writer);
    operation.write_location(end, &writer);
    return buffer[0..writer.end];
}

test "target read rejects reversed and empty ranges" {
    var buffer: [64]u8 = undefined;
    for ([_][2]u64{ .{ 100, 50 }, .{ 100, 100 } }) |bounds| {
        const bytes = encode_raw(&buffer, D.fill(42), bounds[0], bounds[1]);
        var reader = codec.Reader.init(bytes);
        try testing.expectError(error.Invalid, Target.read(gpa, &reader, {}));
        try testing.expectEqualStrings("NonEmptyRange", reader.diagnostic.context);
        try testing.expectEqualStrings("start must be < end", reader.diagnostic.message);
    }
    // An end outside the location domain fails as a location.
    const bytes = encode_raw(&buffer, D.fill(42), 0, Mmr.max_leaves + 1);
    try testing.expectError(error.Invalid, codec.decode(Target, gpa, bytes));
}

test "target advances" {
    const current_root = D.fill(0);
    const advanced_root = D.fill(1);
    const current = target(current_root, 10, 100);
    // End strictly increases, start does not decrease.
    try testing.expect(target(advanced_root, 10, 101).advances(current));
    try testing.expect(target(advanced_root, 50, 200).advances(current));
    // Same or smaller end does not advance.
    try testing.expect(!target(current_root, 10, 100).advances(current));
    try testing.expect(!target(current_root, 10, 50).advances(current));
    // A start moving backward does not advance, even with a larger end.
    try testing.expect(!target(advanced_root, 5, 200).advances(current));
    // An end outside the location domain does not advance.
    try testing.expect(!target(advanced_root, 10, Mmr.max_leaves + 1).advances(current));
}

test "compact target serialization and rejections" {
    const original: CompactTarget = .{ .root = D.fill(42), .size = 100 };
    const encoded = try codec.encode(CompactTarget, gpa, original);
    defer gpa.free(encoded);
    try testing.expectEqual(original.encode_size(), encoded.len);
    try testing.expect(original.eql(try codec.decode(CompactTarget, gpa, encoded)));
    for ([_]u64{ 0, Mmr.max_leaves + 1 }) |size| {
        const invalid: CompactTarget = .{ .root = D.fill(42), .size = size };
        const bytes = try codec.encode(CompactTarget, gpa, invalid);
        defer gpa.free(bytes);
        try testing.expectError(error.Invalid, codec.decode(CompactTarget, gpa, bytes));
    }
}

test "compact target to ranged" {
    const root = D.fill(42);
    // The derived range replays the one operation ending at the target.
    const ranged = try (CompactTarget{ .root = root, .size = 100 }).to_target();
    try testing.expect(ranged.root.eql(root));
    try testing.expectEqual(99, ranged.start);
    try testing.expectEqual(100, ranged.end);
    const genesis = try (CompactTarget{ .root = root, .size = 1 }).to_target();
    try testing.expectEqual(0, genesis.start);
    try testing.expectEqual(1, genesis.end);
    // A zero size has no operation to replay; a size beyond the domain is rejected.
    for ([_]u64{ 0, Mmr.max_leaves + 1 }) |size| {
        const compact: CompactTarget = .{ .root = root, .size = size };
        try testing.expectError(error.InvalidTarget, compact.to_target());
    }
}

const Request = sync.Request(Mmr);

test "request accessors, order, and round trips" {
    const operations: Request = .{ .operations = .{ .size = 10, .start = 3, .max_ops = 5 } };
    const boundary: Request = .{ .boundary = .{ .size = 10, .start = 3 } };
    try testing.expectEqual(5, operations.max_ops());
    try testing.expectEqual(1, boundary.max_ops());
    try testing.expectEqual(3, boundary.start());
    try testing.expectEqual(10, boundary.size());
    // Ordered by (size, start, max_ops, is_boundary).
    try testing.expectEqual(.gt, Request.order(operations, boundary));
    const single: Request = .{ .operations = .{ .size = 10, .start = 3, .max_ops = 1 } };
    try testing.expectEqual(.lt, Request.order(single, boundary));
    try testing.expect(!single.eql(boundary));
    for ([_]Request{ operations, boundary }) |request| {
        const encoded = try codec.encode(Request, gpa, request);
        defer gpa.free(encoded);
        try testing.expectEqual(request.encode_size(), encoded.len);
        try testing.expect(encoded.len <= Request.max_encode_size);
        try testing.expect(request.eql(try codec.decode(Request, gpa, encoded)));
    }
    var text: [64]u8 = undefined;
    const printed = try std.fmt.bufPrint(&text, "{f}", .{operations});
    try testing.expectEqualStrings("Operations(size=10, start=3, max=5)", printed);
}

test "request read rejects start at size, zero max_ops, and unknown tags" {
    var buffer: [32]u8 = undefined;
    var writer = codec.Writer.init(&buffer);
    writer.write_byte(1);
    operation.write_location(5, &writer);
    operation.write_location(5, &writer);
    try testing.expectError(error.Invalid, codec.decode(Request, gpa, buffer[0..writer.end]));
    writer = codec.Writer.init(&buffer);
    writer.write_byte(0);
    operation.write_location(5, &writer);
    operation.write_location(1, &writer);
    writer.write_int(u64, 0);
    try testing.expectError(error.Invalid, codec.decode(Request, gpa, buffer[0..writer.end]));
    try testing.expectError(error.InvalidEnum, codec.decode(Request, gpa, &.{ 2, 5, 1 }));
}

const Response = sync.Response(Mmr, u64, D);

test "response round trips and bounds its lengths by the request" {
    var digests = [_]D{ D.fill(1), D.fill(2) };
    var items = [_]u64{ 7, 8, 9 };
    var pinned = [_]D{D.fill(3)};
    const proof: Response.Proof = .{ .leaves = 12, .inactive_peaks = 1, .digests = &digests };
    const responses = [_]Response{
        .{ .operations = .{ .proof = proof, .operations = &items } },
        .{ .boundary = .{ .proof = proof, .op = 11, .pinned_nodes = &pinned } },
    };
    for (responses) |response| {
        const encoded = try codec.encode(Response, gpa, response);
        defer gpa.free(encoded);
        try testing.expectEqual(response.encode_size(), encoded.len);
        try testing.expect(encoded.len <= sync.max_response_size(Mmr, D, 3, 8));
        var decoded = try codec.decode_cfg(Response, gpa, encoded, .{ .max_ops = 3, .op = {} });
        defer decoded.deinit(gpa);
        try testing.expect(decoded.proof().eql(&proof));
        const again = try codec.encode(Response, gpa, decoded);
        defer gpa.free(again);
        try testing.expectEqualSlices(u8, encoded, again);
    }
    // More operations than requested are refused.
    const encoded = try codec.encode(Response, gpa, responses[0]);
    defer gpa.free(encoded);
    const short: Response.Cfg = .{ .max_ops = 2, .op = {} };
    try testing.expectError(error.InvalidLength, codec.decode_cfg(Response, gpa, encoded, short));
}

const target_prefix = "commonware_storage::qmdb::sync::target::tests::conformance::";
const source_prefix = "commonware_storage::qmdb::sync::source::conformance::";

test "conformance CodecConformance<Target>" {
    try support.verify_codec(Target, target_prefix ++
        "CodecConformance<Target<MmrFamily,sha256::Digest>>");
    try support.verify_codec(sync.Target(Mmb, D), target_prefix ++
        "CodecConformance<Target<mmb::Family,sha256::Digest>>");
}

test "conformance CodecConformance<CompactTarget>" {
    try support.verify_codec(CompactTarget, target_prefix ++
        "CodecConformance<CompactTarget<MmrFamily,sha256::Digest>>");
    try support.verify_codec(sync.CompactTarget(Mmb, D), target_prefix ++
        "CodecConformance<CompactTarget<mmb::Family,sha256::Digest>>");
}

test "conformance CodecConformance<Request>" {
    try support.verify_codec(Request, source_prefix ++ "CodecConformance<Request<mmr::Family>>");
    try support.verify_codec(sync.Request(Mmb), source_prefix ++
        "CodecConformance<Request<mmb::Family>>");
}

test "conformance CodecConformance<Response>" {
    try support.verify_codec(Response, source_prefix ++
        "CodecConformance<Response<mmr::Family,u64,Sha256Digest>>");
    try support.verify_codec(sync.Response(Mmb, u64, D), source_prefix ++
        "CodecConformance<Response<mmb::Family,u64,Sha256Digest>>");
}
