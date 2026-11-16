//! commonware `glue/src/stateful/db/p2p/limits.rs` tests: the payload bound equals the widest
//! encodings a peer decodes, over unordered fixed operations of SHA-256 keys and values.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const resolver = @import("resolver");
const storage = @import("storage");
const limits = @import("limits.zig");

const gpa = testing.allocator;
const qmdb = storage.qmdb;
const merkle = storage.merkle;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const Family = storage.mmr.Family;
const Op = qmdb.any.operation.Unordered(Family, Digest, qmdb.value.Fixed(Digest));
const Response = qmdb.sync.Response(Family, Op, Digest);
const Request = qmdb.sync.Request(Family);
const max_digests = merkle.proof.max_proof_digests_per_element;
const max_location_size = codec.varint.max_size(u64);
const max_length_size = codec.varint.max_u32_varint_size;

fn varint_size(value: u64) usize {
    return codec.varint.size(u64, value);
}

/// Every proof takes the largest leaf count and inactive peak count the codec decodes.
fn widest_proof(digests: []Digest) Response.Proof {
    return .{
        .leaves = Family.max_leaves,
        .inactive_peaks = std.math.maxInt(usize),
        .digests = digests,
    };
}

/// Encodes `response`, checks it decodes for `max_ops`, and returns its length.
fn encoded_length(response: Response, max_ops: usize) !usize {
    const encoded = try codec.encode(Response, gpa, response);
    defer gpa.free(encoded);
    var decoded = try codec.decode_cfg(Response, gpa, encoded, .{ .max_ops = max_ops, .op = {} });
    decoded.deinit(gpa);
    return encoded.len;
}

test "stateful p2p limits: the payload bound is the widest encodings" {
    const digest = Sha256.hash(&.{"digest"});
    const location_slack = max_location_size - varint_size(Family.max_leaves);
    for ([_]usize{ 1, 2, 16 }) |max_ops| {
        // The widest operations response carries `max_ops` operations and the most proof
        // digests a peer decodes for them. The widest boundary response carries the widest
        // single-operation proof and the most pinned nodes.
        const proof_digests = try gpa.alloc(Digest, max_ops * max_digests);
        defer gpa.free(proof_digests);
        @memset(proof_digests, digest);
        const operations = try gpa.alloc(Op, max_ops);
        defer gpa.free(operations);
        @memset(operations, .{ .delete = digest });
        const operations_length = try encoded_length(.{ .operations = .{
            .proof = widest_proof(proof_digests),
            .operations = operations,
        } }, max_ops);
        var pinned: [merkle.max_pinned_nodes]Digest = @splat(digest);
        const boundary_length = try encoded_length(.{ .boundary = .{
            .proof = widest_proof(proof_digests[0..max_digests]),
            .op = .{ .delete = digest },
            .pinned_nodes = &pinned,
        } }, max_ops);

        // Each response falls short of its bound by the unused width of its proof's leaf
        // count and two length prefixes.
        const operations_slack = location_slack + 2 * max_length_size -
            varint_size(max_ops * max_digests) - varint_size(max_ops);
        const boundary_slack = location_slack + 2 * max_length_size -
            varint_size(max_digests) - varint_size(merkle.max_pinned_nodes);
        const bound = try limits.max_payload_size(Family, Digest, max_ops, Op.fixed_size.?);
        const widest = @max(operations_length + operations_slack, boundary_length + boundary_slack);
        try testing.expectEqual(widest + resolver.p2p.wire.response_overhead_max, bound);

        // The widest request falls short of its bound by the unused width of its two
        // locations, and stays smaller than the payload bound.
        const size: u64 = Family.max_leaves;
        const request: Request = .{ .operations = .{
            .size = size,
            .start = size - 1,
            .max_ops = std.math.maxInt(u64),
        } };
        const encoded = try codec.encode(Request, gpa, request);
        defer gpa.free(encoded);
        const request_slack = (max_location_size - varint_size(size)) +
            (max_location_size - varint_size(size - 1));
        try testing.expectEqual(Request.max_encode_size, encoded.len + request_slack);
        try testing.expect(encoded.len + resolver.p2p.wire.request_overhead < bound);
    }
}

test "stateful p2p limits: too many operations per request" {
    const too_many: u64 = 1 << 32;
    const op = Op.fixed_size.?;
    try testing.expectError(
        error.TooManyOperations,
        limits.max_payload_size(Family, Digest, too_many, op),
    );
}
