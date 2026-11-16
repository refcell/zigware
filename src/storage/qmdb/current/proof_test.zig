//! Tests for current's proof codecs: commonware's `qmdb/current/proof` codec tests and the
//! codec conformance hashes of `current/proof`, `current/ordered`, and `current/unordered`.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const utils = @import("utils");
const merkle = @import("../../merkle/mod.zig");
const value = @import("../value.zig");
const support = @import("../test_support.zig");
const current = @import("mod.zig");

const gpa = testing.allocator;
const Sha256 = cryptography.Sha256;
const D = Sha256.Digest;
const Mmr = merkle.mmr.Family;
const Mmb = merkle.mmb.Family;
const U64 = utils.sequence.U64;
const proof = current.proof;

fn hash(data: []const u8) D {
    return Sha256.hash(&.{data});
}

fn roundtrip(comptime T: type, item: T, cfg: codec.Cfg(T)) !void {
    const encoded = try codec.encode(T, gpa, item);
    defer gpa.free(encoded);
    try testing.expectEqual(item.encode_size(), encoded.len);
    var decoded = try codec.decode_cfg(T, gpa, encoded, cfg);
    defer if (comptime @hasDecl(T, "deinit")) decoded.deinit(gpa);
    try testing.expect(item.eql(decoded));
}

test "ops root witness codec roundtrip" {
    const Witness = proof.OpsRootWitness(Mmb, D);
    const partials = [_]?Witness.Partial{
        null,
        .{ .next_bit = 0, .digest = hash("partial-zero") },
        .{ .next_bit = 123, .digest = hash("partial-nonzero") },
    };
    for (partials) |partial| {
        const witness: Witness = .{
            .grafted_root = hash("grafted"),
            .pending_chunk_digest = null,
            .partial_chunk = partial,
        };
        try roundtrip(Witness, witness, {});
    }
}

test "ops root witness root matches verify" {
    const Witness = proof.OpsRootWitness(Mmb, D);
    const ops_root = hash("ops root");
    const witness: Witness = .{
        .grafted_root = hash("grafted root"),
        .pending_chunk_digest = hash("pending chunk"),
        .partial_chunk = .{ .next_bit = 13, .digest = hash("partial chunk") },
    };
    const root = witness.root(Sha256, &ops_root);
    try testing.expect(witness.verify(Sha256, &ops_root, &root));
    try testing.expect(!root.eql(ops_root));
    const wrong_ops_root = hash("wrong ops root");
    try testing.expect(!witness.verify(Sha256, &wrong_ops_root, &root));
}

test "combine roots" {
    const ops = hash("ops");
    const grafted = hash("grafted");
    const partial_digest = hash("partial");
    const plain = proof.combine_roots(Sha256, &ops, &grafted, null, null);
    try testing.expect(plain.eql(proof.combine_roots(Sha256, &ops, &grafted, null, null)));
    // The layout is `ops || grafted [|| pending] [|| next_bit_be || partial]`.
    try testing.expect(plain.eql(Sha256.hash(&.{ ops.as_slice(), grafted.as_slice() })));
    const with = proof.combine_roots(Sha256, &ops, &grafted, null, .{
        .next_bit = 5,
        .digest = partial_digest,
    });
    try testing.expect(!with.eql(plain));
    const next_bit = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 5 };
    const parts = [_][]const u8{
        ops.as_slice(),
        grafted.as_slice(),
        &next_bit,
        partial_digest.as_slice(),
    };
    try testing.expect(with.eql(Sha256.hash(&parts)));
}

fn digests(comptime labels: []const []const u8) ![]D {
    const result = try gpa.alloc(D, labels.len);
    inline for (labels, result) |label, *digest| digest.* = hash(label);
    return result;
}

const MmbRange = proof.RangeProof(Mmb, D);

fn mmb_range(proof_digests: []D, pending: ?D, partial: ?D) MmbRange {
    return .{
        .proof = .{ .leaves = 42, .inactive_peaks = 0, .digests = proof_digests },
        .pending_chunk_digest = pending,
        .partial_chunk_digest = partial,
        .ops_root = hash("ops-root"),
    };
}

test "range proof codec roundtrip" {
    const three = try digests(&.{ "d0", "d1", "d2" });
    defer gpa.free(three);
    const cases = [_]MmbRange{
        // Minimal: no optional fields.
        mmb_range(three, null, null),
        // All optional fields populated.
        mmb_range(three, hash("pending"), hash("partial")),
        // A default proof with only the partial chunk digest.
        .{
            .proof = .{},
            .pending_chunk_digest = null,
            .partial_chunk_digest = hash("only-partial"),
            .ops_root = hash("ops-root"),
        },
    };
    for (cases) |case| try roundtrip(MmbRange, case, 64);
}

test "range proof codec enforces merkle digest budget" {
    const one = try digests(&.{"d0"});
    defer gpa.free(one);
    const range = mmb_range(one, null, null);
    const encoded = try codec.encode(MmbRange, gpa, range);
    defer gpa.free(encoded);
    var decoded = try codec.decode_cfg(MmbRange, gpa, encoded, 1);
    defer decoded.deinit(gpa);
    try testing.expect(range.eql(decoded));
    try testing.expectError(error.InvalidLength, codec.decode_cfg(MmbRange, gpa, encoded, 0));
}

test "range proof decode rejects pending for mmr" {
    const one = try digests(&.{"d0"});
    defer gpa.free(one);
    const range = mmb_range(one, hash("pending"), null);
    const encoded = try codec.encode(MmbRange, gpa, range);
    defer gpa.free(encoded);
    // MMB allows the pending chunk digest.
    var decoded = try codec.decode_cfg(MmbRange, gpa, encoded, 64);
    decoded.deinit(gpa);
    // MMR has no pending slot, so the bytes do not decode.
    const MmrRange = proof.RangeProof(Mmr, D);
    try testing.expect(std.meta.isError(codec.decode_cfg(MmrRange, gpa, encoded, 64)));
    try testing.expectError(error.Invalid, proof.pending_from(Mmr, D, hash("pending")));
    try proof.pending_from(Mmr, D, null);
}

const Constant32 = proof.constant.Operation(Mmb, D, 32);

fn operation_proof(proof_digests: []D) Constant32 {
    var chunk: [32]u8 = undefined;
    for (&chunk, 0..) |*byte, index| byte.* = @intCast(index);
    return .{
        .loc = 5,
        .chunk = chunk,
        .range_proof = .{
            .proof = .{ .leaves = 7, .inactive_peaks = 0, .digests = proof_digests },
            .pending_chunk_digest = null,
            .partial_chunk_digest = null,
            .ops_root = hash("ops"),
        },
    };
}

test "operation proof codec roundtrip and digest budget" {
    const one = try digests(&.{"sib"});
    defer gpa.free(one);
    const item = operation_proof(one);
    try roundtrip(Constant32, item, 64);
    try roundtrip(Constant32, item, 1);
    const encoded = try codec.encode(Constant32, gpa, item);
    defer gpa.free(encoded);
    try testing.expectError(error.InvalidLength, codec.decode_cfg(Constant32, gpa, encoded, 0));
    // Bit 5 of chunk byte 0 (0b0000_0000) is clear: the operation is inactive.
    try testing.expect(!item.is_active());
}

test "dynamic operation proof matches the constant encoding" {
    const Dynamic = proof.dynamic.Operation(Mmb, D);
    const one = try digests(&.{"sib"});
    defer gpa.free(one);
    const item = operation_proof(one);
    const encoded = try codec.encode(Constant32, gpa, item);
    defer gpa.free(encoded);
    const exact: Dynamic.Cfg = .{ .chunk_size = 32, .max_digests = 1 };
    var decoded = try codec.decode_cfg(Dynamic, gpa, encoded, exact);
    defer decoded.deinit(gpa);
    try testing.expectEqual(item.loc, decoded.loc);
    try testing.expectEqualSlices(u8, &item.chunk, decoded.chunk);
    const again = try codec.encode(Dynamic, gpa, decoded);
    defer gpa.free(again);
    try testing.expectEqualSlices(u8, encoded, again);
    // The chunk size is validated before anything is read, and must not run past the input.
    const invalid = [_]usize{ 0, 3, std.math.maxInt(usize), 1 << 63, 1 << 60 };
    for (invalid) |chunk_size| {
        const cfg: Dynamic.Cfg = .{ .chunk_size = chunk_size, .max_digests = 1 };
        try testing.expectError(error.Invalid, codec.decode_cfg(Dynamic, gpa, encoded, cfg));
    }
    const too_long: Dynamic.Cfg = .{ .chunk_size = 1 << 20, .max_digests = 1 };
    try testing.expectError(error.EndOfBuffer, codec.decode_cfg(Dynamic, gpa, encoded, too_long));
}

test "chunk bits" {
    try testing.expectEqual(@as(?u64, 8), proof.chunk_bits(1));
    try testing.expectEqual(@as(?u64, 256), proof.chunk_bits(32));
    try testing.expectEqual(@as(?u64, null), proof.chunk_bits(0));
    try testing.expectEqual(@as(?u64, null), proof.chunk_bits(3));
    try testing.expectEqual(@as(?u64, null), proof.chunk_bits(1 << 60));
    try testing.expectEqual(@as(?u64, 1 << 62), proof.chunk_bits(1 << 59));
}

test "ordered key-value and exclusion proofs roundtrip" {
    const Ordered = current.ordered.proof;
    const KeyValue = Ordered.constant.KeyValue(Mmb, U64, D, 32);
    const Exclusion = Ordered.constant.Exclusion(Mmb, U64, value.Variable([]const u8), D, 32);
    const bytes_cfg: codec.Cfg([]const u8) = .{ .range = .full() };
    const one = try digests(&.{"sib"});
    defer gpa.free(one);
    const key_value: KeyValue = .{ .proof = operation_proof(one), .next_key = U64.init(9) };
    try roundtrip(KeyValue, key_value, .{ 64, {} });
    const span: Exclusion = .{ .key_value = .{
        .proof = operation_proof(one),
        .update = .{ .key = U64.init(1), .value = "v", .next_key = U64.init(9) },
    } };
    try roundtrip(Exclusion, span, .{ 64, .{ {}, bytes_cfg }, bytes_cfg });
    for ([_]?[]const u8{ null, "metadata" }) |metadata| {
        const commit: Exclusion = .{
            .commit = .{ .proof = operation_proof(one), .value = metadata },
        };
        try roundtrip(Exclusion, commit, .{ 64, .{ {}, bytes_cfg }, bytes_cfg });
        try testing.expect(!commit.eql(span));
    }
    const encoded = try codec.encode(Exclusion, gpa, span);
    defer gpa.free(encoded);
    encoded[0] = 2;
    const cfg: Exclusion.Cfg = .{ 64, .{ {}, bytes_cfg }, bytes_cfg };
    try testing.expectError(error.InvalidEnum, codec.decode_cfg(Exclusion, gpa, encoded, cfg));
}

const prefix = "commonware_storage::qmdb::current::";

test "conformance: proof" {
    const name = prefix ++ "proof::tests::conformance::CodecConformance<";
    try support.verify_codec(
        proof.OpsRootWitness(Mmb, D),
        name ++ "OpsRootWitness<mmb::Family,Sha256Digest>>",
    );
    try support.verify_codec(
        proof.OpsRootWitness(Mmr, D),
        name ++ "OpsRootWitness<mmr::Family,Sha256Digest>>",
    );
    try support.verify_codec(
        proof.RangeProof(Mmb, D),
        name ++ "RangeProof<mmb::Family,Sha256Digest>>",
    );
    try support.verify_codec(
        proof.RangeProof(Mmr, D),
        name ++ "RangeProof<mmr::Family,Sha256Digest>>",
    );
    try support.verify_codec(
        proof.constant.Operation(Mmb, D, 32),
        name ++ "constant::OperationProof<mmb::Family,Sha256Digest,\n32>>",
    );
    try support.verify_codec(
        proof.constant.Operation(Mmr, D, 32),
        name ++ "constant::OperationProof<mmr::Family,Sha256Digest,\n32>>",
    );
    try support.verify_codec(
        proof.dynamic.Operation(Mmb, D),
        name ++ "dynamic::OperationProof<mmb::Family,Sha256Digest>>",
    );
    try support.verify_codec(
        proof.dynamic.Operation(Mmr, D),
        name ++ "dynamic::OperationProof<mmr::Family,Sha256Digest>>",
    );
}

test "conformance: unordered" {
    const Unordered = current.unordered.proof;
    const name = prefix ++ "unordered::tests::conformance::CodecConformance<";
    try support.verify_codec(
        Unordered.constant.KeyValue(Mmb, D, 32),
        name ++ "constant::KeyValueProof<mmb::Family,Sha256Digest,32\n>>",
    );
    try support.verify_codec(
        Unordered.constant.KeyValue(Mmr, D, 32),
        name ++ "constant::KeyValueProof<mmr::Family,Sha256Digest,32\n>>",
    );
    try support.verify_codec(
        Unordered.dynamic.KeyValue(Mmb, D),
        name ++ "dynamic::KeyValueProof<mmb::Family,Sha256Digest>>",
    );
    try support.verify_codec(
        Unordered.dynamic.KeyValue(Mmr, D),
        name ++ "dynamic::KeyValueProof<mmr::Family,Sha256Digest>>",
    );
}

test "conformance: ordered key-value" {
    const Ordered = current.ordered.proof;
    const name = prefix ++ "ordered::tests::conformance::CodecConformance<";
    try support.verify_codec(
        Ordered.constant.KeyValue(Mmb, U64, D, 32),
        name ++ "constant::KeyValueProof<mmb::Family,U64,\nSha256Digest,32>>",
    );
    try support.verify_codec(
        Ordered.constant.KeyValue(Mmr, U64, D, 32),
        name ++ "constant::KeyValueProof<mmr::Family,U64,\nSha256Digest,32>>",
    );
    try support.verify_codec(
        Ordered.dynamic.KeyValue(Mmb, U64, D),
        name ++ "dynamic::KeyValueProof<mmb::Family,U64,Sha256Digest\n>>",
    );
    try support.verify_codec(
        Ordered.dynamic.KeyValue(Mmr, U64, D),
        name ++ "dynamic::KeyValueProof<mmr::Family,U64,Sha256Digest\n>>",
    );
}

test "conformance: ordered exclusion" {
    const Ordered = current.ordered.proof;
    const Fixed = value.Fixed(U64);
    const Variable = value.Variable([]const u8);
    const name = prefix ++ "ordered::tests::conformance::CodecConformance<";
    const c = name ++ "constant::ExclusionProof<";
    const d = name ++ "dynamic::ExclusionProof<";
    try support.verify_codec(
        Ordered.constant.Exclusion(Mmb, U64, Fixed, D, 32),
        c ++ "mmb::Family,U64,\nFixedEncoding<U64>,Sha256Digest,32>>",
    );
    try support.verify_codec(
        Ordered.constant.Exclusion(Mmb, U64, Variable, D, 32),
        c ++ "mmb::Family,U64,\nVariableEncoding<Vec<u8>>,Sha256Digest,32>>",
    );
    try support.verify_codec(
        Ordered.constant.Exclusion(Mmr, U64, Fixed, D, 32),
        c ++ "mmr::Family,U64,\nFixedEncoding<U64>,Sha256Digest,32>>",
    );
    try support.verify_codec(
        Ordered.constant.Exclusion(Mmr, U64, Variable, D, 32),
        c ++ "mmr::Family,U64,\nVariableEncoding<Vec<u8>>,Sha256Digest,32>>",
    );
    try support.verify_codec(
        Ordered.dynamic.Exclusion(Mmb, U64, Fixed, D),
        d ++ "mmb::Family,U64,\nFixedEncoding<U64>,Sha256Digest>>",
    );
    try support.verify_codec(
        Ordered.dynamic.Exclusion(Mmb, U64, Variable, D),
        d ++ "mmb::Family,U64,\nVariableEncoding<Vec<u8>>,Sha256Digest>>",
    );
    try support.verify_codec(
        Ordered.dynamic.Exclusion(Mmr, U64, Fixed, D),
        d ++ "mmr::Family,U64,\nFixedEncoding<U64>,Sha256Digest>>",
    );
    try support.verify_codec(
        Ordered.dynamic.Exclusion(Mmr, U64, Variable, D),
        d ++ "mmr::Family,U64,\nVariableEncoding<Vec<u8>>,Sha256Digest>>",
    );
}
