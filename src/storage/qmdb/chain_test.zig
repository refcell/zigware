//! Tests for qmdb/chain.rs.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const merkle = @import("../merkle/mod.zig");
const chain = @import("chain.zig");
const support = @import("test_support.zig");

const F = merkle.mmr.Family;
const D = cryptography.Sha256.Digest;
const State = chain.Commitment(F, D);
const Bounds = chain.Bounds(F, D);

fn state(size: u64, marker: u8) State {
    return .{ .size = size, .root = D.fill(marker) };
}

test "commitment round trips and refuses a size beyond the family" {
    const gpa = testing.allocator;
    const commitment = state(14, 14);
    const encoded = try codec.encode(State, gpa, commitment);
    defer gpa.free(encoded);
    try testing.expectEqual(commitment.encode_size(), encoded.len);
    try testing.expectEqual(@as(u8, 14), encoded[0]);
    try testing.expectEqualSlices(u8, &commitment.root.bytes, encoded[1..]);
    try testing.expect(commitment.eql(try codec.decode(State, gpa, encoded)));

    const too_large: State = .{ .size = F.max_leaves + 1, .root = commitment.root };
    const beyond = try codec.encode(State, gpa, too_large);
    defer gpa.free(beyond);
    var reader = codec.Reader.init(beyond);
    try testing.expectError(error.Invalid, codec.read(State, gpa, &reader));
    try testing.expectEqualStrings("Location", reader.diagnostic.context);
}

test "validate_batch_applicable accepts valid boundaries" {
    const ancestors = [_]State{ state(12, 12), state(16, 16) };
    try chain.validate_batch_applicable(F, D, state(10, 1), state(10, 1), &ancestors);
    try chain.validate_batch_applicable(F, D, state(16, 16), state(10, 1), &ancestors);
}

test "validate_batch_applicable rejects stale batch" {
    const ancestors = [_]State{ state(12, 12), state(16, 16) };
    try testing.expectError(
        error.StaleBatch,
        chain.validate_batch_applicable(F, D, state(18, 18), state(10, 1), &ancestors),
    );
}

test "validate_batch_applicable rejects equal size sibling" {
    const ancestors = [_]State{state(16, 16)};
    try testing.expectError(
        error.StaleBatch,
        chain.validate_batch_applicable(F, D, state(16, 99), state(10, 1), &ancestors),
    );
}

test "compatible accepts own states only" {
    const ancestors = [_]State{ state(16, 16), state(12, 12) };
    const bounds: Bounds = .{
        .base = state(16, 16),
        .db = state(10, 1),
        .tip = state(18, 18),
        .ancestors = &ancestors,
        .inactivity_floor = 14,
    };
    try bounds.compatible(state(18, 18));
    try bounds.compatible(state(10, 1));
    try bounds.compatible(state(16, 16));
    try testing.expectError(error.StaleRead, bounds.compatible(state(19, 19)));
    try testing.expectError(error.StaleRead, bounds.compatible(state(16, 99)));
    try testing.expectError(error.StaleRead, bounds.compatible(state(18, 99)));
}

test "compatible from base commitment requires unchanged state" {
    const base = state(10, 1);
    try base.compatible(state(10, 1));
    try testing.expectError(error.StaleRead, base.compatible(state(10, 2)));
    try testing.expectError(error.StaleRead, base.compatible(state(11, 1)));
}

test "bounds validates apply to current state" {
    const ancestors = [_]State{state(12, 12)};
    const bounds: Bounds = .{
        .base = state(10, 1),
        .db = state(10, 1),
        .tip = state(14, 14),
        .ancestors = &ancestors,
        .inactivity_floor = 11,
    };
    try bounds.validate_apply_to(state(10, 1));
    try bounds.validate_apply_to(state(12, 12));
    try testing.expectError(error.StaleBatch, bounds.validate_apply_to(state(11, 11)));
    // The batch's own tip is readable but not applicable: an applied batch cannot be applied
    // again.
    try testing.expectError(error.StaleBatch, bounds.validate_apply_to(state(14, 14)));
}

test "effective boundary and floor validation" {
    const boundary = chain.effective_boundary;
    try testing.expectEqual(@as(u64, 12), boundary(F, D, state(10, 1), state(12, 2)).size);
    try testing.expectEqual(@as(u64, 10), boundary(F, D, state(10, 1), state(8, 2)).size);
    try testing.expectEqual(@as(u64, 10), boundary(F, D, state(10, 1), null).size);
    try chain.validate_merkleize_floor(3, 3, 3);
    try testing.expectError(error.FloorRegressed, chain.validate_merkleize_floor(4, 3, 9));
    try testing.expectError(error.FloorBeyondCommit, chain.validate_merkleize_floor(3, 10, 9));
}

const prefix = "commonware_storage::qmdb::chain::tests::conformance::";

test "conformance CodecConformance<Commitment<mmr::Family,sha256::Digest>>" {
    try support.verify_codec(State, prefix ++ "CodecConformance<Commitment<mmr::Family," ++
        "sha256::Digest>>");
}

test "conformance CodecConformance<Commitment<mmb::Family,sha256::Digest>>" {
    try support.verify_codec(chain.Commitment(merkle.mmb.Family, D), prefix ++
        "CodecConformance<Commitment<mmb::Family,sha256::Digest>>");
}
