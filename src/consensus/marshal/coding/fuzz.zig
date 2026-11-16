//! Fuzzing of the coding variant's decoders (commonware's consensus/fuzz has no coding
//! target; AGENTS.md asks for one per decoder). Each input codes a fuzzed block for a fuzzed
//! committee, then decodes a mutated encoding of the coded block (`Coding.decode_block`), of
//! its stored form (`StoredCodedBlock`), and of one of its shards (`Shard`). A decode that
//! succeeds must re-encode to its input and keep the commitment; an unmutated input must
//! decode.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const codec = @import("codec");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const sequential = parallel.sequential;
const minifuzz = @import("invariants").minifuzz;

const types = @import("types.zig");
const variant = @import("variant.zig");
const commitment_module = @import("../../commitment.zig");
const mocks_block = @import("../mocks/block.zig");
const simplex_types = @import("../../simplex/types.zig");

const Unstructured = minifuzz.Unstructured;
const Sha256 = cryptography.Sha256;
const PrivateKey = cryptography.ed25519.PrivateKey;
const PublicKey = cryptography.ed25519.PublicKey;
const RS = @import("coding").ReedSolomon(Sha256);
const Commitment = commitment_module.Commitment(Sha256.Digest, Sha256.Digest, Sha256.Digest);
const Context = simplex_types.Context(Commitment, PublicKey);
const Block = mocks_block.Block(Sha256, Context);
const V = variant.Coding(Block, RS, Sha256, PublicKey);
const ShardType = types.Shard(Block, RS, Sha256);

const participants_max = 24;

/// Runs one input.
pub fn run(gpa: Allocator, u: *Unstructured) !void {
    const participants = u.int_in_range(u16, 4, participants_max);
    const config = types.coding_config_for_participants(participants);
    const block: V.Block.Inner = try .compute(gpa, try draw_block(gpa, u));
    var coded = try V.Block.encode(gpa, block, config, sequential);
    defer coded.deinit(gpa);
    const encoded = try encode(gpa, &coded);
    defer gpa.free(encoded);
    try check_coded(gpa, u, encoded, coded.commitment());
    var stored = try V.into_stored(gpa, &coded);
    defer stored.deinit(gpa);
    const stored_bytes = try codec.encode(V.StoredBlock, gpa, stored);
    defer gpa.free(stored_bytes);
    try check_roundtrip(V.StoredBlock, gpa, u, stored_bytes, {});
    const index = u.int_in_range(u16, 0, participants - 1);
    var shard = (try coded.shard(gpa, index)).?;
    defer shard.deinit(gpa);
    const shard_bytes = try codec.encode(ShardType, gpa, shard);
    defer gpa.free(shard_bytes);
    try check_roundtrip(ShardType, gpa, u, shard_bytes, Block.max_encode_size);
}

fn draw_block(gpa: Allocator, u: *Unstructured) !Block {
    const leader = PrivateKey.from_seed(try u.arbitrary(u8)).public_key();
    const epoch = try u.arbitrary(u64);
    const view = try u.arbitrary(u64);
    const four = types.coding_config_for_participants(4);
    const parent: Commitment = .init(.empty, .empty, .empty, four);
    const context: Context = .{
        .round = .new(.new(epoch), .new(view)),
        .leader = leader,
        .parent = .{ .new(try u.arbitrary(u64)), parent },
    };
    const parent_digest = Sha256.hash(&.{try u.bytes(8)});
    const height = try u.arbitrary(u64);
    return Block.init(gpa, context, parent_digest, .new(height), try u.arbitrary(u64));
}

fn encode(gpa: Allocator, coded: *const V.Block) ![]u8 {
    const bytes = try gpa.alloc(u8, coded.encode_size());
    var writer = codec.Writer.init(bytes);
    coded.write(&writer);
    assert(writer.written().len == bytes.len);
    return bytes;
}

/// A copy of `bytes` unchanged, with one byte flipped, truncated, or with a byte appended.
fn mutate(gpa: Allocator, u: *Unstructured, bytes: []const u8) ![]u8 {
    assert(bytes.len > 0);
    switch (u.int_in_range(u8, 0, 3)) {
        0 => return gpa.dupe(u8, bytes),
        1 => {
            const copy = try gpa.dupe(u8, bytes);
            const flip = u.int_in_range(u8, 1, 255);
            copy[u.choose_index(copy.len) catch 0] ^= flip;
            return copy;
        },
        2 => return gpa.dupe(u8, bytes[0 .. u.choose_index(bytes.len) catch 0]),
        else => return std.mem.concat(gpa, u8, &.{ bytes, &.{u.int_in_range(u8, 0, 255)} }),
    }
}

/// Decodes a mutation of the coded block's encoding under its untrusted commitment.
fn check_coded(
    gpa: Allocator,
    u: *Unstructured,
    encoded: []const u8,
    expected: Commitment,
) !void {
    const bytes = try mutate(gpa, u, encoded);
    defer gpa.free(bytes);
    const untrusted: V.Expected = .{ .untrusted = expected };
    var decoded = V.decode_block(gpa, bytes, {}, untrusted, sequential) catch |err| {
        if (err == error.OutOfMemory) return err;
        try testing.expect(!std.mem.eql(u8, bytes, encoded));
        return;
    };
    defer decoded.deinit(gpa);
    try testing.expect(V.commitment(&decoded).eql(expected));
    const again = try encode(gpa, &decoded);
    defer gpa.free(again);
    try testing.expectEqualSlices(u8, bytes, again);
}

/// Decodes a mutation of `T`'s encoding `encoded`, which must re-encode to its input.
fn check_roundtrip(
    comptime T: type,
    gpa: Allocator,
    u: *Unstructured,
    encoded: []const u8,
    cfg: codec.Cfg(T),
) !void {
    const bytes = try mutate(gpa, u, encoded);
    defer gpa.free(bytes);
    var decoded = codec.decode_cfg(T, gpa, bytes, cfg) catch |err| {
        if (err == error.OutOfMemory) return err;
        try testing.expect(!std.mem.eql(u8, bytes, encoded));
        return;
    };
    defer decoded.deinit(gpa);
    const again = try codec.encode(T, gpa, decoded);
    defer gpa.free(again);
    try testing.expectEqualSlices(u8, bytes, again);
}

/// Runs `bytes` as one input, as the coverage-guided target does.
pub fn run_input(gpa: Allocator, bytes: []const u8) !void {
    var u = Unstructured.init(bytes);
    run(gpa, &u) catch |err| switch (err) {
        error.NotEnoughData, error.IncorrectFormat => {},
        else => return err,
    };
}

fn body(_: void, u: *Unstructured) !void {
    return run(testing.allocator, u);
}

test "fuzz marshal coding decoders (minifuzz)" {
    try (minifuzz.Builder{}).with_seed(0).with_search_limit(256).run(testing.allocator, {}, body);
}

test "fuzz marshal coding decoders (coverage-guided)" {
    try testing.fuzz({}, struct {
        fn fuzz(_: void, smith: *testing.Smith) anyerror!void {
            var bytes: [512]u8 = undefined;
            const length = smith.slice(&bytes);
            try run_input(testing.allocator, bytes[0..length]);
        }
    }.fuzz, .{});
}
