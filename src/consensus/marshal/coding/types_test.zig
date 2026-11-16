//! Tests of the coding types, ported from commonware `marshal/coding/types.rs`, with the
//! `CodecConformance<Shard<TestBlock, ReedSolomon<Sha256>, Sha256>>` hash.
//!
//! A shard's encoding uses only its block type's digest, so the shard tests and the
//! conformance hash name a digest-only block in place of `EmptyBlock<Sha256>`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const codec = @import("codec");
const coding = @import("coding");
const conformance = @import("conformance");
const cryptography = @import("cryptography");
const parallel = @import("parallel");

const types = @import("types.zig");

const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const RS = coding.ReedSolomon(Sha256);
const CodingConfig = coding.Config;
const gpa = testing.allocator;
const sequential = parallel.sequential;

/// A block type naming only its digest (the shard encoding uses nothing else).
const TestBlock = struct {
    pub const Digest = Sha256.Digest;
};
const RShard = types.Shard(TestBlock, RS, Sha256);
const Commitment = RShard.Commitment;

const max_block_size = 1024 * 1024;

/// The first shard of `data` coded with `config`, under a commitment claiming `claimed`.
fn first_shard(data: []const u8, config: CodingConfig, claimed: CodingConfig) !RShard {
    var encoding = try RS.encode(gpa, config, data, sequential);
    defer encoding.deinit(gpa);
    const commitment: Commitment = .init(.empty, encoding.commitment, .empty, claimed);
    const borrowed = RShard.init(commitment, 0, encoding.shards[0]);
    return borrowed.clone(gpa);
}

fn encode_shard(shard: RShard) ![]u8 {
    return codec.encode(RShard, gpa, shard);
}

fn decode_shard(bytes: []const u8, max: usize) !RShard {
    return codec.decode_cfg(RShard, gpa, bytes, max);
}

test "shard width bounded by commitment config" {
    // A shard decodes only when it is no wider than a block of the maximum size produces
    // under the coding config its commitment claims.
    const max = 1000;
    const config: CodingConfig = .{ .minimum_shards = 2, .extra_shards = 2 };
    const widest = max + CodingConfig.fixed_size;
    const cases = [_]struct { len: usize, claimed: CodingConfig, ok: bool }{
        // A maximum block and its coding config produce the widest admitted shard.
        .{ .len = widest, .claimed = config, .ok = true },
        // One more byte widens the shard past the bound.
        .{ .len = widest + 1, .claimed = config, .ok = false },
        // A commitment claiming more minimum shards narrows the bound.
        .{ .len = widest, .claimed = .{ .minimum_shards = 4, .extra_shards = 2 }, .ok = false },
    };
    for (cases) |case| {
        const data = try gpa.alloc(u8, case.len);
        defer gpa.free(data);
        @memset(data, 0);
        var shard = try first_shard(data, config, case.claimed);
        defer shard.deinit(gpa);
        const encoded = try encode_shard(shard);
        defer gpa.free(encoded);
        if (decode_shard(encoded, max)) |decoded| {
            var owned = decoded;
            owned.deinit(gpa);
            try testing.expect(case.ok);
        } else |_| try testing.expect(!case.ok);
    }
}

fn expect_roundtrip(data: []const u8) !void {
    const config: CodingConfig = .{ .minimum_shards = 1, .extra_shards = 2 };
    var shard = try first_shard(data, config, config);
    defer shard.deinit(gpa);
    const encoded = try encode_shard(shard);
    defer gpa.free(encoded);
    try testing.expectEqual(shard.encode_size(), encoded.len);
    var decoded = try decode_shard(encoded, max_block_size);
    defer decoded.deinit(gpa);
    try testing.expect(shard.eql(&decoded));
    try testing.expectEqual(@as(u16, 0), decoded.index);
    try testing.expect(decoded.commitment().eql(shard.commitment()));
}

test "shard wrapper codec roundtrip" {
    try expect_roundtrip("commonware shape rotator club");
}

test "shard codec roundtrip" {
    try expect_roundtrip("deadc0de");
}

test "shard decode truncated returns error" {
    try testing.expectError(error.EndOfBuffer, decode_shard(&.{}, max_block_size));
}

test "coding config for participants valid for minimum set" {
    const config = types.coding_config_for_participants(4);
    try testing.expectEqual(@as(u16, 2), config.minimum_shards);
    try testing.expectEqual(@as(u16, 2), config.extra_shards);
    // commonware's `should_panic` test for 3 participants has no counterpart (Zig cannot
    // catch panics); larger sets keep `f + 1` minimum shards.
    const large = types.coding_config_for_participants(10);
    try testing.expectEqual(@as(u16, 4), large.minimum_shards);
    try testing.expectEqual(@as(u16, 6), large.extra_shards);
}

// `CodecConformance<Shard<TestBlock, ReedSolomon<Sha256>, Sha256>>`: the derived `Arbitrary`
// draws the commitment, the index, then the inner chunk.

const arbitrary = codec.arbitrary;

/// commonware's SHA-256 digest `Arbitrary`: the hash of `int_in_range(0..=256)` drawn bytes.
fn gen_digest(allocator: Allocator, u: *arbitrary.Unstructured) arbitrary.Error!Digest {
    const len = u.int_in_range(u64, 0, 256);
    const data = try allocator.alloc(u8, len);
    try u.bytes(data);
    return Sha256.hash(&.{data});
}

fn gen_commitment(allocator: Allocator, u: *arbitrary.Unstructured) arbitrary.Error!Commitment {
    const block = try gen_digest(allocator, u);
    const root = try gen_digest(allocator, u);
    const context = try gen_digest(allocator, u);
    const minimum = u.int_in_range(u16, 1, std.math.maxInt(u16));
    const extra = u.int_in_range(u16, 1, std.math.maxInt(u16));
    return .init(block, root, context, .{ .minimum_shards = minimum, .extra_shards = extra });
}

/// The derived `Chunk::arbitrary`: shard bytes, index, then the proof's leaf count and
/// siblings.
fn gen_chunk(allocator: Allocator, u: *arbitrary.Unstructured) arbitrary.Error!RS.Shard {
    const shard = try arbitrary.collect(u8, allocator, u);
    const index = u.int(u16);
    const leaf_count = u.int(u32);
    var siblings: std.ArrayList(Digest) = .empty;
    while (u.keep_going()) try siblings.append(allocator, try gen_digest(allocator, u));
    return .{
        .shard = shard,
        .index = index,
        .proof = .{ .leaf_count = leaf_count, .siblings = siblings.items },
    };
}

fn gen_shard(allocator: Allocator, u: *arbitrary.Unstructured) arbitrary.Error!RShard {
    const commitment = try gen_commitment(allocator, u);
    const index = u.int(u16);
    return .init(commitment, index, try gen_chunk(allocator, u));
}

const ShardConformance = struct {
    pub fn commit(allocator: Allocator, seed: u64) ![]u8 {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const shard = try arbitrary.generate(RShard, gen_shard, arena.allocator(), seed);
        return codec.encode(RShard, allocator, shard);
    }
};

test "shard conformance hash matches commonware" {
    try conformance.verify(
        ShardConformance,
        std.heap.smp_allocator,
        "commonware_consensus::marshal::coding::types::test::conformance::" ++
            "CodecConformance<Shard<TestBlock,ReedSolomon<Sha256>,Sha256>>",
        conformance.default_cases,
        @embedFile("../../conformance.toml"),
    );
}

// Coded and stored coded blocks, over marshal's `mocks.block.EmptyBlock(Sha256)`.

const EmptyBlock = @import("test_block.zig").EmptyBlock;

const Coded = types.CodedBlock(EmptyBlock, RS, Sha256);
const Stored = types.StoredCodedBlock(EmptyBlock, RS, Sha256);
const BlockCommitment = Coded.Commitment;
const Expected = union(enum) { trusted: BlockCommitment, untrusted: BlockCommitment };
const one_two: CodingConfig = .{ .minimum_shards = 1, .extra_shards = 2 };

fn test_block(height_value: u64) EmptyBlock {
    return .init(Sha256.hash(&.{"parent"}), .new(height_value), 1_234_567);
}

fn encode_block(block: EmptyBlock, config: CodingConfig) !Coded {
    return @import("test_block.zig").encode_block(gpa, block, config);
}

fn encode_pair(block: EmptyBlock, config: CodingConfig) ![]u8 {
    const size = block.encode_size() + CodingConfig.fixed_size;
    const bytes = try gpa.alloc(u8, size);
    var writer = codec.Writer.init(bytes);
    block.write(&writer);
    config.write(&writer);
    return bytes;
}

/// The wire bytes of `coded` (write-only, so not through `codec.encode`).
fn encode_coded(coded: Coded) ![]u8 {
    const bytes = try gpa.alloc(u8, coded.encode_size());
    var writer = codec.Writer.init(bytes);
    coded.write(&writer);
    try testing.expectEqual(bytes.len, writer.written().len);
    return bytes;
}

/// Decodes a coded block's wire bytes against `expected` the way the coding variant does.
fn decode(bytes: []const u8, expected: Expected) !Coded {
    var reader = codec.Reader.init(bytes);
    const block = try codec.read(EmptyBlock, gpa, &reader);
    const config = try codec.read(CodingConfig, gpa, &reader);
    try testing.expectEqual(@as(usize, 0), reader.remaining());
    return Coded.from_decoded(gpa, block, config, expected, sequential);
}

test "coded block codec roundtrip" {
    var coded = try encode_block(test_block(42), one_two);
    defer coded.deinit(gpa);
    const encoded = try encode_coded(coded);
    defer gpa.free(encoded);
    try testing.expectEqual(coded.encode_size(), encoded.len);
    for ([_]Expected{ .{ .trusted = coded.commitment() }, .{ .untrusted = coded.commitment() } }) |
        expected,
    | {
        var decoded = try decode(encoded, expected);
        defer decoded.deinit(gpa);
        try testing.expect(decoded.commitment().eql(coded.commitment()));
        const decoded_shards = try decoded.shards(gpa, sequential);
        const coded_shards = try coded.shards(gpa, sequential);
        try testing.expectEqual(coded_shards.len, decoded_shards.len);
        for (coded_shards, decoded_shards) |*a, *b| try testing.expect(a.eql(b));
        try testing.expect(coded.eql(&decoded));
    }
}

test "coded block decode rejects config mismatch" {
    const expected_config: CodingConfig = .{ .minimum_shards = 1, .extra_shards = 3 };
    const embedded_config: CodingConfig = .{ .minimum_shards = 2, .extra_shards = 2 };
    var coded = try encode_block(test_block(42), expected_config);
    defer coded.deinit(gpa);
    const encoded = try encode_pair(test_block(42), embedded_config);
    defer gpa.free(encoded);
    const commitment = coded.commitment();
    for ([_]Expected{ .{ .trusted = commitment }, .{ .untrusted = commitment } }) |expected| {
        try testing.expectError(error.ConfigMismatch, decode(encoded, expected));
    }
}

/// `commitment` with its coding root replaced by `root`.
fn with_root(commitment: BlockCommitment, root: Digest) BlockCommitment {
    return .init(commitment.block(), root, commitment.context(), commitment.config());
}

test "coded block decode rejects coding root mismatch" {
    var coded = try encode_block(test_block(42), one_two);
    defer coded.deinit(gpa);
    const wrong_root = Sha256.hash(&.{"wrong root"});
    try testing.expect(!wrong_root.eql(coded.commitment().root()));
    const expected = with_root(coded.commitment(), wrong_root);
    const encoded = try encode_coded(coded);
    defer gpa.free(encoded);
    // Decoding must reject bytes that do not satisfy the exact expected commitment.
    try testing.expectError(error.CommitmentMismatch, decode(encoded, .{ .untrusted = expected }));
}

test "coded block decode trusted is lazy" {
    var coded = try encode_block(test_block(42), one_two);
    defer coded.deinit(gpa);
    const encoded = try encode_coded(coded);
    defer gpa.free(encoded);
    var decoded = try decode(encoded, .{ .trusted = coded.commitment() });
    defer decoded.deinit(gpa);
    // The root comes from the commitment and shards are generated on demand.
    try testing.expect(decoded.commitment().eql(coded.commitment()));
    try testing.expect(try decoded.shard(gpa, 0) == null);
    const decoded_shards = try decoded.shards(gpa, sequential);
    const coded_shards = try coded.shards(gpa, sequential);
    for (coded_shards, decoded_shards) |*a, *b| try testing.expect(a.eql(b));
    var shard = (try decoded.shard(gpa, 1)).?;
    defer shard.deinit(gpa);
    try testing.expect(shard.inner.eql(&coded_shards[1]));
    try testing.expect(try decoded.shard(gpa, 3) == null);
}

test "coded block decode trusted rejects block digest mismatch" {
    var coded = try encode_block(test_block(42), one_two);
    defer coded.deinit(gpa);
    const other = test_block(43);
    try testing.expect(!other.digest().eql(coded.commitment().block()));
    const encoded = try encode_pair(other, one_two);
    defer gpa.free(encoded);
    const expected: Expected = .{ .trusted = coded.commitment() };
    try testing.expectError(error.BlockDigestMismatch, decode(encoded, expected));
}

// commonware's `test_coded_block_trusted_wrong_root_panics_on_shards` has no counterpart: Zig
// cannot catch the panic (`shards` panics when a trusted root does not code the block).

test "coded block clone shares shards" {
    var coded = try encode_block(test_block(42), one_two);
    defer coded.deinit(gpa);
    var cloned = coded.clone();
    defer cloned.deinit(gpa);
    try testing.expect(coded.inner() == cloned.inner());
    try testing.expect(coded.shared_shards.? == cloned.shared_shards.?);
}

test "stored coded block codec roundtrip" {
    var coded = try encode_block(test_block(42), one_two);
    defer coded.deinit(gpa);
    var stored = Stored.init(coded.clone());
    defer stored.deinit(gpa);
    try testing.expect(stored.commitment().eql(coded.commitment()));
    try testing.expect(stored.digest().eql(coded.digest()));
    try testing.expectEqual(coded.height().get(), stored.height().get());
    try testing.expect(stored.parent().eql(coded.parent()));
    const encoded = try codec.encode(Stored, gpa, stored);
    defer gpa.free(encoded);
    try testing.expectEqual(stored.encode_size(), encoded.len);
    var decoded = try codec.decode_cfg(Stored, gpa, encoded, {});
    defer decoded.deinit(gpa);
    try testing.expect(stored.eql(&decoded));
    try testing.expect(decoded.commitment().eql(coded.commitment()));
    try testing.expect(decoded.digest().eql(coded.digest()));
}

test "stored coded block into coded block" {
    var coded = try encode_block(test_block(42), one_two);
    const commitment = coded.commitment();
    const digest = coded.digest();
    var stored = Stored.init(coded);
    defer stored.deinit(gpa);
    const encoded = try codec.encode(Stored, gpa, stored);
    defer gpa.free(encoded);
    const decoded = try codec.decode_cfg(Stored, gpa, encoded, {});
    var restored = decoded.into_coded_block();
    defer restored.deinit(gpa);
    try testing.expect(restored.commitment().eql(commitment));
    try testing.expect(restored.digest().eql(digest));
    // A restored block codes its shards on demand, under the trusted root.
    try testing.expect(try restored.shard(gpa, 0) == null);
    _ = try restored.shards(gpa, sequential);
    var shard = (try restored.shard(gpa, 0)).?;
    defer shard.deinit(gpa);
    try testing.expectEqual(@as(u16, 0), shard.index);
}

// `test_shard_encode_iobufs_matches_encode` has no counterpart: codec writes one buffer.
