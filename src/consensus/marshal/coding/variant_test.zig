//! Tests of the coding variant, ported from commonware `marshal/coding/variant.rs`.
//! commonware's `NoCloneBlock` panics if a shared block operation clones the inner block; a
//! Zig block is shared by handle, so the tests check that the handles share instead.

const std = @import("std");
const actor = @import("actor");
const testing = std.testing;
const codec = @import("codec");
const coding = @import("coding");
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const utils = @import("utils");

const variant = @import("variant.zig");
const core_variant = @import("../core/variant.zig");
const core_mailbox = @import("../core/mailbox.zig");
const ancestry = @import("../ancestry.zig");
const commitment_module = @import("../../commitment.zig");
const mocks_block = @import("../mocks/block.zig");
const simplex_types = @import("../../simplex/types.zig");

const gpa = testing.allocator;
const Sha256 = cryptography.Sha256;
const PrivateKey = cryptography.ed25519.PrivateKey;
const PublicKey = cryptography.ed25519.PublicKey;
const TestScheme = coding.ReedSolomon(Sha256);
const TestCommitment = commitment_module.Commitment(Sha256.Digest, Sha256.Digest, Sha256.Digest);
const TestContext = simplex_types.Context(TestCommitment, PublicKey);
const InnerBlock = mocks_block.Block(Sha256, TestContext);
const V = variant.Coding(InnerBlock, TestScheme, Sha256, PublicKey);

comptime {
    core_variant.assert_variant(V);
    core_variant.assert_buffer(variant.Buffer(InnerBlock, TestScheme, Sha256, PublicKey));
}

/// The coding configuration of the coded blocks these tests build.
const config: coding.Config = .{ .minimum_shards = 1, .extra_shards = 2 };

fn test_block() !InnerBlock {
    var rng = utils.test_rng();
    const leader = PrivateKey.random(&rng).public_key();
    const parent: TestCommitment = .init(.empty, .empty, .empty, config);
    const context: TestContext = .{
        .round = .new(.new(1), .new(2)),
        .leader = leader,
        .parent = .{ .new(1), parent },
    };
    return InnerBlock.init(gpa, context, Sha256.hash(&.{"parent"}), .new(7), 1_234_567);
}

/// commonware `encode_block`: the block coded with `config`.
fn encode_block(block: InnerBlock) !V.Block {
    return V.Block.encode(gpa, try .compute(gpa, block), config, parallel.sequential);
}

/// The coded block's encoding: the block, then its coding config.
fn encode(coded: *const V.Block) ![]u8 {
    const bytes = try gpa.alloc(u8, coded.encode_size());
    var writer = codec.Writer.init(bytes);
    coded.write(&writer);
    std.debug.assert(writer.written().len == bytes.len);
    return bytes;
}

test "max backfill block size matches encoding" {
    // Encoding the block with its coding configuration yields what
    // `max_backfill_block_size` reports.
    const block = try test_block();
    const size = codec.encode_size(InnerBlock, block);
    var coded = try encode_block(block);
    defer coded.deinit(gpa);
    const encoded = try encode(&coded);
    defer gpa.free(encoded);
    try testing.expectEqual(V.max_backfill_block_size(size), encoded.len);
}

test "storage conversion shares coding block" {
    var coded = try encode_block(try test_block());
    defer coded.deinit(gpa);
    const expected = coded.commitment();
    const stored = try V.into_stored(gpa, &coded);
    try testing.expect(stored.commitment().eql(expected));
    try testing.expectEqual(coded.inner(), stored.inner());
    var recovered = try V.restore_across(gpa, stored, parallel.sequential);
    try testing.expect(V.commitment(&recovered).eql(expected));
    try testing.expect(V.parent_commitment(&recovered).eql(coded.context().parent[1]));
    var shared = V.into_shared(recovered);
    defer shared.deinit();
    try testing.expectEqual(coded.inner_value.shared, shared.shared);
    var restored = try V.restore(gpa, try V.into_stored(gpa, &coded), coded.digest());
    defer V.deinit_block(gpa, &restored);
    try testing.expect(restored.commitment().eql(expected));
    try testing.expectEqual(coded.inner(), restored.inner());
}

/// The decode shapes of `decode_block_recomputes_untrusted_root` under one strategy.
const DecodeShapes = struct {
    encoded: []const u8,
    expected: TestCommitment,

    pub fn run(op: DecodeShapes, explorer: parallel.mocks.Explorer) ![2]TestCommitment {
        // An untrusted commitment is recomputed, so the decoded block holds its shards.
        const untrusted: V.Expected = .{ .untrusted = op.expected };
        var decoded = try V.decode_block(gpa, op.encoded, {}, untrusted, explorer);
        defer decoded.deinit(gpa);
        try testing.expect(V.commitment(&decoded).eql(op.expected));
        try testing.expect(decoded.shared_shards != null);
        // A root that does not encode the block is rejected unless it is trusted.
        const other: TestCommitment = .init(
            op.expected.block(),
            Sha256.hash(&.{"other root"}),
            op.expected.context(),
            config,
        );
        const rejected = V.decode_block(gpa, op.encoded, {}, .{ .untrusted = other }, explorer);
        try testing.expectError(error.Invalid, rejected);
        var trusted = try V.decode_block(gpa, op.encoded, {}, .{ .trusted = other }, explorer);
        defer trusted.deinit(gpa);
        try testing.expect(V.commitment(&trusted).eql(other));
        try testing.expect(trusted.shared_shards == null);
        // Bytes after the block are rejected.
        const extended = try std.mem.concat(gpa, u8, &.{ op.encoded, &.{0} });
        defer gpa.free(extended);
        const extra = V.decode_block(gpa, extended, {}, untrusted, explorer);
        try testing.expectError(error.ExtraData, extra);
        // Every shape must decode to the same commitments.
        return .{ V.commitment(&decoded), V.commitment(&trusted) };
    }
};

test "decode block recomputes untrusted root" {
    var coded = try encode_block(try test_block());
    defer coded.deinit(gpa);
    const encoded = try encode(&coded);
    defer gpa.free(encoded);
    const op: DecodeShapes = .{ .encoded = encoded, .expected = coded.commitment() };
    const commitments = try parallel.mocks.explore(gpa, testing.io, op);
    try testing.expect(commitments[0].eql(coded.commitment()));
    try testing.expect(commitments[1].block().eql(coded.digest()));
}

test "decode block binds context digest" {
    var coded = try encode_block(try test_block());
    defer coded.deinit(gpa);
    const expected = coded.commitment();
    const encoded = try encode(&coded);
    defer gpa.free(encoded);
    // Only the context digest differs, which only the full-commitment comparison can see.
    const other: TestCommitment = .init(
        expected.block(),
        expected.root(),
        Sha256.hash(&.{"other context"}),
        config,
    );
    for ([_]V.Expected{ .{ .trusted = other }, .{ .untrusted = other } }) |value| {
        const result = V.decode_block(gpa, encoded, {}, value, parallel.sequential);
        try testing.expectError(error.Invalid, result);
    }
}

test "check payload requires the committee's coding config" {
    const Scheme = struct {
        count: usize,
        const Participants = struct {
            count: usize,
            pub fn len(self: @This()) usize {
                return self.count;
            }
        };
        pub fn participants(self: @This()) Participants {
            return .{ .count = self.count };
        }
    };
    const four: TestCommitment = .init(.empty, .empty, .empty, .{
        .minimum_shards = 2,
        .extra_shards = 2,
    });
    try testing.expect(V.check_payload(Scheme{ .count = 4 }, four));
    try testing.expect(!V.check_payload(Scheme{ .count = 5 }, four));
    const one: TestCommitment = .init(.empty, .empty, .empty, config);
    try testing.expect(!V.check_payload(Scheme{ .count = 4 }, one));
}

/// A scheme whose certificates are plain integers: the mailbox never inspects them.
const PlainScheme = struct {
    pub const Certificate = u64;
    pub const PublicKey = cryptography.ed25519.PublicKey;
};

test "subscribe parent fetches the parent by its coding commitment" {
    const Message = core_mailbox.Message(PlainScheme, V);
    const Mailbox = core_mailbox.Mailbox(PlainScheme, V);
    comptime ancestry.assert_block_provider(Mailbox);
    var pair = try actor.mailbox.new(Message, gpa, testing.io, 4);
    defer pair.receiver.deinit();
    var provider: Mailbox = .init(gpa, testing.io, pair.sender, 1);
    defer provider.deinit();

    // The child's context names its parent's coding commitment, which the request carries.
    var parent = try encode_block(try test_block());
    defer parent.deinit(gpa);
    var rng = utils.test_rng();
    const context: TestContext = .{
        .round = .new(.new(1), .new(3)),
        .leader = PrivateKey.random(&rng).public_key(),
        .parent = .{ .new(2), parent.commitment() },
    };
    const inner = try InnerBlock.init(gpa, context, parent.digest(), .new(8), 1_234_568);
    var child = try mocks_block.ready(InnerBlock, gpa, inner);
    defer child.deinit();
    var receiver = try provider.subscribe_parent(&child, null);
    defer receiver.deinit();
    const request = try pair.receiver.try_recv();
    var body = request.body.subscribe_by_commitment;
    try testing.expect(body.commitment.eql(parent.commitment()));
    try testing.expectEqual(7, body.fallback.fetch_by_commitment.height.get());
    try testing.expectError(error.Empty, receiver.try_recv());

    // The coded parent arrives as its application block.
    try body.response.send(parent.clone());
    var delivered = try receiver.try_recv();
    defer delivered.deinit();
    try testing.expect(delivered.digest().eql(parent.digest()));
    try testing.expectEqual(parent.inner(), delivered.inner());

    // Genesis has no parent: its receiver is closed and nothing is sent.
    const genesis_inner = try InnerBlock.init(gpa, context, Sha256.Digest.empty, .zero(), 0);
    var genesis = try mocks_block.ready(InnerBlock, gpa, genesis_inner);
    defer genesis.deinit();
    var none = try provider.subscribe_parent(&genesis, null);
    defer none.deinit();
    try testing.expectError(error.Closed, none.try_recv());
    try testing.expectError(error.Empty, pair.receiver.try_recv());
}
