//! The standard variant: whole blocks, committed by their digest (commonware
//! `marshal/standard/variant.rs`).
//!
//! The actor handles `broadcast.Digested(B)` (the block shared with its digest), consensus
//! orders the block digest, and the archives keep the block itself. The buffer is
//! `broadcast.buffered`'s mailbox, adapted by `Buffer`; the `BlockProvider` comes with the
//! core mailbox.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const broadcast = @import("broadcast");
const codec = @import("codec");
const oneshot = @import("utils").channel.oneshot;
const traits = @import("../../traits.zig");
const variant = @import("../core/variant.zig");

pub fn Standard(comptime B: type) type {
    comptime traits.assert_block(B);
    return struct {
        pub const ApplicationBlock = B;
        pub const Block = broadcast.Digested(B);
        pub const StoredBlock = B;
        pub const Commitment = B.Digest;
        pub const Expected = variant.ExpectedCommitment(Commitment);

        pub fn commitment(block: *const Block) Commitment {
            return block.digest();
        }

        pub fn commitment_to_inner(value: Commitment) B.Digest {
            return value;
        }

        pub fn parent_commitment(block: *const Block) Commitment {
            return block.inner().parent();
        }

        pub fn stored_parent_commitment(block: *const StoredBlock) Commitment {
            return block.parent();
        }

        /// Every payload is orderable: a digest carries no embedded configuration.
        pub fn check_payload(scheme: anytype, payload: Commitment) bool {
            _ = scheme;
            _ = payload;
            return true;
        }

        /// Decodes a block and checks that its digest is the expected commitment, trusted or
        /// not (a digest needs no recomputed commitment material).
        pub fn decode_block(
            gpa: Allocator,
            bytes: []const u8,
            block_config: codec.Cfg(B),
            expected: Expected,
            strategy: anytype,
        ) codec.Error!Block {
            _ = strategy;
            var block = try codec.decode_cfg(B, gpa, bytes, block_config);
            const digest = block.digest();
            if (!digest.eql(expected.commitment())) {
                free_block(gpa, &block);
                return error.Invalid;
            }
            return Block.precomputed(gpa, block, digest) catch |err| {
                free_block(gpa, &block);
                return err;
            };
        }

        /// An owned copy of the block for the archive.
        pub fn into_stored(gpa: Allocator, block: *const Block) Allocator.Error!StoredBlock {
            const inner = block.inner();
            if (comptime !codec.owns_memory(B)) return inner.*;
            // A block with a codec configuration cannot decode under the unit one.
            if (comptime @hasDecl(B, "clone")) return inner.clone(gpa);
            const encoded = try codec.encode(B, gpa, inner.*);
            defer gpa.free(encoded);
            // Proof: a block decodes from its own canonical encoding.
            return codec.decode_cfg(B, gpa, encoded, codec.unit_cfg(codec.Cfg(B))) catch |err|
                switch (err) {
                    error.OutOfMemory => error.OutOfMemory,
                    else => unreachable,
                };
        }

        /// The block's own value, borrowed for an archive write (the caller does not free it).
        pub fn stored_view(block: *const Block) StoredBlock {
            return block.inner().*;
        }

        /// Pairs a stored block with its known digest (takes ownership; on error the
        /// caller keeps it).
        pub fn restore(gpa: Allocator, stored: StoredBlock, digest: B.Digest) !Block {
            return Block.precomputed(gpa, stored, digest);
        }

        /// Recomputes a stored block's digest (takes ownership; on error the caller keeps
        /// it).
        pub fn restore_across(gpa: Allocator, stored: StoredBlock, strategy: anytype) !Block {
            _ = strategy;
            return Block.compute(gpa, stored);
        }

        /// Another handle to `block`.
        pub fn clone_block(block: *const Block) Block {
            return block.clone();
        }

        /// Drops a handle to a block.
        pub fn deinit_block(_: Allocator, block: *Block) void {
            block.deinit();
        }

        pub fn into_shared(block: Block) broadcast.Digested(B) {
            return block;
        }

        /// The parent of `child` through marshal's `mailbox` (commonware's `BlockProvider` for
        /// `Mailbox<S, Standard<B>>`): fetched by commitment, retained up to the parent's
        /// height or until the round floor covers `bound`. A standard block need not carry a
        /// consensus context, so the caller's bound is the only round that can retire the
        /// request. Genesis has no parent, so its receiver is already closed.
        pub fn subscribe_parent(
            mailbox: anytype,
            child: *const Block,
            bound: ?types.Round,
        ) !oneshot.Receiver(Block) {
            const block = child.inner();
            const parent_height = block.height().previous() orelse {
                var pair = try oneshot.channel(Block, mailbox.gpa, mailbox.io);
                pair.sender.deinit();
                return pair.receiver;
            };
            return mailbox.subscribe_by_commitment(block.parent(), .{
                .fetch_by_commitment = .{ .height = parent_height, .round = bound },
            });
        }

        /// The application's block, which must commit to `payload`.
        pub fn from_application_block(block: broadcast.Digested(B), payload: Commitment) Block {
            assert(block.digest().eql(payload)); // The payload commits to the block.
            return block;
        }

        pub fn max_backfill_block_size(application: usize) usize {
            return application;
        }

        pub fn max_buffer_payload_size(participants: u32, application: usize) usize {
            _ = participants;
            return application;
        }

        fn free_block(gpa: Allocator, block: *B) void {
            if (comptime @hasDecl(B, "deinit")) block.deinit(gpa);
        }
    };
}

const testing = std.testing;
const cryptography = @import("cryptography");
const parallel = @import("parallel");
const mocks_block = @import("../mocks/block.zig");
const types = @import("../../types.zig");

test "decode block binds the digest" {
    const Sha256 = cryptography.Sha256;
    const TestBlock = mocks_block.Block(Sha256, u64);
    const V = Standard(TestBlock);
    comptime variant.assert_variant(V);
    const gpa = testing.allocator;
    const block = try TestBlock.init(gpa, 0, Sha256.Digest.empty, .new(1), 0);
    const encoded = try codec.encode(TestBlock, gpa, block);
    defer gpa.free(encoded);

    const digest = block.digest();
    const matching = [_]V.Expected{ .{ .trusted = digest }, .{ .untrusted = digest } };
    for (matching) |expected| {
        var decoded = try V.decode_block(gpa, encoded, {}, expected, parallel.sequential);
        defer decoded.deinit();
        try testing.expect(decoded.digest().eql(block.digest()));
        try testing.expectEqual(block.height(), decoded.inner().height());
        try testing.expect(V.commitment(&decoded).eql(block.digest()));
        try testing.expect(V.parent_commitment(&decoded).eql(Sha256.Digest.empty));
    }

    const other = Sha256.hash(&.{"other block"});
    for ([_]V.Expected{ .{ .trusted = other }, .{ .untrusted = other } }) |expected| {
        const result = V.decode_block(gpa, encoded, {}, expected, parallel.sequential);
        try testing.expectError(error.Invalid, result);
    }
}

test "stored blocks restore with their digest" {
    const Sha256 = cryptography.Sha256;
    const TestBlock = mocks_block.EmptyBlock(Sha256);
    const V = Standard(TestBlock);
    comptime variant.assert_variant(V);
    const gpa = testing.allocator;
    const block = TestBlock.init(Sha256.Digest.fill(3), types.Height.new(8), 21);
    var digested = try V.Block.compute(gpa, block);
    defer digested.deinit();
    const stored = try V.into_stored(gpa, &digested);
    try testing.expect(V.stored_parent_commitment(&stored).eql(Sha256.Digest.fill(3)));
    var restored = try V.restore_across(gpa, stored, parallel.sequential);
    defer restored.deinit();
    try testing.expect(restored.eql(digested));
    var shared = V.into_shared(restored.clone());
    defer shared.deinit();
    var back = V.from_application_block(shared.clone(), digested.digest());
    defer back.deinit();
    try testing.expectEqual(1000, V.max_backfill_block_size(1000));
    try testing.expectEqual(1000, V.max_buffer_payload_size(4, 1000));
}
