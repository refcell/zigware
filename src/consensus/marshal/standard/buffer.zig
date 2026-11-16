//! The standard variant's buffer (commonware's `Buffer<Standard<B>>` for
//! `buffered::Mailbox`): whole blocks travel through `broadcast.buffered`, keyed by digest,
//! which is also the standard commitment.

const std = @import("std");
const assert = std.debug.assert;
const broadcast = @import("broadcast");
const utils = @import("utils");
const types = @import("../../types.zig");
const variant = @import("../core/variant.zig");

/// The buffer over a `broadcast.buffered` mailbox for blocks `B` among peers `P`. It owns
/// its mailbox handle; give each user its own `clone`.
pub fn Buffer(comptime B: type, comptime P: type) type {
    return struct {
        const Self = @This();
        const Shared = broadcast.Digested(B);
        const Receiver = utils.channel.oneshot.Receiver(Shared);
        pub const PublicKey = P;
        pub const Mailbox = broadcast.buffered.Mailbox(P, B);

        mailbox: Mailbox,

        /// Takes ownership of `mailbox`.
        pub fn init(mailbox: Mailbox) Self {
            return .{ .mailbox = mailbox };
        }

        pub fn clone(self: Self) Self {
            return .{ .mailbox = self.mailbox.clone() };
        }

        pub fn deinit(self: *Self) void {
            self.mailbox.deinit();
            self.* = undefined;
        }

        /// The block the buffer caches under `digest` (owned by the caller).
        pub fn find_by_digest(self: *Self, digest: B.Digest) !?Shared {
            const found = try self.mailbox.get(digest);
            if (found) |block| assert(block.digest().eql(digest));
            return found;
        }

        /// A standard commitment is the block digest.
        pub fn find_by_commitment(self: *Self, commitment: B.Digest) !?Shared {
            return self.find_by_digest(commitment);
        }

        /// Resolves once the buffer sees the block; fails closed once the engine stops.
        pub fn subscribe_by_digest(self: *Self, digest: B.Digest) !?Receiver {
            return try self.mailbox.subscribe(digest);
        }

        pub fn subscribe_by_commitment(self: *Self, commitment: B.Digest) !?Receiver {
            return self.subscribe_by_digest(commitment);
        }

        /// Broadcasts `block` (owned) to `recipients` (borrowed).
        pub fn send(self: *Self, round: types.Round, block: Shared, recipients: anytype) !void {
            _ = round;
            _ = try self.mailbox.broadcast(recipients, block);
        }
    };
}

test "the buffer meets the core contract" {
    const cryptography = @import("cryptography");
    const mocks_block = @import("../mocks/block.zig");
    const Block = mocks_block.EmptyBlock(cryptography.Sha256);
    const TestBuffer = Buffer(Block, cryptography.ed25519.PublicKey);
    comptime variant.assert_buffer(TestBuffer);
    try std.testing.expect(TestBuffer.PublicKey == cryptography.ed25519.PublicKey);
}
