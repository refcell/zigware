//! The coding variant of marshal, which disseminates blocks as erasure-coded shards
//! (commonware `marshal/coding/variant.rs`).
//!
//! The actor handles `CodedBlock`s (shared handles to the application block and its
//! shards), consensus orders the coding `Commitment`, and the archives keep
//! `StoredCodedBlock`s. The buffer is the shards engine's mailbox, adapted by `Buffer`, and
//! `subscribe_parent` provides ancestry through core's mailbox.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const broadcast = @import("broadcast");
const codec = @import("codec");
const coding = @import("coding");
const oneshot = @import("utils").channel.oneshot;

const types = @import("types.zig");
const shards_mailbox = @import("shards/mailbox.zig");
const variant = @import("../core/variant.zig");
const traits = @import("../../traits.zig");
const consensus_types = @import("../../types.zig");
const simplex_types = @import("../../simplex/types.zig");

const CodingConfig = coding.Config;
const Round = consensus_types.Round;

/// The coding variant for application blocks `B` proposed in a simplex context over its
/// coding commitment, coded with scheme `C`, contexts hashed with `H`, and leaders keyed `P`.
pub fn Coding(comptime B: type, comptime C: type, comptime H: type, comptime P: type) type {
    comptime traits.assert_block(B);
    comptime coding.assert_scheme(C);
    comptime assert(B.Context == simplex_types.Context(types.CommitmentOf(B, C, H), P));
    return struct {
        pub const ApplicationBlock = B;
        pub const Block = types.CodedBlock(B, C, H);
        pub const StoredBlock = types.StoredCodedBlock(B, C, H);
        pub const Commitment = types.CommitmentOf(B, C, H);
        pub const PublicKey = P;
        pub const Expected = variant.ExpectedCommitment(Commitment);

        pub fn commitment(block: *const Block) Commitment {
            return block.commitment();
        }

        /// The block digest embedded in the coding commitment.
        pub fn commitment_to_inner(value: Commitment) B.Digest {
            return value.block();
        }

        /// The parent commitment embedded in the consensus context.
        pub fn parent_commitment(block: *const Block) Commitment {
            return block.context().parent[1];
        }

        pub fn stored_parent_commitment(block: *const StoredBlock) Commitment {
            return block.context().parent[1];
        }

        /// Whether `payload`'s coding config is the one for `scheme`'s participant set.
        pub fn check_payload(scheme: anytype, payload: Commitment) bool {
            const participants = scheme.participants().len();
            const count = std.math.cast(u16, participants) orelse
                @panic("scheme must have at most 2^16-1 participants");
            const expected = types.coding_config_for_participants(count);
            return payload.config().eql(expected);
        }

        /// Decodes a block and its coding config (no trailing bytes) and checks it against
        /// `expected`; an untrusted commitment codes the block to recompute its root.
        pub fn decode_block(
            gpa: Allocator,
            bytes: []const u8,
            block_config: codec.Cfg(B),
            expected: Expected,
            strategy: anytype,
        ) codec.Error!Block {
            var reader = codec.Reader.init(bytes);
            const block = try codec.read_cfg(B, gpa, &reader, block_config);
            const config = read_config(gpa, &reader) catch |err| {
                codec.free(B, gpa, block);
                return err;
            };
            const decoded = Block.from_decoded(gpa, block, config, expected, strategy);
            return decoded catch |err| switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.Invalid,
            };
        }

        fn read_config(gpa: Allocator, reader: *codec.Reader) codec.Error!CodingConfig {
            const config = try codec.read(CodingConfig, gpa, reader);
            const remaining = reader.remaining();
            if (remaining > 0) return reader.fail(error.ExtraData, remaining);
            assert(reader.remaining() == 0);
            return config;
        }

        /// Another handle to the block for the archive (shares the application block).
        pub fn into_stored(gpa: Allocator, block: *const Block) Allocator.Error!StoredBlock {
            _ = gpa;
            const stored = StoredBlock.from_shared(block);
            assert(stored.commitment().eql(block.commitment()));
            return stored;
        }

        /// The coded block of a stored block keyed by `digest` (takes ownership).
        pub fn restore(gpa: Allocator, stored: StoredBlock, digest: B.Digest) !Block {
            _ = gpa;
            assert(stored.digest().eql(digest)); // Stored blocks are keyed by their digest.
            return stored.into_coded_block();
        }

        /// The stored commitment carries the block's identity, so nothing is computed.
        pub fn restore_across(gpa: Allocator, stored: StoredBlock, strategy: anytype) !Block {
            _ = gpa;
            _ = strategy;
            return stored.into_coded_block();
        }

        /// Another handle to `block`.
        pub fn clone_block(block: *const Block) Block {
            return block.clone();
        }

        /// Drops a handle to a block.
        pub fn deinit_block(gpa: Allocator, block: *Block) void {
            block.deinit(gpa);
        }

        /// The application block of `block` (takes ownership of the handle).
        pub fn into_shared(block: Block) broadcast.Digested(B) {
            const shared = block.inner_digested();
            block.discard();
            return shared;
        }

        /// The parent of `child` through marshal's `mailbox` (commonware's `BlockProvider` for
        /// `Mailbox<S, Coding<..>>`): fetched by the parent commitment in the child's context,
        /// retained up to the parent's height, and delivered as its application block.
        /// Genesis has no parent, so its receiver is already closed.
        pub fn subscribe_parent(
            mailbox: anytype,
            child: *const broadcast.Digested(B),
        ) Allocator.Error!ParentReceiver {
            const block = child.inner();
            const parent_height = block.height().previous() orelse {
                var pair = try oneshot.channel(Block, mailbox.gpa, mailbox.io);
                pair.sender.deinit();
                return .{ .inner = pair.receiver };
            };
            assert(parent_height.get() + 1 == block.height().get());
            const receiver = try mailbox.subscribe_by_commitment(block.context().parent[1], .{
                .fetch_by_commitment = parent_height,
            });
            return .{ .inner = receiver };
        }

        /// A receiver of a coded parent that yields its application block.
        pub const ParentReceiver = struct {
            inner: oneshot.Receiver(Block),

            pub fn recv(self: *ParentReceiver) oneshot.RecvError!broadcast.Digested(B) {
                return into_shared(try self.inner.recv());
            }

            pub fn try_recv(self: *ParentReceiver) oneshot.TryRecvError!broadcast.Digested(B) {
                return into_shared(try self.inner.try_recv());
            }

            pub fn deinit(self: *ParentReceiver) void {
                self.inner.deinit();
                self.* = undefined;
            }
        };

        /// The application's block under `payload`, which must commit to it; its shards are
        /// coded on demand.
        pub fn from_application_block(block: broadcast.Digested(B), payload: Commitment) Block {
            return Block.precomputed(block, payload);
        }

        pub fn max_backfill_block_size(application: usize) usize {
            return Block.max_encode_size(application);
        }

        /// An upper bound on the encoded size of any shard a committee of 4 to
        /// `participants` members codes from a block of at most `application` bytes. Panics
        /// if `participants` is below 4 or above `maxInt(u16)`.
        pub fn max_buffer_payload_size(participants: u32, application: usize) usize {
            return types.max_buffer_payload_size(B, C, H, participants, application);
        }
    };
}

/// The shards engine's mailbox as the coding variant's buffer (commonware's `Buffer` impl on
/// `shards::Mailbox`), called on a pointer.
pub fn Buffer(comptime B: type, comptime C: type, comptime H: type, comptime P: type) type {
    const Mailbox = shards_mailbox.Mailbox(B, C, H);
    return struct {
        const Self = @This();
        pub const PublicKey = P;
        pub const Block = Mailbox.Coded;
        pub const Commitment = Mailbox.Commitment;

        mailbox: Mailbox,

        /// Adapts `mailbox` (owned).
        pub fn init(mailbox: Mailbox) Self {
            return .{ .mailbox = mailbox };
        }

        pub fn deinit(self: *Self) void {
            self.mailbox.deinit();
            self.* = undefined;
        }

        pub fn find_by_digest(self: *Self, digest: B.Digest) !?Block {
            return self.mailbox.get_by_digest(digest);
        }

        pub fn find_by_commitment(self: *Self, commitment: Commitment) !?Block {
            return self.mailbox.get(commitment);
        }

        pub fn subscribe_by_digest(self: *Self, digest: B.Digest) !?oneshot.Receiver(Block) {
            return try self.mailbox.subscribe_by_digest(digest);
        }

        pub fn subscribe_by_commitment(
            self: *Self,
            commitment: Commitment,
        ) !?oneshot.Receiver(Block) {
            return try self.mailbox.subscribe(commitment);
        }

        /// Disperses `block` (owned) to the participants: the coding variant does not
        /// support targeted forwarding, so `recipients` is ignored.
        pub fn send(self: *Self, round: Round, block: Block, recipients: anytype) !void {
            _ = recipients;
            try self.mailbox.disperse(round, block);
        }
    };
}
