//! Mailbox for the shard engine (commonware `marshal/coding/shards/mailbox.rs`).
//!
//! Commonware shares coded blocks as `Arc<CodedBlock>`; here a `CodedBlock` handle already
//! shares its block and shards, so messages carry handles (owned; released with `deinit`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const utils = @import("utils");

const types = @import("../types.zig");
const Round = @import("../../../types.zig").Round;

const oneshot = utils.channel.oneshot;

/// The answer to a `get` request: the reconstructed block, if any.
pub fn GetResult(comptime Coded: type) type {
    return struct {
        value: ?Coded,

        /// Drops an unreceived answer (called by the oneshot channel).
        pub fn discard(result: @This()) void {
            if (result.value) |value| value.discard();
        }
    };
}

/// A message to the shard engine. Blocks and responders are owned.
pub fn Message(comptime B: type, comptime C: type, comptime H: type) type {
    return union(enum) {
        const Self = @This();
        pub const Coded = types.CodedBlock(B, C, H);
        pub const Commitment = Coded.Commitment;
        pub const Overflow = Pending(Self);

        /// Disperse the shards of a proposed block.
        disperse: struct { block: Coded, round: Round },
        /// Gather the shards of a commitment consensus observed through a proposal or a
        /// notarization.
        gather: struct { commitment: Commitment, round: Round },
        /// Get a reconstructed block, if available.
        get_by_commitment: struct {
            commitment: Commitment,
            responder: oneshot.Sender(GetResult(Coded)),
        },
        /// Get a reconstructed block by its digest, if available.
        get_by_digest: struct {
            digest: B.Digest,
            responder: oneshot.Sender(GetResult(Coded)),
        },
        /// Resolves once the local participant's assigned shard is verified (at once for
        /// the proposer, never for a non-participant). A block reconstructed from gossip does
        /// not resolve it.
        subscribe_assigned_shard_verified: struct {
            commitment: Commitment,
            responder: oneshot.Sender(void),
        },
        /// Resolves with the block once it is reconstructed.
        subscribe_by_commitment: struct {
            commitment: Commitment,
            responder: oneshot.Sender(Coded),
        },
        /// Resolves with the block once it is reconstructed.
        subscribe_by_digest: struct {
            digest: B.Digest,
            responder: oneshot.Sender(Coded),
        },

        pub fn response_closed(message: Self) bool {
            return switch (message) {
                .get_by_commitment => |request| request.responder.is_closed(),
                .get_by_digest => |request| request.responder.is_closed(),
                .subscribe_assigned_shard_verified => |request| request.responder.is_closed(),
                .subscribe_by_commitment => |request| request.responder.is_closed(),
                .subscribe_by_digest => |request| request.responder.is_closed(),
                .disperse, .gather => false,
            };
        }

        /// Releases everything the message owns (Rust `Drop`).
        pub fn discard(message: Self) void {
            switch (message) {
                .disperse => |request| request.block.discard(),
                .gather => {},
                inline else => |request| {
                    var responder = request.responder;
                    responder.deinit();
                },
            }
        }

        /// Retains overflowed messages in FIFO order, dropping those nobody awaits.
        pub fn handle(gpa: Allocator, overflow: *Overflow, message: Self) Allocator.Error!void {
            if (message.response_closed()) return discard(message);
            overflow.queue.pushBack(gpa, message) catch |err| {
                discard(message);
                return err;
            };
            assert(!overflow.is_empty());
        }
    };
}

/// Messages waiting for room in the engine's inbox, in arrival order.
pub fn Pending(comptime Msg: type) type {
    return struct {
        const Self = @This();

        queue: std.Deque(Msg) = .empty,

        pub const empty: Self = .{};

        pub fn deinit(pending: *Self, gpa: Allocator) void {
            while (pending.queue.popFront()) |message| Msg.discard(message);
            pending.queue.deinit(gpa);
            pending.* = undefined;
        }

        pub fn is_empty(pending: *const Self) bool {
            return pending.queue.len == 0;
        }

        /// Hands queued messages to `pusher.push(message) ?Msg` in order, dropping those whose
        /// responder closed, until it returns one back; that one stays queued.
        pub fn drain(pending: *Self, pusher: anytype) void {
            const len_before = pending.queue.len;
            var iterations: usize = 0;
            while (pending.queue.popFront()) |message| : (iterations += 1) {
                assert(iterations < len_before);
                if (message.response_closed()) {
                    Msg.discard(message);
                    continue;
                }
                if (pusher.push(message)) |rejected| {
                    // The slot `popFront` just freed holds it, so this never allocates.
                    pending.queue.pushFrontAssumeCapacity(rejected);
                    break;
                }
            }
            assert(pending.queue.len <= len_before);
        }
    };
}

/// A mailbox for the shard engine. Clone with `clone`, release with `deinit`.
pub fn Mailbox(comptime B: type, comptime C: type, comptime H: type) type {
    return struct {
        const Self = @This();
        pub const Msg = Message(B, C, H);
        pub const Coded = Msg.Coded;
        pub const Commitment = Msg.Commitment;

        gpa: Allocator,
        io: Io,
        sender: actor.mailbox.Sender(Msg),

        pub fn clone(mailbox: Self) Self {
            return .{ .gpa = mailbox.gpa, .io = mailbox.io, .sender = mailbox.sender.clone() };
        }

        pub fn deinit(mailbox: *Self) void {
            mailbox.sender.deinit();
            mailbox.* = undefined;
        }

        /// Disperses a proposed block's shards (`block` owned) to the participants.
        pub fn disperse(mailbox: Self, round: Round, block: Coded) Allocator.Error!void {
            _ = try mailbox.sender.enqueue(.{ .disperse = .{ .block = block, .round = round } });
        }

        /// Gathers the shards of `commitment`, observed by consensus in `round`.
        ///
        /// If the engine holds no record of the commitment and its record window admits
        /// `round`, it starts reconstructing the block from the shards its peers sent,
        /// including those buffered before this call; a later call only raises its round.
        /// `round` must come from a trusted consensus observation, its epoch validated for
        /// `commitment`, and the commitment's coding config validated against that epoch's
        /// participant set (proposal verification does it; a notarization implies it).
        pub fn gather(mailbox: Self, commitment: Commitment, round: Round) Allocator.Error!void {
            const message: Msg = .{ .gather = .{ .commitment = commitment, .round = round } };
            _ = try mailbox.sender.enqueue(message);
        }

        /// The reconstructed block with `commitment`, if any (caller-owned).
        pub fn get(mailbox: Self, commitment: Commitment) !?Coded {
            const pair = try oneshot.channel(GetResult(Coded), mailbox.gpa, mailbox.io);
            var receiver = pair.receiver;
            defer receiver.deinit();
            const message: Msg = .{ .get_by_commitment = .{
                .commitment = commitment,
                .responder = pair.sender,
            } };
            _ = try mailbox.sender.enqueue(message);
            return receive_result(&receiver);
        }

        /// The reconstructed block with `digest`, if any (caller-owned).
        pub fn get_by_digest(mailbox: Self, digest: B.Digest) !?Coded {
            const pair = try oneshot.channel(GetResult(Coded), mailbox.gpa, mailbox.io);
            var receiver = pair.receiver;
            defer receiver.deinit();
            const message: Msg = .{ .get_by_digest = .{
                .digest = digest,
                .responder = pair.sender,
            } };
            _ = try mailbox.sender.enqueue(message);
            return receive_result(&receiver);
        }

        fn receive_result(receiver: *oneshot.Receiver(GetResult(Coded))) Io.Cancelable!?Coded {
            const result = receiver.recv() catch |err| switch (err) {
                error.Closed => return null,
                error.Canceled => return error.Canceled,
            };
            return result.value;
        }

        /// Resolves once the local participant's assigned shard for `commitment` is verified.
        pub fn subscribe_assigned_shard_verified(
            mailbox: Self,
            commitment: Commitment,
        ) !oneshot.Receiver(void) {
            const pair = try oneshot.channel(void, mailbox.gpa, mailbox.io);
            var receiver = pair.receiver;
            errdefer receiver.deinit();
            const message: Msg = .{ .subscribe_assigned_shard_verified = .{
                .commitment = commitment,
                .responder = pair.sender,
            } };
            _ = try mailbox.sender.enqueue(message);
            return receiver;
        }

        /// Resolves with the block once `commitment` is reconstructed.
        pub fn subscribe(mailbox: Self, commitment: Commitment) !oneshot.Receiver(Coded) {
            const pair = try oneshot.channel(Coded, mailbox.gpa, mailbox.io);
            var receiver = pair.receiver;
            errdefer receiver.deinit();
            const message: Msg = .{ .subscribe_by_commitment = .{
                .commitment = commitment,
                .responder = pair.sender,
            } };
            _ = try mailbox.sender.enqueue(message);
            return receiver;
        }

        /// Resolves with the block once the block with `digest` is reconstructed.
        pub fn subscribe_by_digest(mailbox: Self, digest: B.Digest) !oneshot.Receiver(Coded) {
            const pair = try oneshot.channel(Coded, mailbox.gpa, mailbox.io);
            var receiver = pair.receiver;
            errdefer receiver.deinit();
            const message: Msg = .{ .subscribe_by_digest = .{
                .digest = digest,
                .responder = pair.sender,
            } };
            _ = try mailbox.sender.enqueue(message);
            return receiver;
        }
    };
}

const testing = std.testing;
const cryptography = @import("cryptography");
const test_block = @import("../test_block.zig");

const TestMessage = Message(test_block.EmptyBlock, test_block.RS, cryptography.Sha256);

/// Collects every message it is handed.
const Collector = struct {
    drained: std.ArrayList(TestMessage) = .empty,

    fn push(collector: *Collector, message: TestMessage) ?TestMessage {
        collector.drained.appendAssumeCapacity(message);
        return null;
    }
};

fn test_round() Round {
    const consensus_types = @import("../../../types.zig");
    return .new(.zero(), consensus_types.View.new(1));
}

test "policy drains fifo" {
    const gpa = testing.allocator;
    const inner = test_block.EmptyBlock.init(.empty, 1, 1);
    var block = try test_block.encode_block(gpa, inner, types.coding_config_for_participants(4));
    defer block.deinit(gpa);
    const commitment = block.commitment();
    var overflow: TestMessage.Overflow = .empty;
    defer overflow.deinit(gpa);
    try TestMessage.handle(gpa, &overflow, .{ .gather = .{
        .commitment = commitment,
        .round = test_round(),
    } });
    const pair = try oneshot.channel(GetResult(TestMessage.Coded), gpa, testing.io);
    var receiver = pair.receiver;
    defer receiver.deinit();
    try TestMessage.handle(gpa, &overflow, .{ .get_by_commitment = .{
        .commitment = commitment,
        .responder = pair.sender,
    } });
    var collector: Collector = .{};
    try collector.drained.ensureTotalCapacity(gpa, 2);
    defer collector.drained.deinit(gpa);
    overflow.drain(&collector);
    defer for (collector.drained.items) |message| TestMessage.discard(message);
    try testing.expectEqual(@as(usize, 2), collector.drained.items.len);
    try testing.expect(collector.drained.items[0] == .gather);
    try testing.expect(collector.drained.items[1] == .get_by_commitment);
    try testing.expect(overflow.is_empty());
}

test "policy drops messages whose responder closed" {
    const gpa = testing.allocator;
    var overflow: TestMessage.Overflow = .empty;
    defer overflow.deinit(gpa);
    const digest = cryptography.Sha256.hash(&.{"block"});
    // Closed before `handle`: never retained.
    const early = try oneshot.channel(TestMessage.Coded, gpa, testing.io);
    var early_receiver = early.receiver;
    early_receiver.deinit();
    try TestMessage.handle(gpa, &overflow, .{ .subscribe_by_digest = .{
        .digest = digest,
        .responder = early.sender,
    } });
    try testing.expect(overflow.is_empty());
    // Closed while retained: dropped by `drain`, which still delivers the rest.
    const late = try oneshot.channel(TestMessage.Coded, gpa, testing.io);
    var late_receiver = late.receiver;
    try TestMessage.handle(gpa, &overflow, .{ .subscribe_by_digest = .{
        .digest = digest,
        .responder = late.sender,
    } });
    const kept = try oneshot.channel(void, gpa, testing.io);
    var kept_receiver = kept.receiver;
    defer kept_receiver.deinit();
    try TestMessage.handle(gpa, &overflow, .{ .subscribe_assigned_shard_verified = .{
        .commitment = .empty,
        .responder = kept.sender,
    } });
    late_receiver.deinit();
    var collector: Collector = .{};
    try collector.drained.ensureTotalCapacity(gpa, 2);
    defer collector.drained.deinit(gpa);
    overflow.drain(&collector);
    defer for (collector.drained.items) |message| TestMessage.discard(message);
    try testing.expectEqual(@as(usize, 1), collector.drained.items.len);
    try testing.expect(collector.drained.items[0] == .subscribe_assigned_shard_verified);
}
