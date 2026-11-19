//! Orchestrator ingress (commonware `glue::dkg::orchestrator::mailbox`).
//!
//! `Mailbox(B, A)` is a marshal reporter: it forwards each finalized block of `B` (a
//! `dkg.assert_reshare_block` application block) with its acknowledgement `A` to the
//! orchestrator and ignores tip updates. Overflow is reliable, because a dropped report would
//! leave its block unacknowledged and stall marshal.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const actor = @import("actor");
const broadcast = @import("broadcast");
const consensus = @import("consensus");
const utils = @import("utils");
const dkg = @import("../root.zig");

const Feedback = actor.Feedback;

/// A message to the orchestrator (commonware `Message`).
pub fn Message(comptime B: type, comptime A: type) type {
    comptime dkg.assert_reshare_block(B);
    comptime utils.acknowledgement.assert_acknowledgement(A);
    return union(enum) {
        const Self = @This();
        pub const Overflow = std.Deque(Self);

        /// A block finalized by marshal. The orchestrator acknowledges the final block of the
        /// active epoch only after entering the next epoch, and every earlier block at once.
        /// A later block means marshal skipped the final block (`error.InvalidLocalState`).
        finalized: struct { block: broadcast.Digested(B), ack: A },

        /// Releases a message nobody handles.
        pub fn discard(message: Self) void {
            switch (message) {
                .finalized => |value| {
                    var body = value;
                    body.block.deinit();
                    body.ack.deinit();
                },
            }
        }

        /// The overflow policy (commonware `Policy::handle`): queues every message.
        pub fn handle(gpa: Allocator, overflow: *Overflow, message: Self) Allocator.Error!void {
            assert(message == .finalized);
            errdefer discard(message);
            try overflow.pushBack(gpa, message);
            assert(overflow.len > 0);
        }
    };
}

/// Marshal reporter that forwards finalized blocks to the orchestrator (commonware
/// `Mailbox`).
pub fn Mailbox(comptime B: type, comptime A: type) type {
    return struct {
        const Self = @This();
        pub const M = Message(B, A);

        sender: actor.mailbox.Sender(M),

        /// A mailbox that sends to the orchestrator behind `sender` (takes it).
        pub fn init(sender: actor.mailbox.Sender(M)) Self {
            const result: Self = .{ .sender = sender };
            assert(result.sender.capacity() > 0);
            return result;
        }

        pub fn clone(self: Self) Self {
            const copy: Self = .{ .sender = self.sender.clone() };
            assert(copy.sender.capacity() == self.sender.capacity());
            return copy;
        }

        pub fn deinit(self: *Self) void {
            assert(self.sender.capacity() > 0);
            self.sender.deinit();
            self.* = undefined;
        }

        /// Forwards a finalized block (commonware `Reporter::report`); a tip is ignored.
        /// Takes `update`.
        pub fn report(self: Self, update: consensus.marshal.Update(B, A)) Allocator.Error!Feedback {
            assert(self.sender.capacity() > 0);
            switch (update) {
                .tip => return .ok,
                .block => |value| {
                    return self.sender.enqueue(.{
                        .finalized = .{ .block = value.block, .ack = value.ack },
                    });
                },
            }
        }
    };
}
