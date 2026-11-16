//! Resolver engine callbacks forwarded to the state sync p2p actor (commonware
//! `glue/src/stateful/db/p2p/handler.rs`).
//!
//! `Handler` is the engine's consumer and producer: it turns each callback into an
//! `EngineMessage` on the actor's mailbox, so all mutable state stays on the actor task. When
//! the mailbox's ready queue is full, peer requests are dropped (the peer can ask a less loaded
//! peer) and deliveries are retained while their requester still waits.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const resolver = @import("resolver");
const storage = @import("storage");
const utils = @import("utils");

const oneshot = utils.channel.oneshot;
pub const Produced = resolver.p2p.Produced;

/// A caller's reply route, identified independently of the peer-visible request; subscribers
/// compare by `id` alone.
pub fn Subscriber(comptime Reply: type) type {
    return struct {
        const Self = @This();

        id: u64,
        reply: Reply,

        pub fn order(a: Self, b: Self) std.math.Order {
            return std.math.order(a.id, b.id);
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.id == b.id;
        }
    };
}

/// An engine callback forwarded to the actor. A message owns its copies of the delivery's
/// subscribers and value; `deinit` (or `discard`) releases them and drops an unanswered
/// response, which the engine sees as closed.
pub fn EngineMessage(comptime F: type, comptime S: type) type {
    return union(enum) {
        const Self = @This();
        pub const Request = storage.qmdb.sync.Request(F);
        pub const Delivery = resolver.Delivery(Request, S);

        /// A peer response for the subscribers in `delivery`. Send its validity through
        /// `response`, or drop it to leave the delivery unjudged.
        deliver: struct {
            gpa: Allocator,
            delivery: Delivery,
            value: []const u8,
            response: oneshot.Sender(bool),
        },
        /// A peer request for `key`. Send an encoded sync `Response` through `response`, or
        /// drop it if the request cannot be served.
        produce: struct { key: Request, response: oneshot.Sender(Produced) },

        /// Whether the engine stopped waiting for this message's response.
        pub fn response_closed(self: *const Self) bool {
            return switch (self.*) {
                inline else => |*message| message.response.is_closed(),
            };
        }

        /// Releases the message, dropping its response unanswered.
        pub fn deinit(self: *Self) void {
            switch (self.*) {
                .deliver => |*message| {
                    message.gpa.free(message.delivery.subscribers);
                    message.gpa.free(message.value);
                    message.response.deinit();
                },
                .produce => |*message| message.response.deinit(),
            }
            self.* = undefined;
        }

        /// The mailbox's hook for a message it drops.
        pub fn discard(message: Self) void {
            var owned = message;
            owned.deinit();
        }

        /// Deliveries retained while the ready queue is full.
        pub const Overflow = struct {
            pending: std.Deque(Self) = .empty,

            pub const empty: Overflow = .{};

            pub fn deinit(overflow: *Overflow, gpa: Allocator) void {
                assert(overflow.pending.len == 0);
                overflow.pending.deinit(gpa);
            }

            pub fn is_empty(overflow: *const Overflow) bool {
                return overflow.pending.len == 0;
            }

            /// Hands retained deliveries to `pusher` in order, dropping those whose
            /// requester left, until ready is full again.
            pub fn drain(overflow: *Overflow, pusher: anytype) void {
                while (overflow.pending.popFront()) |message| {
                    if (message.response_closed()) {
                        discard(message);
                        continue;
                    }
                    const returned = pusher.push(message) orelse continue;
                    // Proof: the slot `popFront` freed is still free.
                    overflow.pending.pushFrontAssumeCapacity(returned);
                    break;
                }
            }
        };

        /// Drops an overflowed peer request (deliveries to local callers keep priority) and
        /// retains a delivery whose requester still waits.
        pub fn handle(gpa: Allocator, overflow: *Overflow, message: Self) Allocator.Error!void {
            if (message == .produce or message.response_closed()) {
                discard(message);
                return;
            }
            overflow.pending.pushBack(gpa, message) catch |err| {
                discard(message);
                return err;
            };
        }
    };
}

/// Forwards resolver consumer and producer callbacks to the actor as `EngineMessage`s.
pub fn Handler(comptime F: type, comptime S: type) type {
    return struct {
        const Self = @This();
        pub const Message = EngineMessage(F, S);
        // resolver.Consumer
        pub const Key = Message.Request;
        pub const Value = []const u8;
        pub const Subscriber = S;
        pub const Outcome = bool;

        gpa: Allocator,
        io: Io,
        sender: actor.mailbox.Sender(Message),

        pub fn clone(self: Self) Self {
            return .{ .gpa = self.gpa, .io = self.io, .sender = self.sender.clone() };
        }

        pub fn deinit(self: *Self) void {
            self.sender.deinit();
            self.* = undefined;
        }

        /// Forwards a peer response; the receiver resolves with its validity, or closes when
        /// the actor leaves it unjudged.
        pub fn deliver(
            self: Self,
            delivery: Message.Delivery,
            value: []const u8,
        ) Allocator.Error!oneshot.Receiver(bool) {
            assert(delivery.subscribers.len > 0);
            var pair = try oneshot.channel(bool, self.gpa, self.io);
            const message = self.copy_delivery(delivery, value, pair.sender) catch |err| {
                pair.sender.deinit();
                pair.receiver.deinit();
                return err;
            };
            // The mailbox owns the message from here, also when `enqueue` fails (the policy
            // discards it, closing the receiver). commonware ignores the feedback too.
            _ = self.sender.enqueue(message) catch |err| {
                pair.receiver.deinit();
                return err;
            };
            return pair.receiver;
        }

        fn copy_delivery(
            self: Self,
            delivery: Message.Delivery,
            value: []const u8,
            response: oneshot.Sender(bool),
        ) Allocator.Error!Message {
            const subscribers = try self.gpa.dupe(S, delivery.subscribers);
            errdefer self.gpa.free(subscribers);
            return .{ .deliver = .{
                .gpa = self.gpa,
                .delivery = .{ .key = delivery.key, .subscribers = subscribers },
                .value = try self.gpa.dupe(u8, value),
                .response = response,
            } };
        }

        /// Forwards a peer request; the receiver closes when it cannot be served.
        pub fn produce(self: Self, key: Key) Allocator.Error!oneshot.Receiver(Produced) {
            var pair = try oneshot.channel(Produced, self.gpa, self.io);
            const message: Message = .{ .produce = .{ .key = key, .response = pair.sender } };
            _ = self.sender.enqueue(message) catch |err| {
                pair.receiver.deinit();
                return err;
            };
            return pair.receiver;
        }
    };
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("handler_test.zig");
}
