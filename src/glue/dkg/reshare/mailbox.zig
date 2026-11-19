//! Reshare actor ingress (commonware `glue::dkg::reshare::mailbox`).
//!
//! The actor's type parameters come in one comptime struct `T` (commonware's `B, V, C, A`),
//! checked by `assert_types`: `T.Block` (a `dkg.assert_reshare_block` application block),
//! `T.Ack` (a `utils.acknowledgement`, such as `Exact`), and `T.Ancestry` (a
//! `consensus.marshal.ancestry` stream of `broadcast.Digested(Block)`, newest first).
//!
//! Rust's async mailbox methods block on the runtime's `std.Io` here. Responders are
//! `utils.channel.oneshot` senders; a message the mailbox drops releases what it owns
//! (`discard`), so a dropped request reads as closed to its caller. Rust's tracing spans are
//! not carried.
//!
//! Unlike commonware, a `next_log` request carries no sender of this mailbox: the actor
//! answers with the payload, and `Mailbox.next_log` wraps it in a `LogReservation` holding its
//! own sender. A message that owned a sender could not be dropped by the overflow policy,
//! which runs under the mailbox lock. A canceled `next_log` closes its responder first and
//! releases a log that already arrived, as dropping commonware's reservation does.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const broadcast = @import("broadcast");
const consensus = @import("consensus");
const utils = @import("utils");
const dkg = @import("../root.zig");
const types = @import("../types.zig");

const Feedback = actor.Feedback;
const Height = consensus.Height;
const oneshot = utils.channel.oneshot;

/// Asserts `T` carries the reshare actor's type parameters (see the file header).
pub fn assert_types(comptime T: type) void {
    comptime {
        for (.{ "Block", "Ack", "Ancestry" }) |decl| {
            if (!@hasDecl(T, decl)) @compileError(@typeName(T) ++ " lacks reshare." ++ decl);
        }
        dkg.assert_reshare_block(T.Block);
        utils.acknowledgement.assert_acknowledgement(T.Ack);
        consensus.marshal.ancestry.assert_ancestry(T.Ancestry);
    }
}

/// The reshare `types.Payload` carried by `T.Block`.
pub fn PayloadOf(comptime T: type) type {
    return types.Payload(T.Block.Variant, T.Block.PublicKey, T.Block.Directory);
}

/// What marshal reports to the application (`consensus.marshal.Update`).
pub const Update = consensus.marshal.Update;

/// Response to `Mailbox.epoch_info`.
pub fn EpochInfoResponse(comptime Pl: type) type {
    return union(enum) {
        const Self = @This();

        /// The payload the final block must carry. A null `payload` means the final block
        /// must carry none; continuous reshare always returns one.
        available: struct { gpa: Allocator, payload: ?Pl },
        /// The actor has no payload for this request, so the response says nothing about
        /// whether a proposed payload is valid.
        unavailable,

        pub fn deinit(self: *Self) void {
            switch (self.*) {
                .available => |*available| if (available.payload) |*payload| {
                    payload.deinit(available.gpa);
                },
                .unavailable => {},
            }
            self.* = undefined;
        }

        /// Releases a response nobody received.
        pub fn discard(self: Self) void {
            var response = self;
            response.deinit();
        }

        pub fn eql(a: Self, b: Self) bool {
            if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
            if (a == .unavailable) return true;
            const left = a.available.payload;
            const right = b.available.payload;
            if (left == null or right == null) return left == null and right == null;
            return left.?.eql(right.?);
        }
    };
}

/// A dealer log reserved for one proposal attempt.
///
/// `deinit` without `included` releases the log back to the actor (Rust's `Drop`). Call
/// `included` only after the application returns a block built with the payload.
pub fn LogReservation(comptime T: type) type {
    return struct {
        const Self = @This();
        const Payload = PayloadOf(T);

        gpa: Allocator,
        height: Height,
        payload: ?Payload,
        release: ?actor.mailbox.Sender(Message(T)),

        pub fn init(
            gpa: Allocator,
            height: Height,
            payload: Payload,
            release: actor.mailbox.Sender(Message(T)),
        ) Self {
            const result: Self = .{
                .gpa = gpa,
                .height = height,
                .payload = payload,
                .release = release,
            };
            assert(result.payload != null);
            assert(result.release != null);
            return result;
        }

        /// Takes the reserved payload; null if it was already taken.
        pub fn take_payload(self: *Self) ?Payload {
            const payload = self.payload;
            self.payload = null;
            assert(self.payload == null);
            return payload;
        }

        /// Keeps the log reserved: no other proposal receives it unless finalization reaches
        /// this height without including it. Releases the reservation.
        pub fn included(self: *Self) void {
            assert(self.release != null);
            var release = self.release.?;
            self.release = null;
            release.deinit();
            self.deinit();
        }

        /// Releases the reservation, returning the log to the actor unless `included` ran.
        pub fn deinit(self: *Self) void {
            if (self.payload) |*payload| payload.deinit(self.gpa);
            if (self.release) |*release| {
                const body: Message(T).Body = .{ .release_log = self.height };
                _ = release.enqueue(.{ .gpa = self.gpa, .body = body }) catch {};
                release.deinit();
            }
            self.* = undefined;
        }
    };
}

/// A message to the reshare actor (commonware `Message`).
pub fn Message(comptime T: type) type {
    return struct {
        const Self = @This();
        pub const Digested = broadcast.Digested(T.Block);
        pub const Response = EpochInfoResponse(PayloadOf(T));
        pub const Overflow = std.Deque(Self);

        /// Frees what the body owns.
        gpa: Allocator,
        body: Body,

        pub const Body = union(enum) {
            /// A request for this node's dealer log to include in a block before the epoch's
            /// final block. Once a log is served at `height`, later requests receive none
            /// until its reservation is released or finalization reaches `height` without
            /// including it.
            next_log: struct { height: Height, response: oneshot.Sender(?PayloadOf(T)) },
            /// A proposal attempt was canceled or returned no block after receiving a log.
            release_log: Height,
            /// A request for the payload of an epoch's final block (`Mailbox.epoch_info`).
            epoch_info: struct { ancestry: T.Ancestry, response: oneshot.Sender(Response) },
            /// A finalized block reported by marshal, acknowledged through `response` once
            /// its effects are complete.
            finalized: struct { block: Digested, response: T.Ack },
        };

        /// Whether the caller dropped the receiver of this request's response.
        pub fn response_closed(self: *const Self) bool {
            return switch (self.body) {
                .next_log => |body| body.response.is_closed(),
                .epoch_info => |body| body.response.is_closed(),
                else => false,
            };
        }

        /// Releases a message nobody handles: closes its responder and frees what it owns.
        pub fn discard(message: Self) void {
            switch (message.body) {
                .next_log => |value| {
                    var body = value;
                    body.response.deinit();
                },
                .epoch_info => |value| {
                    var body = value;
                    body.response.deinit();
                    body.ancestry.deinit();
                },
                .finalized => |value| {
                    var body = value;
                    body.block.deinit();
                    body.response.deinit();
                },
                .release_log => {},
            }
        }

        /// The overflow policy (commonware `Policy::handle`): queues every message except a
        /// request whose caller is gone.
        pub fn handle(gpa: Allocator, overflow: *Overflow, message: Self) Allocator.Error!void {
            if (message.response_closed()) return discard(message);
            errdefer discard(message);
            try overflow.pushBack(gpa, message);
            assert(overflow.len > 0);
        }
    };
}

/// Inbox for sending messages to the reshare actor (commonware `Mailbox`).
pub fn Mailbox(comptime T: type) type {
    comptime assert_types(T);
    return struct {
        const Self = @This();
        pub const M = Message(T);
        pub const Reservation = LogReservation(T);
        pub const Response = M.Response;
        pub const Error = Allocator.Error || Io.Cancelable;

        gpa: Allocator,
        io: Io,
        sender: actor.mailbox.Sender(M),

        /// A mailbox that sends to the actor behind `sender` (takes it).
        pub fn init(gpa: Allocator, io: Io, sender: actor.mailbox.Sender(M)) Self {
            const result: Self = .{ .gpa = gpa, .io = io, .sender = sender };
            assert(result.sender.capacity() > 0);
            return result;
        }

        pub fn clone(self: Self) Self {
            var copy = self;
            copy.sender = self.sender.clone();
            assert(copy.sender.capacity() == self.sender.capacity());
            return copy;
        }

        pub fn deinit(self: *Self) void {
            self.sender.deinit();
            self.* = undefined;
        }

        /// Requests this node's dealer log for the block being proposed at `height`.
        ///
        /// Returns null if no log is available (this node does not deal this epoch, outside
        /// the inclusion window, while an earlier reservation is outstanding, or once the
        /// log is included) or if the actor has stopped.
        pub fn next_log(self: Self, height: Height) Error!?Reservation {
            var pair = try oneshot.channel(?PayloadOf(T), self.gpa, self.io);
            defer pair.receiver.deinit();
            const body: M.Body = .{ .next_log = .{ .height = height, .response = pair.sender } };
            const feedback = try self.sender.enqueue(.{ .gpa = self.gpa, .body = body });
            if (!feedback.accepted()) return null;
            const answer = pair.receiver.recv() catch |err| switch (err) {
                error.Closed => return null,
                error.Canceled => {
                    // Refuse a later answer, then release one that already arrived.
                    pair.receiver.close();
                    const late = pair.receiver.try_recv() catch return error.Canceled;
                    if (late) |payload| {
                        var reservation = Reservation.init(
                            self.gpa,
                            height,
                            payload,
                            self.sender.clone(),
                        );
                        reservation.deinit();
                    }
                    return error.Canceled;
                },
            };
            const payload = answer orelse return null;
            return Reservation.init(self.gpa, height, payload, self.sender.clone());
        }

        /// Requests the payload for an epoch's final block (takes `ancestry`).
        ///
        /// `ancestry` starts at the final block (verification) or at its parent (proposal)
        /// and must build on the last finalized block the actor has applied. A participating
        /// actor answers once it has applied every block before the midpoint; an earlier
        /// request waits until then.
        ///
        /// Returns `.unavailable` when `ancestry` is cut short or does not build on that
        /// block, when the actor follows the chain without participating, when the request
        /// is still queued as the actor applies the epoch's final block, or when the actor
        /// has stopped.
        pub fn epoch_info(self: Self, ancestry: T.Ancestry) Error!Response {
            var owned = ancestry;
            var pair = oneshot.channel(Response, self.gpa, self.io) catch |err| {
                owned.deinit();
                return err;
            };
            defer pair.receiver.deinit();
            const body: M.Body = .{ .epoch_info = .{ .ancestry = owned, .response = pair.sender } };
            const feedback = try self.sender.enqueue(.{ .gpa = self.gpa, .body = body });
            if (!feedback.accepted()) return .unavailable;
            return pair.receiver.recv() catch |err| switch (err) {
                error.Closed => .unavailable,
                error.Canceled => error.Canceled,
            };
        }

        /// Forwards a finalized block from marshal (commonware `Reporter::report`); a tip
        /// update is ignored. Takes `update`. Panics when the overflow cannot grow, as Rust
        /// aborts on allocation failure.
        pub fn report(self: Self, update: Update(T.Block, T.Ack)) Feedback {
            switch (update) {
                .tip => return .ok,
                .block => |block| {
                    const body: M.Body = .{ .finalized = .{
                        .block = block.block,
                        .response = block.ack,
                    } };
                    const feedback = self.sender.enqueue(.{ .gpa = self.gpa, .body = body });
                    return feedback catch @panic("out of memory");
                },
            }
        }
    };
}
