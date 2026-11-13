//! The engine's mailbox (commonware `broadcast/src/buffered/ingress.rs`).
//!
//! Requests beyond the inbox capacity wait in `Pending`, in order. While in overflow,
//! broadcasts with the same digest combine recipients and are handled once at the first
//! broadcast's position. Canceled get and subscribe requests are discarded.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const actor = @import("actor");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const utils = @import("utils");

const Feedback = actor.Feedback;
const Digested = @import("../digested.zig").Digested;
const oneshot = utils.channel.oneshot;
const SortedMap = p2p.simulated.sorted_map.SortedMap;

/// The answer to a `get` request: the cached message, if any.
pub fn GetResult(comptime M: type) type {
    return struct {
        value: ?Digested(M),

        /// Drops an unreceived answer (called by the oneshot channel).
        pub fn discard(result: @This()) void {
            if (result.value) |value| value.discard();
        }
    };
}

/// Message types that can be sent to the `Mailbox`.
pub const Message = Request;

fn Request(comptime P: type, comptime M: type) type {
    return union(enum) {
        const Self = @This();
        pub const Overflow = Pending(P, M);

        /// Broadcast a message to the network. `recipients` is owned (a `some` slice is
        /// freed with `gpa`).
        broadcast: Broadcast,
        /// Subscribe to receive a message by digest.
        subscribe: Subscribe,
        /// Get a message by digest.
        get: Get,

        pub const Broadcast = struct {
            gpa: Allocator,
            recipients: p2p.Recipients(P),
            message: Digested(M),
        };
        pub const Subscribe = struct {
            digest: M.Digest,
            responder: oneshot.Sender(Digested(M)),
        };
        pub const Get = struct {
            digest: M.Digest,
            responder: oneshot.Sender(GetResult(M)),
        };

        pub fn response_closed(message: Self) bool {
            return switch (message) {
                .subscribe => |request| request.responder.is_closed(),
                .get => |request| request.responder.is_closed(),
                .broadcast => false,
            };
        }

        /// Releases everything the message owns (Rust `Drop`).
        pub fn discard(message: Self) void {
            switch (message) {
                .broadcast => |request| {
                    request.recipients.deinit(request.gpa);
                    request.message.discard();
                },
                .subscribe => |request| {
                    var responder = request.responder;
                    responder.deinit();
                },
                .get => |request| {
                    var responder = request.responder;
                    responder.deinit();
                },
            }
        }

        /// The overflow policy (commonware `Policy::handle`).
        pub fn handle(gpa: Allocator, overflow: *Overflow, message: Self) Allocator.Error!void {
            if (message.response_closed()) return discard(message);
            switch (message) {
                .broadcast => |request| return overflow.add_broadcast(gpa, request),
                else => {
                    overflow.queue.pushBack(gpa, .{ .message = message }) catch |err| {
                        discard(message);
                        return err;
                    };
                },
            }
            assert(!overflow.is_empty());
        }
    };
}

/// Requests waiting for room in the engine's inbox. Each pending broadcast digest occurs
/// exactly once in both `queue` and `broadcasts`.
pub fn Pending(comptime P: type, comptime M: type) type {
    return struct {
        const Self = @This();
        const Msg = Message(P, M);
        const Recipients = p2p.Recipients(P);

        /// A queued request; a broadcast's recipients are held in `broadcasts`.
        const Entry = union(enum) {
            message: Msg,
            broadcast: struct { gpa: Allocator, message: Digested(M) },
        };

        /// Requests in arrival order, with coalesced broadcasts at their first position.
        queue: std.Deque(Entry) = .empty,
        /// Recipients of each queued broadcast.
        broadcasts: SortedMap(M.Digest, Recipients) = .empty,

        pub const empty: Self = .{};

        pub fn deinit(pending: *Self, gpa: Allocator) void {
            assert(pending.is_empty());
            assert(pending.broadcasts.count() == 0);
            pending.queue.deinit(gpa);
            pending.broadcasts.deinit(gpa);
            pending.* = undefined;
        }

        pub fn is_empty(pending: *const Self) bool {
            return pending.queue.len == 0;
        }

        /// Merges at the first queued occurrence so duplicates cannot postpone its delivery.
        fn add_broadcast(pending: *Self, gpa: Allocator, request: Msg.Broadcast) !void {
            const message: Msg = .{ .broadcast = request };
            errdefer Msg.discard(message);
            const digest = request.message.digest();
            if (pending.broadcasts.get(digest)) |queued| {
                const merged = try Recipients.union_with(gpa, queued.*, request.recipients);
                queued.deinit(gpa);
                queued.* = merged;
                Msg.discard(message);
                return;
            }
            try pending.queue.ensureUnusedCapacity(gpa, 1);
            assert(try pending.broadcasts.put(gpa, digest, request.recipients) == null);
            pending.queue.pushBackAssumeCapacity(.{
                .broadcast = .{ .gpa = request.gpa, .message = request.message },
            });
        }

        /// Hands queued requests to `pusher.push(message) ?Message` in order, skipping
        /// canceled ones, until it returns one back. The returned request stays queued (with
        /// its digest still indexed for coalescing), so nothing allocates here.
        pub fn drain(pending: *Self, pusher: anytype) void {
            const len_before = pending.queue.len;
            var iterations: usize = 0;
            while (pending.queue.len > 0) : (iterations += 1) {
                assert(iterations < len_before);
                const entry = pending.queue.at(0);
                const message: Msg = switch (entry) {
                    .message => |queued| queued,
                    .broadcast => |queued| .{ .broadcast = .{
                        .gpa = queued.gpa,
                        .recipients = pending.broadcasts.get(queued.message.digest()).?.*,
                        .message = queued.message,
                    } },
                };
                if (message.response_closed()) {
                    _ = pending.queue.popFront();
                    Msg.discard(message);
                    continue;
                }
                // A returned message is the queued one, still owned by the queue.
                if (pusher.push(message) != null) return;
                _ = pending.queue.popFront();
                if (entry == .broadcast) {
                    _ = pending.broadcasts.remove(entry.broadcast.message.digest()).?;
                }
            }
            assert(pending.broadcasts.count() == 0);
        }
    };
}

/// Ingress mailbox for the engine. Clone with `clone`, release with `deinit`.
pub fn Mailbox(comptime P: type, comptime M: type) type {
    return struct {
        const Self = @This();
        const Msg = Request(P, M);
        pub const Recipients = p2p.Recipients(P);
        pub const Message = Digested(M);

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

        /// Subscribe to a message by digest. Resolves with the message if cached when this
        /// request is handled; otherwise waits for a matching local broadcast or network
        /// message. Dropping the receiver cancels the request. If the engine has shut down,
        /// the receiver fails with `error.Closed`.
        pub fn subscribe(mailbox: Self, digest: M.Digest) !oneshot.Receiver(Digested(M)) {
            const pair = try oneshot.channel(Digested(M), mailbox.gpa, mailbox.io);
            const request: Msg = .{ .subscribe = .{ .digest = digest, .responder = pair.sender } };
            var receiver = pair.receiver;
            errdefer receiver.deinit();
            _ = try mailbox.sender.enqueue(request);
            return receiver;
        }

        /// The message cached under `digest` when the request is handled; null if none or if
        /// the engine has shut down. The caller owns the returned handle.
        pub fn get(mailbox: Self, digest: M.Digest) !?Digested(M) {
            const pair = try oneshot.channel(GetResult(M), mailbox.gpa, mailbox.io);
            var receiver = pair.receiver;
            defer receiver.deinit();
            const request: Msg = .{ .get = .{ .digest = digest, .responder = pair.sender } };
            _ = try mailbox.sender.enqueue(request);
            const result = receiver.recv() catch |err| switch (err) {
                error.Closed => return null,
                error.Canceled => return error.Canceled,
            };
            return result.value;
        }

        /// Broadcast `message` (owned from now on) to `recipients` (copied). Feedback says
        /// whether the engine accepted the request, not whether recipients received it;
        /// `closed` once the engine has shut down (commonware `Broadcaster::broadcast`).
        pub fn broadcast(
            mailbox: Self,
            recipients: Recipients,
            message: Digested(M),
        ) Allocator.Error!Feedback {
            const owned: Recipients = switch (recipients) {
                .some => |peers| .{ .some = mailbox.gpa.dupe(P, peers) catch |err| {
                    message.discard();
                    return err;
                } },
                else => recipients,
            };
            return mailbox.sender.enqueue(.{ .broadcast = .{
                .gpa = mailbox.gpa,
                .recipients = owned,
                .message = message,
            } });
        }
    };
}
