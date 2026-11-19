//! Registered channels of an authenticated network (commonware
//! `p2p/src/authenticated/channels.rs`): a rate-limited sender and a lossy receiver per
//! channel. Every peer connection feeds a channel's one bounded inbound queue after its own
//! per-peer rate limiting; when the queue is full the arriving message is dropped.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const p2p = @import("../root.zig");
const limited = @import("../utils/limited.zig");
const Quota = @import("../rate_limit.zig").Quota;
const SortedMap = @import("../simulated/sorted_map.zig").SortedMap;
const router_mod = @import("router.zig");

const Channel = p2p.Channel;
const Feedback = p2p.Feedback;
const Unreliable = p2p.Unreliable;

/// A bounded, lossy, multi-producer queue of received messages. It grows only as messages
/// arrive, so a large capacity costs nothing until used.
pub fn Inbound(comptime P: type) type {
    return struct {
        const Self = @This();
        const Message = p2p.Message(P);

        gpa: Allocator,
        io: Io,
        mutex: Io.Mutex = .init,
        condition: Io.Condition = .init,
        capacity: usize,
        queue: std.Deque(Message) = .empty,
        /// No more messages arrive: the network shut down.
        closed: bool = false,
        /// The receiver is gone; arrivals are dropped.
        abandoned: bool = false,
        /// Handles holding the queue: the receiver and the network.
        handles: u32 = 2,

        pub fn create(gpa: Allocator, io: Io, capacity: usize) Allocator.Error!*Self {
            assert(capacity > 0);
            const inbound = try gpa.create(Self);
            inbound.* = .{ .gpa = gpa, .io = io, .capacity = capacity };
            return inbound;
        }

        /// Takes ownership of `message`. `rejected` when full, `closed` when the receiver
        /// is gone; either way the message is freed.
        pub fn enqueue(inbound: *Self, message: Message) Unreliable(Feedback) {
            var owned = message;
            inbound.mutex.lockUncancelable(inbound.io);
            defer inbound.mutex.unlock(inbound.io);
            if (inbound.abandoned or inbound.closed) {
                owned.deinit();
                return .new(.closed);
            }
            if (inbound.queue.len >= inbound.capacity) {
                owned.deinit();
                return .rejected;
            }
            inbound.queue.pushBack(inbound.gpa, owned) catch {
                owned.deinit();
                return .rejected;
            };
            inbound.condition.signal(inbound.io);
            return .new(.ok);
        }

        /// The next message, or null once closed and drained.
        pub fn recv(inbound: *Self) Io.Cancelable!?Message {
            try inbound.mutex.lock(inbound.io);
            defer inbound.mutex.unlock(inbound.io);
            while (true) {
                if (inbound.queue.popFront()) |message| return message;
                if (inbound.closed) return null;
                try inbound.condition.wait(inbound.io, &inbound.mutex);
            }
        }

        pub fn try_recv(inbound: *Self) error{ Empty, Disconnected }!Message {
            inbound.mutex.lockUncancelable(inbound.io);
            defer inbound.mutex.unlock(inbound.io);
            if (inbound.queue.popFront()) |message| return message;
            return if (inbound.closed) error.Disconnected else error.Empty;
        }

        /// Ends the queue for the receiver (it drains, then sees null).
        pub fn close(inbound: *Self) void {
            inbound.mutex.lockUncancelable(inbound.io);
            defer inbound.mutex.unlock(inbound.io);
            inbound.closed = true;
            inbound.condition.broadcast(inbound.io);
        }

        /// Drops one handle (`abandon` for the receiver); the last frees the queue.
        pub fn unref(inbound: *Self, receiver: bool) void {
            inbound.mutex.lockUncancelable(inbound.io);
            if (receiver) inbound.abandoned = true;
            assert(inbound.handles > 0);
            inbound.handles -= 1;
            const last = inbound.handles == 0;
            inbound.mutex.unlock(inbound.io);
            if (!last) return;
            while (inbound.queue.popFront()) |message| {
                var owned = message;
                owned.deinit();
            }
            inbound.queue.deinit(inbound.gpa);
            inbound.gpa.destroy(inbound);
        }
    };
}

pub fn Channels(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const Router = router_mod.Router(P);
        pub const Queue = Inbound(P);

        /// Sends on one channel without rate limiting; panics past `max_size`.
        pub const UnlimitedSender = struct {
            pub const PublicKey = P;

            router: *Router,
            channel: Channel,
            max_size: u32,

            pub fn send(
                sender: UnlimitedSender,
                recipients: p2p.Recipients(P),
                parts: []const []const u8,
                priority: bool,
            ) Unreliable(Feedback) {
                var len: usize = 0;
                for (parts) |part| len += part.len;
                if (len > sender.max_size) @panic("message too large");
                return sender.router.content(recipients, sender.channel, parts, priority);
            }
        };

        /// The rate-limited sender of one channel: the quota applies to each recipient.
        pub const Sender = limited.LimitedSender(UnlimitedSender, Router.Connected);

        /// Receives the messages of one channel from every peer.
        pub const Receiver = struct {
            pub const PublicKey = P;

            queue: *Queue,

            /// The next message (free it with `deinit`), or `NetworkClosed`.
            pub const RecvError = Io.Cancelable || error{NetworkClosed};

            pub fn recv(receiver: *Receiver) RecvError!p2p.Message(P) {
                return (try receiver.queue.recv()) orelse error.NetworkClosed;
            }

            pub fn try_recv(receiver: *Receiver) error{ Empty, Disconnected }!p2p.Message(P) {
                return receiver.queue.try_recv();
            }

            /// One quota burst for every peer the network may hold.
            pub fn capacity(receiver: *const Receiver) usize {
                return receiver.queue.capacity;
            }

            pub fn deinit(receiver: *Receiver) void {
                receiver.queue.unref(true);
                receiver.* = undefined;
            }
        };

        pub const Registered = struct {
            sender: Sender,
            receiver: Receiver,

            pub fn deinit(registered: *Registered) void {
                registered.sender.deinit();
                registered.receiver.deinit();
            }
        };

        pub const Entry = struct { quota: Quota, queue: *Queue };

        gpa: Allocator,
        io: Io,
        router: *Router,
        max_size: u32,
        max_peers: usize,
        receivers: SortedMap(Channel, Entry) = .empty,

        pub fn init(gpa: Allocator, io: Io, router: *Router, max_size: u32, max_peers: usize) Self {
            assert(max_peers > 0);
            return .{
                .gpa = gpa,
                .io = io,
                .router = router,
                .max_size = max_size,
                .max_peers = max_peers,
            };
        }

        /// Closes every inbound queue and releases the network's handles.
        pub fn deinit(channels: *Self) void {
            for (channels.receivers.items()) |entry| {
                entry.value.queue.close();
                entry.value.queue.unref(false);
            }
            channels.receivers.deinit(channels.gpa);
            channels.* = undefined;
        }

        /// Registers `channel` with `quota`. Panics on a duplicate channel.
        pub fn register(channels: *Self, channel: Channel, quota: Quota) !Registered {
            if (channels.receivers.contains(channel)) @panic("duplicate channel registration");
            const burst: usize = quota.burst_size();
            const capacity = std.math.mul(usize, channels.max_peers, burst) catch
                @panic("channel mailbox capacity overflow");
            const queue = try Queue.create(channels.gpa, channels.io, capacity);
            const entry: Entry = .{ .quota = quota, .queue = queue };
            _ = channels.receivers.put(channels.gpa, channel, entry) catch |err| {
                queue.unref(true);
                queue.unref(false);
                return err;
            };
            const unlimited: UnlimitedSender = .{
                .router = channels.router,
                .channel = channel,
                .max_size = channels.max_size,
            };
            const source = channels.router.source();
            const sender = try Sender.init(channels.gpa, channels.io, unlimited, quota, source);
            return .{ .sender = sender, .receiver = .{ .queue = queue } };
        }

        pub fn entries(channels: *const Self) []const SortedMap(Channel, Entry).Entry {
            return channels.receivers.items();
        }
    };
}

const testing = std.testing;
const runtime = @import("runtime");
const death = @import("utils").death;

const Peer = struct {
    id: u8,
    pub fn order(a: Peer, b: Peer) std.math.Order {
        return std.math.order(a.id, b.id);
    }
};

test "registered rate sizes the inbound queue for every peer" {
    var runner = try runtime.deterministic.Runner.init(testing.allocator, .{});
    defer runner.deinit();
    const io = runner.io();
    var router = try router_mod.Router(Peer).init(testing.allocator, io);
    defer router.deinit();
    var channels = Channels(Peer).init(testing.allocator, io, &router, 1024, 2);
    defer channels.deinit();
    var registered = try channels.register(1, .per_second(2));
    defer registered.deinit();
    // Two peers can each contribute a two-message burst; overflow keeps the four accepted.
    try testing.expectEqual(@as(usize, 4), registered.receiver.capacity());
    const queue = channels.entries()[0].value.queue;
    for (0..4) |_| {
        const message = try owned_message("message");
        try testing.expect(queue.enqueue(message).accepted());
    }
    const overflow = queue.enqueue(try owned_message("over"));
    try testing.expectEqual(Unreliable(Feedback).rejected, overflow);
    for (0..4) |_| {
        var message = try registered.receiver.try_recv();
        message.deinit();
    }
    try testing.expectError(error.Empty, registered.receiver.try_recv());
}

fn owned_message(text: []const u8) !p2p.Message(Peer) {
    const payload = try testing.allocator.dupe(u8, text);
    return .{ .peer = .{ .id = 1 }, .payload = payload, .gpa = testing.allocator };
}

test "register panics when the mailbox capacity overflows (derived_capacity_panics_on_overflow)" {
    try death.expect_panic(@src(), "channel mailbox capacity overflow", struct {
        fn body() !void {
            var runner = try runtime.deterministic.Runner.init(testing.allocator, .{});
            defer runner.deinit();
            const io = runner.io();
            var router = try router_mod.Router(Peer).init(testing.allocator, io);
            defer router.deinit();
            const max_peers = std.math.maxInt(usize);
            var channels = Channels(Peer).init(testing.allocator, io, &router, 1024, max_peers);
            defer channels.deinit();
            var registered = try channels.register(0, .per_second(2));
            registered.deinit();
        }
    }.body);
}
