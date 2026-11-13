//! Routes outbound data to connected peers (commonware `p2p/src/authenticated/router`).
//!
//! commonware runs the router as an actor fed by a mailbox. Here the connected peers sit
//! behind one lock and `content` encodes a frame once and queues it on each recipient's
//! outbox in the caller's task; routing order and the per-peer `Rejected` on a full outbox
//! are unchanged. Subscribers see the sorted list of connected peers.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const p2p = @import("../root.zig");
const SortedMap = @import("../simulated/sorted_map.zig").SortedMap;
const Watch = @import("../utils/watch.zig").Watch;
const outbox_mod = @import("outbox.zig");

const Channel = p2p.Channel;
const Feedback = p2p.Feedback;
const Unreliable = p2p.Unreliable;
const Frame = outbox_mod.Frame;
const Outbox = outbox_mod.Outbox;

pub fn Router(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const PublicKey = P;

        gpa: Allocator,
        io: Io,
        mutex: Io.Mutex = .init,
        closed: bool = false,
        connections: SortedMap(P, *Outbox) = .empty,
        /// The connected peers, for `Recipients.all` and subscribers.
        connected: Watch(P),

        pub fn init(gpa: Allocator, io: Io) Allocator.Error!Self {
            var router: Self = .{ .gpa = gpa, .io = io, .connected = .init(gpa, io) };
            assert(try router.connected.publish(&.{}));
            return router;
        }

        /// Call once every sender and peer has released the router.
        pub fn deinit(router: *Self) void {
            assert(router.connections.count() == 0 or router.closed);
            router.connections.deinit(router.gpa);
            router.connected.deinit();
            router.* = undefined;
        }

        /// Stops routing: later content reports `closed`.
        pub fn close(router: *Self) void {
            router.mutex.lockUncancelable(router.io);
            defer router.mutex.unlock(router.io);
            router.closed = true;
            router.connections.deinit(router.gpa);
            router.connections = .empty;
        }

        /// Routes to `peer` through `outbox` until `release` (commonware `Message::Ready`).
        pub fn ready(router: *Self, peer: P, outbox: *Outbox) Allocator.Error!bool {
            router.mutex.lockUncancelable(router.io);
            defer router.mutex.unlock(router.io);
            if (router.closed) return false;
            _ = try router.connections.put(router.gpa, peer, outbox);
            try router.publish();
            return true;
        }

        /// Stops routing to `peer` if `outbox` still serves it (commonware `Release`).
        pub fn release(router: *Self, peer: P, outbox: *Outbox) void {
            router.mutex.lockUncancelable(router.io);
            defer router.mutex.unlock(router.io);
            const current = router.connections.get(peer) orelse return;
            if (current.* != outbox) return;
            _ = router.connections.remove(peer);
            router.publish() catch {}; // Subscribers keep the previous list on OOM.
        }

        fn publish(router: *Self) Allocator.Error!void {
            const entries = router.connections.items();
            const peers = try router.gpa.alloc(P, entries.len);
            defer router.gpa.free(peers);
            for (peers, entries) |*peer, entry| peer.* = entry.key;
            _ = try router.connected.publish(peers);
        }

        /// Encodes `parts` once on `channel` and queues it for `recipients` that are
        /// connected; a full outbox drops it for that peer alone.
        pub fn content(
            router: *Self,
            recipients: p2p.Recipients(P),
            channel: Channel,
            parts: []const []const u8,
            priority: bool,
        ) Unreliable(Feedback) {
            router.mutex.lockUncancelable(router.io);
            defer router.mutex.unlock(router.io);
            if (router.closed) return .new(.closed);
            const frame = Frame.create(router.gpa, channel, parts) catch return .rejected;
            defer frame.release();
            switch (recipients) {
                .all => for (router.connections.items()) |entry| {
                    _ = entry.value.send(frame, priority);
                },
                .some, .one => for (recipients.peers()) |peer| {
                    const outbox = router.connections.get(peer) orelse continue;
                    _ = outbox.*.send(frame, priority);
                },
            }
            return .new(.ok);
        }

        /// The `Connected` source for limited senders.
        pub fn source(router: *Self) Connected {
            return .{ .router = router };
        }

        pub const Connected = struct {
            pub const PublicKey = P;
            pub const Subscription = Watch(P).Subscription;

            router: *Self,

            pub fn peers(connected: Connected, gpa: Allocator) ![]P {
                const router = connected.router;
                router.mutex.lockUncancelable(router.io);
                defer router.mutex.unlock(router.io);
                const entries = router.connections.items();
                const result = try gpa.alloc(P, entries.len);
                for (result, entries) |*peer, entry| peer.* = entry.key;
                return result;
            }

            pub fn subscribe(connected: Connected) Subscription {
                return connected.router.connected.subscribe(false);
            }
        };
    };
}

const testing = std.testing;
const runtime = @import("runtime");

const Peer = struct {
    id: u8,
    pub fn order(a: Peer, b: Peer) std.math.Order {
        return std.math.order(a.id, b.id);
    }
};

test "content reaches connected recipients only" {
    var runner = try runtime.deterministic.Runner.init(testing.allocator, .{});
    defer runner.deinit();
    const io = runner.io();
    var router = try Router(Peer).init(testing.allocator, io);
    defer router.deinit();
    var one = Outbox.init(testing.allocator, io, 1);
    defer one.deinit();
    var two = Outbox.init(testing.allocator, io, 1);
    defer two.deinit();
    try testing.expect(try router.ready(.{ .id = 1 }, &one));
    try testing.expect(try router.ready(.{ .id = 2 }, &two));
    var subscription = router.source().subscribe();

    const accepted = router.content(.{ .one = .{ .id = 2 } }, 7, &.{"hi"}, false);
    try testing.expect(accepted.accepted());
    try testing.expect(one.try_next() == null);
    const routed = two.try_next().?.frame;
    try testing.expectEqual(@as(Channel, 7), routed.channel);
    routed.release();

    _ = router.content(.all, 8, &.{"all"}, true);
    one.try_next().?.frame.release();
    two.try_next().?.frame.release();

    router.release(.{ .id = 1 }, &one);
    const peers = (try subscription.try_recv(testing.allocator)).?;
    defer testing.allocator.free(peers);
    try testing.expectEqual(@as(usize, 1), peers.len);
    try testing.expectEqual(@as(u8, 2), peers[0].id);
    _ = router.content(.all, 9, &.{"left"}, false);
    try testing.expect(one.try_next() == null);
    two.try_next().?.frame.release();

    router.close();
    const closed = router.content(.all, 1, &.{}, false);
    try testing.expectEqual(Unreliable(Feedback).new(.closed), closed);
}
