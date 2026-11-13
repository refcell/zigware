//! Peer sets one simulated peer (or the network-wide manager) tracks (commonware
//! `simulated::network::Tracker`).
//!
//! Keeps the newest `limit` sets by id, a per-peer count of the sets naming it as primary or
//! secondary (a peer named as both in one set counts as primary), and subscribers that receive
//! a `Update` after every `track`. Sets and updates are owned copies.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const p2p = @import("../root.zig");
const SortedMap = @import("sorted_map.zig").SortedMap;
const Unbounded = @import("channel.zig").Unbounded;

pub fn Tracker(comptime P: type) type {
    return struct {
        const Self = @This();
        pub const Tracked = p2p.TrackedPeers(P);

        /// An owned copy of a primary and secondary set.
        pub const Owned = struct {
            primary: []P,
            secondary: []P,

            pub fn view(owned: Owned) Tracked {
                return .{ .primary = .init(owned.primary), .secondary = .init(owned.secondary) };
            }

            fn clone(owned: Owned, gpa: Allocator) Allocator.Error!Owned {
                const primary = try gpa.dupe(P, owned.primary);
                errdefer gpa.free(primary);
                return .{ .primary = primary, .secondary = try gpa.dupe(P, owned.secondary) };
            }

            pub fn free(owned: Owned, gpa: Allocator) void {
                gpa.free(owned.primary);
                gpa.free(owned.secondary);
            }
        };

        /// A peer set update owned by its receiver (`deinit` frees it).
        pub const Update = struct {
            gpa: Allocator,
            index: u64,
            latest: Owned,
            all: Owned,

            pub fn deinit(update: *Update) void {
                update.latest.free(update.gpa);
                update.all.free(update.gpa);
                update.* = undefined;
            }

            pub fn view(update: Update) p2p.PeerSetUpdate(P) {
                const latest = update.latest.view();
                return .{ .index = update.index, .latest = latest, .all = update.all.view() };
            }
        };

        pub const Subscription = Unbounded(Update).Receiver;
        const Counts = struct { primary: u32 = 0, secondary: u32 = 0 };
        const Set = struct { id: u64, peers: Owned };

        gpa: Allocator,
        io: Io,
        /// Ascending by id.
        sets: std.ArrayList(Set) = .empty,
        counts: SortedMap(P, Counts) = .empty,
        subscribers: std.ArrayList(Unbounded(Update).Sender) = .empty,

        pub fn init(gpa: Allocator, io: Io) Self {
            return .{ .gpa = gpa, .io = io };
        }

        pub fn deinit(tracker: *Self) void {
            for (tracker.sets.items) |set| set.peers.free(tracker.gpa);
            tracker.sets.deinit(tracker.gpa);
            tracker.counts.deinit(tracker.gpa);
            for (tracker.subscribers.items) |*subscriber| subscriber.deinit();
            tracker.subscribers.deinit(tracker.gpa);
            tracker.* = undefined;
        }

        /// A copy of the sets and counts without the subscribers.
        pub fn fork(tracker: *const Self) Allocator.Error!Self {
            var copy = Self.init(tracker.gpa, tracker.io);
            errdefer copy.deinit();
            try copy.sets.ensureTotalCapacity(tracker.gpa, tracker.sets.items.len);
            for (tracker.sets.items) |set| {
                const peers_copy = try set.peers.clone(tracker.gpa);
                copy.sets.appendAssumeCapacity(.{ .id = set.id, .peers = peers_copy });
            }
            try copy.counts.entries.appendSlice(tracker.gpa, tracker.counts.items());
            assert(copy.counts.count() == tracker.counts.count());
            return copy;
        }

        pub fn contains(tracker: *const Self, peer: P) bool {
            return tracker.counts.contains(peer);
        }

        /// Every tracked peer, ascending.
        pub fn peers(tracker: *const Self) []const SortedMap(P, Counts).Entry {
            return tracker.counts.items();
        }

        /// A copy of the set tracked at `id`, owned by the caller.
        pub fn peer_set(tracker: *const Self, gpa: Allocator, id: u64) Allocator.Error!?Owned {
            for (tracker.sets.items) |set| {
                if (set.id == id) return try set.peers.clone(gpa);
            }
            return null;
        }

        /// Whether `id` is newer than every tracked set.
        pub fn accepts(tracker: *const Self, id: u64) bool {
            const newest = tracker.sets.getLastOrNull() orelse return true;
            return id > newest.id;
        }

        /// Tracks `tracked` at `id` (which `accepts`), evicts sets beyond `limit`, and notifies
        /// subscribers.
        pub fn track(tracker: *Self, id: u64, tracked: Tracked, limit: usize) Allocator.Error!void {
            assert(tracker.accepts(id));
            assert(limit > 0);
            const gpa = tracker.gpa;
            const primary = try gpa.dupe(P, tracked.primary.items);
            errdefer gpa.free(primary);
            var secondary: std.ArrayList(P) = .empty;
            errdefer secondary.deinit(gpa);
            for (tracked.secondary.items) |peer| {
                if (!tracked.primary.contains(peer)) try secondary.append(gpa, peer);
            }
            const set: Set = .{ .id = id, .peers = .{
                .primary = primary,
                .secondary = try secondary.toOwnedSlice(gpa),
            } };
            try tracker.sets.append(gpa, set);
            for (set.peers.primary) |peer| {
                (try tracker.counts.get_or_put(gpa, peer, .{})).primary += 1;
            }
            for (set.peers.secondary) |peer| {
                (try tracker.counts.get_or_put(gpa, peer, .{})).secondary += 1;
            }
            while (tracker.sets.items.len > limit) tracker.evict_oldest();
            try tracker.notify();
        }

        fn evict_oldest(tracker: *Self) void {
            const set = tracker.sets.orderedRemove(0);
            defer set.peers.free(tracker.gpa);
            for (set.peers.primary) |peer| tracker.release(peer, true);
            for (set.peers.secondary) |peer| tracker.release(peer, false);
        }

        fn release(tracker: *Self, peer: P, primary: bool) void {
            const counts = tracker.counts.get(peer) orelse @panic("reference map out of sync");
            const count = if (primary) &counts.primary else &counts.secondary;
            assert(count.* > 0);
            count.* -= 1;
            if (counts.primary == 0 and counts.secondary == 0) _ = tracker.counts.remove(peer);
        }

        /// Sends the latest update to every subscriber, dropping the ones that are gone.
        fn notify(tracker: *Self) Allocator.Error!void {
            var kept: usize = 0;
            for (tracker.subscribers.items) |subscriber_value| {
                var subscriber = subscriber_value;
                const update = (try tracker.latest_update(tracker.gpa)).?;
                if (try subscriber.send(update)) {
                    tracker.subscribers.items[kept] = subscriber;
                    kept += 1;
                } else {
                    subscriber.deinit();
                }
            }
            tracker.subscribers.shrinkRetainingCapacity(kept);
        }

        /// Peers tracked as primary anywhere, and peers tracked only as secondary.
        fn aggregate(tracker: *const Self, gpa: Allocator) Allocator.Error!Owned {
            var primary: std.ArrayList(P) = .empty;
            errdefer primary.deinit(gpa);
            var secondary: std.ArrayList(P) = .empty;
            errdefer secondary.deinit(gpa);
            for (tracker.counts.items()) |entry| {
                if (entry.value.primary > 0) {
                    try primary.append(gpa, entry.key);
                } else if (entry.value.secondary > 0) {
                    try secondary.append(gpa, entry.key);
                }
            }
            const primary_slice = try primary.toOwnedSlice(gpa);
            errdefer gpa.free(primary_slice);
            return .{ .primary = primary_slice, .secondary = try secondary.toOwnedSlice(gpa) };
        }

        /// The newest set and the aggregate membership, or null when nothing is tracked.
        pub fn latest_update(tracker: *const Self, gpa: Allocator) Allocator.Error!?Update {
            const newest = tracker.sets.getLastOrNull() orelse return null;
            const latest = try newest.peers.clone(gpa);
            errdefer latest.free(gpa);
            const all = try tracker.aggregate(gpa);
            return .{ .gpa = gpa, .index = newest.id, .latest = latest, .all = all };
        }

        /// A subscription that first receives the current update, if any.
        pub fn subscribe(tracker: *Self) Allocator.Error!Subscription {
            var pair = try Unbounded(Update).init(tracker.gpa, tracker.io);
            errdefer {
                pair.sender.deinit();
                pair.receiver.deinit();
            }
            if (try tracker.latest_update(tracker.gpa)) |update| {
                assert(try pair.sender.send(update));
            }
            try tracker.subscribers.append(tracker.gpa, pair.sender);
            return pair.receiver;
        }
    };
}

const testing = std.testing;

const codec = @import("codec");

/// A minimal public key: one byte, ordered by value, encoded through codec.
const Peer = struct {
    id: u8,
    pub const fixed_size = 1;
    pub fn order(a: Peer, b: Peer) std.math.Order {
        return std.math.order(a.id, b.id);
    }
    pub fn write(peer: Peer, writer: *codec.Writer) void {
        writer.write_byte(peer.id);
    }
    pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!Peer {
        return .{ .id = try reader.read_byte() };
    }
};

fn peer_list(comptime ids: []const u8) [ids.len]Peer {
    var result: [ids.len]Peer = undefined;
    for (ids, &result) |id, *peer| peer.* = .{ .id = id };
    return result;
}

fn expect_ids(expected: []const u8, actual: []const Peer) !void {
    try testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |id, peer| try testing.expectEqual(id, peer.id);
}

test "tracker windows sets, deduplicates roles, and notifies subscribers" {
    const T = Tracker(Peer);
    var tracker = T.init(testing.allocator, Io.failing);
    defer tracker.deinit();
    var subscription = try tracker.subscribe();
    defer subscription.deinit();
    try testing.expectError(error.Empty, subscription.try_recv());

    const first_primary = peer_list(&.{ 1, 2 });
    const first_secondary = peer_list(&.{ 2, 3 });
    const first: T.Tracked = .{
        .primary = .init(&first_primary),
        .secondary = .init(&first_secondary),
    };
    try tracker.track(5, first, 2);
    try testing.expect(!tracker.accepts(5) and tracker.accepts(6));
    var update = try subscription.try_recv();
    try testing.expectEqual(@as(u64, 5), update.index);
    try expect_ids(&.{ 1, 2 }, update.latest.primary);
    try expect_ids(&.{3}, update.latest.secondary);
    update.deinit();

    const second = peer_list(&.{4});
    try tracker.track(6, .{ .primary = .init(&.{}), .secondary = .init(&second) }, 2);
    const third = peer_list(&.{3});
    try tracker.track(7, .{ .primary = .init(&third), .secondary = .init(&.{}) }, 2);
    // Set 5 was evicted: peers 1 and 2 are gone, and 3 is now primary.
    try testing.expect(!tracker.contains(.{ .id = 1 }) and !tracker.contains(.{ .id = 2 }));
    try testing.expect(try tracker.peer_set(testing.allocator, 5) == null);
    var last = (try tracker.latest_update(testing.allocator)).?;
    defer last.deinit();
    try expect_ids(&.{3}, last.all.primary);
    try expect_ids(&.{4}, last.all.secondary);

    var forked = try tracker.fork();
    defer forked.deinit();
    try testing.expect(forked.contains(.{ .id = 4 }) and !forked.accepts(7));
    var copy = (try forked.peer_set(testing.allocator, 6)).?;
    defer copy.free(testing.allocator);
    try expect_ids(&.{4}, copy.secondary);
    for (0..2) |_| {
        var queued = try subscription.try_recv();
        queued.deinit();
    }
}
