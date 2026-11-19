//! Tests of the core actor's `Durability`: acknowledgements wait for a covering barrier,
//! duplicates keep their height's place, and a failed barrier acknowledges nothing.

const std = @import("std");
const testing = std.testing;
const consensus = @import("consensus");
const runtime = @import("runtime");
const utils = @import("utils");
const db = @import("../../db/mod.zig");
const durability_mod = @import("durability.zig");

const gpa = testing.allocator;
const io = testing.io;
const Durability = durability_mod.Durability;
const Exact = utils.acknowledgement.Exact;
const Height = consensus.Height;

const Tracked = struct {
    waiters: [8]Exact.Waiter = undefined,
    count: usize = 0,

    fn next(self: *Tracked) !Exact {
        const handle = try Exact.handle(gpa, io);
        self.waiters[self.count] = handle.waiter;
        self.count += 1;
        return handle.acknowledgement;
    }

    /// Whether each tracked acknowledgement resolved (true), was canceled (false), or waits.
    fn states(self: *Tracked) [8]?bool {
        var result: [8]?bool = @splat(null);
        for (self.waiters[0..self.count], 0..) |*waiter, index| {
            const outcome = waiter.poll() orelse continue;
            result[index] = if (outcome) |_| true else |_| false;
        }
        return result;
    }

    fn deinit(self: *Tracked) void {
        for (self.waiters[0..self.count]) |*waiter| waiter.deinit();
    }
};

fn ok_barrier() db.Barrier {
    var barrier: db.Barrier = .{};
    barrier.record("test", null, {});
    return barrier;
}

test "stateful durability: acknowledgements wait for a covering barrier" {
    var tracked: Tracked = .{};
    defer tracked.deinit();
    var durability: Durability = .init(gpa, .new(2));
    defer durability.deinit();
    try testing.expect(!durability.needs_barrier());

    try durability.record(.new(3), try tracked.next());
    try testing.expect(durability.needs_barrier());
    durability.set_barrier(ok_barrier());
    // A height applied after the barrier was captured waits for the next one.
    try durability.record(.new(4), try tracked.next());
    try testing.expect(!durability.needs_barrier());
    try durability.complete();
    try testing.expectEqual(3, durability.durable.get());
    try testing.expectEqualSlices(?bool, &.{ true, null }, tracked.states()[0..2]);

    try testing.expect(durability.needs_barrier());
    durability.set_barrier(ok_barrier());
    try durability.complete();
    try testing.expectEqualSlices(?bool, &.{ true, true }, tracked.states()[0..2]);
    try testing.expect(!durability.needs_barrier());
}

test "stateful durability: duplicates wait with their height or resolve at once" {
    var tracked: Tracked = .{};
    defer tracked.deinit();
    var durability: Durability = .init(gpa, .new(1));
    defer durability.deinit();
    try durability.record(.new(2), try tracked.next());
    try durability.record(.new(3), try tracked.next());
    // A durable height's duplicate resolves at once; height 2's waits with it.
    try durability.record_duplicate(.new(1), try tracked.next());
    try durability.record_duplicate(.new(2), try tracked.next());
    try testing.expectEqualSlices(?bool, &.{ null, null, true, null }, tracked.states()[0..4]);
    try testing.expectEqual(3, durability.applied().get());

    // A barrier covering only height 2 acknowledges it and its duplicate, not height 3.
    durability.barrier = .{ .height = .new(2), .barrier = ok_barrier() };
    try durability.complete();
    try testing.expectEqualSlices(?bool, &.{ true, null, true, true }, tracked.states()[0..4]);
}

test "stateful durability: a failed barrier acknowledges nothing" {
    var tracked: Tracked = .{};
    defer tracked.deinit();
    {
        var durability: Durability = .init(gpa, .new(0));
        defer durability.deinit();
        try durability.record(.new(1), try tracked.next());
        var failed: db.Barrier = .{};
        failed.record("test", null, error.SyncFailed);
        durability.set_barrier(failed);
        try testing.expectError(error.DatabaseSyncFailed, durability.complete());
        try testing.expectEqual(0, durability.durable.get());
        try testing.expectEqual(null, tracked.states()[0]);
    }
    // Dropping the tracker cancels what it still held.
    try testing.expectEqual(false, tracked.states()[0]);
}

/// A barrier over one in-flight sync, and the producer's reference to finish it.
fn pending_barrier() !struct { db.Barrier, runtime.storage.Completion } {
    const producer = try runtime.storage.Completion.init_pending(gpa, io);
    var barrier: db.Barrier = .{};
    barrier.add("test", null, producer.retain());
    return .{ barrier, producer };
}

test "stateful durability: heights coalesce behind a pending barrier" {
    var tracked: Tracked = .{};
    defer tracked.deinit();
    var durability: Durability = .init(gpa, .new(0));
    defer durability.deinit();
    try durability.record(.new(1), try tracked.next());
    const barrier, const producer = try pending_barrier();
    defer producer.release();
    durability.set_barrier(barrier);
    // Heights finalized while the sync runs need no barrier of their own yet.
    try durability.record(.new(2), try tracked.next());
    try durability.record(.new(3), try tracked.next());
    try testing.expect(!durability.settled());
    try testing.expect(!durability.needs_barrier());
    try testing.expectEqualSlices(?bool, &.{ null, null, null }, tracked.states()[0..3]);
    producer.finish({});
    try testing.expect(durability.settled());
    try durability.complete();
    try testing.expectEqualSlices(?bool, &.{ true, null, null }, tracked.states()[0..3]);
    // One successor barrier covers both coalesced heights.
    try testing.expect(durability.needs_barrier());
    durability.set_barrier(ok_barrier());
    try durability.complete();
    try testing.expectEqualSlices(?bool, &.{ true, true, true }, tracked.states()[0..3]);
}

test "stateful durability: stopping with a pending barrier cancels its acknowledgements" {
    var tracked: Tracked = .{};
    defer tracked.deinit();
    const producer = producer: {
        var durability: Durability = .init(gpa, .new(0));
        defer durability.deinit();
        try durability.record(.new(1), try tracked.next());
        const barrier, const producer = try pending_barrier();
        durability.set_barrier(barrier);
        break :producer producer;
    };
    defer producer.release();
    // The dropped barrier released its reference; the sync itself continues.
    try testing.expectEqual(1, producer.state.leaf.refs.load(.acquire));
    try testing.expectEqual(false, tracked.states()[0]);
    producer.finish({});
}
