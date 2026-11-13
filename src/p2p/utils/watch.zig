//! A latest-value channel for peer lists (commonware `utils::channel::ring` with capacity 1,
//! as p2p uses it): a publisher replaces the value, and each subscription receives the newest
//! value it has not seen yet. An unread value is overwritten, so a reader always sees the
//! latest state and memory stays bounded by one value.
//!
//! Lives in p2p until the utils lane ports `channel::ring`. Values are owned copies: `publish`
//! copies its argument and `try_recv` hands the subscriber its own copy, so neither side holds
//! a pointer into the other's memory.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub fn Watch(comptime T: type) type {
    return struct {
        const Self = @This();

        gpa: Allocator,
        io: Io,
        mutex: Io.Mutex = .init,
        /// Broadcast on every publish and on close, for `Subscription.recv`.
        condition: Io.Condition = .init,
        /// Bumped on every publish; zero means nothing was published yet.
        version: u64 = 0,
        value: []T = &.{},
        closed: bool = false,

        pub fn init(gpa: Allocator, io: Io) Self {
            return .{ .gpa = gpa, .io = io };
        }

        pub fn deinit(watch: *Self) void {
            watch.gpa.free(watch.value);
            watch.* = undefined;
        }

        /// Replaces the value. Returns false (and keeps the old value) when closed.
        pub fn publish(watch: *Self, value: []const T) Allocator.Error!bool {
            const copy = try watch.gpa.dupe(T, value);
            watch.mutex.lockUncancelable(watch.io);
            defer watch.mutex.unlock(watch.io);
            if (watch.closed) {
                watch.gpa.free(copy);
                return false;
            }
            watch.gpa.free(watch.value);
            watch.value = copy;
            watch.version += 1;
            assert(watch.version > 0);
            watch.condition.broadcast(watch.io);
            return true;
        }

        /// Stops publishing; subscriptions keep the last value they received.
        pub fn close(watch: *Self) void {
            watch.mutex.lockUncancelable(watch.io);
            defer watch.mutex.unlock(watch.io);
            watch.closed = true;
            watch.condition.broadcast(watch.io);
        }

        /// A subscription that receives values published from now on (and the current one, if
        /// any, when `include_current`).
        pub fn subscribe(watch: *Self, include_current: bool) Subscription {
            watch.mutex.lockUncancelable(watch.io);
            defer watch.mutex.unlock(watch.io);
            return .{ .watch = watch, .seen = if (include_current) 0 else watch.version };
        }

        pub const Subscription = struct {
            watch: *Self,
            seen: u64,

            /// The newest unseen value as a copy owned by the caller (allocated from `gpa`),
            /// or null when there is nothing new.
            pub fn try_recv(subscription: *Subscription, gpa: Allocator) Allocator.Error!?[]T {
                const watch = subscription.watch;
                watch.mutex.lockUncancelable(watch.io);
                defer watch.mutex.unlock(watch.io);
                assert(subscription.seen <= watch.version);
                if (subscription.seen == watch.version) return null;
                const copy = try gpa.dupe(T, watch.value);
                subscription.seen = watch.version;
                return copy;
            }

            /// Waits for the newest unseen value (a copy owned by the caller, allocated from
            /// `gpa`); null once the watch is closed with nothing new (commonware's awaited
            /// `ring::Receiver::recv`).
            pub fn recv(
                subscription: *Subscription,
                gpa: Allocator,
            ) (Allocator.Error || Io.Cancelable)!?[]T {
                const watch = subscription.watch;
                try watch.mutex.lock(watch.io);
                defer watch.mutex.unlock(watch.io);
                while (subscription.seen == watch.version) {
                    if (watch.closed) return null;
                    try watch.condition.wait(watch.io, &watch.mutex);
                }
                assert(subscription.seen < watch.version);
                const copy = try gpa.dupe(T, watch.value);
                subscription.seen = watch.version;
                return copy;
            }
        };
    };
}

const testing = std.testing;

test "watch delivers only the latest unseen value" {
    var watch = Watch(u32).init(testing.allocator, Io.failing);
    defer watch.deinit();
    var early = watch.subscribe(true);
    try testing.expect(try early.try_recv(testing.allocator) == null);
    try testing.expect(try watch.publish(&.{ 1, 2 }));
    try testing.expect(try watch.publish(&.{3}));
    var late = watch.subscribe(false);
    var current = watch.subscribe(true);

    const first = (try early.try_recv(testing.allocator)).?;
    defer testing.allocator.free(first);
    try testing.expectEqualSlices(u32, &.{3}, first);
    try testing.expect(try early.try_recv(testing.allocator) == null);
    try testing.expect(try late.try_recv(testing.allocator) == null);
    const snapshot = (try current.try_recv(testing.allocator)).?;
    defer testing.allocator.free(snapshot);
    try testing.expectEqualSlices(u32, &.{3}, snapshot);

    watch.close();
    try testing.expect(!try watch.publish(&.{4}));
    try testing.expect(try early.try_recv(testing.allocator) == null);
}

test "watch recv waits for a publish and ends on close" {
    var watch = Watch(u32).init(testing.allocator, testing.io);
    defer watch.deinit();
    var subscription = watch.subscribe(false);
    const Publisher = struct {
        fn run(target: *Watch(u32)) void {
            _ = target.publish(&.{7}) catch unreachable; // Proof: the test allocator has room.
        }
    };
    var future = try testing.io.concurrent(Publisher.run, .{&watch});
    const value = (try subscription.recv(testing.allocator)).?;
    defer testing.allocator.free(value);
    future.await(testing.io);
    try testing.expectEqualSlices(u32, &.{7}, value);
    watch.close();
    try testing.expect(try subscription.recv(testing.allocator) == null);
}
