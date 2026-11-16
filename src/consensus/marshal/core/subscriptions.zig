//! Local subscribers waiting for blocks (commonware `marshal/core/subscriptions.rs`).
//!
//! Each key holds its callers and, when the buffer can deliver, one buffer waiter. A caller
//! stays registered until delivery, its own cancellation, or the buffer closing its waiter.
//! Removing a subscription aborts its buffer waiter.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const utils = @import("utils");

const oneshot = utils.channel.oneshot;

/// The key a subscription waits on. Digest-scoped and commitment-scoped subscriptions are
/// distinct so a block that aliases on digest cannot satisfy a different commitment wait.
pub fn Key(comptime C: type, comptime D: type) type {
    return union(enum) {
        const Self = @This();

        digest: D,
        commitment: C,

        pub fn eql(a: Self, b: Self) bool {
            return switch (a) {
                .digest => |digest| b == .digest and digest.eql(b.digest),
                .commitment => |commitment| b == .commitment and commitment.eql(b.commitment),
            };
        }
    };
}

/// The subscription key of variant `V`.
pub fn KeyFor(comptime V: type) type {
    return Key(V.Commitment, V.Block.Digest);
}

/// Subscriptions to the blocks of variant `V`. `Aborter` cancels a buffer waiter
/// (`abort(*Aborter) void`).
pub fn Subscriptions(comptime V: type, comptime Aborter: type) type {
    comptime assert(@hasDecl(Aborter, "abort"));
    return struct {
        const Self = @This();
        pub const Subscriber = oneshot.Sender(V.Block);
        pub const SubscriptionKey = KeyFor(V);

        /// The callers waiting for one block, and the buffer waiter if one exists.
        const Entry = struct {
            key: SubscriptionKey,
            subscribers: std.ArrayList(Subscriber),
            aborter: ?Aborter,

            fn deinit(entry: *Entry, gpa: Allocator) void {
                if (entry.aborter) |*aborter| aborter.abort();
                for (entry.subscribers.items) |*subscriber| subscriber.deinit();
                entry.subscribers.deinit(gpa);
                entry.* = undefined;
            }
        };

        entries: std.ArrayList(Entry) = .empty,

        pub const empty: Self = .{};

        /// Drops every subscriber and aborts every buffer waiter.
        pub fn deinit(self: *Self, gpa: Allocator) void {
            for (self.entries.items) |*entry| entry.deinit(gpa);
            self.entries.deinit(gpa);
            self.* = undefined;
        }

        pub fn len(self: *const Self) usize {
            return self.entries.items.len;
        }

        fn find(self: *const Self, key: SubscriptionKey) ?usize {
            for (self.entries.items, 0..) |entry, index| {
                if (entry.key.eql(key)) return index;
            }
            return null;
        }

        /// The number of callers waiting on `key`.
        pub fn subscriber_count(self: *const Self, key: SubscriptionKey) usize {
            const index = self.find(key) orelse return 0;
            return self.entries.items[index].subscribers.items.len;
        }

        /// Drops the subscription for `key`, its callers, and its buffer waiter.
        pub fn remove(self: *Self, gpa: Allocator, key: SubscriptionKey) void {
            const index = self.find(key) orelse return;
            var entry = self.entries.swapRemove(index);
            entry.deinit(gpa);
            assert(self.find(key) == null);
        }

        /// Drops callers that stopped waiting, and subscriptions left without callers.
        pub fn retain_open(self: *Self, gpa: Allocator) void {
            var index: usize = 0;
            while (index < self.entries.items.len) {
                const entry = &self.entries.items[index];
                var kept: usize = 0;
                for (entry.subscribers.items) |subscriber| {
                    var dropped = subscriber;
                    if (subscriber.is_closed()) {
                        dropped.deinit();
                        continue;
                    }
                    entry.subscribers.items[kept] = subscriber;
                    kept += 1;
                }
                entry.subscribers.shrinkRetainingCapacity(kept);
                if (kept > 0) {
                    index += 1;
                    continue;
                }
                var removed = self.entries.swapRemove(index);
                removed.deinit(gpa);
            }
        }

        /// Delivers `block` (borrowed) to the callers waiting for its digest or commitment.
        pub fn notify(self: *Self, gpa: Allocator, block: *const V.Block) void {
            const keys = [2]SubscriptionKey{
                .{ .digest = block.digest() },
                .{ .commitment = V.commitment(block) },
            };
            for (keys) |key| {
                const index = self.find(key) orelse continue;
                var entry = self.entries.swapRemove(index);
                for (entry.subscribers.items) |*subscriber| {
                    // A caller that stopped waiting drops its copy (commonware `send_lossy`).
                    var copy = V.clone_block(block);
                    subscriber.send(copy) catch |err| switch (err) {
                        error.Closed => V.deinit_block(gpa, &copy),
                    };
                }
                entry.subscribers.clearRetainingCapacity();
                entry.deinit(gpa);
            }
        }

        /// Registers `response` for `key`. The first caller of a key subscribes to `buffer`
        /// (`subscribe_by_digest` or `subscribe_by_commitment`, null when it cannot deliver)
        /// and hands the receiver to `waiters.push(key, receiver) !Aborter`, which waits on it
        /// and owns it from then on, also on error.
        pub fn insert(
            self: *Self,
            gpa: Allocator,
            key: SubscriptionKey,
            response: Subscriber,
            waiters: anytype,
            buffer: anytype,
        ) !void {
            var subscriber = response;
            errdefer subscriber.deinit();
            if (self.find(key)) |index| {
                try self.entries.items[index].subscribers.append(gpa, subscriber);
                return;
            }
            try self.entries.ensureUnusedCapacity(gpa, 1);
            var subscribers: std.ArrayList(Subscriber) = try .initCapacity(gpa, 1);
            errdefer subscribers.deinit(gpa);
            const receiver = switch (key) {
                .digest => |digest| try buffer.subscribe_by_digest(digest),
                .commitment => |commitment| try buffer.subscribe_by_commitment(commitment),
            };
            const aborter: ?Aborter = if (receiver) |waiting|
                try waiters.push(key, waiting)
            else
                null;
            subscribers.appendAssumeCapacity(subscriber);
            self.entries.appendAssumeCapacity(.{
                .key = key,
                .subscribers = subscribers,
                .aborter = aborter,
            });
        }
    };
}

const testing = std.testing;
const Sha256 = @import("cryptography").Sha256;
const broadcast = @import("broadcast");
const mocks_block = @import("../mocks/block.zig");
const Standard = @import("../standard/variant.zig").Standard;

const TestBlock = mocks_block.EmptyBlock(Sha256);
const TestVariant = Standard(TestBlock);
const Shared = broadcast.Digested(TestBlock);

/// Counts aborts of the buffer waiters it hands out.
const TestAborter = struct {
    aborts: *u32,

    pub fn abort(self: *TestAborter) void {
        self.aborts.* += 1;
    }
};
const TestSubscriptions = Subscriptions(TestVariant, TestAborter);

/// Holds every receiver it is given, as the actor's waiter tasks would.
const TestWaiters = struct {
    aborts: u32 = 0,
    receivers: std.ArrayList(oneshot.Receiver(Shared)) = .empty,

    fn deinit(self: *TestWaiters) void {
        for (self.receivers.items) |*receiver| receiver.deinit();
        self.receivers.deinit(testing.allocator);
    }

    pub fn push(
        self: *TestWaiters,
        _: KeyFor(TestVariant),
        receiver: oneshot.Receiver(Shared),
    ) !TestAborter {
        var owned = receiver;
        errdefer owned.deinit();
        try self.receivers.append(testing.allocator, owned);
        return .{ .aborts = &self.aborts };
    }
};

/// Records the senders behind the receivers it hands out.
const TestBuffer = struct {
    deliver: bool = true,
    digest_senders: std.ArrayList(oneshot.Sender(Shared)) = .empty,
    commitment_senders: std.ArrayList(oneshot.Sender(Shared)) = .empty,

    fn deinit(self: *TestBuffer) void {
        for (self.digest_senders.items) |*sender| sender.deinit();
        for (self.commitment_senders.items) |*sender| sender.deinit();
        self.digest_senders.deinit(testing.allocator);
        self.commitment_senders.deinit(testing.allocator);
    }

    fn subscribe(
        self: *TestBuffer,
        senders: *std.ArrayList(oneshot.Sender(Shared)),
    ) !?oneshot.Receiver(Shared) {
        if (!self.deliver) return null;
        const pair = try oneshot.channel(Shared, testing.allocator, testing.io);
        try senders.append(testing.allocator, pair.sender);
        return pair.receiver;
    }

    pub fn subscribe_by_digest(self: *TestBuffer, _: Sha256.Digest) !?oneshot.Receiver(Shared) {
        return self.subscribe(&self.digest_senders);
    }

    pub fn subscribe_by_commitment(
        self: *TestBuffer,
        _: Sha256.Digest,
    ) !?oneshot.Receiver(Shared) {
        return self.subscribe(&self.commitment_senders);
    }
};

fn test_block(height: u64, timestamp: u64) !Shared {
    return Shared.compute(testing.allocator, .init(.fill(0), .new(height), timestamp));
}

fn subscribe(
    subscriptions: *TestSubscriptions,
    key: KeyFor(TestVariant),
    waiters: *TestWaiters,
    buffer: *TestBuffer,
) !oneshot.Receiver(Shared) {
    const pair = try oneshot.channel(Shared, testing.allocator, testing.io);
    try subscriptions.insert(testing.allocator, key, pair.sender, waiters, buffer);
    return pair.receiver;
}

fn expect_receives(receiver: *oneshot.Receiver(Shared), expected: Shared) !void {
    var received = try receiver.try_recv();
    defer received.deinit();
    try testing.expect(received.digest().eql(expected.digest()));
    receiver.deinit();
}

test "insert coalesces duplicate keys" {
    const gpa = testing.allocator;
    var buffer: TestBuffer = .{};
    defer buffer.deinit();
    var waiters: TestWaiters = .{};
    defer waiters.deinit();
    var subscriptions: TestSubscriptions = .empty;
    defer subscriptions.deinit(gpa);
    var block = try test_block(1, 10);
    defer block.deinit();

    var first = try subscribe(&subscriptions, .{ .digest = block.digest() }, &waiters, &buffer);
    var second = try subscribe(&subscriptions, .{ .digest = block.digest() }, &waiters, &buffer);
    try testing.expectEqual(1, buffer.digest_senders.items.len);
    try testing.expectEqual(1, subscriptions.len());

    subscriptions.notify(gpa, &block);
    try expect_receives(&first, block);
    try expect_receives(&second, block);
    try testing.expectEqual(0, subscriptions.len());
    // Delivery drops the buffer waiter's subscription.
    try testing.expectEqual(1, waiters.aborts);
}

test "notify wakes digest and commitment subscribers" {
    const gpa = testing.allocator;
    var buffer: TestBuffer = .{};
    defer buffer.deinit();
    var waiters: TestWaiters = .{};
    defer waiters.deinit();
    var subscriptions: TestSubscriptions = .empty;
    defer subscriptions.deinit(gpa);
    var block = try test_block(2, 20);
    defer block.deinit();

    var by_digest = try subscribe(&subscriptions, .{ .digest = block.digest() }, &waiters, &buffer);
    var by_commitment = try subscribe(&subscriptions, .{
        .commitment = block.digest(),
    }, &waiters, &buffer);
    try testing.expectEqual(1, buffer.digest_senders.items.len);
    try testing.expectEqual(1, buffer.commitment_senders.items.len);
    try testing.expectEqual(2, subscriptions.len());

    subscriptions.notify(gpa, &block);
    try expect_receives(&by_digest, block);
    try expect_receives(&by_commitment, block);
    try testing.expectEqual(0, subscriptions.len());
}

test "retain open drops closed subscribers and keeps open ones" {
    const gpa = testing.allocator;
    var buffer: TestBuffer = .{};
    defer buffer.deinit();
    var waiters: TestWaiters = .{};
    defer waiters.deinit();
    var subscriptions: TestSubscriptions = .empty;
    defer subscriptions.deinit(gpa);
    var block = try test_block(3, 30);
    defer block.deinit();
    const key: KeyFor(TestVariant) = .{ .digest = block.digest() };

    var closed = try subscribe(&subscriptions, key, &waiters, &buffer);
    var open = try subscribe(&subscriptions, key, &waiters, &buffer);
    closed.deinit();

    subscriptions.retain_open(gpa);
    try testing.expectEqual(1, subscriptions.subscriber_count(key));
    try testing.expectEqual(0, waiters.aborts);

    subscriptions.notify(gpa, &block);
    try expect_receives(&open, block);
    try testing.expectEqual(0, subscriptions.len());

    // A subscription whose callers all stopped waiting is dropped with its waiter.
    var gone = try subscribe(&subscriptions, key, &waiters, &buffer);
    gone.deinit();
    subscriptions.retain_open(gpa);
    try testing.expectEqual(0, subscriptions.len());
    try testing.expectEqual(2, waiters.aborts);
}

test "remove drops waiter and aborts buffer waiter" {
    const gpa = testing.allocator;
    var buffer: TestBuffer = .{};
    defer buffer.deinit();
    var waiters: TestWaiters = .{};
    defer waiters.deinit();
    var subscriptions: TestSubscriptions = .empty;
    defer subscriptions.deinit(gpa);
    var block = try test_block(4, 40);
    defer block.deinit();
    const key: KeyFor(TestVariant) = .{ .digest = block.digest() };

    var receiver = try subscribe(&subscriptions, key, &waiters, &buffer);
    defer receiver.deinit();
    subscriptions.remove(gpa, key);
    try testing.expectEqual(1, waiters.aborts);
    try testing.expectEqual(0, subscriptions.len());
    // The caller's sender was dropped.
    try testing.expectError(error.Closed, receiver.try_recv());
}

test "insert without buffer keeps local subscriber" {
    const gpa = testing.allocator;
    var buffer: TestBuffer = .{ .deliver = false };
    defer buffer.deinit();
    var waiters: TestWaiters = .{};
    defer waiters.deinit();
    var subscriptions: TestSubscriptions = .empty;
    defer subscriptions.deinit(gpa);
    var block = try test_block(5, 50);
    defer block.deinit();

    var receiver = try subscribe(&subscriptions, .{ .digest = block.digest() }, &waiters, &buffer);
    try testing.expectEqual(1, subscriptions.len());
    try testing.expectEqual(0, waiters.receivers.items.len);
    subscriptions.notify(gpa, &block);
    try expect_receives(&receiver, block);
    try testing.expectEqual(0, subscriptions.len());
    try testing.expectEqual(0, waiters.aborts);
}
