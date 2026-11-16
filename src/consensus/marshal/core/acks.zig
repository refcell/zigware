//! In-flight application acknowledgements (commonware `marshal/core/acks.rs`).
//!
//! Marshal dispatches finalized blocks in height order and the application acknowledges each.
//! `PendingAcks` keeps their waiters in FIFO order: the oldest is the current ack the actor
//! awaits, and the next arms once it completes.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const utils = @import("utils");
const Height = @import("../../types.zig").Height;

/// A pending acknowledgement from the application for the block at `height`.
pub fn PendingAck(comptime A: type) type {
    return struct { height: Height, waiter: A.Waiter };
}

/// Tracks in-flight application acknowledgements with FIFO semantics, at most `max` at once.
/// The ring holds the current ack at `head` and the queued ones after it.
pub fn PendingAcks(comptime A: type) type {
    comptime utils.acknowledgement.assert_acknowledgement(A);
    return struct {
        const Self = @This();
        pub const Ack = PendingAck(A);
        pub const Result = utils.acknowledgement.Canceled!void;

        ring: []Ack,
        head: u32 = 0,
        count: u32 = 0,

        /// A tracker for at most `max` in-flight acks, all allocated here.
        pub fn init(gpa: Allocator, max: u32) Allocator.Error!Self {
            assert(max > 0);
            return .{ .ring = try gpa.alloc(Ack, max) };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.clear();
            gpa.free(self.ring);
            self.* = undefined;
        }

        fn at(self: *const Self, offset: u32) *Ack {
            assert(offset < self.count);
            const index = (self.head + offset) % @as(u32, @intCast(self.ring.len));
            return &self.ring[index];
        }

        /// Drops the current ack and all queued acks.
        pub fn clear(self: *Self) void {
            for (0..self.count) |offset| self.at(@intCast(offset)).waiter.deinit();
            self.head = 0;
            self.count = 0;
        }

        /// The currently armed ack, if any.
        pub fn current(self: *const Self) ?*Ack {
            if (self.count == 0) return null;
            return self.at(0);
        }

        /// Whether another block can be dispatched without exceeding capacity.
        pub fn has_capacity(self: *const Self) bool {
            assert(self.count <= self.ring.len);
            return self.count < self.ring.len;
        }

        /// The next height to dispatch while preserving sequential order.
        pub fn next_dispatch_height(self: *const Self, start_height: Height) Height {
            if (self.count == 0) return start_height;
            return self.at(self.count - 1).height.next();
        }

        /// Enqueues a newly dispatched ack (taking ownership of its waiter), arming it
        /// immediately when idle.
        pub fn enqueue(self: *Self, ack: Ack) void {
            assert(self.has_capacity());
            if (self.count > 0) assert(ack.height.get() > self.at(self.count - 1).height.get());
            self.count += 1;
            self.at(self.count - 1).* = ack;
        }

        /// Releases the completed current ack, arms the next queued ack, and returns the
        /// completed height with `result`.
        pub fn complete_current(self: *Self, result: Result) struct { Height, Result } {
            const ack = self.current() orelse unreachable; // The caller awaited a current ack.
            const height = ack.height;
            ack.waiter.deinit();
            self.head = (self.head + 1) % @as(u32, @intCast(self.ring.len));
            self.count -= 1;
            return .{ height, result };
        }

        /// If the current ack is already resolved, takes it and arms the next ack.
        pub fn pop_ready(self: *Self) ?struct { Height, Result } {
            const ack = self.current() orelse return null;
            const result = ack.waiter.poll() orelse return null;
            return self.complete_current(result);
        }
    };
}

const testing = std.testing;
const Exact = utils.acknowledgement.Exact;

fn pending_ack(height: u64) !struct { PendingAck(Exact), Exact } {
    const handle = try Exact.handle(testing.allocator, testing.io);
    return .{ .{ .height = .new(height), .waiter = handle.waiter }, handle.acknowledgement };
}

test "enqueue tracks capacity and fifo ready order" {
    var pending: PendingAcks(Exact) = try .init(testing.allocator, 2);
    defer pending.deinit(testing.allocator);
    try testing.expect(pending.has_capacity());
    try testing.expectEqual(8, pending.next_dispatch_height(.new(8)).get());

    const first, var first_ack = try pending_ack(8);
    pending.enqueue(first);
    try testing.expect(pending.has_capacity());
    try testing.expectEqual(9, pending.next_dispatch_height(.new(8)).get());

    const second, var second_ack = try pending_ack(9);
    pending.enqueue(second);
    try testing.expect(!pending.has_capacity());
    try testing.expectEqual(10, pending.next_dispatch_height(.new(8)).get());

    second_ack.acknowledge();
    try testing.expectEqual(null, pending.pop_ready());

    first_ack.acknowledge();
    const height, const result = pending.pop_ready().?;
    try testing.expectEqual(8, height.get());
    try result;

    const queued_height, const queued_result = pending.pop_ready().?;
    try testing.expectEqual(9, queued_height.get());
    try queued_result;
    try testing.expect(pending.has_capacity());
}

test "clear drops all pending acks" {
    var pending: PendingAcks(Exact) = try .init(testing.allocator, 2);
    defer pending.deinit(testing.allocator);
    const first, var first_ack = try pending_ack(3);
    const second, var second_ack = try pending_ack(4);
    pending.enqueue(first);
    pending.enqueue(second);
    try testing.expect(!pending.has_capacity());

    pending.clear();
    first_ack.acknowledge();
    second_ack.acknowledge();

    try testing.expectEqual(null, pending.pop_ready());
    try testing.expect(pending.has_capacity());
    try testing.expectEqual(10, pending.next_dispatch_height(.new(10)).get());
}

test "a dropped acknowledgement completes as canceled" {
    var pending: PendingAcks(Exact) = try .init(testing.allocator, 1);
    defer pending.deinit(testing.allocator);
    const first, var first_ack = try pending_ack(1);
    pending.enqueue(first);
    first_ack.deinit();
    const height, const result = pending.pop_ready().?;
    try testing.expectEqual(1, height.get());
    try testing.expectError(error.AcknowledgementCanceled, result);
}
