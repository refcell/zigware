//! Tracks a monotonic boundary below which storage is proven durable (journal/durability.rs).
//!
//! commonware records the shared future of the last started sync and polls it without
//! blocking. zigware takes the completion as a comptime type with
//! `poll(self: *Completion) ?bool`: null while the sync runs, then true if it succeeded and
//! false if it failed. Polling must not block and must keep returning the same outcome. A
//! completion with `release(self: Completion) void` is released when the barrier drops it.
//! `Sync` adapts `runtime.storage.Completion`.

const std = @import("std");
const assert = std.debug.assert;
const runtime = @import("runtime");

/// A barrier completion holding one reference to a started sync.
pub const Sync = struct {
    completion: runtime.storage.Completion,

    pub fn poll(self: *Sync) ?bool {
        const result = self.completion.poll() orelse return null;
        result catch return false;
        return true;
    }

    pub fn release(self: Sync) void {
        self.completion.release();
    }
};

/// The boundary below which every item is known durable.
pub fn Barrier(comptime Completion: type) type {
    comptime assert(@hasDecl(Completion, "poll"));
    return struct {
        const Self = @This();

        /// The highest boundary known to be durable.
        boundary_durable: u64,
        /// The boundary captured by the last sync, and its completion.
        pending: ?Pending = null,

        const Pending = struct { boundary: u64, completion: Completion };

        /// Create a tracker starting at `boundary`.
        pub fn init(boundary_initial: u64) Self {
            return .{ .boundary_durable = boundary_initial };
        }

        /// Drop the pending completion, if any (the sync itself continues).
        pub fn deinit(self: *Self) void {
            self.drop();
            assert(self.settled());
        }

        fn drop(self: *Self) void {
            const pending = self.pending orelse return;
            if (@hasDecl(Completion, "release")) pending.completion.release();
            self.pending = null;
        }

        /// The highest proven boundary, observing the pending sync completion if any.
        pub fn boundary(self: *Self) u64 {
            self.observe();
            return self.boundary_durable;
        }

        /// Observe the outcome of the last started sync without blocking.
        fn observe(self: *Self) void {
            const pending = &(self.pending orelse return);
            const succeeded = pending.completion.poll() orelse return;
            if (succeeded) self.boundary_durable = @max(self.boundary_durable, pending.boundary);
            // The layer that started a failed sync owns surfacing the failure. A failed
            // observation cannot advance this proof, so retaining it would add nothing.
            self.drop();
            assert(self.settled());
        }

        /// Whether no recorded sync remains unobserved. Call `boundary` first to observe a
        /// completion that already resolved.
        pub fn settled(self: *const Self) bool {
            return self.pending == null;
        }

        /// Record that everything below `boundary_new` was proven durable.
        pub fn mark_durable(self: *Self, boundary_new: u64) void {
            self.boundary_durable = @max(self.boundary_durable, boundary_new);
            if (self.pending) |pending| {
                if (pending.boundary <= boundary_new) self.drop();
            }
            assert(self.boundary_durable >= boundary_new);
        }

        /// Track a sync started at `boundary_synced` without observing its completion.
        pub fn record(self: *Self, boundary_synced: u64, completion: Completion) void {
            // Preserve a completed prior proof before replacing its observer.
            self.observe();
            self.drop();
            self.pending = .{ .boundary = boundary_synced, .completion = completion };
            assert(!self.settled());
        }
    };
}

const testing = std.testing;

/// A completion whose outcome the test sets through a shared cell.
const TestCompletion = struct {
    outcome: *const ?bool,

    pub fn poll(self: *TestCompletion) ?bool {
        return self.outcome.*;
    }
};

test "barrier advances only on observed successful syncs" {
    var barrier = Barrier(TestCompletion).init(5);
    try testing.expectEqual(@as(u64, 5), barrier.boundary());
    try testing.expect(barrier.settled());

    // A pending sync does not advance the boundary.
    var first: ?bool = null;
    barrier.record(10, .{ .outcome = &first });
    try testing.expectEqual(@as(u64, 5), barrier.boundary());
    try testing.expect(!barrier.settled());

    // Its success does, once observed.
    first = true;
    try testing.expectEqual(@as(u64, 10), barrier.boundary());
    try testing.expect(barrier.settled());

    // A failed sync is dropped without advancing.
    var failed: ?bool = false;
    barrier.record(20, .{ .outcome = &failed });
    try testing.expectEqual(@as(u64, 10), barrier.boundary());
    try testing.expect(barrier.settled());

    // The boundary never moves backwards.
    var lower: ?bool = true;
    barrier.record(3, .{ .outcome = &lower });
    try testing.expectEqual(@as(u64, 10), barrier.boundary());
}

test "barrier record preserves a completed prior proof" {
    var barrier = Barrier(TestCompletion).init(0);
    var first: ?bool = true;
    barrier.record(7, .{ .outcome = &first });
    // Replacing the observer first observes the finished sync.
    var second: ?bool = null;
    barrier.record(9, .{ .outcome = &second });
    try testing.expectEqual(@as(u64, 7), barrier.boundary());
    try testing.expect(!barrier.settled());
}

test "barrier mark durable clears covered pending syncs" {
    var barrier = Barrier(TestCompletion).init(0);
    var pending: ?bool = null;
    barrier.record(8, .{ .outcome = &pending });

    // A proof below the pending boundary keeps waiting on it.
    barrier.mark_durable(4);
    try testing.expectEqual(@as(u64, 4), barrier.boundary());
    try testing.expect(!barrier.settled());

    // A proof covering it settles the barrier.
    barrier.mark_durable(8);
    try testing.expect(barrier.settled());
    try testing.expectEqual(@as(u64, 8), barrier.boundary());
    barrier.mark_durable(2);
    try testing.expectEqual(@as(u64, 8), barrier.boundary());
}
