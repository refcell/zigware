//! Durability helpers for marshal's deferred syncs (commonware `marshal/core/durability.rs`):
//! the fatal policy for awaiting durable syncs, and the gate that defers application dispatch
//! until finalized-archive writes are durable.
//!
//! A sync failure is fatal to local storage state and must never become a recoverable
//! verdict: turning it into "not durable" would let consensus treat lost local state as a live
//! rejection. Only runtime shutdown (cancelation) reports "not durable".

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const types = @import("../../types.zig");

const Height = types.Height;
const Round = types.Round;

/// Applies marshal's fatal policy to a sync result (commonware `Durable::durable`): true once
/// durable, false when the runtime shut down before the sync resolved (`error.Canceled`), and a
/// panic naming `name` and `round` on any other failure.
pub fn durable(result: anyerror!void, round: Round, name: []const u8) bool {
    result catch |err| switch (err) {
        error.Canceled, error.Closed => return false,
        else => std.debug.panic("failed to sync {s} at {f}: {s}", .{
            name,
            round,
            @errorName(err),
        }),
    };
    return true;
}

/// Defers application dispatch of finalized-archive writes until a sync covering them
/// completes.
///
/// Buffered archive writes are readable before they are durable, so every write is tracked
/// from the moment it is buffered until a sync covers it: `defer_write` holds a write while no
/// started sync covers it, `adopt` moves the held writes into an in-flight batch when a pooled
/// sync starts, and `release` (pooled) or `clear` (blocking) drops batches once they are
/// durable. `barrier` reports the lowest tracked height, below which dispatch must stay.
pub const DispatchGate = struct {
    const Batch = struct { seq: u64, lowest: Height };

    /// Lowest deferred write no started sync covers.
    unsynced: ?Height = null,
    /// Lowest deferred write per in-flight pooled sync, in start order.
    inflight: std.ArrayList(Batch) = .empty,
    /// Sequence assigned to the next adopted batch. Monotonic across `clear` so a stale
    /// completion can never release a batch adopted later.
    next_seq: u64 = 0,

    pub fn deinit(self: *DispatchGate, gpa: Allocator) void {
        self.inflight.deinit(gpa);
        self.* = undefined;
    }

    /// Defers dispatch at or above `height` until a sync covering this write completes
    /// (commonware `defer`).
    pub fn defer_write(self: *DispatchGate, height: Height) void {
        const lowest = self.unsynced orelse height;
        self.unsynced = if (height.get() < lowest.get()) height else lowest;
    }

    /// Adopts every deferred write no sync covers into a new in-flight batch, returning the
    /// sequence its sync must `release`, or null if every deferred write is already covered:
    /// no sync needs to start.
    pub fn adopt(self: *DispatchGate, gpa: Allocator) Allocator.Error!?u64 {
        const lowest = self.unsynced orelse return null;
        const seq = self.next_seq;
        try self.inflight.append(gpa, .{ .seq = seq, .lowest = lowest });
        self.unsynced = null;
        self.next_seq += 1;
        return seq;
    }

    /// Releases every batch covered by the completed pooled sync `seq`. A sync makes durable
    /// every write accepted before it started, so all batches with an equal or lower sequence
    /// are released, regardless of the order in which pooled syncs complete.
    pub fn release(self: *DispatchGate, seq: u64) void {
        var count: usize = 0;
        for (self.inflight.items) |batch| {
            if (batch.seq > seq) break;
            count += 1;
        }
        const all = self.inflight.items;
        std.mem.copyForwards(Batch, all[0 .. all.len - count], all[count..]);
        self.inflight.shrinkRetainingCapacity(all.len - count);
        if (self.inflight.items.len > 0) assert(self.inflight.items[0].seq > seq);
    }

    /// Releases everything. A blocking sync waits on (and covers) every previously accepted
    /// write, including writes adopted by in-flight pooled syncs and writes no sync has
    /// adopted yet.
    pub fn clear(self: *DispatchGate) void {
        self.unsynced = null;
        self.inflight.clearRetainingCapacity();
    }

    /// The lowest height whose write may not be durable yet. Dispatch must not send blocks at
    /// or above it.
    pub fn barrier(self: *const DispatchGate) ?Height {
        var lowest = self.unsynced;
        for (self.inflight.items) |batch| {
            if (lowest == null or batch.lowest.get() < lowest.?.get()) lowest = batch.lowest;
        }
        return lowest;
    }
};

const testing = std.testing;

test "durable resolves true on success" {
    try testing.expect(durable({}, .zero(), "test"));
}

test "durable reports shutdown as not durable" {
    try testing.expect(!durable(error.Canceled, .zero(), "test"));
    try testing.expect(!durable(error.Closed, .zero(), "test"));
}

// commonware `test_durable_panics_on_sync_failure`.
test "durable panics on sync failure" {
    try @import("utils").death.expect_panic(@src(), "failed to sync test", struct {
        fn body() !void {
            _ = durable(error.WriteFailed, .zero(), "test");
        }
    }.body);
}

test "gate defer keeps lowest write" {
    var gate: DispatchGate = .{};
    defer gate.deinit(testing.allocator);
    try testing.expectEqual(null, gate.barrier());
    gate.defer_write(.new(5));
    gate.defer_write(.new(3));
    gate.defer_write(.new(7));
    try testing.expectEqual(3, gate.barrier().?.get());
}

test "gate adopt moves writes to one batch" {
    const gpa = testing.allocator;
    var gate: DispatchGate = .{};
    defer gate.deinit(gpa);
    try testing.expectEqual(null, try gate.adopt(gpa));
    gate.defer_write(.new(5));
    const seq = (try gate.adopt(gpa)).?;
    try testing.expectEqual(5, gate.barrier().?.get());
    try testing.expectEqual(null, try gate.adopt(gpa));
    gate.release(seq);
    try testing.expectEqual(null, gate.barrier());
}

test "gate release covers earlier batches only" {
    const gpa = testing.allocator;
    var gate: DispatchGate = .{};
    defer gate.deinit(gpa);
    gate.defer_write(.new(5));
    const first = (try gate.adopt(gpa)).?;
    gate.defer_write(.new(8));
    const second = (try gate.adopt(gpa)).?;

    var out_of_order: DispatchGate = .{};
    defer out_of_order.deinit(gpa);
    out_of_order.defer_write(.new(5));
    _ = (try out_of_order.adopt(gpa)).?;
    out_of_order.defer_write(.new(8));
    const newest = (try out_of_order.adopt(gpa)).?;
    out_of_order.release(newest);
    try testing.expectEqual(null, out_of_order.barrier());

    gate.release(first);
    try testing.expectEqual(8, gate.barrier().?.get());
    gate.release(second);
    try testing.expectEqual(null, gate.barrier());
}

test "gate clear is not release for later batches" {
    const gpa = testing.allocator;
    var gate: DispatchGate = .{};
    defer gate.deinit(gpa);
    gate.defer_write(.new(5));
    const stale = (try gate.adopt(gpa)).?;
    gate.defer_write(.new(3));
    gate.clear();
    try testing.expectEqual(null, gate.barrier());

    gate.defer_write(.new(9));
    _ = (try gate.adopt(gpa)).?;
    gate.release(stale);
    try testing.expectEqual(9, gate.barrier().?.get());
}
