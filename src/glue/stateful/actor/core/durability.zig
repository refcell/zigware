//! The durable database prefix and the marshal acknowledgements awaiting it (commonware
//! `glue/src/stateful/actor/core/processing.rs`'s `Durability`).
//!
//! Marshal learns a finalized block was processed only once a database barrier covering it
//! completes. At most one barrier is active; heights applied after it was captured wait for the
//! next one. zigware databases persist synchronously in `finalize`, so the active barrier is
//! already complete and `complete` reads its outcome (commonware awaits a handle).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const consensus = @import("consensus");
const utils = @import("utils");
const db = @import("../../db/mod.zig");

const Height = consensus.Height;
const Exact = utils.acknowledgement.Exact;

pub const Durability = struct {
    const Pending = struct { height: Height, acknowledgement: Exact };
    const Active = struct { height: Height, barrier: db.Barrier };

    gpa: Allocator,
    /// The highest applied height known to be durable.
    durable: Height,
    /// Applied heights whose acknowledgements await durability, in nondecreasing order.
    pending: std.Deque(Pending) = .empty,
    /// The active barrier and the applied height it covers.
    barrier: ?Active = null,

    /// Tracking from a height already known to be durable.
    pub fn init(gpa: Allocator, height: Height) Durability {
        return .{ .gpa = gpa, .durable = height };
    }

    /// Drops every pending acknowledgement unacknowledged (marshal redelivers after restart).
    pub fn deinit(self: *Durability) void {
        while (self.pending.popFront()) |entry| {
            var acknowledgement = entry.acknowledgement;
            acknowledgement.deinit();
        }
        self.pending.deinit(self.gpa);
        self.* = undefined;
    }

    /// The highest applied height (the durable height when nothing is pending).
    pub fn applied(self: *const Durability) Height {
        if (self.pending.len == 0) return self.durable;
        return self.pending.back().?.height;
    }

    /// Whether `height` lies within the durable prefix.
    pub fn covers(self: *const Durability, height: Height) bool {
        return self.durable.get() >= height.get();
    }

    /// Holds the acknowledgement (taken) of a newly applied `height` until it is durable.
    /// `height` must be above every applied height.
    pub fn record(self: *Durability, height: Height, acknowledgement: Exact) Allocator.Error!void {
        assert(height.get() > self.applied().get());
        var owned = acknowledgement;
        const entry: Pending = .{ .height = height, .acknowledgement = owned };
        self.pending.pushBack(self.gpa, entry) catch |err| {
            owned.deinit();
            return err;
        };
        assert(self.applied().get() == height.get());
    }

    /// Holds a redelivered block's acknowledgement (taken) until its height is durable, or
    /// acknowledges it at once when it already is. `height` must be durable or applied.
    pub fn record_duplicate(self: *Durability, height: Height, acknowledgement: Exact) !void {
        var owned = acknowledgement;
        if (self.covers(height)) {
            owned.acknowledge();
            return;
        }
        // Insert after the last entry at `height`, keeping heights nondecreasing.
        var index: usize = self.pending.len;
        while (index > 0) : (index -= 1) {
            if (self.pending.at(index - 1).height.get() == height.get()) break;
        } else @panic("an undurable applied height must retain its acknowledgement");
        self.insert_at(index, .{ .height = height, .acknowledgement = owned }) catch |err| {
            owned.deinit();
            return err;
        };
    }

    fn insert_at(self: *Durability, index: usize, entry: Pending) Allocator.Error!void {
        assert(index <= self.pending.len);
        try self.pending.pushBack(self.gpa, entry);
        // Rotate the new entry back to `index`; bounded by the pending count.
        var position = self.pending.len - 1;
        while (position > index) : (position -= 1) {
            std.mem.swap(Pending, self.pending.atPtr(position - 1), self.pending.atPtr(position));
        }
    }

    /// Whether applied state is not yet durable and no barrier is active.
    pub fn needs_barrier(self: *const Durability) bool {
        return self.barrier == null and self.durable.get() < self.applied().get();
    }

    /// Tracks `barrier` as covering applied state through the current applied height.
    pub fn set_barrier(self: *Durability, barrier: db.Barrier) void {
        assert(self.needs_barrier());
        self.barrier = .{ .height = self.applied(), .barrier = barrier };
    }

    /// Clears the active barrier and acknowledges every height it made durable. Returns false,
    /// without advancing, when the barrier failed (a database failure is fatal to the caller).
    pub fn complete(self: *Durability) bool {
        const active = self.barrier orelse @panic("barrier not active");
        self.barrier = null;
        active.barrier.durable() catch return false;
        assert(active.height.get() > self.durable.get());
        assert(active.height.get() <= self.applied().get());
        self.durable = active.height;
        // Each pass acknowledges one pending entry.
        while (self.pending.len > 0) {
            if (self.pending.front().?.height.get() > self.durable.get()) break;
            var entry = self.pending.popFront().?;
            entry.acknowledgement.acknowledge();
        }
        return true;
    }
};
