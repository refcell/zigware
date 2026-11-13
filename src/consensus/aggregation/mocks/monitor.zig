//! A mock epoch monitor (commonware `aggregation/mocks/monitor.rs`): the test sets the epoch,
//! and each subscription sees the newest epoch (a subscriber that falls behind skips the
//! epochs in between, as commonware's capacity-one ring does).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Epoch = @import("../../types.zig").Epoch;

pub const Monitor = struct {
    pub const Index = Epoch;

    gpa: Allocator,
    io: Io,
    mutex: Io.Mutex = .init,
    condition: Io.Condition = .init,
    epoch: Epoch,
    /// Bumped on every update.
    version: u64 = 0,
    closed: bool = false,

    /// A monitor at `epoch`. Release with `destroy` after every subscription is gone.
    pub fn create(gpa: Allocator, io: Io, epoch: Epoch) Allocator.Error!*Monitor {
        const monitor = try gpa.create(Monitor);
        monitor.* = .{ .gpa = gpa, .io = io, .epoch = epoch };
        return monitor;
    }

    pub fn destroy(self: *Monitor) void {
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    /// Moves to `epoch` and wakes every subscription.
    pub fn update(self: *Monitor, epoch: Epoch) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        assert(!self.closed);
        self.epoch = epoch;
        self.version += 1;
        self.condition.broadcast(self.io);
    }

    /// Ends every subscription: `recv` returns null once it has seen the last epoch.
    pub fn close(self: *Monitor) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.closed = true;
        self.condition.broadcast(self.io);
    }

    /// The current epoch and a subscription to later ones.
    pub fn subscribe(self: *Monitor) Allocator.Error!struct { Epoch, Subscription } {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return .{ self.epoch, .{ .monitor = self, .seen = self.version } };
    }

    pub const Subscription = struct {
        monitor: *Monitor,
        seen: u64,

        /// Waits for an epoch newer than the last one seen; null once the monitor closes.
        pub fn recv(self: *Subscription) Io.Cancelable!?Epoch {
            const monitor = self.monitor;
            try monitor.mutex.lock(monitor.io);
            defer monitor.mutex.unlock(monitor.io);
            while (monitor.version == self.seen) {
                if (monitor.closed) return null;
                try monitor.condition.wait(monitor.io, &monitor.mutex);
            }
            assert(monitor.version > self.seen);
            self.seen = monitor.version;
            return monitor.epoch;
        }

        /// The newest epoch if one arrived since the last `recv`.
        pub fn try_recv(self: *Subscription) ?Epoch {
            const monitor = self.monitor;
            monitor.mutex.lockUncancelable(monitor.io);
            defer monitor.mutex.unlock(monitor.io);
            if (monitor.version == self.seen) return null;
            self.seen = monitor.version;
            return monitor.epoch;
        }

        pub fn deinit(self: *Subscription) void {
            self.* = undefined;
        }
    };
};

test "a subscriber that falls behind sees the newest epoch" {
    const io = std.testing.io;
    const monitor = try Monitor.create(std.testing.allocator, io, .new(1));
    defer monitor.destroy();
    const latest, var subscription = try monitor.subscribe();
    defer subscription.deinit();
    try std.testing.expectEqual(Epoch.new(1), latest);
    // Two updates before the subscriber reads: only the newest is delivered.
    monitor.update(.new(2));
    monitor.update(.new(3));
    try std.testing.expectEqual(Epoch.new(3), subscription.try_recv().?);
    try std.testing.expectEqual(null, subscription.try_recv());
    monitor.close();
    try std.testing.expectEqual(null, try subscription.recv());
}
