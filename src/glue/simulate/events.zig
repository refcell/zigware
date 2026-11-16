//! The plan's event queue (commonware's `select_loop!` over the monitor, restart, schedule, and
//! crash channels): every source pushes into one queue, and the plan pops one event at a time,
//! waking at least every poll interval. A mutex and condition give the timed wait.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const consensus = @import("consensus");
const tracker = @import("tracker.zig");

/// Most events queued at once; a push beyond it is dropped (commonware's monitor channel is
/// unbounded, so a simulation that queues this many reports is already broken).
pub const capacity_max: usize = 1 << 20;

pub fn Events(comptime P: type) type {
    return struct {
        const Self = @This();

        /// A finalization report whose digest the queue owns.
        pub const Report = struct {
            pk: P,
            round: consensus.Round,
            height: consensus.Height,
            digest: []u8,

            pub fn update(report: *const Report) tracker.FinalizationUpdate(P) {
                return .{
                    .pk = report.pk,
                    .round = report.round,
                    .height = report.height,
                    .block_digest = report.digest,
                };
            }
        };

        pub const Event = union(enum) {
            /// A validator reported a finalization.
            report: Report,
            /// Crash a validator (from a schedule).
            crash: P,
            /// Restart a validator (after a downtime, or from a schedule).
            restart: P,
            /// Crash random validators (`Crash.random`'s ticker).
            crash_tick,
        };

        gpa: Allocator,
        io: Io,
        mutex: Io.Mutex = .init,
        condition: Io.Condition = .init,
        queue: std.Deque(Event) = .empty,
        closed: bool = false,

        pub fn init(gpa: Allocator, io: Io) Self {
            return .{ .gpa = gpa, .io = io };
        }

        pub fn deinit(self: *Self) void {
            while (self.queue.popFront()) |event| self.release(event);
            self.queue.deinit(self.gpa);
            self.* = undefined;
        }

        /// Frees what `event` owns.
        pub fn release(self: *const Self, event: Event) void {
            switch (event) {
                .report => |report| self.gpa.free(report.digest),
                else => {},
            }
        }

        /// Queues `event`. Returns false, and releases the event, once the queue is closed
        /// or full.
        pub fn push(self: *Self, event: Event) bool {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (self.closed or self.queue.len >= capacity_max) {
                self.release(event);
                return false;
            }
            self.queue.pushBack(self.gpa, event) catch {
                self.release(event);
                return false;
            };
            self.condition.signal(self.io);
            return true;
        }

        /// The next event, or null if none arrives within `timeout` or the queue is closed and
        /// empty. The caller releases the event.
        pub fn next(self: *Self, timeout: Io.Duration) Io.Cancelable!?Event {
            const limit: Io.Timeout = .{ .duration = .{ .raw = timeout, .clock = .awake } };
            const deadline = limit.toDeadline(self.io);
            try self.mutex.lock(self.io);
            defer self.mutex.unlock(self.io);
            while (true) {
                if (self.queue.popFront()) |event| return event;
                if (self.closed) return null;
                const waited = self.condition.waitTimeout(self.io, &self.mutex, deadline);
                waited catch |err| switch (err) {
                    error.Timeout => return self.queue.popFront(),
                    error.Canceled => return error.Canceled,
                };
            }
        }

        /// Stops accepting events; those already queued can still be taken with `next`.
        pub fn close(self: *Self) void {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            self.closed = true;
            self.condition.broadcast(self.io);
        }
    };
}

/// The handle an engine reports finalizations through (commonware's monitor sender).
pub fn Monitor(comptime P: type) type {
    return struct {
        const Self = @This();

        events: *Events(P),

        /// Reports `update`, copying its digest. Returns false if the plan no longer accepts
        /// reports (it is draining or finished), as commonware's send fails once the receiver
        /// closed.
        pub fn send(self: Self, update: tracker.FinalizationUpdate(P)) bool {
            const events = self.events;
            const digest = events.gpa.dupe(u8, update.block_digest) catch return false;
            return events.push(.{ .report = .{
                .pk = update.pk,
                .round = update.round,
                .height = update.height,
                .digest = digest,
            } });
        }
    };
}
