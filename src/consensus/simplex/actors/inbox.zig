//! One bounded event queue that several sources feed (commonware's `select_loop!` over a
//! mailbox, network receivers, automaton responses, and a deadline).
//!
//! Each forwarded source gets a pump task that blocks on its `recv` and pushes what arrives;
//! other tasks (such as automaton requests) `push` their results directly. The actor pops one
//! event at a time with `next`, or with `next_until` to stop at a deadline. A forwarded source
//! that closes pushes `closed`. `shutdown` closes the queue, cancels the pumps, and releases
//! every event still queued. A mutex and condition (rather than `Io.Queue`) give the timed wait.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

/// `Event` is a tagged union with one field per source plus `closed: void`; `release` frees
/// an event that is never handled.
pub fn Inbox(
    comptime Event: type,
    comptime capacity: u32,
    comptime release: fn (Event) void,
) type {
    comptime assert(capacity > 0);
    comptime assert(@hasField(Event, "closed"));
    return struct {
        const Self = @This();
        pub const Field = std.meta.FieldEnum(Event);
        const Item = Event;
        const release_item = release;
        const max_sources = 4;

        io: Io,
        mutex: Io.Mutex = .init,
        condition: Io.Condition = .init,
        buffer: [capacity]Event = undefined,
        head: u32 = 0,
        count: u32 = 0,
        is_closed: bool = false,
        pumps: [max_sources]Io.Future(void) = undefined,
        pump_count: u32 = 0,

        /// Must not move after `init`: pumps hold its address.
        pub fn init(self: *Self, io: Io) void {
            self.* = .{ .io = io };
            assert(self.count == 0 and self.pump_count == 0);
        }

        /// Starts forwarding `source.recv()` into the `field` events.
        pub fn forward(
            self: *Self,
            comptime field: Field,
            source: anytype,
        ) Io.ConcurrentError!void {
            comptime assert(field != .closed);
            assert(self.pump_count < max_sources);
            const Source = @TypeOf(source);
            const Task = struct {
                fn run(inbox: *Self, from: Source) void {
                    pump(inbox, @tagName(field), from);
                }
            };
            const future = try self.io.concurrent(Task.run, .{ self, source });
            self.pumps[self.pump_count] = future;
            self.pump_count += 1;
        }

        /// Queues `event`, waiting while the queue is full. Returns false (the caller still
        /// owns `event`) once the queue is closed or the wait is canceled.
        pub fn push(self: *Self, event: Event) bool {
            return push_event(self, event);
        }

        /// The next event; `error.Canceled` when the actor is canceled.
        pub fn next(self: *Self) Io.Cancelable!Event {
            return (try self.next_until(null)).?;
        }

        /// The next event, or null once the awake clock reaches `deadline_ns`, queued or not.
        pub fn next_until(self: *Self, deadline_ns: ?i96) Io.Cancelable!?Event {
            return next_event(self, deadline_ns);
        }

        pub fn shutdown(self: *Self) void {
            close(self);
        }
    };
}

fn push_event(inbox: anytype, event: @TypeOf(inbox.*).Item) bool {
    const capacity = inbox.buffer.len;
    inbox.mutex.lockUncancelable(inbox.io);
    defer inbox.mutex.unlock(inbox.io);
    // Each wake re-checks for room; waits end on a pop, close, or cancel.
    while (!inbox.is_closed and inbox.count == capacity) {
        inbox.condition.wait(inbox.io, &inbox.mutex) catch return false;
    }
    if (inbox.is_closed) return false;
    assert(inbox.count < capacity);
    inbox.buffer[(inbox.head + inbox.count) % capacity] = event;
    inbox.count += 1;
    inbox.condition.broadcast(inbox.io);
    return true;
}

fn next_event(inbox: anytype, deadline_ns: ?i96) Io.Cancelable!?@TypeOf(inbox.*).Item {
    const capacity = inbox.buffer.len;
    inbox.mutex.lockUncancelable(inbox.io);
    defer inbox.mutex.unlock(inbox.io);
    // An expired deadline wins over queued events: commonware's biased `select_loop!` polls
    // `sleep_until(deadline)` ahead of its other branches.
    if (deadline_ns) |due| {
        if (Io.Timestamp.now(inbox.io, .awake).nanoseconds >= due) return null;
    }
    // Each wake re-checks the queue and the deadline.
    while (inbox.count == 0) {
        assert(!inbox.is_closed); // Proof: only `shutdown` closes the queue.
        const timeout: Io.Timeout = if (deadline_ns) |due| .{ .deadline = .{
            .raw = .{ .nanoseconds = due },
            .clock = .awake,
        } } else .none;
        inbox.condition.waitTimeout(inbox.io, &inbox.mutex, timeout) catch |err| switch (err) {
            error.Timeout => if (inbox.count == 0) return null,
            error.Canceled => return error.Canceled,
        };
    }
    const event = inbox.buffer[inbox.head];
    inbox.head = @intCast((inbox.head + 1) % capacity);
    inbox.count -= 1;
    inbox.condition.broadcast(inbox.io);
    return event;
}

/// Closes the queue, cancels the pumps, and releases what they left behind.
fn close(inbox: anytype) void {
    const Inbox_ = @TypeOf(inbox.*);
    const capacity = inbox.buffer.len;
    inbox.mutex.lockUncancelable(inbox.io);
    inbox.is_closed = true;
    inbox.condition.broadcast(inbox.io);
    inbox.mutex.unlock(inbox.io);
    for (inbox.pumps[0..inbox.pump_count]) |*future| future.cancel(inbox.io);
    inbox.pump_count = 0;
    while (inbox.count > 0) {
        Inbox_.release_item(inbox.buffer[inbox.head]);
        inbox.head = @intCast((inbox.head + 1) % capacity);
        inbox.count -= 1;
    }
    assert(inbox.count == 0);
}

/// Forwards `source.recv()` into `inbox` as `field` events until the source closes, the queue
/// closes, or the pump is canceled.
fn pump(inbox: anytype, comptime field: []const u8, source: anytype) void {
    const Inbox_ = @TypeOf(inbox.*);
    comptime assert(!std.mem.eql(u8, field, "closed"));
    while (true) {
        const item = receive(source) catch |err| switch (err) {
            error.Canceled => return,
            error.Closed => {
                _ = inbox.push(.closed);
                return;
            },
        };
        const event = @unionInit(Inbox_.Item, field, item);
        if (!inbox.push(event)) {
            Inbox_.release_item(event);
            return;
        }
    }
}

/// One item from `source.recv()`, mapping a closed source (null or any error other than
/// cancelation) to `error.Closed`.
fn receive(source: anytype) error{ Canceled, Closed }!Payload(@TypeOf(source)) {
    const result = source.recv() catch |err| {
        return if (err == error.Canceled) error.Canceled else error.Closed;
    };
    if (@typeInfo(@TypeOf(result)) == .optional) return result orelse error.Closed;
    return result;
}

fn Payload(comptime Source: type) type {
    const Pointee = @typeInfo(Source).pointer.child;
    const Return = @typeInfo(@TypeOf(Pointee.recv)).@"fn".return_type.?;
    const Value = @typeInfo(Return).error_union.payload;
    return switch (@typeInfo(Value)) {
        .optional => |optional| optional.child,
        else => Value,
    };
}

test "inbox: an expired deadline wins over a queued event" {
    const runtime = @import("runtime");
    try runtime.deterministic.soak(std.testing.allocator, .{}, {}, struct {
        fn run(_: void, runner: *runtime.deterministic.Runner) anyerror!void {
            try try runner.start_context(body, .{});
        }
        const Event = union(enum) { value: u32, closed };
        fn release(_: Event) void {}
        fn body(ctx: runtime.deterministic.Context) anyerror!void {
            const io = ctx.io();
            var inbox: Inbox(Event, 4, release) = undefined;
            inbox.init(io);
            defer inbox.shutdown();
            try ctx.sleep(.fromMilliseconds(10));
            const now = Io.Timestamp.now(io, .awake).nanoseconds;
            try std.testing.expect(inbox.push(.{ .value = 7 }));
            // commonware's biased select: the expired deadline fires first.
            try std.testing.expectEqual(null, try inbox.next_until(now));
            // A live deadline still yields the queued event at once.
            const event = (try inbox.next_until(now + std.time.ns_per_s)).?;
            try std.testing.expectEqual(7, event.value);
            // With nothing queued, the deadline ends the wait.
            try std.testing.expectEqual(null, try inbox.next_until(now + std.time.ns_per_s));
        }
    }.run);
}
