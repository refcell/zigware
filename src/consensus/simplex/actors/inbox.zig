//! One queue that several sources feed (commonware's `select_loop!` over a mailbox and
//! network receivers).
//!
//! Each source gets a pump task that blocks on its `recv` and forwards what arrives into a
//! bounded `std.Io.Queue`; the actor pops one event at a time. A source that closes forwards
//! `closed`. `shutdown` closes the queue, cancels the pumps, and releases every
//! event still queued.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

/// `Event` is a tagged union with one field per source plus `closed: void`; `release`
/// frees an event that is never handled.
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
        buffer: [capacity]Event = undefined,
        queue: Io.Queue(Event) = undefined,
        pumps: [max_sources]Io.Future(void) = undefined,
        pump_count: u32 = 0,

        /// Must not move after `init`: the queue points into `buffer`.
        pub fn init(self: *Self, io: Io) void {
            self.* = .{ .io = io };
            self.queue = .init(&self.buffer);
            assert(self.pump_count == 0);
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

        /// The next event; `error.Canceled` when the actor is canceled.
        pub fn next(self: *Self) Io.Cancelable!Event {
            return self.queue.getOne(self.io) catch |err| switch (err) {
                error.Canceled => error.Canceled,
                error.Closed => unreachable, // Proof: only `shutdown` closes the queue.
            };
        }

        pub fn shutdown(self: *Self) void {
            self.queue.close(self.io);
            for (self.pumps[0..self.pump_count]) |*future| future.cancel(self.io);
            var drained: u32 = 0;
            while (self.queue.getOneUncancelable(self.io)) |event| : (drained += 1) {
                assert(drained < capacity);
                release(event);
            } else |_| {}
            self.pump_count = 0;
        }
    };
}

/// One item from `source.recv()`, mapping a closed source (null or any error other
/// than cancelation) to `error.Closed`.
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

/// Forwards `source.recv()` into `inbox` as `field` events until the source closes, the queue
/// closes, or the pump is canceled.
fn pump(inbox: anytype, comptime field: []const u8, source: anytype) void {
    const Inbox_ = @TypeOf(inbox.*);
    comptime assert(!std.mem.eql(u8, field, "closed"));
    while (true) {
        const item = receive(source) catch |err| switch (err) {
            error.Canceled => return,
            error.Closed => {
                inbox.queue.putOne(inbox.io, .closed) catch {};
                return;
            },
        };
        const event = @unionInit(Inbox_.Item, field, item);
        inbox.queue.putOne(inbox.io, event) catch {
            Inbox_.release_item(event);
            return;
        };
    }
}
