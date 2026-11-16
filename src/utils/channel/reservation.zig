//! Channel reservation helpers (commonware `utils/src/channel/reservation.rs`).
//!
//! `send_or_reserve` sends at once when a bounded `mpsc` channel has room, and otherwise
//! returns a `Reservation` that keeps the value and its own sender until a slot frees up.
//! Rust's `SendError(value)` becomes a tagged union that hands the value back.

const std = @import("std");
const mpsc = @import("mpsc.zig");
const assert = std.debug.assert;
const Io = std.Io;

/// A reserved slot bundled with the value to send.
pub fn Reserved(comptime T: type) type {
    return struct {
        const Self = @This();

        permit: mpsc.Permit(T),
        value: T,

        /// Sends the value through the reserved slot.
        pub fn send(self: *Self) void {
            self.permit.send(self.value);
            self.* = undefined;
        }
    };
}

/// A value waiting for a channel slot. Released by `wait` or `deinit`.
pub fn Reservation(comptime T: type) type {
    return struct {
        const Self = @This();

        sender: mpsc.Sender(T),
        value: T,

        pub const Outcome = union(enum) {
            reserved: Reserved(T),
            /// The receiver went away; the value is the caller's again.
            closed: T,
        };

        /// Waits for a slot. Consumes the reservation unless canceled; after `error.Canceled`
        /// the reservation still owns its value and must be released.
        pub fn wait(self: *Self) Io.Cancelable!Outcome {
            const permit = self.sender.reserve() catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.Closed => {
                    const value = self.value;
                    self.sender.deinit();
                    self.* = undefined;
                    return .{ .closed = value };
                },
            };
            const reserved: Reserved(T) = .{ .permit = permit, .value = self.value };
            self.sender.deinit();
            self.* = undefined;
            return .{ .reserved = reserved };
        }

        /// Gives up; returns the value to the caller.
        pub fn cancel(self: *Self) T {
            const value = self.value;
            self.sender.deinit();
            self.* = undefined;
            return value;
        }
    };
}

pub fn SendOrReserve(comptime T: type) type {
    return union(enum) {
        sent,
        /// The channel was full: wait on the reservation, then send.
        reserved: Reservation(T),
        /// The receiver is gone; the value is the caller's again.
        closed: T,
    };
}

/// Sends `value` now, or reserves it when the bounded channel is full.
pub fn send_or_reserve(comptime T: type, sender: mpsc.Sender(T), value: T) SendOrReserve(T) {
    sender.try_send(value) catch |err| return switch (err) {
        error.Full => .{ .reserved = .{ .sender = sender.clone(), .value = value } },
        error.Closed => .{ .closed = value },
        // A bounded channel's buffer is allocated up front.
        error.OutOfMemory => unreachable,
    };
    return .sent;
}

const testing = std.testing;
const gpa = testing.allocator;

test "reservation: sends immediately with room" {
    var pair = try mpsc.channel(u32, gpa, testing.io, 1);
    defer pair.receiver.deinit();
    defer pair.sender.deinit();
    try testing.expect(send_or_reserve(u32, pair.sender, 1) == .sent);
    try testing.expectEqual(1, try pair.receiver.try_recv());
}

test "reservation: a closed channel returns the value" {
    var pair = try mpsc.channel(u32, gpa, testing.io, 1);
    defer pair.sender.deinit();
    pair.receiver.deinit();
    const outcome = send_or_reserve(u32, pair.sender, 1);
    try testing.expectEqual(1, outcome.closed);
}

test "reservation: waits for capacity, and reservations can be stored" {
    var pair = try mpsc.channel(u32, gpa, testing.io, 1);
    defer pair.receiver.deinit();
    defer pair.sender.deinit();
    try pair.sender.try_send(0);
    var stored: [2]Reservation(u32) = .{
        send_or_reserve(u32, pair.sender, 1).reserved,
        send_or_reserve(u32, pair.sender, 2).reserved,
    };
    for (&stored, 0..) |*reservation, index| {
        try testing.expectEqual(@as(?u32, @intCast(index)), try pair.receiver.recv());
        var outcome = try reservation.wait();
        outcome.reserved.send();
    }
    try testing.expectEqual(@as(?u32, 2), try pair.receiver.recv());
}

test "reservation: returns the value when closed while waiting" {
    var pair = try mpsc.channel(u32, gpa, testing.io, 1);
    defer pair.sender.deinit();
    try pair.sender.try_send(1);
    var reservation = send_or_reserve(u32, pair.sender, 2).reserved;
    pair.receiver.deinit();
    const outcome = try reservation.wait();
    try testing.expectEqual(2, outcome.closed);

    var again = try mpsc.channel(u32, gpa, testing.io, 1);
    defer again.receiver.deinit();
    defer again.sender.deinit();
    try again.sender.try_send(1);
    var cancelled = send_or_reserve(u32, again.sender, 3).reserved;
    try testing.expectEqual(3, cancelled.cancel());
    assert(again.sender.capacity() == 0);
}
