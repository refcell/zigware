//! Graceful channel shutdown helpers (commonware `utils/src/channel/fallible.rs`).
//!
//! Senders may outlive receivers during shutdown. These helpers treat disconnection as an
//! outcome instead of an error: `send_lossy` reports whether the value was delivered (a value
//! that was not is passed to `T.discard`, if declared), and `request` sends a message carrying
//! a oneshot responder and returns null when either side went away.
//!
//! Rust's `make_msg` closure is a `maker` with `fn make(self, responder: oneshot.Sender(R)) T`.

const std = @import("std");
const mpsc = @import("mpsc.zig");
const oneshot = @import("oneshot.zig");
const reservation = @import("reservation.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;

fn discard(comptime T: type, value: T) void {
    switch (@typeInfo(T)) {
        .@"struct", .@"union", .@"enum", .@"opaque" => {
            if (@hasDecl(T, "discard")) T.discard(value);
        },
        else => {},
    }
}

/// Sends `value` (waiting for room on a bounded channel); false when the receiver is gone.
pub fn send_lossy(
    comptime T: type,
    sender: mpsc.Sender(T),
    value: T,
) (Io.Cancelable || Allocator.Error)!bool {
    sender.send(value) catch |err| switch (err) {
        error.Closed => {
            discard(T, value);
            return false;
        },
        error.Canceled, error.OutOfMemory => |e| {
            discard(T, value);
            return e;
        },
    };
    return true;
}

/// Sends `value` without waiting; false when the channel is full or the receiver is gone.
pub fn try_send_lossy(comptime T: type, sender: mpsc.Sender(T), value: T) Allocator.Error!bool {
    sender.try_send(value) catch |err| switch (err) {
        error.Full, error.Closed => {
            discard(T, value);
            return false;
        },
        error.OutOfMemory => |e| {
            discard(T, value);
            return e;
        },
    };
    return true;
}

/// Sends now or reserves when full; null when sent or when the receiver is gone.
pub fn send_or_reserve_lossy(
    comptime T: type,
    sender: mpsc.Sender(T),
    value: T,
) ?reservation.Reservation(T) {
    return switch (reservation.send_or_reserve(T, sender, value)) {
        .sent => null,
        .reserved => |pending| pending,
        .closed => |returned| {
            discard(T, returned);
            return null;
        },
    };
}

/// A oneshot `send` that reports delivery instead of failing (Rust `OneshotExt::send_lossy`).
pub fn oneshot_send_lossy(comptime T: type, sender: *oneshot.Sender(T), value: T) bool {
    sender.send(value) catch {
        discard(T, value);
        return false;
    };
    return true;
}

/// Sends `maker.make(responder)` and waits for the response; null when the receiver or the
/// responder went away.
pub fn request(
    comptime T: type,
    comptime R: type,
    gpa: Allocator,
    io: Io,
    sender: mpsc.Sender(T),
    maker: anytype,
) (Io.Cancelable || Allocator.Error)!?R {
    var pair = try oneshot.channel(R, gpa, io);
    defer pair.receiver.deinit();
    if (!try send_lossy(T, sender, maker.make(pair.sender))) return null;
    return pair.receiver.recv() catch |err| switch (err) {
        error.Closed => null,
        error.Canceled => error.Canceled,
    };
}

/// `request`, or `default` on failure.
pub fn request_or(
    comptime T: type,
    comptime R: type,
    gpa: Allocator,
    io: Io,
    sender: mpsc.Sender(T),
    maker: anytype,
    default: R,
) (Io.Cancelable || Allocator.Error)!R {
    return try request(T, R, gpa, io, sender, maker) orelse default;
}

/// `request`, or `R`'s default on failure (`R.default()` when declared, else zero).
pub fn request_or_default(
    comptime T: type,
    comptime R: type,
    gpa: Allocator,
    io: Io,
    sender: mpsc.Sender(T),
    maker: anytype,
) (Io.Cancelable || Allocator.Error)!R {
    const default: R = switch (@typeInfo(R)) {
        .@"struct", .@"union", .@"enum" => if (@hasDecl(R, "default")) R.default() else .{},
        else => std.mem.zeroes(R),
    };
    return request_or(T, R, gpa, io, sender, maker, default);
}

const testing = std.testing;
const gpa_test = testing.allocator;

const Message = union(enum) {
    fire_and_forget: u32,
    request_bool: oneshot.Sender(bool),
    request_count: oneshot.Sender(u32),

    /// Rust drops the responder with the message.
    pub fn discard(message: Message) void {
        switch (message) {
            .fire_and_forget => {},
            inline .request_bool, .request_count => |responder| {
                var owned = responder;
                owned.deinit();
            },
        }
    }
};

const AskBool = struct {
    pub fn make(_: AskBool, responder: oneshot.Sender(bool)) Message {
        return .{ .request_bool = responder };
    }
};

const AskCount = struct {
    pub fn make(_: AskCount, responder: oneshot.Sender(u32)) Message {
        return .{ .request_count = responder };
    }
};

test "fallible: send_lossy on unbounded and bounded channels" {
    inline for (.{ false, true }) |bounded| {
        var pair = if (bounded)
            try mpsc.channel(Message, gpa_test, testing.io, 1)
        else
            try mpsc.unbounded(Message, gpa_test, testing.io);
        defer pair.sender.deinit();
        try testing.expect(try send_lossy(Message, pair.sender, .{ .fire_and_forget = 42 }));
        try testing.expectEqual(42, (try pair.receiver.try_recv()).fire_and_forget);
        pair.receiver.deinit();
        try testing.expect(!try send_lossy(Message, pair.sender, .{ .fire_and_forget = 42 }));
    }
}

test "fallible: try_send_lossy" {
    var pair = try mpsc.channel(Message, gpa_test, testing.io, 1);
    defer pair.sender.deinit();
    try testing.expect(try try_send_lossy(Message, pair.sender, .{ .fire_and_forget = 42 }));
    try testing.expect(!try try_send_lossy(Message, pair.sender, .{ .fire_and_forget = 43 }));
    try testing.expectEqual(42, (try pair.receiver.try_recv()).fire_and_forget);
    pair.receiver.deinit();
    try testing.expect(!try try_send_lossy(Message, pair.sender, .{ .fire_and_forget = 42 }));
}

test "fallible: requests to a dropped receiver return null or the default" {
    inline for (.{ false, true }) |bounded| {
        var pair = if (bounded)
            try mpsc.channel(Message, gpa_test, testing.io, 1)
        else
            try mpsc.unbounded(Message, gpa_test, testing.io);
        defer pair.sender.deinit();
        pair.receiver.deinit();
        const io = testing.io;
        const sender = pair.sender;
        const asked = try request(Message, bool, gpa_test, io, sender, AskBool{});
        try testing.expectEqual(null, asked);
        try testing.expect(!try request_or(Message, bool, gpa_test, io, sender, AskBool{}, false));
        const count = try request_or_default(Message, u32, gpa_test, io, sender, AskCount{});
        try testing.expectEqual(0, count);
    }
}

fn answer(receiver: *mpsc.Receiver(Message)) !void {
    const message = (try receiver.recv()).?;
    var responder = message.request_count;
    try testing.expect(oneshot_send_lossy(u32, &responder, 7));
}

test "fallible: a request gets its response" {
    const io = testing.io;
    var pair = try mpsc.channel(Message, gpa_test, io, 1);
    defer pair.receiver.deinit();
    defer pair.sender.deinit();
    var responder = try io.concurrent(answer, .{&pair.receiver});
    const response = try request(Message, u32, gpa_test, io, pair.sender, AskCount{});
    try testing.expectEqual(@as(?u32, 7), response);
    try responder.await(io);
}

test "fallible: send_or_reserve_lossy" {
    var pair = try mpsc.channel(Message, gpa_test, testing.io, 1);
    defer pair.sender.deinit();
    const sent = send_or_reserve_lossy(Message, pair.sender, .{ .fire_and_forget = 1 });
    try testing.expectEqual(null, sent);
    var pending = send_or_reserve_lossy(Message, pair.sender, .{ .fire_and_forget = 2 }).?;
    try testing.expectEqual(1, (try pair.receiver.recv()).?.fire_and_forget);
    var outcome = try pending.wait();
    outcome.reserved.send();
    try testing.expectEqual(2, (try pair.receiver.recv()).?.fire_and_forget);

    // Reserved, then the receiver goes away.
    try pair.sender.try_send(.{ .fire_and_forget = 3 });
    var orphan = send_or_reserve_lossy(Message, pair.sender, .{ .fire_and_forget = 4 }).?;
    pair.receiver.deinit();
    try testing.expect((try orphan.wait()) == .closed);
    const closed = send_or_reserve_lossy(Message, pair.sender, .{ .fire_and_forget = 5 });
    try testing.expectEqual(null, closed);
}

test "fallible: oneshot send_lossy" {
    var delivered = try oneshot.channel(u32, gpa_test, testing.io);
    try testing.expect(oneshot_send_lossy(u32, &delivered.sender, 42));
    try testing.expectEqual(42, try delivered.receiver.recv());
    delivered.receiver.deinit();

    var refused = try oneshot.channel(u32, gpa_test, testing.io);
    refused.receiver.deinit();
    try testing.expect(!oneshot_send_lossy(u32, &refused.sender, 42));
}
