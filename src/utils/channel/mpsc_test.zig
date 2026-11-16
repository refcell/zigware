//! Tests for `channel.mpsc` (tokio `mpsc` semantics that commonware relies on).

const std = @import("std");
const mpsc = @import("mpsc.zig");
const fuzz = @import("../fuzz.zig");
const rng = @import("../rng.zig");
const Io = std.Io;

const testing = std.testing;
const gpa = testing.allocator;

test "mpsc: bounded send, try_send, and recv in order" {
    var pair = try mpsc.channel(u32, gpa, testing.io, 2);
    defer pair.receiver.deinit();
    defer pair.sender.deinit();
    try pair.sender.send(1);
    try pair.sender.try_send(2);
    try testing.expectError(error.Full, pair.sender.try_send(3));
    try testing.expectEqual(0, pair.sender.capacity());
    try testing.expectEqual(2, pair.receiver.len());
    try testing.expectEqual(@as(?u32, 1), try pair.receiver.recv());
    try testing.expectEqual(1, pair.sender.capacity());
    try testing.expectEqual(2, try pair.receiver.try_recv());
    try testing.expectError(error.Empty, pair.receiver.try_recv());
}

test "mpsc: recv ends once every sender is gone" {
    var pair = try mpsc.unbounded(u32, gpa, testing.io);
    defer pair.receiver.deinit();
    var second = pair.sender.clone();
    try testing.expect(pair.sender.same_channel(second));
    try pair.sender.send(1);
    pair.sender.deinit();
    try second.send(2);
    second.deinit();
    try testing.expectEqual(@as(?u32, 1), try pair.receiver.recv());
    try testing.expectEqual(@as(?u32, 2), try pair.receiver.recv());
    try testing.expectEqual(@as(?u32, null), try pair.receiver.recv());
    try testing.expectError(error.Disconnected, pair.receiver.try_recv());
}

test "mpsc: a dropped or closed receiver refuses sends" {
    var dropped = try mpsc.channel(u32, gpa, testing.io, 1);
    defer dropped.sender.deinit();
    try testing.expect(!dropped.sender.is_closed());
    dropped.receiver.deinit();
    try testing.expect(dropped.sender.is_closed());
    try dropped.sender.closed();
    try testing.expectError(error.Closed, dropped.sender.send(1));
    try testing.expectError(error.Closed, dropped.sender.try_send(1));
    try testing.expectError(error.Closed, dropped.sender.reserve());

    // Close keeps buffered values readable.
    var closed = try mpsc.channel(u32, gpa, testing.io, 2);
    defer closed.receiver.deinit();
    defer closed.sender.deinit();
    try closed.sender.send(7);
    closed.receiver.close();
    try testing.expectError(error.Closed, closed.sender.try_send(8));
    try testing.expectEqual(@as(?u32, 7), try closed.receiver.recv());
    try testing.expectEqual(@as(?u32, null), try closed.receiver.recv());
}

test "mpsc: permits hold capacity and keep the channel open" {
    var pair = try mpsc.channel(u32, gpa, testing.io, 2);
    defer pair.receiver.deinit();
    var first = try pair.sender.reserve();
    var second = try pair.sender.try_reserve();
    try testing.expectError(error.Full, pair.sender.try_send(1));
    try testing.expectError(error.Full, pair.sender.try_reserve());
    pair.sender.deinit();
    // The permits are senders: the receiver waits for them.
    try testing.expectError(error.Empty, pair.receiver.try_recv());
    first.send(10);
    second.deinit();
    try testing.expectEqual(@as(?u32, 10), try pair.receiver.recv());
    try testing.expectEqual(@as(?u32, null), try pair.receiver.recv());
}

const Owned = struct {
    dropped: *u32,

    pub fn discard(value: Owned) void {
        value.dropped.* += 1;
    }
};

test "mpsc: dropping the receiver discards buffered values" {
    var dropped: u32 = 0;
    var pair = try mpsc.channel(Owned, gpa, testing.io, 4);
    defer pair.sender.deinit();
    var permit = try pair.sender.reserve();
    try pair.sender.send(.{ .dropped = &dropped });
    try pair.sender.send(.{ .dropped = &dropped });
    pair.receiver.deinit();
    try testing.expectEqual(2, dropped);
    // A permit sending after the receiver is gone discards its value.
    permit.send(.{ .dropped = &dropped });
    try testing.expectEqual(3, dropped);
}

fn send_range(sender: mpsc.Sender(u32), start: u32, count: u32) !void {
    var owned = sender;
    defer owned.deinit();
    for (start..start + count) |value| try owned.send(@intCast(value));
}

test "mpsc: concurrent senders wait for room and deliver everything" {
    const io = testing.io;
    var pair = try mpsc.channel(u32, gpa, io, 3);
    defer pair.receiver.deinit();
    var first = try io.concurrent(send_range, .{ pair.sender.clone(), 0, 200 });
    var second = try io.concurrent(send_range, .{ pair.sender.clone(), 1000, 200 });
    pair.sender.deinit();
    var next_low: u32 = 0;
    var next_high: u32 = 1000;
    while (try pair.receiver.recv()) |value| {
        // Each sender's values arrive in order.
        if (value < 1000) {
            try testing.expectEqual(next_low, value);
            next_low += 1;
        } else {
            try testing.expectEqual(next_high, value);
            next_high += 1;
        }
    }
    try first.await(io);
    try second.await(io);
    try testing.expectEqual(200, next_low);
    try testing.expectEqual(1200, next_high);
}

/// Model fuzz: random sends, reservations, receives, and closes against a FIFO model.
fn fuzz_mpsc(_: void, generator: *rng.FuzzRng) !void {
    const capacity = rng.range_at_most(generator, usize, 1, 4);
    var pair = try mpsc.channel(u32, gpa, testing.io, capacity);
    defer pair.receiver.deinit();
    defer pair.sender.deinit();
    var permits: std.ArrayList(mpsc.Permit(u32)) = .empty;
    defer {
        for (permits.items) |*permit| permit.deinit();
        permits.deinit(gpa);
    }
    var model: std.Deque(u32) = .empty;
    defer model.deinit(gpa);
    var open = true;
    var next: u32 = 0;
    for (0..rng.range_at_most(generator, u32, 0, 64)) |_| {
        switch (rng.range_less_than(generator, u8, 0, 5)) {
            0 => if (pair.sender.try_send(next)) {
                try model.pushBack(gpa, next);
            } else |err| try testing.expectEqual(
                if (!open) error.Closed else error.Full,
                err,
            ),
            1 => if (pair.sender.try_reserve()) |permit| {
                try permits.append(gpa, permit);
            } else |err| try testing.expectEqual(if (!open) error.Closed else error.Full, err),
            2 => if (permits.pop()) |permit_value| {
                var permit = permit_value;
                if (rng.boolean(generator)) {
                    permit.send(next);
                    if (open) try model.pushBack(gpa, next);
                } else permit.deinit();
            },
            3 => {
                const expected = model.popFront();
                const actual = pair.receiver.try_recv() catch null;
                try testing.expectEqual(expected, actual);
            },
            else => if (rng.ratio(generator, 1, 8)) {
                pair.receiver.close();
                open = false;
            },
        }
        try testing.expect(model.len + permits.items.len <= capacity);
        next += 1;
    }
}

test "fuzz mpsc" {
    try fuzz.run({}, fuzz_mpsc, 0x6d70_7363, 300);
}
