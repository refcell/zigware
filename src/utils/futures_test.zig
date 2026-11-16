//! Tests for `futures` (commonware `utils/src/futures.rs`, `futures/try_join_all.rs`, and the
//! `utils/fuzz` futures target).

const std = @import("std");
const futures = @import("futures.zig");
const oneshot = @import("channel/oneshot.zig");
const fuzz = @import("fuzz.zig");
const rng = @import("rng.zig");
const testing = std.testing;
const gpa = testing.allocator;
const io = testing.io;
const Io = std.Io;

fn ready(value: i32) i32 {
    return value;
}

fn wait_then(receiver: *oneshot.Receiver(void), value: i32) i32 {
    receiver.recv() catch {};
    return value;
}

fn relay(
    receiver: *oneshot.Receiver(void),
    sender: *oneshot.Sender(void),
    value: i32,
) i32 {
    receiver.recv() catch {};
    sender.send({}) catch {};
    return value;
}

fn signal(sender: *oneshot.Sender(void), value: i32) i32 {
    sender.send({}) catch {};
    return value;
}

test "futures: pool initialization and adding tasks" {
    var pool = try futures.Pool(i32).init(gpa, io, 4);
    defer pool.deinit(gpa);
    try testing.expect(pool.is_empty());
    pool.push(ready, .{1});
    pool.push(ready, .{2});
    try testing.expectEqual(2, pool.len());
}

test "futures: pool results arrive in completion order" {
    var pool = try futures.Pool(i32).init(gpa, io, 3);
    defer pool.deinit(gpa);
    var first = try oneshot.channel(void, gpa, io);
    defer first.receiver.deinit();
    var third = try oneshot.channel(void, gpa, io);
    defer third.receiver.deinit();
    // Task 1 waits for task 2, and task 3 waits for task 1.
    pool.push(relay, .{ &first.receiver, &third.sender, 1 });
    pool.push(wait_then, .{ &third.receiver, 3 });
    pool.push(signal, .{ &first.sender, 2 });
    try testing.expectEqual(2, try pool.next_completed());
    try testing.expectEqual(1, try pool.next_completed());
    try testing.expectEqual(3, try pool.next_completed());
    try testing.expect(pool.is_empty());
}

fn wait_flag(receiver: *oneshot.Receiver(void), flag: *std.atomic.Value(bool)) i32 {
    receiver.recv() catch return 0;
    flag.store(true, .seq_cst);
    return 42;
}

test "futures: cancel_all drops pending tasks" {
    var pool = try futures.Pool(i32).init(gpa, io, 2);
    defer pool.deinit(gpa);
    var flag: std.atomic.Value(bool) = .init(false);
    var pair = try oneshot.channel(void, gpa, io);
    defer pair.receiver.deinit();
    pool.push(wait_flag, .{ &pair.receiver, &flag });
    try testing.expectEqual(1, pool.len());
    pool.cancel_all();
    try testing.expect(pool.is_empty());
    try testing.expect(!flag.load(.seq_cst));
    pair.sender.send({}) catch {};
    pool.push(ready, .{42});
    try testing.expectEqual(42, try pool.next_completed());
}

test "futures: many tasks" {
    var pool = try futures.Pool(i32).init(gpa, io, 1000);
    defer pool.deinit(gpa);
    for (0..1000) |value| pool.push(ready, .{@as(i32, @intCast(value))});
    try testing.expectEqual(1000, pool.len());
    var sum: i32 = 0;
    for (0..1000) |_| sum += try pool.next_completed();
    try testing.expectEqual(999 * 1000 / 2, sum);
}

fn ready_cancelable(value: i32) Io.Cancelable!i32 {
    return value;
}

fn wait_cancelable(receiver: *oneshot.Receiver(void), value: i32) Io.Cancelable!i32 {
    receiver.recv() catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Closed => {},
    };
    return value;
}

test "futures: abortable pool completes and aborts" {
    var pool = try futures.AbortablePool(i32).init(gpa, io, 4);
    defer pool.deinit(gpa);
    try testing.expect(pool.is_empty());
    _ = pool.push(ready_cancelable, .{42});
    try testing.expectEqual(42, try pool.next_completed());

    // An aborted task reports `Aborted` even when it already finished.
    const done = pool.push(ready_cancelable, .{43});
    done.abort();
    try testing.expectError(error.Aborted, pool.next_completed());

    // A task blocked on a channel is canceled.
    var pair = try oneshot.channel(void, gpa, io);
    defer pair.sender.deinit();
    defer pair.receiver.deinit();
    const blocked = pool.push(wait_cancelable, .{ &pair.receiver, 1 });
    blocked.abort();
    try testing.expectError(error.Aborted, pool.next_completed());
    try testing.expect(pool.is_empty());
    // A stale aborter does nothing to the slot's next task.
    _ = pool.push(ready_cancelable, .{7});
    blocked.abort();
    try testing.expectEqual(7, try pool.next_completed());
}

test "futures: abortable pool partial abort" {
    var pool = try futures.AbortablePool(i32).init(gpa, io, 3);
    defer pool.deinit(gpa);
    var pair = try oneshot.channel(void, gpa, io);
    defer pair.sender.deinit();
    defer pair.receiver.deinit();
    _ = pool.push(ready_cancelable, .{1});
    const second = pool.push(wait_cancelable, .{ &pair.receiver, 2 });
    _ = pool.push(ready_cancelable, .{3});
    try testing.expectEqual(3, pool.len());
    second.abort();
    var sum: i32 = 0;
    var aborted: u32 = 0;
    for (0..3) |_| {
        if (pool.next_completed()) |value| sum += value else |err| {
            try testing.expectEqual(error.Aborted, err);
            aborted += 1;
        }
    }
    try testing.expectEqual(4, sum);
    try testing.expectEqual(1, aborted);
}

fn half(value: u32) error{Odd}!u32 {
    if (value % 2 == 1) return error.Odd;
    return value / 2;
}

test "futures: try_join_all keeps input order or fails" {
    const values = try futures.try_join_all(u32, error{Odd}, gpa, io, half, &.{
        .{8}, .{2}, .{6},
    });
    defer gpa.free(values);
    try testing.expectEqualSlices(u32, &.{ 4, 1, 3 }, values);
    const empty = try futures.try_join_all(u32, error{Odd}, gpa, io, half, &.{});
    defer gpa.free(empty);
    try testing.expectEqual(0, empty.len);
    const failed = futures.try_join_all(u32, error{Odd}, gpa, io, half, &.{ .{2}, .{3} });
    try testing.expectError(error.Odd, failed);
}

const Pending = struct { aborter: futures.AbortablePool(i32).Aborter, id: i32 };

/// Model fuzz (commonware `utils/fuzz/fuzz_targets/futures.rs`), checking that every pushed
/// value comes back once unless canceled or aborted.
fn fuzz_pools(_: void, generator: *rng.FuzzRng) !void {
    var pool = try futures.Pool(i32).init(gpa, io, 64);
    defer pool.deinit(gpa);
    var abortable = try futures.AbortablePool(i32).init(gpa, io, 64);
    defer abortable.deinit(gpa);
    var pending: std.ArrayList(Pending) = .empty;
    defer pending.deinit(gpa);
    var sum_pushed: i64 = 0;
    var sum_completed: i64 = 0;
    var next_id: i32 = 0;
    for (0..rng.range_at_most(generator, u32, 0, 64)) |_| {
        switch (rng.range_less_than(generator, u8, 0, 5)) {
            0 => if (pool.len() < 64) {
                const value: i32 = @bitCast(generator.next_u32() >> 8);
                pool.push(ready, .{value});
                sum_pushed += value;
            },
            1 => if (!pool.is_empty()) {
                sum_completed += try pool.next_completed();
            },
            2 => {
                pool.cancel_all();
                sum_pushed = sum_completed;
            },
            3 => if (abortable.len() < 64) {
                const aborter = abortable.push(ready_cancelable, .{next_id});
                try pending.append(gpa, .{ .aborter = aborter, .id = next_id });
                next_id += 1;
            },
            4 => if (pending.items.len > 0) {
                const index = rng.range_less_than(generator, usize, 0, pending.items.len);
                pending.swapRemove(index).aborter.abort();
                try drain_until_aborted(&abortable, &pending);
            },
            else => unreachable,
        }
        try testing.expectEqual(pending.items.len, abortable.len());
    }
    while (!pool.is_empty()) sum_completed += try pool.next_completed();
    try testing.expectEqual(sum_pushed, sum_completed);
}

/// Takes completions until the one aborted task's comes up; every other is a pending id.
fn drain_until_aborted(pool: *futures.AbortablePool(i32), pending: *std.ArrayList(Pending)) !void {
    while (true) {
        const id = pool.next_completed() catch |err| {
            return testing.expectEqual(error.Aborted, err);
        };
        for (pending.items, 0..) |entry, index| {
            if (entry.id != id) continue;
            _ = pending.swapRemove(index);
            break;
        } else return error.TestUnexpectedResult;
    }
}

test "fuzz futures" {
    try fuzz.run({}, fuzz_pools, 0x6675_7475, 100);
}
