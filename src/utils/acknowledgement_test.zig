//! Tests for `acknowledgement.Exact` (commonware `utils/src/acknowledgement.rs` and the
//! `utils/fuzz` ack target).

const std = @import("std");
const acknowledgement = @import("acknowledgement.zig");
const fuzz = @import("fuzz.zig");
const rng = @import("rng.zig");
const Exact = acknowledgement.Exact;
const Io = std.Io;

const testing = std.testing;
const gpa = testing.allocator;

fn expect_pending(waiter: *const Exact.Waiter) !void {
    try testing.expectEqual(@as(?acknowledgement.Canceled!void, null), waiter.poll());
}

fn expect_done(waiter: *const Exact.Waiter) !void {
    const outcome = waiter.poll() orelse return error.TestUnexpectedResult;
    try outcome;
}

fn expect_canceled(waiter: *const Exact.Waiter) !void {
    const outcome = waiter.poll() orelse return error.TestUnexpectedResult;
    try testing.expectError(error.AcknowledgementCanceled, outcome);
}

test "acknowledgement: acknowledges after all listeners" {
    var pair = try Exact.handle(gpa, testing.io);
    defer pair.waiter.deinit();
    var second = pair.acknowledgement.clone();
    pair.acknowledgement.acknowledge();
    try expect_pending(&pair.waiter);
    second.acknowledge();
    try expect_done(&pair.waiter);
    try pair.waiter.wait();
}

test "acknowledgement: cancels on drop" {
    var pair = try Exact.handle(gpa, testing.io);
    defer pair.waiter.deinit();
    pair.acknowledgement.deinit();
    try expect_canceled(&pair.waiter);
    try testing.expectError(error.AcknowledgementCanceled, pair.waiter.wait());
}

test "acknowledgement: cancels on drop before or after acknowledgement" {
    var before = try Exact.handle(gpa, testing.io);
    defer before.waiter.deinit();
    var before_clone = before.acknowledgement.clone();
    before_clone.deinit();
    before.acknowledgement.acknowledge();
    try expect_canceled(&before.waiter);

    var after = try Exact.handle(gpa, testing.io);
    defer after.waiter.deinit();
    var after_clone = after.acknowledgement.clone();
    after.acknowledgement.acknowledge();
    after_clone.deinit();
    try expect_canceled(&after.waiter);
}

test "acknowledgement: dropping the waiter does not interfere" {
    var pair = try Exact.handle(gpa, testing.io);
    const state = pair.acknowledgement.state;
    var second = pair.acknowledgement.clone();
    pair.acknowledgement.acknowledge();
    // The last two references are the waiter and `second`.
    try testing.expectEqual(2, state.references);
    pair.waiter.deinit();
    try testing.expectEqual(1, state.remaining);
    try testing.expect(!state.canceled);
    // Acknowledging the last handle frees the state (the allocator checks for leaks).
    second.acknowledge();
}

fn acknowledge_later(handle: *Exact, io: Io) Io.Cancelable!void {
    try io.sleep(.fromMilliseconds(1), .awake);
    handle.acknowledge();
}

test "acknowledgement: wait resolves on a concurrent acknowledgement" {
    const io = testing.io;
    var pair = try Exact.handle(gpa, io);
    defer pair.waiter.deinit();
    var future = try io.concurrent(acknowledge_later, .{ &pair.acknowledgement, io });
    try pair.waiter.wait();
    try future.await(io);
}

/// Fuzz (commonware utils/fuzz ack.rs): clone up to 255 handles, acknowledge some, drop the
/// rest in a random order, and check the waiter's outcome.
fn fuzz_acknowledgement(_: void, generator: *rng.FuzzRng) !void {
    var pair = try Exact.handle(gpa, testing.io);
    defer pair.waiter.deinit();
    const clones = rng.range_at_most(generator, usize, 1, 255);
    const handles = try gpa.alloc(Exact, clones);
    defer gpa.free(handles);
    handles[0] = pair.acknowledgement;
    for (handles[1..]) |*handle| handle.* = handles[0].clone();
    rng.random(generator).shuffle(Exact, handles);

    const acknowledged = rng.range_at_most(generator, usize, 0, clones);
    for (handles, 0..) |*handle, index| {
        // Every handle must be released before the outcome is final.
        if (index + 1 < clones) try expect_pending_or_canceled(&pair.waiter);
        if (index < acknowledged) handle.acknowledge() else handle.deinit();
    }
    if (acknowledged == clones) {
        try expect_done(&pair.waiter);
    } else {
        try expect_canceled(&pair.waiter);
    }
}

fn expect_pending_or_canceled(waiter: *const Exact.Waiter) !void {
    const outcome = waiter.poll() orelse return;
    try testing.expectError(error.AcknowledgementCanceled, outcome);
}

test "fuzz acknowledgement" {
    try fuzz.run({}, fuzz_acknowledgement, 0x61636b, 300);
}
