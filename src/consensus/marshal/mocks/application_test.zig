//! Tests for the mock finalized-block application.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const cryptography = @import("cryptography");
const utils = @import("utils");
const types = @import("../../types.zig");
const block_mod = @import("block.zig");
const application = @import("application.zig");

const Sha256 = cryptography.Sha256;
const B = block_mod.EmptyBlock(Sha256);
const App = application.Application(B);
const Ctx = runtime.deterministic.Context;
const Exact = utils.acknowledgement.Exact;
const Height = types.Height;
const gpa = testing.allocator;

fn run(comptime body: fn (Ctx) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try try runner.start_context(body, .{});
}

/// Reports the block at `height` (timestamped `stamp`) and returns its acknowledgement waiter.
fn report_block(app: *App, io: std.Io, height: u64, stamp: u64) !Exact.Waiter {
    const handle = try Exact.handle(gpa, io);
    const block = try block_mod.ready(B, gpa, B.init(Sha256.Digest.empty, .new(height), stamp));
    try testing.expectEqual(.ok, app.report(.{ .block = .{
        .block = block,
        .ack = handle.acknowledgement,
    } }));
    return handle.waiter;
}

fn expect_heights(actual: []const Height, expected: []const u64) !void {
    try testing.expectEqual(expected.len, actual.len);
    for (actual, expected) |height, want| try testing.expectEqual(want, height.get());
}

fn auto_ack(ctx: Ctx) !void {
    const io = ctx.io();
    var app = try App.init(gpa, io);
    defer app.deinit();
    var view = app.clone();
    defer view.deinit();
    var second = try report_block(&app, io, 2, 0);
    defer second.deinit();
    var first = try report_block(&app, io, 1, 0);
    defer first.deinit();
    // Each block is acknowledged on arrival; the clone sees them ordered by height.
    try second.wait();
    try first.wait();
    const entries = try view.blocks(gpa);
    defer App.free_blocks(gpa, entries);
    try testing.expectEqual(2, entries.len);
    try testing.expectEqual(1, entries[0].height.get());
    try testing.expectEqual(2, entries[1].height.get());
    try testing.expect(view.contains(.new(2)) and !view.contains(.new(3)));
    const pending = try view.pending_ack_heights(gpa);
    defer gpa.free(pending);
    try testing.expectEqual(0, pending.len);
    try testing.expectEqual(null, view.acknowledge_next());
}

test "an auto-acknowledging application records blocks in height order" {
    try run(auto_ack);
}

fn tip_and_replace(ctx: Ctx) !void {
    const io = ctx.io();
    var app = try App.init(gpa, io);
    defer app.deinit();
    try testing.expectEqual(null, app.tip());
    const digest = B.init(Sha256.Digest.empty, .new(7), 0).digest();
    const round: types.Round = .new(.new(0), .new(9));
    _ = app.report(.{ .tip = .{ .round = round, .height = .new(7), .digest = digest } });
    const tip = app.tip().?;
    try testing.expectEqual(7, tip.height.get());
    try testing.expect(tip.digest.eql(digest));
    // A second block at a height replaces the first (and frees it).
    var old = try report_block(&app, io, 3, 1);
    defer old.deinit();
    var new = try report_block(&app, io, 3, 2);
    defer new.deinit();
    try testing.expectEqual(1, app.block_count());
    var stored = app.block(.new(3)).?;
    defer stored.deinit();
    try testing.expectEqual(2, stored.inner().timestamp);
    try testing.expectEqual(null, app.block(.new(4)));
}

test "the application keeps the latest tip and one block per height" {
    try run(tip_and_replace);
}

fn manual_ack(ctx: Ctx) !void {
    const io = ctx.io();
    var app = try App.manual_ack(gpa, io);
    defer app.deinit();
    var waiters: [3]Exact.Waiter = undefined;
    for (&waiters, [_]u64{ 2, 1, 3 }) |*waiter, height| {
        waiter.* = try report_block(&app, io, height, 0);
    }
    defer for (&waiters) |*waiter| waiter.deinit();
    const pending = try app.pending_ack_heights(gpa);
    defer gpa.free(pending);
    try expect_heights(pending, &.{ 2, 1, 3 });
    try testing.expectEqual(null, waiters[0].poll());
    // Acknowledgements release in arrival order, not height order.
    try testing.expectEqual(2, app.acknowledge_next().?.get());
    try waiters[0].poll().?;
    try testing.expectEqual(null, waiters[1].poll());
    try testing.expectEqual(1, (try app.acknowledged()).get());
    try testing.expectEqual(3, app.acknowledge_next().?.get());
    try waiters[2].poll().?;
    try testing.expectEqual(null, app.acknowledge_next());
    try testing.expectEqual(3, app.block_count());
}

test "a manual-ack application queues acknowledgements in arrival order" {
    try run(manual_ack);
}

fn late_report(app: *App, io: std.Io) !Exact.Waiter {
    try io.sleep(.fromMilliseconds(50), .awake);
    return report_block(app, io, 4, 0);
}

fn acknowledged_waits(ctx: Ctx) !void {
    const io = ctx.io();
    var app = try App.manual_ack(gpa, io);
    defer app.deinit();
    var reporter = app.clone();
    defer reporter.deinit();
    var task = try io.concurrent(late_report, .{ &reporter, io });
    const started = std.Io.Timestamp.now(io, .awake).nanoseconds;
    try testing.expectEqual(4, (try app.acknowledged()).get());
    const elapsed_ns = std.Io.Timestamp.now(io, .awake).nanoseconds - started;
    try testing.expect(elapsed_ns >= 50 * std.time.ns_per_ms);
    var waiter = try task.await(io);
    defer waiter.deinit();
    try waiter.wait();
}

test "acknowledged waits for the next block, then acknowledges it" {
    try run(acknowledged_waits);
}

fn drop_pending(ctx: Ctx) !void {
    const io = ctx.io();
    var app = try App.manual_ack(gpa, io);
    var view = app.clone();
    var waiter = try report_block(&app, io, 1, 0);
    defer waiter.deinit();
    // A live clone keeps the acknowledgement pending; the last handle drops it.
    app.deinit();
    try testing.expectEqual(null, waiter.poll());
    view.deinit();
    try testing.expectError(error.AcknowledgementCanceled, waiter.wait());
}

test "dropping the last handle cancels pending acknowledgements" {
    try run(drop_pending);
}
