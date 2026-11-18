//! Tests of `reporter.zig`: tips reach the harness and the wrapped reporter, blocks reach only
//! the wrapped reporter, and a closed monitor still delegates.

const std = @import("std");
const testing = std.testing;
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const utils = @import("utils");
const events_mod = @import("events.zig");
const reporter = @import("reporter.zig");

const marshal = consensus.marshal;
const Sha256 = cryptography.Sha256;
const B = marshal.mocks.EmptyBlock(Sha256);
const App = marshal.mocks.Application(B);
const PublicKey = cryptography.ed25519.PublicKey;
const Events = events_mod.Events(PublicKey);
const Reporter = reporter.MonitorReporter(PublicKey, *App);
const Ctx = runtime.deterministic.Context;
const Exact = utils.acknowledgement.Exact;
const gpa = testing.allocator;

fn run(comptime body: fn (Ctx) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try try runner.start_context(body, .{});
}

fn key() PublicKey {
    return cryptography.ed25519.PrivateKey.from_seed(7).public_key();
}

fn tip_forwarded(ctx: Ctx) !void {
    const io = ctx.io();
    var queue = Events.init(gpa, io);
    defer queue.deinit();
    var app = try App.init(gpa, io);
    defer app.deinit();
    var wrapped = Reporter.init(key(), .{ .events = &queue }, &app);
    const round = consensus.Round.new(.new(2), .new(9));
    const digest = Sha256.hash(&.{"tip"});
    const tip: Reporter.Activity = .{
        .tip = .{ .round = round, .height = .new(5), .digest = digest },
    };
    try testing.expectEqual(.ok, wrapped.report(tip));

    // The harness sees the validator, round, height, and digest bytes.
    const event = (try queue.next(.fromMilliseconds(1))).?;
    defer queue.release(event);
    const report = event.report;
    try testing.expect(report.pk.eql(key()));
    try testing.expectEqual(round, report.round);
    try testing.expectEqual(5, report.height.get());
    try testing.expectEqualSlices(u8, &digest.bytes, report.digest);
    // The wrapped reporter sees the tip too.
    const seen = app.tip().?;
    try testing.expectEqual(5, seen.height.get());
    try testing.expect(seen.digest.eql(digest));
}

test "reporter: a tip reaches the harness and the wrapped reporter" {
    try run(tip_forwarded);
}

fn block_delegated(ctx: Ctx) !void {
    const io = ctx.io();
    var queue = Events.init(gpa, io);
    defer queue.deinit();
    var app = try App.init(gpa, io);
    defer app.deinit();
    var wrapped = Reporter.init(key(), .{ .events = &queue }, &app);
    const handle = try Exact.handle(gpa, io);
    var waiter = handle.waiter;
    defer waiter.deinit();
    const block = try marshal.mocks.ready(B, gpa, B.init(Sha256.Digest.empty, .new(1), 0));
    try testing.expectEqual(.ok, wrapped.report(.{ .block = .{
        .block = block,
        .ack = handle.acknowledgement,
    } }));
    // Blocks are not finalization reports; the wrapped reporter still records them.
    try testing.expectEqual(null, try queue.next(.fromMilliseconds(1)));
    try waiter.wait();
    try testing.expect(app.contains(.new(1)));

    // Once the plan stops listening, tips still reach the wrapped reporter.
    queue.close();
    const digest = Sha256.hash(&.{"late"});
    const round = consensus.Round.new(.new(0), .new(3));
    try testing.expectEqual(.ok, wrapped.report(.{ .tip = .{
        .round = round,
        .height = .new(2),
        .digest = digest,
    } }));
    try testing.expectEqual(2, app.tip().?.height.get());
    try testing.expectEqual(null, try queue.next(.fromMilliseconds(1)));
}

test "reporter: blocks and late tips reach only the wrapped reporter" {
    try run(block_delegated);
}
