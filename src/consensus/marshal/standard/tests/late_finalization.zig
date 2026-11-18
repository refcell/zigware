//! Finalizations that arrive for blocks at or below the processed height (commonware
//! `marshal/standard/mod.rs`, lines 1219-1599), on the direct actor from `common.zig`.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const utils = @import("utils");
const types = @import("../../../types.zig");
const core = @import("../../core/root.zig");
const harness = @import("../../mocks/harness.zig");
const mocks_block = @import("../../mocks/block.zig");
const common = @import("common.zig");

const gpa = testing.allocator;
const H = harness.StandardHarness;
const App = @import("../../mocks/application.zig").Application(harness.B);
const Ctx = runtime.deterministic.Context;
const Height = types.Height;
const Round = types.Round;
const D = harness.D;
const Block = common.Block;
const Processed = core.Processed;
const Started = common.Started(harness.Provider, App, common.RecordingBuffer);

/// commonware's `Runner::timed(30s)`.
const timed: runtime.deterministic.Config = .{ .timeout_ns = 30 * std.time.ns_per_s };

fn run(comptime body: fn (Ctx) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(gpa, timed);
    defer runner.deinit();
    try try runner.start_context(body, .{});
}

/// Genesis, then blocks 1 through `out.len - 1`, block `h` stamped `100 * h`.
fn make_chain(out: []Block) !void {
    var made: usize = 0;
    errdefer for (out[0..made]) |*block| block.deinit();
    out[0] = try H.genesis_block(gpa, harness.num_validators);
    made = 1;
    for (out[1..], 1..) |*block, height| {
        const parent = out[height - 1].digest();
        const raw = try harness.make_raw_block(gpa, parent, .new(height), height * 100);
        block.* = try mocks_block.ready(harness.B, gpa, raw);
        made += 1;
    }
}

fn free_chain(blocks: []Block) void {
    for (blocks) |*block| block.deinit();
}

/// The quorum finalization of `block` at view = height, over its parent's view.
fn finalize(fixture: *const harness.Fixture, block: *const Block) !harness.Finalization {
    const view = block.inner().height().get();
    const round: Round = .new(.zero(), .new(view));
    const proposal = harness.Proposal.init(round, .new(view - 1), block.digest());
    return harness.make_finalization(gpa, fixture, proposal, harness.quorum);
}

/// Reports a fresh finalization of `block`, as `report_finalization` does.
fn report(started: *Started, fixture: *const harness.Fixture, block: *const Block) !void {
    var finalization = try finalize(fixture, block);
    defer finalization.deinit(gpa);
    _ = started.mailbox.report(.{ .finalization = finalization });
}

/// Starts the actor from `chain[0]` (genesis) with a buffer holding `buffered` and a manually
/// acknowledging `application` (the actor gets a clone).
fn start(
    ctx: Ctx,
    prefix: []const u8,
    fixture: *const harness.Fixture,
    application: App,
    chain: []const Block,
    buffered: []const Block,
) !Started {
    var buffer = try common.RecordingBuffer.init(gpa, ctx.io());
    errdefer buffer.deinit();
    for (buffered) |*block| try buffer.insert(block.clone());
    const provider: harness.Provider = .init(&fixture.schemes[0]);
    const genesis: common.Start = .{ .genesis = chain[0].clone() };
    return common.start_standard_actor(
        harness.Provider,
        App,
        common.RecordingBuffer,
        ctx.child("validator"),
        prefix,
        provider,
        application.clone(),
        buffer,
        genesis,
    );
}

/// Polls until the actor reports `expected` processed (commonware's `reschedule` loop).
fn wait_processed(ctx: Ctx, started: *Started, expected: Processed) !void {
    for (0..1000) |_| {
        if (try started.mailbox.get_processed()) |current| {
            if (std.meta.eql(current, expected)) return;
        }
        try ctx.sleep(.fromMilliseconds(1));
    }
    return error.TestProcessedNotReached;
}

/// The sync counters of the finalized archives, one line each, in encoding order.
fn finalized_sync_metrics(ctx: Ctx) ![]u8 {
    const text = try ctx.encode(gpa);
    defer gpa.free(text);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        if (std.mem.indexOf(u8, line, "_syncs") == null) continue;
        const finalized = std.mem.indexOf(u8, line, "finalized_blocks") != null or
            std.mem.indexOf(u8, line, "finalizations_by_height") != null;
        if (!finalized) continue;
        try out.appendSlice(gpa, line);
        try out.append(gpa, '\n');
    }
    return out.toOwnedSlice(gpa);
}

/// Walkback repair stores blocks one and two without their finalizations. A finalization
/// reported later for processed block two is kept, and reporting it again does not sync the
/// finalized archives.
fn keeps_late_finalization_body(ctx: Ctx) anyerror!void {
    var rng = utils.rng.test_rng();
    var fixture = try harness.fixture(gpa, &rng);
    defer fixture.deinit(gpa);
    var chain: [4]Block = undefined;
    try make_chain(&chain);
    defer free_chain(&chain);
    var application = try App.manual_ack(gpa, ctx.io());
    defer application.deinit();
    const prefix = "late-finalization-repaired";
    var started = try start(ctx, prefix, &fixture, application, &chain, chain[1..]);
    defer started.crash();
    try testing.expectEqual(Height.zero(), try application.acknowledged());

    // Finalizing block three repairs blocks one and two from the buffer.
    try report(&started, &fixture, &chain[3]);
    for (1..4) |height| try testing.expectEqual(Height.new(height), try application.acknowledged());
    try wait_processed(ctx, &started, .{ .block = .new(3) });
    try testing.expect(try started.mailbox.get_finalization(.new(2)) == null);

    // A late finalization for block two is kept.
    var finalization = try finalize(&fixture, &chain[2]);
    defer finalization.deinit(gpa);
    _ = started.mailbox.report(.{ .finalization = finalization });
    var kept = try started.mailbox.get_finalization(.new(2)) orelse return error.TestNotKept;
    defer kept.deinit(gpa);
    try testing.expect(std.meta.eql(kept.proposal, finalization.proposal));

    // Duplicate reports find it stored, so the finalized archives' sync counts stay put.
    const before = try finalized_sync_metrics(ctx);
    defer gpa.free(before);
    try testing.expect(before.len > 0);
    for (0..3) |_| {
        _ = started.mailbox.report(.{ .finalization = finalization });
        var again = try started.mailbox.get_finalization(.new(2)) orelse return error.TestLost;
        again.deinit(gpa);
    }
    const after = try finalized_sync_metrics(ctx);
    defer gpa.free(after);
    try testing.expectEqualStrings(before, after);
    const tip = application.tip() orelse return error.TestNoTip;
    try testing.expectEqual(Height.new(3), tip.height);
    try testing.expectEqual(chain[3].digest(), tip.digest);
}

test "standard keeps late finalization for repaired block once" {
    try run(keeps_late_finalization_body);
}

/// A floor at block two marks height one processed without storing block one, so a
/// finalization reported for block one is dropped even though the buffer holds the block.
fn drops_below_floor_body(ctx: Ctx) anyerror!void {
    var rng = utils.rng.test_rng();
    var fixture = try harness.fixture(gpa, &rng);
    defer fixture.deinit(gpa);
    var chain: [3]Block = undefined;
    try make_chain(&chain);
    defer free_chain(&chain);
    var application = try App.manual_ack(gpa, ctx.io());
    defer application.deinit();
    const prefix = "finalization-below-floor";
    var started = try start(ctx, prefix, &fixture, application, &chain, chain[1..]);
    defer started.crash();
    try testing.expectEqual(Height.zero(), try application.acknowledged());

    try started.mailbox.set_floor(try finalize(&fixture, &chain[2]));
    try wait_processed(ctx, &started, .{ .absent = .new(1) });
    if (try started.mailbox.get_block(.{ .height = .new(1) })) |found| {
        var block = found;
        block.deinit();
        return error.TestBlockStored;
    }
    try report(&started, &fixture, &chain[1]);
    // A block the archive lacks must not acquire a finalization.
    try testing.expect(try started.mailbox.get_finalization(.new(1)) == null);
}

test "standard drops finalization for block below floor" {
    try run(drops_below_floor_body);
}
