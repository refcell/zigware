//! The standard actor's prune, pipelined handoff, reproposal coverage across restarts,
//! closed-epoch floors, and cache retention (commonware `standard/mod.rs`, lines
//! 12605-14905).

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const utils = @import("utils");
const types = @import("../../../types.zig");
const harness = @import("../../mocks/harness.zig");
const mocks_block = @import("../../mocks/block.zig");
const common = @import("common.zig");

const gpa = testing.allocator;
const H = harness.StandardHarness;
const App = @import("../../mocks/application.zig").Application(harness.B);
const Ctx = runtime.deterministic.Context;
const Height = types.Height;
const Round = types.Round;

/// commonware's `Runner::timed(30s)`.
const timed: runtime.deterministic.Config = .{ .timeout_ns = 30 * std.time.ns_per_s };

fn run(comptime body: fn (Ctx) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(gpa, timed);
    defer runner.deinit();
    try try runner.start_context(body, .{});
}

/// Whether `mailbox` holds a finalization at `height` (releasing the copy it returns).
fn has_finalization(mailbox: anytype, height: Height) !bool {
    var finalization = (try mailbox.get_finalization(height)) orelse return false;
    finalization.deinit(gpa);
    return true;
}

/// Whether `mailbox` holds the block at `height` (releasing the copy it returns).
fn has_block(mailbox: anytype, height: Height) !bool {
    var block = (try mailbox.get_block(.{ .height = height })) orelse return false;
    block.deinit();
    return true;
}

fn prune_above_floor_body(ctx: Ctx) anyerror!void {
    var rng = utils.rng.test_rng();
    var fixture = try harness.fixture(gpa, &rng);
    defer fixture.deinit(gpa);
    const round: Round = .new(.zero(), .new(1));
    const raw = try harness.make_raw_block(gpa, harness.genesis_parent(), .new(1), 100);
    const block = try mocks_block.ready(harness.B, gpa, raw);
    const proposal = harness.Proposal.init(round, .zero(), block.digest());
    var finalization = try harness.make_finalization(gpa, &fixture, proposal, harness.quorum);
    defer finalization.deinit(gpa);

    var prefix: [128]u8 = undefined;
    const name = try std.fmt.bufPrint(&prefix, "prune-above-floor-{f}", .{fixture.participants[0]});
    const genesis = try H.genesis_block(gpa, harness.num_validators);
    var started = try common.start_standard_actor(
        harness.Provider,
        App,
        common.RecordingBuffer,
        ctx.child("validator").with_attribute("index", 0),
        name,
        .init(&fixture.schemes[0]),
        try App.manual_ack(gpa, ctx.io()),
        try common.RecordingBuffer.init(gpa, ctx.io()),
        .{ .genesis = genesis },
    );
    defer started.crash();
    const mailbox = &started.mailbox;
    try testing.expect(try mailbox.verified(round, block));
    _ = mailbox.report(.{ .finalization = finalization });
    while (!try has_finalization(mailbox, .new(1))) try ctx.sleep(.fromMilliseconds(10));

    // Prune above the floor must be a no-op, not an error.
    try mailbox.prune(.new(100));
    try ctx.sleep(.fromMilliseconds(50));

    // The finalized block and its finalization must still be retrievable.
    try testing.expect(try has_block(mailbox, .new(1)));
    try testing.expect(try has_finalization(mailbox, .new(1)));
}

test "standard prune above floor is rejected (test_standard_prune_above_floor_is_rejected)" {
    try run(prune_above_floor_body);
}
