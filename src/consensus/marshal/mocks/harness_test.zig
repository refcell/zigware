//! Smoke tests for the harness itself; commonware's scenarios run from the variants' tests.

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const utils = @import("utils");
const types = @import("../../types.zig");
const harness = @import("harness.zig");

const gpa = testing.allocator;
const H = harness.StandardHarness;
const Ctx = runtime.deterministic.Context;

const App = @import("application.zig").Application(harness.B);
const Validator = H.Validator(App);
const blocks_total = 24;

fn finalize_body(ctx: Ctx) anyerror!void {
    var rng = utils.rng.test_rng();
    var validators = try harness.fixture(gpa, &rng);
    defer validators.deinit(gpa);
    const participants = validators.participants;
    var network: harness.TestNetwork = try .start(
        gpa,
        ctx.io(),
        3,
        participants,
        harness.max_message_size(H.Variant),
    );
    defer network.stop();
    var apps: [harness.num_validators]App = undefined;
    var made: usize = 0;
    defer for (apps[0..made]) |*app| app.deinit();
    for (&apps) |*app| {
        app.* = try .init(gpa, ctx.io());
        made += 1;
    }
    var nodes: [harness.num_validators]*Validator = undefined;
    var started: usize = 0;
    // Crash every started node before the network stops under it.
    defer for (nodes[0..started]) |node| node.crash();
    for (&nodes, participants, &apps, 0..) |*node, me, *app, index| {
        const node_ctx = ctx.child("validator").with_attribute("index", index);
        const provider: harness.Provider = .init(&validators.schemes[index]);
        node.* = try Validator.setup(node_ctx, network.network, me, provider, 1, app.clone());
        started += 1;
    }
    try network.link_all(participants, harness.link);

    var parent = harness.genesis_parent();
    for (1..blocks_total + 1) |value| {
        const height: types.Height = .new(value);
        var block = try H.make_test_block(gpa, parent, parent, height, value, 4);
        defer block.deinit();
        parent = H.digest(&block);
        const round: types.Round = .new(.new(value / harness.blocks_per_epoch), .new(value));
        const proposer = nodes[value % harness.num_validators];
        try H.propose(proposer, round, &block);
        try H.verify(proposer, round, &block);
        try ctx.sleep(.fromMilliseconds(100));
        const proposal = harness.Proposal.init(round, .new(value - 1), H.commitment(&block));
        var notarization = try harness.make_notarization(gpa, &validators, proposal, 3);
        defer notarization.deinit(gpa);
        _ = proposer.mailbox.report(.{ .notarization = notarization });
        var finalization = try harness.make_finalization(gpa, &validators, proposal, 3);
        defer finalization.deinit(gpa);
        for (nodes) |node| _ = node.mailbox.report(.{ .finalization = finalization });
    }
    var waited: u32 = 0;
    while (!finished(&apps)) : (waited += 1) {
        if (waited > 600) return error.TestTimedOut;
        try ctx.sleep(.fromSeconds(1));
    }
}

fn finished(apps: []const App) bool {
    for (apps) |app| {
        if (app.block_count() != blocks_total + 1) return false;
        const tip = app.tip() orelse return false;
        if (tip.height.get() < blocks_total) return false;
    }
    return true;
}

test "every validator finalizes the chain over the simulated network" {
    var runner = try runtime.deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try try runner.start_context(finalize_body, .{});
}
