//! Checks of the coding harness's blocks.

const std = @import("std");
const testing = std.testing;
const harness = @import("harness.zig");
const types = @import("types.zig");
const core_variant = @import("../core/variant.zig");

const gpa = testing.allocator;
const H = harness.CodingHarness;

comptime {
    core_variant.assert_variant(H.Variant);
    core_variant.assert_buffer(H.Buffer);
}

test "coding harness genesis commits to its block under the genesis config" {
    var genesis = try H.genesis_block(gpa, 4);
    defer genesis.deinit(gpa);
    const value = H.commitment(&genesis);
    try testing.expect(value.block().eql(H.digest(&genesis)));
    try testing.expect(value.root().eql(H.digest(&genesis)));
    try testing.expect(value.config().eql(harness.genesis_coding_config));
    const context_digest = try types.hash_context(harness.Sha256, gpa, genesis.context());
    try testing.expect(value.context().eql(context_digest));
    try testing.expectEqual(0, H.height(&genesis).get());
}

test "coding harness test blocks chain over their parents' commitments" {
    var genesis = try H.genesis_block(gpa, 4);
    defer genesis.deinit(gpa);
    const parent = H.commitment(&genesis);
    var block = try H.make_test_block(gpa, H.digest(&genesis), parent, .new(1), 7, 4);
    defer block.deinit(gpa);
    try testing.expectEqual(1, H.height(&block).get());
    try testing.expect(block.parent().eql(H.digest(&genesis)));
    try testing.expect(block.context().parent[1].eql(parent));
    try testing.expectEqual(0, block.context().parent[0].get());
    const config = types.coding_config_for_participants(4);
    try testing.expect(H.commitment(&block).config().eql(config));
}

test "coding validator type checks against the core actor" {
    const App = @import("../mocks/application.zig").Application(harness.CodingB);
    const Validator = H.Validator(App);
    testing.refAllDecls(Validator);
    _ = &Validator.setup;
    _ = &Validator.crash;
}

const runtime = @import("runtime");
const utils = @import("utils");
const shared = @import("../mocks/harness.zig");
const consensus_types = @import("../../types.zig");
const simplex_types = @import("../../simplex/types.zig");
const SmokeApp = @import("../mocks/application.zig").Application(harness.CodingB);
const SmokeValidator = H.Validator(SmokeApp);
const smoke_blocks = 12;

fn smoke_finished(apps: []const SmokeApp) bool {
    for (apps) |app| {
        if (app.block_count() != smoke_blocks + 1) return false;
        const tip = app.tip() orelse return false;
        if (tip.height.get() < smoke_blocks) return false;
    }
    return true;
}

fn smoke_body(ctx: runtime.deterministic.Context) anyerror!void {
    var rng = utils.rng.test_rng();
    var validators = try H.fixture(gpa, &rng);
    defer validators.deinit(gpa);
    const participants = validators.participants;
    const max_size = shared.max_message_size(H.Variant);
    var network: shared.TestNetwork = try .start(gpa, ctx.io(), 3, participants, max_size);
    defer network.stop();
    var apps: [shared.num_validators]SmokeApp = undefined;
    var made: usize = 0;
    defer for (apps[0..made]) |*app| app.deinit();
    for (&apps) |*app| {
        app.* = try .init(gpa, ctx.io());
        made += 1;
    }
    var nodes: [shared.num_validators]*SmokeValidator = undefined;
    var started: usize = 0;
    defer for (nodes[0..started]) |node| node.crash();
    for (&nodes, participants, &apps, 0..) |*node, me, *app, index| {
        const node_ctx = ctx.child("validator").with_attribute("index", index);
        const provider: H.Provider = .init(&validators.schemes[index]);
        node.* = try SmokeValidator.setup(node_ctx, network.network, me, provider, 1, app.clone());
        started += 1;
    }
    try network.link_all(participants, shared.link);

    var genesis = try H.genesis_block(gpa, shared.num_validators);
    var parent = H.digest(&genesis);
    var parent_commitment = H.commitment(&genesis);
    genesis.deinit(gpa);
    for (1..smoke_blocks + 1) |value| {
        const height: consensus_types.Height = .new(value);
        var block = try H.make_test_block(gpa, parent, parent_commitment, height, value, 4);
        defer block.deinit(gpa);
        parent = H.digest(&block);
        parent_commitment = H.commitment(&block);
        const round: consensus_types.Round = .new(.zero(), .new(value));
        // Every validator verifies the block (each holds it whole in this smoke test).
        for (nodes) |node| try H.verify(node, round, &block);
        const Proposal = simplex_types.Proposal(harness.TestCommitment);
        const proposal = Proposal.init(round, .new(value - 1), parent_commitment);
        var finalization = try H.make_finalization(gpa, &validators, proposal, 3);
        defer finalization.deinit(gpa);
        for (nodes) |node| _ = node.mailbox.report(.{ .finalization = finalization });
    }
    var waited: u32 = 0;
    while (!smoke_finished(&apps)) : (waited += 1) {
        if (waited > 600) return error.TestTimedOut;
        try ctx.sleep(.fromSeconds(1));
    }
}

test "coding validators finalize a verified chain over the simulated network" {
    var runner = try runtime.deterministic.Runner.init(gpa, .{});
    defer runner.deinit();
    try try runner.start_context(smoke_body, .{});
}
