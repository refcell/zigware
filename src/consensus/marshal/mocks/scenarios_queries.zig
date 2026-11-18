//! commonware `mocks/harness.rs`'s query and subscription scenarios (line 3442 to the end),
//! generic over a harness `H` (`harness.StandardHarness`, or the coding variant's harness).
//!
//! Besides the decls `scenarios.zig` lists, these scenarios read `H.genesis_block`. A
//! scenario that drives an actor over prunable finalized archives also needs
//! `setup_prunable_validator(ctx, network, me, validators, prefix, app)` and
//! `verify_for_prune(validator, round, block)`. Marshal blocks provide `digest()` and either
//! `height()` or `inner().height()`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const runtime = @import("runtime");
const utils = @import("utils");
const types = @import("../../types.zig");
const simplex_types = @import("../../simplex/types.zig");
const core = @import("../core/root.zig");
const harness = @import("harness.zig");
const scenarios = @import("scenarios.zig");
const Application = @import("application.zig").Application;

const Ctx = runtime.deterministic.Context;
const Height = types.Height;
const Round = types.Round;
const num_validators = harness.num_validators;
const quorum = harness.quorum;

/// `harness.link`'s latency.
const link_latency_ms: i64 = @intCast(harness.link.latency.as_millis());
/// commonware's `Runner::timed(60s)`.
const timeout_default_s = 60;

/// Runs `body(ctx, args...)` on a deterministic runner with `seed` and a timeout.
fn run_timed(
    gpa: Allocator,
    seed: u64,
    timeout_s: u64,
    comptime body: anytype,
    args: anytype,
) !void {
    assert(timeout_s > 0);
    var runner = try runtime.deterministic.Runner.init(gpa, .{
        .seed = seed,
        .timeout_ns = timeout_s * std.time.ns_per_s,
    });
    defer runner.deinit();
    try try runner.start_context(body, args);
}

/// The height of a marshal block.
pub fn block_height(block: anytype) Height {
    const T = @TypeOf(block.*);
    if (comptime std.meta.hasMethod(T, "height")) return block.height();
    return block.inner().height();
}

fn round_at(view: u64) Round {
    return .new(.zero(), .new(view));
}

/// One validator on a simulated network of every participant, with application `app`.
pub fn Single(comptime H: type) type {
    return struct {
        const Self = @This();
        pub const App = Application(H.ApplicationBlock);
        pub const Validator = H.Validator(App);
        pub const Proposal = simplex_types.Proposal(H.Commitment);

        validators: H.Fixture,
        network: harness.TestNetwork,
        node: *Validator,

        pub fn start(self: *Self, ctx: Ctx, app: App) !void {
            const gpa = ctx.gpa();
            var owned = app;
            errdefer owned.deinit();
            var rng = utils.rng.test_rng();
            self.validators = try H.fixture(gpa, &rng);
            errdefer self.validators.deinit(gpa);
            const participants = self.validators.participants;
            const max_size = harness.max_message_size(H.Variant);
            self.network = try .start(gpa, ctx.io(), 1, participants, max_size);
            errdefer self.network.stop();
            const provider: H.Provider = .init(&self.validators.schemes[0]);
            const node_ctx = ctx.child("validator").with_attribute("index", 0);
            self.node = try Validator.setup(
                node_ctx,
                self.network.network,
                participants[0],
                provider,
                1,
                owned,
            );
        }

        pub fn stop(self: *Self, gpa: Allocator) void {
            self.node.crash();
            self.network.stop();
            self.validators.deinit(gpa);
            self.* = undefined;
        }

        /// Reports the quorum finalization of `block` at view = height to the validator.
        pub fn finalize(self: *Self, gpa: Allocator, block: *const H.TestBlock) !void {
            const view = H.height(block).get();
            assert(view > 0);
            const proposal = Proposal.init(round_at(view), .new(view - 1), H.commitment(block));
            var finalization = try H.make_finalization(gpa, &self.validators, proposal, quorum);
            defer finalization.deinit(gpa);
            _ = self.node.mailbox.report(.{ .finalization = finalization });
        }
    };
}

/// Chain heights 1 through `blocks.len` from genesis, block `h` stamped `h` (owned).
fn make_chain(comptime H: type, gpa: Allocator, blocks: []H.TestBlock) !void {
    var made: usize = 0;
    errdefer for (blocks[0..made]) |*block| block.deinit();
    var parent = harness.genesis_parent();
    var parent_commitment = H.genesis_parent_commitment(num_validators);
    for (blocks, 1..) |*block, value| {
        block.* = try H.make_test_block(gpa, parent, parent_commitment, .new(value), value, 4);
        made += 1;
        parent = H.digest(block);
        parent_commitment = H.commitment(block);
    }
    assert(made == blocks.len);
}

fn free_chain(blocks: anytype) void {
    for (blocks) |*block| block.deinit();
}

/// Proposes each block of `blocks` at view = height, sleeps one link latency, and finalizes
/// it (commonware's single-validator query setup).
fn propose_and_finalize(
    comptime H: type,
    ctx: Ctx,
    single: *Single(H),
    blocks: []H.TestBlock,
) !void {
    for (blocks) |*block| {
        try H.propose(single.node, round_at(H.height(block).get()), block);
        try ctx.sleep(.fromMilliseconds(link_latency_ms));
        try single.finalize(ctx.gpa(), block);
    }
}

fn expect_info(info: anytype, height: Height, digest: anytype) !void {
    const found = info orelse return error.TestNoInfo;
    try testing.expectEqual(height, found.height);
    try testing.expect(found.digest.eql(digest));
}

/// commonware `get_info_basic_queries_present_and_missing`.
pub fn GetInfoBasic(comptime H: type) type {
    return struct {
        pub fn run(gpa: Allocator) !void {
            try run_timed(gpa, 0, timeout_default_s, body, .{});
        }

        fn body(ctx: Ctx) anyerror!void {
            const gpa = ctx.gpa();
            var single: Single(H) = undefined;
            try single.start(ctx, try .init(gpa, ctx.io()));
            defer single.stop(gpa);
            const mailbox = single.node.mailbox;
            // Initially, no latest.
            try testing.expectEqual(null, try mailbox.get_info(.latest));
            // The genesis anchor is stored as a finalized block without a finalization row.
            var genesis = try H.genesis_block(gpa, num_validators);
            defer genesis.deinit();
            const genesis_digest = H.digest(&genesis);
            try expect_info(try mailbox.get_info(.{ .height = .zero() }), .zero(), genesis_digest);
            const by_digest = try mailbox.get_info(.{ .digest = genesis_digest });
            try expect_info(by_digest, .zero(), genesis_digest);
            // Before finalization, a specific height returns null.
            try testing.expectEqual(null, try mailbox.get_info(.{ .height = .new(1) }));

            var blocks: [1]H.TestBlock = undefined;
            try make_chain(H, gpa, &blocks);
            defer free_chain(&blocks);
            try propose_and_finalize(H, ctx, &single, &blocks);
            const digest = H.digest(&blocks[0]);
            try expect_info(try mailbox.get_info(.latest), .new(1), digest);
            try expect_info(try mailbox.get_info(.{ .height = .new(1) }), .new(1), digest);
            try expect_info(try mailbox.get_info(.{ .digest = digest }), .new(1), digest);
            try testing.expectEqual(null, try mailbox.get_info(.{ .height = .new(2) }));
            const missing = harness.Sha256.hash(&.{"missing"});
            try testing.expectEqual(null, try mailbox.get_info(.{ .digest = missing }));
        }
    };
}

/// commonware `get_info_latest_progression_multiple_finalizations`.
pub fn GetInfoLatestProgression(comptime H: type) type {
    return struct {
        pub fn run(gpa: Allocator) !void {
            try run_timed(gpa, 0, timeout_default_s, body, .{});
        }

        fn body(ctx: Ctx) anyerror!void {
            const gpa = ctx.gpa();
            var single: Single(H) = undefined;
            try single.start(ctx, try .init(gpa, ctx.io()));
            defer single.stop(gpa);
            var blocks: [5]H.TestBlock = undefined;
            try make_chain(H, gpa, &blocks);
            defer free_chain(&blocks);
            for (&blocks, 1..) |*block, height| {
                try propose_and_finalize(H, ctx, &single, block[0..1]);
                // Latest always points to the most recently finalized block.
                const latest = try single.node.mailbox.get_info(.latest);
                try expect_info(latest, .new(height), H.digest(block));
            }
            for (&blocks, 1..) |*block, height| {
                const info = try single.node.mailbox.get_info(.{ .height = .new(height) });
                try expect_info(info, .new(height), H.digest(block));
            }
        }
    };
}

/// Expects `found` (owned, freed here) to be a block with `digest` at `height`.
fn expect_block(
    comptime H: type,
    gpa: Allocator,
    found: anytype,
    height: Height,
    digest: anytype,
) !void {
    var block = found orelse return error.TestNoBlock;
    defer H.Variant.deinit_block(gpa, &block);
    try testing.expect(block.digest().eql(digest));
    try testing.expectEqual(height, block_height(&block));
}

/// commonware `get_block_by_height_and_latest`.
pub fn GetBlockByHeightAndLatest(comptime H: type) type {
    return struct {
        pub fn run(gpa: Allocator) !void {
            try run_timed(gpa, 0, timeout_default_s, body, .{});
        }

        fn body(ctx: Ctx) anyerror!void {
            const gpa = ctx.gpa();
            var single: Single(H) = undefined;
            try single.start(ctx, try .init(gpa, ctx.io()));
            defer single.stop(gpa);
            const mailbox = single.node.mailbox;
            try testing.expectEqual(null, try mailbox.get_block(.{ .height = .new(1) }));
            try testing.expectEqual(null, try mailbox.get_block(.latest));
            var blocks: [3]H.TestBlock = undefined;
            try make_chain(H, gpa, &blocks);
            defer free_chain(&blocks);
            try propose_and_finalize(H, ctx, &single, &blocks);
            for (&blocks, 1..) |*block, height| {
                const found = try mailbox.get_block(.{ .height = .new(height) });
                try expect_block(H, gpa, found, .new(height), H.digest(block));
            }
            const latest = try mailbox.get_block(.latest);
            try expect_block(H, gpa, latest, .new(3), H.digest(&blocks[2]));
            try testing.expectEqual(null, try mailbox.get_block(.{ .height = .new(10) }));
        }
    };
}

/// commonware `get_block_by_commitment_from_sources_and_missing`.
pub fn GetBlockByCommitment(comptime H: type) type {
    return struct {
        pub fn run(gpa: Allocator) !void {
            try run_timed(gpa, 0, timeout_default_s, body, .{});
        }

        fn body(ctx: Ctx) anyerror!void {
            const gpa = ctx.gpa();
            var single: Single(H) = undefined;
            try single.start(ctx, try .init(gpa, ctx.io()));
            defer single.stop(gpa);
            var blocks: [1]H.TestBlock = undefined;
            try make_chain(H, gpa, &blocks);
            defer free_chain(&blocks);
            try propose_and_finalize(H, ctx, &single, &blocks);
            const digest = H.digest(&blocks[0]);
            const found = try single.node.mailbox.get_block(.{ .digest = digest });
            try expect_block(H, gpa, found, .new(1), digest);
            const missing = harness.Sha256.hash(&.{"missing"});
            const absent = try single.node.mailbox.get_block(.{ .digest = missing });
            try testing.expectEqual(null, absent);
        }
    };
}

/// commonware `get_finalization_by_height`.
pub fn GetFinalizationByHeight(comptime H: type) type {
    return struct {
        pub fn run(gpa: Allocator) !void {
            try run_timed(gpa, 0, timeout_default_s, body, .{});
        }

        fn body(ctx: Ctx) anyerror!void {
            const gpa = ctx.gpa();
            var single: Single(H) = undefined;
            try single.start(ctx, try .init(gpa, ctx.io()));
            defer single.stop(gpa);
            const mailbox = single.node.mailbox;
            try testing.expectEqual(null, try mailbox.get_finalization(.new(1)));
            var blocks: [3]H.TestBlock = undefined;
            try make_chain(H, gpa, &blocks);
            defer free_chain(&blocks);
            for (&blocks, 1..) |*block, height| {
                try propose_and_finalize(H, ctx, &single, block[0..1]);
                var found = (try mailbox.get_finalization(.new(height))) orelse
                    return error.TestNoFinalization;
                defer found.deinit(gpa);
                try testing.expect(found.proposal.payload.eql(H.commitment(block)));
                try testing.expectEqual(height, found.proposal.round.view.get());
            }
            try testing.expectEqual(null, try mailbox.get_finalization(.new(10)));
        }
    };
}
