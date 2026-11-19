//! commonware `mocks/harness.rs`'s query and subscription scenarios (line 3442 to the end),
//! generic over a harness `H` (`harness.StandardHarness`, or the coding variant's harness).
//!
//! Besides the decls `scenarios.zig` lists, these scenarios read `H.genesis_block`. A
//! scenario that drives an actor over prunable finalized archives also needs
//! `setup_prunable_validator(ctx, network, me, validators, prefix, app)` and
//! `verify_for_prune(validator, round, block)`. Marshal blocks provide `digest()` and either
//! `height()` or `inner().height()`. `Single` starts validators unlinked on a network tracking
//! every participant over three peer sets (commonware uses one for most single-validator
//! scenarios; the count does not affect them).

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

/// The round of `height` at view = height, in the epoch the test epocher assigns it.
fn round_of(height: u64) Round {
    const epoch_length = utils.NonZero(u64).init(harness.blocks_per_epoch).?;
    const bounds = types.FixedEpocher.new(epoch_length).containing(.new(height)).?;
    return .new(bounds.epoch, .new(height));
}

/// Validators on a simulated network of every participant, started one at a time (validator
/// 0 first) and unlinked unless a scenario links them.
pub fn Single(comptime H: type) type {
    return struct {
        const Self = @This();
        pub const App = Application(H.ApplicationBlock);
        pub const Validator = H.Validator(App);
        pub const Proposal = simplex_types.Proposal(H.Commitment);

        validators: H.Fixture,
        network: harness.TestNetwork,
        nodes: [num_validators]*Validator,
        started: usize,

        /// Starts the network and validator 0 with application `app` (owned).
        pub fn start(self: *Self, ctx: Ctx, app: App) !void {
            const gpa = ctx.gpa();
            var owned = app;
            errdefer owned.deinit();
            var rng = utils.rng.test_rng();
            self.validators = try H.fixture(gpa, &rng);
            errdefer self.validators.deinit(gpa);
            const participants = self.validators.participants;
            const max_size = harness.max_message_size(H.Variant);
            self.network = try .start(gpa, ctx.io(), 3, participants, max_size);
            errdefer self.network.stop();
            self.started = 0;
            self.nodes[0] = try self.setup(ctx, "validator", 0, owned);
            self.started = 1;
        }

        /// Starts the next validator with application `app` (owned).
        pub fn add(self: *Self, ctx: Ctx, app: App) !void {
            assert(self.started > 0 and self.started < num_validators);
            const index = self.started;
            self.nodes[index] = try self.setup(ctx, "validator", index, app);
            self.started += 1;
        }

        /// Crashes validator 0 and starts it again over the same storage.
        pub fn restart(self: *Self, ctx: Ctx, app: App) !void {
            assert(self.started > 0);
            self.nodes[0].crash();
            self.nodes[0] = self.setup(ctx, "validator_restart", 0, app) catch |err| {
                // Validator 0 is gone; stop must not crash it again.
                for (self.nodes[1..self.started]) |node| node.crash();
                self.started = 0;
                return err;
            };
        }

        fn setup(self: *Self, ctx: Ctx, label: []const u8, index: usize, app: App) !*Validator {
            const provider: H.Provider = .init(&self.validators.schemes[index]);
            const node_ctx = ctx.child(label).with_attribute("index", index);
            const me = self.validators.participants[index];
            return Validator.setup(node_ctx, self.network.network, me, provider, 1, app);
        }

        pub fn stop(self: *Self, gpa: Allocator) void {
            for (self.nodes[0..self.started]) |node| node.crash();
            self.network.stop();
            self.validators.deinit(gpa);
            self.* = undefined;
        }

        /// The proposal of `block` at `view`, over the previous view.
        pub fn proposal_of(block: *const H.TestBlock, view: u64) Proposal {
            assert(view > 0);
            return Proposal.init(round_at(view), .new(view - 1), H.commitment(block));
        }

        /// Reports the quorum finalization of `block` at view = height to validator 0.
        pub fn finalize(self: *Self, gpa: Allocator, block: *const H.TestBlock) !void {
            try self.finalize_at(gpa, 0, proposal_of(block, H.height(block).get()));
        }

        /// Reports the quorum finalization of `proposal` to validator `index`.
        pub fn finalize_at(self: *Self, gpa: Allocator, index: usize, proposal: Proposal) !void {
            assert(index < self.started);
            var finalization = try H.make_finalization(gpa, &self.validators, proposal, quorum);
            defer finalization.deinit(gpa);
            _ = self.nodes[index].mailbox.report(.{ .finalization = finalization });
        }

        /// Reports the quorum notarization of `proposal` to validator `index`.
        pub fn notarize(self: *Self, gpa: Allocator, index: usize, proposal: Proposal) !void {
            assert(index < self.started);
            var notarization = try H.make_notarization(gpa, &self.validators, proposal, quorum);
            defer notarization.deinit(gpa);
            _ = self.nodes[index].mailbox.report(.{ .notarization = notarization });
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
        try H.propose(single.nodes[0], round_at(H.height(block).get()), block);
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
            const mailbox = single.nodes[0].mailbox;
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
                const latest = try single.nodes[0].mailbox.get_info(.latest);
                try expect_info(latest, .new(height), H.digest(block));
            }
            for (&blocks, 1..) |*block, height| {
                const info = try single.nodes[0].mailbox.get_info(.{ .height = .new(height) });
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
            const mailbox = single.nodes[0].mailbox;
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
            const found = try single.nodes[0].mailbox.get_block(.{ .digest = digest });
            try expect_block(H, gpa, found, .new(1), digest);
            const missing = harness.Sha256.hash(&.{"missing"});
            const absent = try single.nodes[0].mailbox.get_block(.{ .digest = missing });
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
            const mailbox = single.nodes[0].mailbox;
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

/// Every validator on links `harness.link`, driven at validator 0.
fn ClusterAt(comptime H: type) type {
    return struct {
        const Self = @This();
        const C = scenarios.Cluster(H);
        const Proposal = simplex_types.Proposal(H.Commitment);

        cluster: C,

        fn start(self: *Self, ctx: Ctx) !void {
            try self.cluster.start(ctx, harness.link);
        }

        fn stop(self: *Self, gpa: Allocator) void {
            self.cluster.stop(gpa);
        }

        fn mailbox(self: *Self) *@FieldType(C.Validator, "mailbox") {
            return &self.cluster.nodes[0].mailbox;
        }

        fn proposal(block: *const H.TestBlock) Proposal {
            const view = H.height(block).get();
            assert(view > 0);
            return Proposal.init(round_at(view), .new(view - 1), H.commitment(block));
        }

        fn propose(self: *Self, block: *const H.TestBlock) !void {
            try H.propose(self.cluster.nodes[0], round_at(H.height(block).get()), block);
        }

        fn verify(self: *Self, block: *const H.TestBlock) !void {
            const node = self.cluster.nodes[0];
            try self.cluster.verify(node, round_at(H.height(block).get()), block);
        }

        fn notarize(self: *Self, gpa: Allocator, block: *const H.TestBlock) !void {
            const validators = &self.cluster.validators;
            var notarization = try H.make_notarization(gpa, validators, proposal(block), quorum);
            defer notarization.deinit(gpa);
            _ = self.mailbox().report(.{ .notarization = notarization });
        }

        fn finalize(self: *Self, gpa: Allocator, block: *const H.TestBlock) !void {
            const validators = &self.cluster.validators;
            var finalization = try H.make_finalization(gpa, validators, proposal(block), quorum);
            defer finalization.deinit(gpa);
            _ = self.mailbox().report(.{ .finalization = finalization });
        }

        /// Proposes, verifies, notarizes, and finalizes `block` at validator 0.
        fn drive(self: *Self, gpa: Allocator, block: *const H.TestBlock) !void {
            try self.propose(block);
            try self.verify(block);
            try self.notarize(gpa, block);
            try self.finalize(gpa, block);
        }
    };
}

/// The receiver `subscribe_by_digest` returns on a `*Mailbox`.
fn Subscription(comptime MailboxPointer: type) type {
    const Mailbox = @typeInfo(MailboxPointer).pointer.child;
    const Return = @typeInfo(@TypeOf(Mailbox.subscribe_by_digest)).@"fn".return_type.?;
    return @typeInfo(Return).error_union.payload;
}

fn subscribe_at_round(
    mailbox: anytype,
    block: anytype,
    comptime H: type,
) !Subscription(@TypeOf(mailbox)) {
    const round = round_at(H.height(block).get());
    return mailbox.subscribe_by_digest(H.digest(block), .{ .fetch_by_round = round });
}

/// Receives the subscribed block and expects `block`'s digest and height.
fn expect_received(
    comptime H: type,
    gpa: Allocator,
    receiver: anytype,
    block: *const H.TestBlock,
) !void {
    var received = try receiver.recv();
    defer H.Variant.deinit_block(gpa, &received);
    try testing.expect(received.digest().eql(H.digest(block)));
    try testing.expectEqual(H.height(block), block_height(&received));
}

/// commonware `subscribe_basic_block_delivery`.
pub fn SubscribeBasic(comptime H: type) type {
    return struct {
        pub fn run(gpa: Allocator) !void {
            try run_timed(gpa, 0, timeout_default_s, body, .{});
        }

        fn body(ctx: Ctx) anyerror!void {
            const gpa = ctx.gpa();
            var at: ClusterAt(H) = undefined;
            try at.start(ctx);
            defer at.stop(gpa);
            var blocks: [1]H.TestBlock = undefined;
            try make_chain(H, gpa, &blocks);
            defer free_chain(&blocks);
            var receiver = try subscribe_at_round(at.mailbox(), &blocks[0], H);
            defer receiver.deinit();
            try at.drive(gpa, &blocks[0]);
            try expect_received(H, gpa, &receiver, &blocks[0]);
        }
    };
}

/// commonware `subscribe_multiple_subscriptions`: two subscriptions to one block and one to
/// another all deliver.
pub fn SubscribeMultiple(comptime H: type) type {
    return struct {
        pub fn run(gpa: Allocator) !void {
            try run_timed(gpa, 0, timeout_default_s, body, .{});
        }

        fn body(ctx: Ctx) anyerror!void {
            const gpa = ctx.gpa();
            var at: ClusterAt(H) = undefined;
            try at.start(ctx);
            defer at.stop(gpa);
            var blocks: [2]H.TestBlock = undefined;
            try make_chain(H, gpa, &blocks);
            defer free_chain(&blocks);
            var first = try subscribe_at_round(at.mailbox(), &blocks[0], H);
            defer first.deinit();
            var second = try subscribe_at_round(at.mailbox(), &blocks[1], H);
            defer second.deinit();
            var third = try subscribe_at_round(at.mailbox(), &blocks[0], H);
            defer third.deinit();
            for (&blocks) |*block| try at.drive(gpa, block);
            try expect_received(H, gpa, &first, &blocks[0]);
            try expect_received(H, gpa, &second, &blocks[1]);
            try expect_received(H, gpa, &third, &blocks[0]);
        }
    };
}

/// commonware `subscribe_canceled_subscriptions`: dropping one subscription leaves the other.
pub fn SubscribeCanceled(comptime H: type) type {
    return struct {
        pub fn run(gpa: Allocator) !void {
            try run_timed(gpa, 0, timeout_default_s, body, .{});
        }

        fn body(ctx: Ctx) anyerror!void {
            const gpa = ctx.gpa();
            var at: ClusterAt(H) = undefined;
            try at.start(ctx);
            defer at.stop(gpa);
            var blocks: [2]H.TestBlock = undefined;
            try make_chain(H, gpa, &blocks);
            defer free_chain(&blocks);
            var first = try subscribe_at_round(at.mailbox(), &blocks[0], H);
            var second = try subscribe_at_round(at.mailbox(), &blocks[1], H);
            defer second.deinit();
            first.deinit();
            for (&blocks) |*block| try at.drive(gpa, block);
            try expect_received(H, gpa, &second, &blocks[1]);
        }
    };
}

/// commonware `subscribe_blocks_from_different_sources`: blocks reach waiting subscriptions
/// whether proposed, verified, notarized first, finalized first, or both.
pub fn SubscribeDifferentSources(comptime H: type) type {
    return struct {
        pub fn run(gpa: Allocator) !void {
            try run_timed(gpa, 0, timeout_default_s, body, .{});
        }

        fn body(ctx: Ctx) anyerror!void {
            const gpa = ctx.gpa();
            var at: ClusterAt(H) = undefined;
            try at.start(ctx);
            defer at.stop(gpa);
            var blocks: [5]H.TestBlock = undefined;
            try make_chain(H, gpa, &blocks);
            defer free_chain(&blocks);
            var receivers: [5]Subscription(@TypeOf(at.mailbox())) = undefined;
            var made: usize = 0;
            defer for (receivers[0..made]) |*receiver| receiver.deinit();
            for (&receivers, &blocks) |*receiver, *block| {
                receiver.* = try at.mailbox().subscribe_by_digest(H.digest(block), .wait);
                made += 1;
            }
            // Block 1: proposed by the actor.
            try at.propose(&blocks[0]);
            try ctx.sleep(.fromMilliseconds(20));
            try expect_received(H, gpa, &receivers[0], &blocks[0]);
            // Block 2: verified by the actor.
            try at.propose(&blocks[1]);
            try at.verify(&blocks[1]);
            try expect_received(H, gpa, &receivers[1], &blocks[1]);
            // Block 3: notarized, then proposed and verified.
            try at.notarize(gpa, &blocks[2]);
            try at.propose(&blocks[2]);
            try at.verify(&blocks[2]);
            try expect_received(H, gpa, &receivers[2], &blocks[2]);
            // Block 4: finalized, then proposed and verified.
            try at.finalize(gpa, &blocks[3]);
            try at.propose(&blocks[3]);
            try at.verify(&blocks[3]);
            try expect_received(H, gpa, &receivers[3], &blocks[3]);
            // Block 5: notarized and finalized, then proposed and verified.
            try at.notarize(gpa, &blocks[4]);
            try at.finalize(gpa, &blocks[4]);
            try at.propose(&blocks[4]);
            try at.verify(&blocks[4]);
            try expect_received(H, gpa, &receivers[4], &blocks[4]);
        }
    };
}

/// commonware `ancestry_stream`: the stream from the latest finalized block yields heights 5
/// down to 1.
pub fn AncestryStream(comptime H: type) type {
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
            try propose_and_finalize(H, ctx, &single, &blocks);
            const mailbox = single.nodes[0].mailbox;
            const latest = (try mailbox.get_info(.latest)) orelse return error.TestNoInfo;
            var stream = (try mailbox.ancestry_from(.wait, latest.digest, null)) orelse
                return error.TestNoAncestry;
            defer stream.deinit();
            for (0..5) |index| {
                var block = (try stream.next()) orelse return error.TestStreamEnded;
                defer block.deinit();
                try testing.expectEqual(5 - index, block_height(&block).get());
            }
        }
    };
}

/// commonware `init_processed_height`: a restart restores the processed height.
pub fn InitProcessedHeight(comptime H: type) type {
    return struct {
        pub fn run(gpa: Allocator) !void {
            try run_timed(gpa, 0, timeout_default_s, body, .{});
        }

        fn body(ctx: Ctx) anyerror!void {
            const gpa = ctx.gpa();
            var single: Single(H) = undefined;
            try single.start(ctx, try .init(gpa, ctx.io()));
            defer single.stop(gpa);
            try testing.expectEqual(null, single.nodes[0].height);
            var blocks: [5]H.TestBlock = undefined;
            try make_chain(H, gpa, &blocks);
            defer free_chain(&blocks);
            try propose_and_finalize(H, ctx, &single, &blocks);
            try wait_for_tip(ctx, single.nodes[0].application, .new(5));
            try single.restart(ctx, try .init(gpa, ctx.io()));
            try testing.expectEqual(Height.new(5), single.nodes[0].height);
        }
    };
}

/// Sleeps 10 ms at a time until `app`'s tip reaches `height`.
fn wait_for_tip(ctx: Ctx, app: anytype, height: Height) !void {
    while (true) {
        if (app.tip()) |tip| if (tip.height.get() == height.get()) return;
        try ctx.sleep(.fromMilliseconds(10));
    }
}

/// commonware `broadcast_caches_block`: a proposed block is readable by digest, and still is
/// after a restart once its notarization arrives.
pub fn BroadcastCachesBlock(comptime H: type) type {
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
            const block = &blocks[0];
            const digest = H.digest(block);
            try H.propose(single.nodes[0], round_at(1), block);
            const cached = try single.nodes[0].mailbox.get_block(.{ .digest = digest });
            try expect_block(H, gpa, cached, .new(1), digest);
            try single.restart(ctx, try .init(gpa, ctx.io()));
            try single.notarize(gpa, 0, Single(H).proposal_of(block, 1));
            const restored = try single.nodes[0].mailbox.get_block(.{ .digest = digest });
            try expect_block(H, gpa, restored, .new(1), digest);
        }
    };
}

/// commonware `finalize_same_height_different_views`: each validator keeps the first
/// finalization it saw for a height, even when another view finalizes the same block.
pub fn FinalizeSameHeightDifferentViews(comptime H: type) type {
    return struct {
        const S = Single(H);

        pub fn run(gpa: Allocator) !void {
            try run_timed(gpa, 0, timeout_default_s, body, .{});
        }

        fn body(ctx: Ctx) anyerror!void {
            const gpa = ctx.gpa();
            var single: S = undefined;
            try single.start(ctx, try .init(gpa, ctx.io()));
            defer single.stop(gpa);
            try single.add(ctx, try .init(gpa, ctx.io()));
            var blocks: [1]H.TestBlock = undefined;
            try make_chain(H, gpa, &blocks);
            defer free_chain(&blocks);
            const block = &blocks[0];
            for (single.nodes[0..2]) |node| try H.propose(node, round_at(1), block);
            try ctx.sleep(.fromMilliseconds(link_latency_ms));
            const first = S.Proposal.init(round_at(1), .zero(), H.commitment(block));
            // A different view finalizing the same block.
            const second = S.Proposal.init(round_at(2), .zero(), H.commitment(block));
            try single.notarize(gpa, 0, first);
            try single.finalize_at(gpa, 0, first);
            try single.notarize(gpa, 1, second);
            try single.finalize_at(gpa, 1, second);
            try ctx.sleep(.fromMilliseconds(100));
            try expect_finalized(&single, gpa, block, .{ 1, 2 });
            // Swapped finalizations do not replace the stored ones.
            try single.finalize_at(gpa, 0, second);
            try single.finalize_at(gpa, 1, first);
            try ctx.sleep(.fromMilliseconds(100));
            try expect_finalized(&single, gpa, block, .{ 1, 2 });
        }

        /// Both validators hold `block` at height 1, finalized at `views`.
        fn expect_finalized(
            single: *S,
            gpa: Allocator,
            block: *const H.TestBlock,
            views: [2]u64,
        ) !void {
            const digest = H.digest(block);
            for (single.nodes[0..2], views) |node, view| {
                const found = try node.mailbox.get_block(.{ .height = .new(1) });
                try expect_block(H, gpa, found, .new(1), digest);
                var finalization = (try node.mailbox.get_finalization(.new(1))) orelse
                    return error.TestNoFinalization;
                defer finalization.deinit(gpa);
                try testing.expect(finalization.proposal.payload.eql(H.commitment(block)));
                try testing.expectEqual(view, finalization.proposal.round.view.get());
                const info = try node.mailbox.get_info(.{ .height = .new(1) });
                try expect_info(info, .new(1), digest);
            }
        }
    };
}

/// commonware `hint_finalized_triggers_fetch`: a hint makes validator 1 fetch the
/// finalization at height 5 from validator 0.
pub fn HintFinalizedTriggersFetch(comptime H: type) type {
    return struct {
        pub fn run(gpa: Allocator) !void {
            try run_timed(gpa, 42, timeout_default_s, body, .{});
        }

        fn body(ctx: Ctx) anyerror!void {
            const gpa = ctx.gpa();
            var single: Single(H) = undefined;
            try single.start(ctx, try .init(gpa, ctx.io()));
            defer single.stop(gpa);
            try single.add(ctx, try .init(gpa, ctx.io()));
            const participants = single.validators.participants;
            try single.network.link_all(participants[0..2], harness.link);
            var blocks: [5]H.TestBlock = undefined;
            try make_chain(H, gpa, &blocks);
            defer free_chain(&blocks);
            try propose_and_finalize(H, ctx, &single, &blocks);
            try wait_for_tip(ctx, single.nodes[0].application, .new(5));
            const mailbox = single.nodes[1].mailbox;
            try testing.expectEqual(null, try mailbox.get_finalization(.new(5)));
            try mailbox.hint_finalized(.new(5), participants[0..1]);
            while (true) {
                var found = (try mailbox.get_finalization(.new(5))) orelse {
                    try ctx.sleep(.fromMilliseconds(10));
                    continue;
                };
                defer found.deinit(gpa);
                try testing.expectEqual(5, found.proposal.round.view.get());
                return;
            }
        }
    };
}

/// commonware `genesis_emitted_once`: genesis is delivered and acknowledged once, and a
/// restart after its acknowledgement does not deliver it again.
pub fn GenesisEmittedOnce(comptime H: type) type {
    return struct {
        pub fn run(gpa: Allocator) !void {
            try run_timed(gpa, 0, timeout_default_s, body, .{});
        }

        fn body(ctx: Ctx) anyerror!void {
            const gpa = ctx.gpa();
            var single: Single(H) = undefined;
            try single.start(ctx, try .manual_ack(gpa, ctx.io()));
            defer single.stop(gpa);
            const node = single.nodes[0];
            try testing.expectEqual(null, node.height);
            try testing.expectEqual(null, try node.mailbox.get_processed());
            try testing.expectEqual(null, try node.mailbox.get_anchor());
            try testing.expectEqual(Height.zero(), try node.application.acknowledged());
            try ctx.sleep(.fromMilliseconds(10));
            const processed = try node.mailbox.get_processed();
            try testing.expectEqual(core.Processed{ .block = .zero() }, processed);
            try testing.expect(node.application.contains(.zero()));

            // Let marshal persist the height-zero acknowledgement before restart.
            try ctx.sleep(.fromMilliseconds(10));
            try single.restart(ctx, try .manual_ack(gpa, ctx.io()));
            const restarted = single.nodes[0];
            try testing.expectEqual(Height.zero(), restarted.height);
            try ctx.sleep(.fromMilliseconds(100));
            // Genesis is not emitted again after height zero is acknowledged.
            try testing.expectEqual(0, restarted.application.block_count());
            const pending = try restarted.application.pending_ack_heights(gpa);
            defer gpa.free(pending);
            try testing.expectEqual(0, pending.len);
        }
    };
}

/// commonware `commitment_fetch_height_hint_mismatch_wakes_subscriber`: a commitment fetch
/// whose height hint is wrong still wakes the subscriber; the block is cached only when its
/// decoded height is within the hint.
pub fn CommitmentFetchHeightHintMismatch(comptime H: type) type {
    return struct {
        pub fn run(gpa: Allocator) !void {
            try run_timed(gpa, 0, timeout_default_s, body, .{});
        }

        fn body(ctx: Ctx) anyerror!void {
            const gpa = ctx.gpa();
            var single: Single(H) = undefined;
            try single.start(ctx, try .init(gpa, ctx.io()));
            defer single.stop(gpa);
            try single.add(ctx, try .init(gpa, ctx.io()));
            // Below its hint: woken and cached by the decoded height.
            const seed_below = "commitment-fetch-height-hint-mismatch";
            try fetch(ctx, &single, seed_below, .{ 7, 7 }, 1_000_000, true, true);
            // Above its hint: woken, not cached.
            const seed_above = "commitment-fetch-height-above-hint";
            try fetch(ctx, &single, seed_above, .{ 1_000_000, 8 }, 7, false, false);
        }

        /// Validator 1 holds a block at `at[0]` (view `at[1]`); validator 0 subscribes to it by
        /// commitment with a height `hint` (linking the pair after subscribing when `link`),
        /// receives it, and caches it only when `cached`.
        fn fetch(
            ctx: Ctx,
            single: *Single(H),
            seed: []const u8,
            at: [2]u64,
            hint: u64,
            cached: bool,
            link: bool,
        ) !void {
            const gpa = ctx.gpa();
            const parent = harness.Sha256.hash(&.{seed});
            const parent_commitment = H.genesis_parent_commitment(num_validators);
            const height: Height = .new(at[0]);
            var block = try H.make_test_block(gpa, parent, parent_commitment, height, at[1], 4);
            defer block.deinit();
            try H.propose(single.nodes[1], round_at(at[1]), &block);
            const fallback: core.CommitmentFallback = .{ .fetch_by_commitment = .new(hint) };
            const mailbox = single.nodes[0].mailbox;
            var receiver = try mailbox.subscribe_by_commitment(H.commitment(&block), fallback);
            defer receiver.deinit();
            const pair = single.validators.participants[0..2];
            if (link) try single.network.link_all(pair, harness.link);
            var received = try receiver.recv();
            defer H.Variant.deinit_block(gpa, &received);
            try testing.expect(H.Variant.commitment(&received).eql(H.commitment(&block)));
            try testing.expectEqual(Height.new(at[0]), block_height(&received));
            const found = try mailbox.get_block(.{ .digest = received.digest() });
            if (cached) {
                try expect_block(H, gpa, found, .new(at[0]), received.digest());
            } else {
                try testing.expectEqual(null, found);
            }
        }
    };
}

/// One validator over prunable finalized archives (commonware `setup_prunable_validator`),
/// on a network of every participant.
fn PrunableSingle(comptime H: type) type {
    return struct {
        const Self = @This();
        pub const App = Application(H.ApplicationBlock);
        pub const Validator = H.PrunableValidator(App);
        pub const Proposal = simplex_types.Proposal(H.Commitment);

        validators: H.Fixture,
        network: harness.TestNetwork,
        nodes: [2]*Validator,
        started: usize,

        fn start(self: *Self, ctx: Ctx) !void {
            const gpa = ctx.gpa();
            var rng = utils.rng.test_rng();
            self.validators = try H.fixture(gpa, &rng);
            errdefer self.validators.deinit(gpa);
            const participants = self.validators.participants;
            const max_size = harness.max_message_size(H.Variant);
            self.network = try .start(gpa, ctx.io(), 1, participants, max_size);
            self.started = 0;
        }

        /// Starts validator `index` under metrics label `label`.
        fn add(self: *Self, ctx: Ctx, label: []const u8, index: usize) !*Validator {
            assert(self.started < self.nodes.len);
            const me = self.validators.participants[index];
            const app: App = try .init(ctx.gpa(), ctx.io());
            const node = try H.setup_prunable_validator(
                ctx.child(label),
                self.network.network,
                me,
                &self.validators,
                label,
                app,
            );
            self.nodes[self.started] = node;
            self.started += 1;
            return node;
        }

        /// Crashes validator slot `slot` and starts validator `index` there again.
        fn restart(self: *Self, ctx: Ctx, slot: usize, index: usize) !*Validator {
            assert(slot < self.started);
            self.nodes[slot].crash();
            const last = self.started - 1;
            self.nodes[slot] = self.nodes[last];
            self.started -= 1;
            return self.add(ctx, "restart", index);
        }

        fn stop(self: *Self, gpa: Allocator) void {
            for (self.nodes[0..self.started]) |node| node.crash();
            self.network.stop();
            self.validators.deinit(gpa);
            self.* = undefined;
        }

        fn finalization(self: *Self, gpa: Allocator, block: *const H.TestBlock) !H.Finalization {
            const view = H.height(block).get();
            const proposal = Proposal.init(round_of(view), .new(view - 1), H.commitment(block));
            return H.make_finalization(gpa, &self.validators, proposal, quorum);
        }
    };
}

/// Polls `get_processed` every 10 ms until it reaches `height`.
fn wait_processed(ctx: Ctx, mailbox: anytype, height: u64) !void {
    while (true) {
        if (try mailbox.get_processed()) |processed| {
            if (processed.height().get() == height) return;
        }
        try ctx.sleep(.fromMilliseconds(10));
    }
}

/// Expects the block and finalization at each of `heights` to be present or absent.
fn expect_stored(
    comptime H: type,
    gpa: Allocator,
    mailbox: anytype,
    from: u64,
    to: u64,
    present: bool,
) !void {
    assert(from <= to);
    for (from..to + 1) |height| {
        var block = try mailbox.get_block(.{ .height = .new(height) });
        defer if (block) |*value| H.Variant.deinit_block(gpa, value);
        var finalization = try mailbox.get_finalization(.new(height));
        defer if (finalization) |*value| value.deinit(gpa);
        if ((block != null) != present or (finalization != null) != present) {
            std.log.err("height {d}: expected present={}", .{ height, present });
            return error.TestStoredMismatch;
        }
    }
}

/// Verifies and finalizes heights 1 through `count` of `blocks` at `node`.
fn verify_and_finalize(
    comptime H: type,
    ctx: Ctx,
    single: *PrunableSingle(H),
    node: anytype,
    blocks: []const H.TestBlock,
) !void {
    const gpa = ctx.gpa();
    for (blocks) |*block| {
        try H.verify_for_prune(node, round_of(H.height(block).get()), block);
        try ctx.sleep(.fromMilliseconds(link_latency_ms));
        var finalization = try single.finalization(gpa, block);
        defer finalization.deinit(gpa);
        _ = node.mailbox.report(.{ .finalization = finalization });
    }
}

/// commonware `prune_finalized_archives`.
pub fn PruneFinalizedArchives(comptime H: type) type {
    return struct {
        pub fn run(gpa: Allocator) !void {
            try run_timed(gpa, 0, 120, body, .{});
        }

        fn body(ctx: Ctx) anyerror!void {
            const gpa = ctx.gpa();
            var single: PrunableSingle(H) = undefined;
            try single.start(ctx);
            defer single.stop(gpa);
            var node = try single.add(ctx, "init", 0);
            var blocks: [20]H.TestBlock = undefined;
            try make_chain(H, gpa, &blocks);
            defer free_chain(&blocks);
            try verify_and_finalize(H, ctx, &single, node, &blocks);
            try wait_for_tip(ctx, node.application, .new(20));
            try wait_processed(ctx, node.mailbox, 20);
            try expect_stored(H, gpa, node.mailbox, 1, 20, true);
            // Requests above the processed height are ignored.
            try node.mailbox.prune(.new(25));
            try ctx.sleep(.fromMilliseconds(50));
            try expect_stored(H, gpa, node.mailbox, 1, 20, true);
            // Pruning keeps the requested height and removes older sections.
            try node.mailbox.prune(.new(10));
            try ctx.sleep(.fromMilliseconds(100));
            try expect_stored(H, gpa, node.mailbox, 1, 9, false);
            try expect_stored(H, gpa, node.mailbox, 10, 20, true);
            // Pruning at the processed height keeps the processed block.
            try node.mailbox.prune(.new(20));
            try ctx.sleep(.fromMilliseconds(100));
            try expect_stored(H, gpa, node.mailbox, 10, 19, false);
            try expect_stored(H, gpa, node.mailbox, 20, 20, true);
            node = try single.restart(ctx, 0, 0);
            // Startup classifies the stored processed block.
            const processed = try node.mailbox.get_processed();
            try testing.expectEqual(core.Processed{ .block = .new(20) }, processed);
            try expect_stored(H, gpa, node.mailbox, 1, 19, false);
            try expect_stored(H, gpa, node.mailbox, 20, 20, true);
        }
    };
}

/// commonware `floor_retains_processed_predecessor`: a floor at a section boundary keeps
/// its processed predecessor.
pub fn FloorRetainsProcessedPredecessor(comptime H: type) type {
    return struct {
        pub fn run(gpa: Allocator) !void {
            try run_timed(gpa, 0, 120, body, .{});
        }

        fn body(ctx: Ctx) anyerror!void {
            const gpa = ctx.gpa();
            var single: PrunableSingle(H) = undefined;
            try single.start(ctx);
            defer single.stop(gpa);
            // Prunable archives use ten-item sections, so a floor at 20 starts a new section.
            const node = try single.add(ctx, "validator", 0);
            var blocks: [20]H.TestBlock = undefined;
            try make_chain(H, gpa, &blocks);
            defer free_chain(&blocks);
            // Finalize 1 through 19; block 20 is only verified, so its floor lands above the
            // processed height.
            try verify_and_finalize(H, ctx, &single, node, blocks[0..19]);
            try H.verify_for_prune(node, round_of(20), &blocks[19]);
            try ctx.sleep(.fromMilliseconds(link_latency_ms));
            try wait_processed(ctx, node.mailbox, 19);
            const processed = try node.mailbox.get_processed();
            try testing.expectEqual(core.Processed{ .block = .new(19) }, processed);
            var anchor = (try node.mailbox.get_anchor()) orelse return error.TestNoAnchor;
            defer H.Variant.deinit_block(gpa, &anchor.block);
            try testing.expectEqual(core.Processed{ .block = .new(19) }, anchor.processed);
            try testing.expectEqual(Height.new(19), block_height(&anchor.block));
            // Installing the floor prunes before it dispatches block 20, so processing 20
            // means pruning finished.
            try node.mailbox.set_floor(try single.finalization(gpa, &blocks[19]));
            try wait_processed(ctx, node.mailbox, 20);
            // The section holding block 19 survives; older sections are pruned.
            try expect_stored(H, gpa, node.mailbox, 19, 19, true);
            try expect_stored(H, gpa, node.mailbox, 9, 9, false);
        }
    };
}
