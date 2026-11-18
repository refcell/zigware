//! The standard actor restarting over inconsistent storage (commonware `standard/mod.rs`,
//! `test_standard_restart_*`).

const std = @import("std");
const testing = std.testing;
const runtime = @import("runtime");
const utils = @import("utils");
const types = @import("../../../types.zig");
const harness = @import("../../mocks/harness.zig");
const core = @import("../../core/root.zig");
const seed = @import("seed.zig");
const common = @import("common.zig");

const gpa = testing.allocator;
const H = harness.StandardHarness;
const App = @import("../../mocks/application.zig").Application(harness.B);
const Validator = H.Validator(App);
const Ctx = runtime.deterministic.Context;
const Height = types.Height;
const Round = types.Round;

/// commonware's `Runner::timed(30s)`.
const timed: runtime.deterministic.Config = .{ .timeout_ns = 30 * std.time.ns_per_s };

fn round_at(view: u64) Round {
    return .new(.new(0), .new(view));
}

/// The chain genesis -> 1 -> ... -> `blocks.len - 1`, block `h` stamped `100 * h`.
fn make_chain(blocks: []H.TestBlock) !void {
    var made: usize = 0;
    errdefer for (blocks[0..made]) |*block| block.deinit();
    var parent = harness.genesis_parent();
    for (blocks, 0..) |*block, index| {
        const height: Height = .new(index);
        block.* = try H.make_test_block(gpa, parent, parent, height, 100 * index, 4);
        made += 1;
        parent = H.digest(block);
    }
}

fn free_chain(blocks: []H.TestBlock) void {
    for (blocks) |*block| block.deinit();
}

/// The quorum finalizations of `blocks` at heights 1 through `blocks.len`; free with
/// `free_finalizations`.
fn finalize_all(
    validators: *const harness.Fixture,
    blocks: []const H.TestBlock,
    out: []seed.FinalizationAt,
) !void {
    std.debug.assert(blocks.len == out.len);
    var made: usize = 0;
    errdefer free_finalizations(out[0..made]);
    for (blocks, out) |*block, *entry| {
        entry.* = .{ .height = H.height(block), .finalization = try finalize(validators, block) };
        made += 1;
    }
}

fn free_finalizations(entries: []seed.FinalizationAt) void {
    for (entries) |*entry| entry.finalization.deinit(gpa);
}

/// The quorum finalization of `block` at view = height, over its parent's view.
fn finalize(validators: *const harness.Fixture, block: *const H.TestBlock) !harness.Finalization {
    const view = H.height(block).get();
    const proposal = harness.Proposal.init(round_at(view), .new(view - 1), H.digest(block));
    return harness.make_finalization(gpa, validators, proposal, harness.quorum);
}

/// A 4-validator network with every link up, and the fixture behind it.
const Setup = struct {
    validators: harness.Fixture,
    network: harness.TestNetwork,

    fn init(self: *Setup, ctx: Ctx) !void {
        try self.init_links(ctx, true);
    }

    /// Without `linked`, no validator reaches another.
    fn init_links(self: *Setup, ctx: Ctx, linked: bool) !void {
        var rng = utils.rng.test_rng();
        self.validators = try harness.fixture(gpa, &rng);
        errdefer self.validators.deinit(gpa);
        const participants = self.validators.participants;
        self.network = try .start(gpa, ctx.io(), 3, participants, 1024 * 1024);
        errdefer self.network.stop();
        if (linked) try self.network.link_all(participants, harness.link);
    }

    fn deinit(self: *Setup) void {
        self.network.stop();
        self.validators.deinit(gpa);
    }

    fn start(self: *Setup, ctx: Ctx, index: usize, app: App) !*Validator {
        const me = self.validators.participants[index];
        const provider: harness.Provider = .init(&self.validators.schemes[index]);
        return Validator.setup(ctx, self.network.network, me, provider, 1, app);
    }

    /// The partition prefix of validator `index`.
    fn prefix(self: *const Setup, buffer: []u8, index: usize) ![]const u8 {
        const me = self.validators.participants[index];
        return std.fmt.bufPrint(buffer, "validator-{f}", .{me});
    }
};

/// Seeds validator 0 with `stored` blocks and `finalized` (all borrowed) and starts it with a
/// manually acknowledging application.
fn seed_and_restart(
    ctx: Ctx,
    setup: *Setup,
    stored: []const H.TestBlock,
    finalized: []const seed.FinalizationAt,
) !*Validator {
    var name: [192]u8 = undefined;
    const prefix = try setup.prefix(&name, 0);
    try seed.inconsistent_restart_state(ctx.child("storage"), prefix, stored, finalized);
    const app: App = try .manual_ack(gpa, ctx.io());
    return setup.start(ctx.child("recovering_validator"), 0, app);
}

/// Acknowledges heights 0 through `count - 1`, expecting each in order.
fn expect_acks(validator: *Validator, count: u64) !void {
    for (0..count) |expected| {
        try testing.expectEqual(Height.new(expected), try validator.application.acknowledged());
    }
}

/// Expects `get_info(identifier)` to name `block` at its height.
fn expect_info(
    validator: *Validator,
    identifier: core.Identifier(harness.D),
    block: *const H.TestBlock,
) !void {
    const info = (try validator.mailbox.get_info(identifier)) orelse return error.TestNoInfo;
    try testing.expectEqual(H.height(block), info.height);
    try testing.expectEqual(H.digest(block), info.digest);
}

/// Starts a peer holding `blocks[1..]` verified and `finalized` reported, seeds validator 0
/// with `stored` blocks and `finalized`, restarts it, and expects every height in order.
fn repair_body(
    ctx: Ctx,
    setup: *Setup,
    blocks: []const H.TestBlock,
    stored: []const H.TestBlock,
    finalized: []const seed.FinalizationAt,
) !void {
    const peer = try setup.start(ctx.child("peer_validator"), 1, try .init(gpa, ctx.io()));
    defer peer.crash();
    for (blocks[1..]) |*block| try H.verify(peer, round_at(H.height(block).get()), block);
    for (finalized) |entry| _ = peer.mailbox.report(.{ .finalization = entry.finalization });
    try ctx.sleep(.fromMilliseconds(200));
    const recovering = try seed_and_restart(ctx, setup, stored, finalized);
    defer recovering.crash();
    // Every height arrives in order: the missing ones only once repaired from the peer.
    try expect_acks(recovering, blocks.len);
}

/// Validator 0 has block 1 and the finalization of block 2, but not block 2 itself.
fn repairs_trailing_missing_body(ctx: Ctx) anyerror!void {
    var setup: Setup = undefined;
    try setup.init(ctx);
    defer setup.deinit();
    const validators = &setup.validators;
    var blocks: [3]H.TestBlock = undefined;
    try make_chain(&blocks);
    defer free_chain(&blocks);
    var finalization = try finalize(validators, &blocks[2]);
    defer finalization.deinit(gpa);
    const finalized = [_]seed.FinalizationAt{.{ .height = .new(2), .finalization = finalization }};
    try repair_body(ctx, &setup, &blocks, blocks[1..2], &finalized);
}

test "standard restart repairs trailing missing finalized block" {
    var runner = try runtime.deterministic.Runner.init(gpa, timed);
    defer runner.deinit();
    try try runner.start_context(repairs_trailing_missing_body, .{});
}

/// Validator 0 has blocks 1 and 3 and the finalizations of 2 and 3, but not block 2.
fn repairs_internal_missing_body(ctx: Ctx) anyerror!void {
    var setup: Setup = undefined;
    try setup.init(ctx);
    defer setup.deinit();
    const validators = &setup.validators;
    var blocks: [4]H.TestBlock = undefined;
    try make_chain(&blocks);
    defer free_chain(&blocks);
    var finalization_two = try finalize(validators, &blocks[2]);
    defer finalization_two.deinit(gpa);
    var finalization_three = try finalize(validators, &blocks[3]);
    defer finalization_three.deinit(gpa);
    const finalized = [_]seed.FinalizationAt{
        .{ .height = .new(2), .finalization = finalization_two },
        .{ .height = .new(3), .finalization = finalization_three },
    };
    const stored = [_]H.TestBlock{ blocks[1], blocks[3] };
    try repair_body(ctx, &setup, &blocks, &stored, &finalized);
}

test "standard restart repairs internal missing finalized block" {
    var runner = try runtime.deterministic.Runner.init(gpa, timed);
    defer runner.deinit();
    try try runner.start_context(repairs_internal_missing_body, .{});
}

/// Validator 0 has blocks 1 and 2 but only the finalization of block 1.
fn surfaces_unfinalized_block_body(ctx: Ctx) anyerror!void {
    var setup: Setup = undefined;
    try setup.init(ctx);
    defer setup.deinit();
    var blocks: [3]H.TestBlock = undefined;
    try make_chain(&blocks);
    defer free_chain(&blocks);
    var finalization = try finalize(&setup.validators, &blocks[1]);
    defer finalization.deinit(gpa);
    const finalized = [_]seed.FinalizationAt{.{ .height = .new(1), .finalization = finalization }};
    const recovering = try seed_and_restart(ctx, &setup, blocks[1..], &finalized);
    defer recovering.crash();
    // The tip tracks the highest finalization, not the highest block.
    try expect_info(recovering, .latest, &blocks[1]);
    // A block without a finalization row is still queryable, by height and for its info.
    var block_two = (try recovering.mailbox.get_block(.{ .height = .new(2) })).?;
    defer block_two.deinit();
    try testing.expectEqual(H.digest(&blocks[2]), H.digest(&block_two));
    try expect_info(recovering, .{ .height = .new(2) }, &blocks[2]);
    // It is dispatched too, since its block data exists in the archive.
    try expect_acks(recovering, blocks.len);
}

test "standard restart surfaces block without finalization" {
    var runner = try runtime.deterministic.Runner.init(gpa, timed);
    defer runner.deinit();
    try try runner.start_context(surfaces_unfinalized_block_body, .{});
}

/// A finalized block can be durable without its finalization when a crash interrupts the
/// concurrent sync of both archives. Restart dispatches it from the archive, so its finalization
/// arrives for a processed height; the archive keeps it, and the latest finalized height and the
/// application tip follow it.
fn stores_late_finalization_body(ctx: Ctx) anyerror!void {
    var setup: Setup = undefined;
    try setup.init(ctx);
    defer setup.deinit();
    var blocks: [3]H.TestBlock = undefined;
    try make_chain(&blocks);
    defer free_chain(&blocks);
    var finalization_one = try finalize(&setup.validators, &blocks[1]);
    defer finalization_one.deinit(gpa);
    var finalization_two = try finalize(&setup.validators, &blocks[2]);
    defer finalization_two.deinit(gpa);
    const finalized = [_]seed.FinalizationAt{
        .{ .height = .new(1), .finalization = finalization_one },
    };
    const recovering = try seed_and_restart(ctx, &setup, blocks[1..], &finalized);
    defer recovering.crash();
    try expect_acks(recovering, blocks.len);
    const processed: core.Processed = .{ .block = .new(2) };
    while (!std.meta.eql(try recovering.mailbox.get_processed(), processed)) {
        try ctx.sleep(.fromMilliseconds(10));
    }
    try testing.expect(try recovering.mailbox.get_finalization(.new(2)) == null);

    _ = recovering.mailbox.report(.{ .finalization = finalization_two });
    var stored = (try recovering.mailbox.get_finalization(.new(2))) orelse
        return error.TestFinalizationDropped;
    defer stored.deinit(gpa);
    try testing.expect(std.meta.eql(stored.proposal, finalization_two.proposal));
    try expect_info(recovering, .latest, &blocks[2]);
    const tip = recovering.application.tip() orelse return error.TestNoTip;
    try testing.expectEqual(Height.new(2), tip.height);
    try testing.expectEqual(H.digest(&blocks[2]), tip.digest);
}

test "standard restart stores reported finalization for processed block" {
    var runner = try runtime.deterministic.Runner.init(gpa, timed);
    defer runner.deinit();
    try try runner.start_context(stores_late_finalization_body, .{});
}

/// Validator 0 has block 1 and the finalizations of blocks 1 through 5.
fn repairs_multiple_trailing_body(ctx: Ctx) anyerror!void {
    var setup: Setup = undefined;
    try setup.init(ctx);
    defer setup.deinit();
    var blocks: [6]H.TestBlock = undefined;
    try make_chain(&blocks);
    defer free_chain(&blocks);
    var finalized: [5]seed.FinalizationAt = undefined;
    try finalize_all(&setup.validators, blocks[1..], &finalized);
    defer free_finalizations(&finalized);
    try repair_body(ctx, &setup, &blocks, blocks[1..2], &finalized);
}

test "standard restart repairs multiple trailing missing finalized blocks" {
    var runner = try runtime.deterministic.Runner.init(gpa, timed);
    defer runner.deinit();
    try try runner.start_context(repairs_multiple_trailing_body, .{});
}

/// The finalized tip is far ahead of the last stored block and only the tip has a
/// finalization, so recovery walks back by commitment past `max_repair` missing heights.
fn repairs_large_pending_tip_body(ctx: Ctx) anyerror!void {
    const pending_tip = 18;
    var setup: Setup = undefined;
    try setup.init(ctx);
    defer setup.deinit();
    var blocks: [pending_tip + 1]H.TestBlock = undefined;
    try make_chain(&blocks);
    defer free_chain(&blocks);
    var tip_finalization = try finalize(&setup.validators, &blocks[pending_tip]);
    defer tip_finalization.deinit(gpa);
    // The peer has every block; validator 0 knows block 1 and the tip finalization only.
    const peer = try setup.start(ctx.child("peer_validator"), 1, try .init(gpa, ctx.io()));
    defer peer.crash();
    for (blocks[1..]) |*block| try H.verify(peer, round_at(H.height(block).get()), block);
    try ctx.sleep(.fromMilliseconds(200));
    const finalized = [_]seed.FinalizationAt{
        .{ .height = .new(pending_tip), .finalization = tip_finalization },
    };
    const recovering = try seed_and_restart(ctx, &setup, blocks[1..2], &finalized);
    defer recovering.crash();
    // Restart surfaces the pending finalized tip before every block is repaired.
    for (0..100) |_| {
        if (recovering.application.tip()) |tip| if (tip.height.get() == pending_tip) break;
        try ctx.sleep(.fromMilliseconds(10));
    }
    const tip = recovering.application.tip() orelse return error.TestNoTip;
    try testing.expectEqual(Height.new(pending_tip), tip.height);
    try expect_acks(recovering, blocks.len);
    for ([_]u64{ 2, 10, pending_tip }) |height| {
        var block = (try recovering.mailbox.get_block(.{ .height = .new(height) })).?;
        defer block.deinit();
        try testing.expectEqual(H.digest(&blocks[height]), H.digest(&block));
    }
}

test "standard restart repairs large pending tip by commitment" {
    var runner = try runtime.deterministic.Runner.init(gpa, .{
        .timeout_ns = 120 * std.time.ns_per_s,
    });
    defer runner.deinit();
    try try runner.start_context(repairs_large_pending_tip_body, .{});
}

/// Every finalized block is on disk, so restart needs no repair.
fn consistent_restart_body(ctx: Ctx) anyerror!void {
    var setup: Setup = undefined;
    try setup.init(ctx);
    defer setup.deinit();
    var blocks: [3]H.TestBlock = undefined;
    try make_chain(&blocks);
    defer free_chain(&blocks);
    var finalized: [2]seed.FinalizationAt = undefined;
    try finalize_all(&setup.validators, blocks[1..], &finalized);
    defer free_finalizations(&finalized);
    const recovering = try seed_and_restart(ctx, &setup, blocks[1..], &finalized);
    defer recovering.crash();
    try expect_acks(recovering, blocks.len);
}

test "standard restart no trailing finalizations is noop" {
    var runner = try runtime.deterministic.Runner.init(gpa, timed);
    defer runner.deinit();
    try try runner.start_context(consistent_restart_body, .{});
}

/// Block 2 was notarized into the cache but never reached the finalized archive; with no
/// network links, trailing repair must find it locally.
fn repairs_from_cache_body(ctx: Ctx) anyerror!void {
    var setup: Setup = undefined;
    try setup.init_links(ctx, false);
    defer setup.deinit();
    var blocks: [3]H.TestBlock = undefined;
    try make_chain(&blocks);
    defer free_chain(&blocks);
    var finalization = try finalize(&setup.validators, &blocks[2]);
    defer finalization.deinit(gpa);
    var name: [192]u8 = undefined;
    const prefix = try setup.prefix(&name, 0);
    try seed.cache_block(ctx.child("cache_storage"), prefix, round_at(2), &blocks[2]);
    const finalized = [_]seed.FinalizationAt{.{ .height = .new(2), .finalization = finalization }};
    const recovering = try seed_and_restart(ctx, &setup, blocks[1..2], &finalized);
    defer recovering.crash();
    try expect_acks(recovering, blocks.len);
}

test "standard restart repairs trailing block from local cache" {
    var runner = try runtime.deterministic.Runner.init(gpa, timed);
    defer runner.deinit();
    try try runner.start_context(repairs_from_cache_body, .{});
}

/// A resolved acknowledgement is handled before a later mailbox message (commonware's biased
/// `select_loop!`): `get_processed` right after an ack already reports that height.
fn ack_precedes_mailbox_body(ctx: Ctx) anyerror!void {
    var setup: Setup = undefined;
    try setup.init(ctx);
    defer setup.deinit();
    var blocks: [4]H.TestBlock = undefined;
    try make_chain(&blocks);
    defer free_chain(&blocks);
    var finalized: [3]seed.FinalizationAt = undefined;
    try finalize_all(&setup.validators, blocks[1..], &finalized);
    defer free_finalizations(&finalized);
    const recovering = try seed_and_restart(ctx, &setup, blocks[1..], &finalized);
    defer recovering.crash();
    for (0..blocks.len) |expected| {
        const height = try recovering.application.acknowledged();
        try testing.expectEqual(Height.new(expected), height);
        const processed: core.Processed = .{ .block = height };
        const current = try recovering.mailbox.get_processed() orelse return error.TestNoProcessed;
        try testing.expectEqual(processed, current);
    }
}

test "standard acknowledgement is processed before a later mailbox message" {
    var runner = try runtime.deterministic.Runner.init(gpa, timed);
    defer runner.deinit();
    try try runner.start_context(ack_precedes_mailbox_body, .{});
}

fn subscribed_once(buffer: common.RecordingBuffer) bool {
    return buffer.commitment_subscription_count() == 1;
}

/// A start floor waits on the buffer for its anchor. Once the buffer hands the anchor over, a
/// later `get_anchor` sees the installed floor: the actor takes a ready buffer waiter before
/// any mailbox message, as commonware's biased `select_loop!` does, even when the waiter's own
/// notice has not reached the inbox yet.
fn waiter_precedes_mailbox_body(ctx: Ctx) anyerror!void {
    var rng = utils.rng.test_rng();
    var validators = try harness.fixture(gpa, &rng);
    defer validators.deinit(gpa);
    var blocks: [6]H.TestBlock = undefined;
    try make_chain(&blocks);
    defer free_chain(&blocks);
    const anchor = &blocks[5];
    var application = try App.manual_ack(gpa, ctx.io());
    defer application.deinit();
    var buffer = try common.RecordingBuffer.init(gpa, ctx.io());
    defer buffer.deinit();
    const provider: harness.Provider = .init(&validators.schemes[0]);
    var started = try common.start_standard_actor(
        harness.Provider,
        App,
        common.RecordingBuffer,
        ctx.child("validator"),
        "waiter-precedes-mailbox",
        provider,
        application.clone(),
        buffer.clone(),
        .{ .floor = try finalize(&validators, anchor) },
    );
    defer started.crash();
    try common.wait_until(ctx, 5000, "floor anchor subscription", buffer, subscribed_once);
    try testing.expect(buffer.deliver_commitment_subscription(0, anchor.clone()));
    const installed = try started.mailbox.get_anchor() orelse return error.TestFloorPending;
    var installed_block = installed.block;
    defer installed_block.deinit();
    try testing.expect(H.digest(&installed_block).eql(H.digest(anchor)));
}

test "standard ready buffer waiter is handled before a later mailbox message" {
    for (0..8) |run_seed| {
        var config = timed;
        config.seed = run_seed;
        var runner = try runtime.deterministic.Runner.init(gpa, config);
        defer runner.deinit();
        try try runner.start_context(waiter_precedes_mailbox_body, .{});
    }
}
