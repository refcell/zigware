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
const seed = @import("seed.zig");

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
const Prunable = common.PrunableStores(harness.B);
const PrunableActor = common.Actor(
    harness.Provider,
    App,
    common.Unbuffered,
    Prunable.Certificates,
    Prunable.Blocks,
);

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
fn report(mailbox: anytype, fixture: *const harness.Fixture, block: *const Block) !void {
    var finalization = try finalize(fixture, block);
    defer finalization.deinit(gpa);
    _ = mailbox.report(.{ .finalization = finalization });
}

/// Delivers `(finalization, block)` as the finalized-by-height response for `block`'s height
/// through `sender`; the receiver yields marshal's verdict.
fn deliver_finalized(
    sender: anytype,
    fixture: *const harness.Fixture,
    block: *const Block,
) !utils.channel.oneshot.Receiver(common.Outcome) {
    const height = block.inner().height();
    var finalization = try finalize(fixture, block);
    defer finalization.deinit(gpa);
    const Pair = struct { harness.Finalization, harness.B };
    const value = try @import("codec").encode(Pair, gpa, .{ finalization, block.inner().* });
    defer gpa.free(value);
    const subscribers = [_]common.Annotation{.{ .finalized = .{ .by_height = height } }};
    return sender.deliver(.{ .key = .{ .finalized = height }, .subscribers = &subscribers }, value);
}

/// Waits until block one is dispatched and awaiting its acknowledgement.
fn wait_pending_one(ctx: Ctx, application: App) !void {
    for (0..1000) |_| {
        const pending = try application.pending_ack_heights(gpa);
        defer gpa.free(pending);
        if (pending.len == 1 and pending[0].get() == 1) return;
        try ctx.sleep(.fromMilliseconds(1));
    }
    return error.TestNotPending;
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
    try report(&started.mailbox, &fixture, &chain[3]);
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
    try report(&started.mailbox, &fixture, &chain[1]);
    // A block the archive lacks must not acquire a finalization.
    try testing.expect(try started.mailbox.get_finalization(.new(1)) == null);
}

test "standard drops finalization for block below floor" {
    try run(drops_below_floor_body);
}

/// An unbuffered actor over prunable finalized stores under `prefix`, with a recording
/// resolver; the stores must be seeded before `start`.
const Direct = struct {
    stores: *Prunable,
    mailbox: PrunableActor.Mailbox,
    resolver: common.RecordingResolver,
    restored: core.Floor,
    handle: runtime.context.Handle(anyerror!void),

    /// Opens the stores (call `seed_*` on `stores` before `start`).
    fn open(ctx: Ctx, prefix: []const u8) !*Prunable {
        const stores = try gpa.create(Prunable);
        errdefer gpa.destroy(stores);
        try stores.open(ctx, prefix);
        return stores;
    }

    /// Initializes the actor over `stores` (owned) with `epoch_length` epochs, and starts it
    /// with `application` (borrowed; the actor gets a clone).
    fn start(
        ctx: Ctx,
        stores: *Prunable,
        prefix: []const u8,
        fixture: *const harness.Fixture,
        epoch_length: u64,
        application: App,
    ) !Direct {
        errdefer {
            stores.deinit();
            gpa.destroy(stores);
        }
        const provider: harness.Provider = .init(&fixture.schemes[0]);
        const A = PrunableActor;
        var config = try common.test_config(A, gpa, prefix, provider, 1, &stores.cache_ref);
        config.epocher = .new(utils.NonZero(u64).init(epoch_length).?);
        const certificates = stores.certificates();
        const blocks = stores.blocks_store();
        const initialized = try A.init(ctx.child("actor"), certificates, blocks, config);
        var scope = ctx.scope.child("mailbox");
        var holding = try common.RecordingResolver.holding(gpa, ctx.io(), &scope);
        errdefer holding.resolver.deinit();
        const handle = try initialized.actor.start(
            application.clone(),
            common.Unbuffered{ .gpa = gpa },
            holding.receiver,
            holding.resolver.clone(),
        );
        return .{
            .stores = stores,
            .mailbox = initialized.mailbox,
            .resolver = holding.resolver,
            .restored = initialized.floor,
            .handle = handle,
        };
    }

    fn crash(self: *Direct) void {
        const ended = self.handle.abort() catch {};
        ended catch {};
        self.mailbox.deinit();
        self.resolver.deinit();
        self.stores.deinit();
        gpa.destroy(self.stores);
        self.* = undefined;
    }
};

/// Stores `blocks` (borrowed) in the finalized blocks archive and syncs it.
fn seed_blocks(stores: *Prunable, blocks: []const Block) !void {
    for (blocks) |*block| {
        try stores.blocks.put(block.inner().height().get(), block.digest().bytes, block.inner().*);
    }
    try stores.blocks.sync();
}

/// Stores `finalization` (borrowed) for `block` at its height and syncs it.
fn seed_finalization(
    stores: *Prunable,
    block: *const Block,
    finalization: harness.Finalization,
) !void {
    const height = block.inner().height().get();
    try stores.finalizations.put(height, block.digest().bytes, finalization);
    try stores.finalizations.sync();
}

/// Prune retains the newest finalization at or below the processed height as the round floor
/// a restart recovers. A finalization kept for processed block 20 is durable before prune can
/// select it, so pruning finalization 10 and restarting after a crash recovers round 20.
fn kept_survives_prune_body(ctx: Ctx) anyerror!void {
    const prefix = "kept-finalization-prune-restart";
    var rng = utils.rng.test_rng();
    var fixture = try harness.fixture(gpa, &rng);
    defer fixture.deinit(gpa);
    var chain: [21]Block = undefined;
    try make_chain(&chain);
    defer free_chain(&chain);
    var finalization_ten = try finalize(&fixture, &chain[10]);
    defer finalization_ten.deinit(gpa);

    // Blocks 1-20 are stored and processed, and only block 10 has its finalization.
    const stores = try Direct.open(ctx, prefix);
    {
        errdefer {
            stores.deinit();
            gpa.destroy(stores);
        }
        try seed_blocks(stores, chain[1..]);
        try seed_finalization(stores, &chain[10], finalization_ten);
        try seed.processed_height(ctx.child("metadata"), prefix, .new(20), null);
    }
    var application = try App.manual_ack(gpa, ctx.io());
    defer application.deinit();
    var direct = try Direct.start(ctx, stores, prefix, &fixture, 100, application);
    const cutoff_ten: core.floor.Cutoff = .{ .round = .new(.zero(), .new(10)) };
    try testing.expectEqual(cutoff_ten, direct.restored.cutoff);
    // Finalization 20 is kept, and pruning to height 20 removes finalization 10.
    try report(&direct.mailbox, &fixture, &chain[20]);
    var kept = try direct.mailbox.get_finalization(.new(20)) orelse return error.TestNotKept;
    kept.deinit(gpa);
    try direct.mailbox.prune(.new(20));
    try testing.expect(try direct.mailbox.get_finalization(.new(10)) == null);
    direct.crash();

    // A restart after the crash recovers the round from finalization 20.
    const reopened = try Direct.open(ctx, prefix);
    try testing.expect(try reopened.finalizations.has(.{ .index = 20 }));
    var restarted_application = try App.manual_ack(gpa, ctx.io());
    defer restarted_application.deinit();
    var restarted = try Direct.start(ctx, reopened, prefix, &fixture, 100, restarted_application);
    defer restarted.crash();
    const cutoff_twenty: core.floor.Cutoff = .{ .round = .new(.zero(), .new(20)) };
    try testing.expectEqual(cutoff_twenty, restarted.restored.cutoff);
}

test "standard kept finalization survives prune and restart" {
    try run(kept_survives_prune_body);
}

/// A fetch admitted before block one is acknowledged can deliver block one's late finalization
/// in the resolver batch that stores block two. Keeping it must leave block two's dispatch
/// deferred, so the pooled sync that ends the batch still dispatches block two.
fn late_in_batch_body(ctx: Ctx) anyerror!void {
    const prefix = "late-finalization-batch";
    var rng = utils.rng.test_rng();
    var fixture = try harness.fixture(gpa, &rng);
    defer fixture.deinit(gpa);
    var chain: [3]Block = undefined;
    try make_chain(&chain);
    defer free_chain(&chain);
    const stores = try Direct.open(ctx, prefix);
    {
        errdefer {
            stores.deinit();
            gpa.destroy(stores);
        }
        try seed_blocks(stores, chain[1..2]);
    }
    var application = try App.manual_ack(gpa, ctx.io());
    defer application.deinit();
    const epoch_length = harness.blocks_per_epoch;
    var direct = try Direct.start(ctx, stores, prefix, &fixture, epoch_length, application);
    defer direct.crash();
    try testing.expectEqual(Height.zero(), try application.acknowledged());
    try wait_pending_one(ctx, application);

    // Both fetches are admitted, and their responses queued, while block one is unacknowledged.
    const peer = fixture.participants[1];
    try direct.mailbox.hint_finalized(.new(1), &.{peer});
    try direct.mailbox.hint_finalized(.new(2), &.{peer});
    const zero: Processed = .{ .block = .zero() };
    try testing.expectEqual(zero, try direct.mailbox.get_processed() orelse return error.TestNone);
    const targeted = try direct.resolver.targeted_keys(gpa);
    gpa.free(targeted);
    try testing.expectEqual(@as(usize, 2), targeted.len);
    var sender = direct.resolver.handler_clone();
    defer sender.deinit();
    var two = try deliver_finalized(&sender, &fixture, &chain[2]);
    defer two.deinit();
    var one = try deliver_finalized(&sender, &fixture, &chain[1]);
    defer one.deinit();
    try testing.expectEqual(@as(?Height, .new(1)), application.acknowledge_next());
    // The batch stores block two, then keeps finalization one; its pooled sync dispatches two.
    const complete: common.Outcome = .{ .resolved = .complete };
    try testing.expect(std.meta.eql(try two.recv(), complete));
    try testing.expect(std.meta.eql(try one.recv(), complete));
    for ([_]u64{ 1, 2 }) |height| {
        const lookup = try direct.mailbox.get_finalization(.new(height));
        var found = lookup orelse return error.TestMissing;
        found.deinit(gpa);
    }
    try testing.expectEqual(Height.new(2), try application.acknowledged());
}

test "standard late finalization in batch keeps dispatch" {
    try run(late_in_batch_body);
}
