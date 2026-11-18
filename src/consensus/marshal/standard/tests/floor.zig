//! The standard actor's floors, floor anchors, and acknowledgements (commonware
//! `marshal/standard/mod.rs`, lines 6740-10611), on the direct actor from `common.zig`.
//!
//! commonware's `#[should_panic(expected = "floor finalization must verify")]` tests
//! (`test_standard_start_floor_rejects_invalid_finalization` and
//! `test_standard_set_floor_rejects_invalid_finalization`) have no counterpart: Zig cannot
//! catch a panic, and the actor panics with the same message (`core/actor_ingress.zig`).

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
const D = harness.D;
const Block = common.Block;

/// commonware's `Runner::timed(30s)`.
const timed: runtime.deterministic.Config = .{ .timeout_ns = 30 * std.time.ns_per_s };

fn run(comptime body: fn (Ctx) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(gpa, timed);
    defer runner.deinit();
    try try runner.start_context(body, .{});
}

fn round_at(view: u64) Round {
    return .new(.zero(), .new(view));
}

fn hash(text: []const u8) D {
    return harness.Sha256.hash(&.{text});
}

/// `ready(make_raw_block(parent, height, timestamp))`.
fn block_at(parent: D, height: u64, timestamp: u64) !Block {
    const raw = try harness.make_raw_block(gpa, parent, .new(height), timestamp);
    return mocks_block.ready(harness.B, gpa, raw);
}

/// The quorum finalization of `block` at `view` over `parent_view`.
fn finalize(
    fixture: *const harness.Fixture,
    view: u64,
    parent_view: u64,
    block: *const Block,
) !harness.Finalization {
    const proposal = harness.Proposal.init(round_at(view), .new(parent_view), block.digest());
    return harness.make_finalization(gpa, fixture, proposal, harness.quorum);
}

/// Reports `finalization` (borrowed) to the actor, as `report_finalization` does.
fn report(mailbox: anytype, finalization: harness.Finalization) void {
    var value = finalization;
    _ = mailbox.report(.{ .finalization = value });
    value.deinit(gpa);
}

fn genesis_start() !common.Start {
    return .{ .genesis = try H.genesis_block(gpa, harness.num_validators) };
}

/// Whether `resolver` fetched the block `digest`.
fn fetched_block(resolver: common.RecordingResolver, digest: D) bool {
    return resolver.fetched(.{ .block = digest });
}

const BlockFetch = struct { resolver: common.RecordingResolver, digest: D };

fn block_fetched(state: BlockFetch) bool {
    return fetched_block(state.resolver, state.digest);
}

fn wait_block_fetch(ctx: Ctx, resolver: common.RecordingResolver, digest: D) !void {
    const state: BlockFetch = .{ .resolver = resolver, .digest = digest };
    try common.wait_until(ctx, 5000, "floor block fetch", state, block_fetched);
}

const Holding = common.Started(
    harness.Provider,
    common.HoldingBlockReporter,
    common.RecordingBuffer,
);
const Manual = common.Started(harness.Provider, App, common.RecordingBuffer);

fn start_holding(
    ctx: Ctx,
    prefix: []const u8,
    fixture: *const harness.Fixture,
    reporter: common.HoldingBlockReporter,
    buffer: common.RecordingBuffer,
    start: common.Start,
) !Holding {
    const provider: harness.Provider = .init(&fixture.schemes[0]);
    return common.start_standard_actor(
        harness.Provider,
        common.HoldingBlockReporter,
        common.RecordingBuffer,
        ctx,
        prefix,
        provider,
        reporter,
        buffer,
        start,
    );
}

fn start_manual(
    ctx: Ctx,
    prefix: []const u8,
    fixture: *const harness.Fixture,
    application: App,
    buffer: common.RecordingBuffer,
) !Manual {
    const provider: harness.Provider = .init(&fixture.schemes[0]);
    return common.start_standard_actor(
        harness.Provider,
        App,
        common.RecordingBuffer,
        ctx,
        prefix,
        provider,
        application,
        buffer,
        try genesis_start(),
    );
}

/// The floor at height 5 (view 5 over view 4) on parent `parent_label`, and its block.
const Floor = struct {
    block: Block,
    finalization: harness.Finalization,

    fn init(fixture: *const harness.Fixture, parent_label: []const u8) !Floor {
        var block = try block_at(hash(parent_label), 5, 500);
        errdefer block.deinit();
        return .{ .block = block, .finalization = try finalize(fixture, 5, 4, &block) };
    }

    fn deinit(self: *Floor) void {
        self.block.deinit();
        self.finalization.deinit(gpa);
    }

    fn clone_finalization(self: *const Floor) !harness.Finalization {
        return self.finalization.clone(gpa);
    }
};

test "standard actor starts without buffer" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            var genesis = try H.genesis_block(gpa, harness.num_validators);
            defer genesis.deinit();
            const provider: harness.Provider = .init(&fixture.schemes[0]);
            var started = try common.start_standard_actor(
                harness.Provider,
                App,
                common.Unbuffered,
                ctx.child("validator"),
                "standard-no-buffer",
                provider,
                try App.manual_ack(gpa, ctx.io()),
                null,
                .{ .genesis = genesis.clone() },
            );
            defer started.crash();
            const mailbox = started.mailbox;
            var stored = (try mailbox.get_block(.{ .height = .zero() })).?;
            defer stored.deinit();
            try testing.expect(stored.digest().eql(genesis.digest()));

            var block = try block_at(genesis.digest(), 1, 100);
            defer block.deinit();
            try testing.expect(try mailbox.verified(round_at(1), block.clone()));
            // The mailbox takes ownership of the recipients.
            const peers = try gpa.dupe(harness.K, fixture.participants[1..2]);
            _ = try mailbox.forward(round_at(1), block.digest(), .{ .some = peers });
            var verified = (try mailbox.get_verified(round_at(1))).?;
            defer verified.deinit();
            try testing.expect(verified.digest().eql(block.digest()));
        }
    }.body);
}

test "standard start floor fetches async and serves requests" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            var floor: Floor = try .init(&fixture, "floor-parent");
            defer floor.deinit();
            var created = try common.HoldingBlockReporter.init_after(gpa, ctx.io(), .zero());
            defer created.started.deinit();
            var started = try start_holding(
                ctx.child("validator"),
                "start-floor-async",
                &fixture,
                created.reporter,
                try common.RecordingBuffer.init(gpa, ctx.io()),
                .{ .floor = try floor.clone_finalization() },
            );
            defer started.crash();
            const mailbox = started.mailbox;
            try wait_block_fetch(ctx, started.resolver, floor.block.digest());

            // A verified block is served to peers while the floor anchor is still missing.
            var served = try block_at(hash("served-parent"), 1, 100);
            defer served.deinit();
            try testing.expect(try mailbox.verified(round_at(1), served.clone()));
            var producer = started.resolver.handler_clone();
            defer producer.deinit();
            var response = try producer.produce(.{ .block = served.digest() });
            defer response.deinit();
            const produced = try response.recv();
            defer produced.deinit();
            const encoded = try @import("codec").encode(harness.B, gpa, served.inner().*);
            defer gpa.free(encoded);
            try testing.expectEqualSlices(u8, encoded, produced.bytes);

            // Dispatch waits for the floor anchor even once a later block finalizes.
            var next = try block_at(floor.block.digest(), 6, 600);
            defer next.deinit();
            try testing.expect(try mailbox.verified(round_at(6), next.clone()));
            report(&started.mailbox, try finalize(&fixture, 6, 5, &next));
            try ctx.sleep(.fromMilliseconds(100));
            try testing.expectError(error.Empty, created.started.try_recv());

            try testing.expect(try mailbox.verified(round_at(5), floor.block.clone()));
            try testing.expectEqual(5, (try created.started.recv()).get());
        }
    }.body);
}

const Retains = struct { resolver: common.RecordingResolver, at_least: u64 };

fn retained(state: Retains) bool {
    return state.resolver.retain_count() >= state.at_least;
}

fn expect_absent_anchor(mailbox: anytype, floor_digest: D) !void {
    const processed = (try mailbox.get_processed()).?;
    try testing.expectEqual(@as(u64, 4), processed.absent.get());
    var anchor = (try mailbox.get_anchor()).?;
    defer anchor.block.deinit();
    try testing.expectEqual(@as(u64, 4), anchor.processed.absent.get());
    try testing.expect(anchor.block.digest().eql(floor_digest));
}

test "standard start floor applies local anchor without fetch" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            const prefix = "start-floor-local-anchor";
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            var floor: Floor = try .init(&fixture, "local-floor-parent");
            defer floor.deinit();
            var buffer = try common.RecordingBuffer.init(gpa, ctx.io());
            try buffer.insert(floor.block.clone());
            var created = try common.HoldingBlockReporter.init(gpa, ctx.io());
            defer created.started.deinit();
            var started = try start_holding(
                ctx.child("validator"),
                prefix,
                &fixture,
                created.reporter,
                buffer,
                .{ .floor = try floor.clone_finalization() },
            );
            const state: Retains = .{ .resolver = started.resolver, .at_least = 2 };
            try common.wait_until(ctx, 5000, "local floor anchor application", state, retained);
            try testing.expectEqual(0, started.resolver.fetch_count());
            var stored = (try started.mailbox.get_block(.{ .height = .new(5) })).?;
            stored.deinit();

            // Without local history, the processed height has no stored block and the floor
            // block backs it instead.
            try expect_absent_anchor(started.mailbox, floor.block.digest());
            try testing.expect(try started.mailbox.get_block(.{ .height = .new(4) }) == null);

            var next = try block_at(floor.block.digest(), 6, 600);
            defer next.deinit();
            try testing.expect(try started.mailbox.verified(round_at(6), next.clone()));
            report(&started.mailbox, try finalize(&fixture, 6, 5, &next));
            try testing.expectEqual(5, (try created.started.recv()).get());

            // Restarting before block 5 is acknowledged finds the same floor.
            started.crash();
            var again = try common.HoldingBlockReporter.init(gpa, ctx.io());
            defer again.started.deinit();
            var restarted = try start_holding(
                ctx.child("restart"),
                prefix,
                &fixture,
                again.reporter,
                try common.RecordingBuffer.init(gpa, ctx.io()),
                .{ .floor = try floor.clone_finalization() },
            );
            defer restarted.crash();
            try expect_absent_anchor(restarted.mailbox, floor.block.digest());
        }
    }.body);
}

test "standard set floor holds dispatch until anchor arrives" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            var floor: Floor = try .init(&fixture, "floor-parent");
            defer floor.deinit();
            var created = try common.HoldingBlockReporter.init_after(gpa, ctx.io(), .zero());
            defer created.started.deinit();
            var started = try start_holding(
                ctx.child("validator"),
                "set-floor-holds-dispatch",
                &fixture,
                created.reporter,
                try common.RecordingBuffer.init(gpa, ctx.io()),
                try genesis_start(),
            );
            defer started.crash();
            try started.mailbox.set_floor(try floor.clone_finalization());
            try wait_block_fetch(ctx, started.resolver, floor.block.digest());

            var next = try block_at(floor.block.digest(), 6, 600);
            defer next.deinit();
            try testing.expect(try started.mailbox.verified(round_at(6), next.clone()));
            report(&started.mailbox, try finalize(&fixture, 6, 5, &next));
            try ctx.sleep(.fromMilliseconds(100));
            try testing.expectError(error.Empty, created.started.try_recv());

            // Deliver the floor block through the resolver for the recorded fetch.
            const fetches = try started.resolver.fetches(gpa);
            defer gpa.free(fetches);
            const floor_fetch = for (fetches) |item| {
                if (item.key.eql(.{ .block = floor.block.digest() })) break item;
            } else return error.FloorFetchMissing;
            var handler = started.resolver.handler_clone();
            defer handler.deinit();
            const encoded = try @import("codec").encode(harness.B, gpa, floor.block.inner().*);
            defer gpa.free(encoded);
            const subscribers = [_]common.Annotation{floor_fetch.subscriber};
            var response = try handler.deliver(
                .{ .key = floor_fetch.key, .subscribers = &subscribers },
                encoded,
            );
            defer response.deinit();
            const outcome = try response.recv();
            try testing.expect(std.meta.eql(outcome, common.Outcome{ .resolved = .complete }));
            try testing.expectEqual(5, (try created.started.recv()).get());
        }
    }.body);
}

const Pending = struct { application: App, height: u64 };

fn pending_is(state: Pending) bool {
    const heights = state.application.pending_ack_heights(gpa) catch return false;
    defer gpa.free(heights);
    return heights.len == 1 and heights[0].get() == state.height;
}

/// Finalizes block 1 (on parent `block1-parent`) and waits until it awaits acknowledgement.
fn dispatch_block_one(
    ctx: Ctx,
    started: *Manual,
    fixture: *const harness.Fixture,
    application: App,
) !void {
    var block = try block_at(hash("block1-parent"), 1, 100);
    defer block.deinit();
    try testing.expect(try started.mailbox.verified(round_at(1), block.clone()));
    report(&started.mailbox, try finalize(fixture, 1, 0, &block));
    const state: Pending = .{ .application = application, .height = 1 };
    try common.wait_until(ctx, 5000, "first block dispatch", state, pending_is);
}

/// Releases the stale ack at height 1, then checks a commitment subscription below the floor
/// fetches nothing.
fn expect_stale_ack_ignored(ctx: Ctx, started: *Manual, application: App, label: []const u8) !void {
    const fetches_after_floor = started.resolver.fetch_count();
    try testing.expectEqual(1, application.acknowledge_next().?.get());
    try ctx.sleep(.fromMilliseconds(100));
    var subscription = try started.mailbox.subscribe_by_commitment(
        hash(label),
        .{ .fetch_by_commitment = .new(2) },
    );
    defer subscription.deinit();
    var block = (try started.mailbox.get_block(.{ .height = .new(5) })).?;
    block.deinit();
    try testing.expectEqual(fetches_after_floor, started.resolver.fetch_count());
}

test "standard floor jump ignores stale application ack" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            var application = try App.manual_ack(gpa, ctx.io());
            defer application.deinit();
            var started = try start_manual(
                ctx.child("validator"),
                "floor-jump-ignores-stale-ack",
                &fixture,
                application.clone(),
                try common.RecordingBuffer.init(gpa, ctx.io()),
            );
            defer started.crash();
            try testing.expectEqual(0, (try application.acknowledged()).get());
            try dispatch_block_one(ctx, &started, &fixture, application);

            // The anchor is not local yet, so the floor stays pending until it arrives.
            var floor: Floor = try .init(&fixture, "floor-parent");
            defer floor.deinit();
            try started.mailbox.set_floor(try floor.clone_finalization());
            try wait_block_fetch(ctx, started.resolver, floor.block.digest());
            try testing.expect(try started.mailbox.verified(round_at(5), floor.block.clone()));
            var stored = (try started.mailbox.get_block(.{ .height = .new(5) })).?;
            defer stored.deinit();
            try testing.expect(stored.digest().eql(floor.block.digest()));

            // The stale ack must not lower the processed floor back below height 5.
            try expect_stale_ack_ignored(ctx, &started, application, "below-floor-after-stale-ack");
        }
    }.body);
}

test "standard local floor jump ignores stale application ack" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            var application = try App.manual_ack(gpa, ctx.io());
            defer application.deinit();
            var buffer = try common.RecordingBuffer.init(gpa, ctx.io());
            defer buffer.deinit();
            var started = try start_manual(
                ctx.child("validator"),
                "local-floor-jump-ignores-stale-ack",
                &fixture,
                application.clone(),
                buffer.clone(),
            );
            defer started.crash();
            try testing.expectEqual(0, (try application.acknowledged()).get());
            try dispatch_block_one(ctx, &started, &fixture, application);

            // The anchor is already local, so the floor installs at once without a fetch.
            var floor: Floor = try .init(&fixture, "local-floor-parent");
            defer floor.deinit();
            try buffer.insert(floor.block.clone());
            try started.mailbox.set_floor(try floor.clone_finalization());
            var stored = (try started.mailbox.get_block(.{ .height = .new(5) })).?;
            defer stored.deinit();
            try testing.expect(stored.digest().eql(floor.block.digest()));
            try testing.expectEqual(0, started.resolver.fetch_count());

            const label = "below-local-floor-after-stale-ack";
            try expect_stale_ack_ignored(ctx, &started, application, label);
        }
    }.body);
}
