//! The standard actor's floors, floor anchors, and acknowledgements (commonware
//! `marshal/standard/mod.rs`, lines 6740-10611), on the direct actor from `common.zig`.
//!
//! commonware's `#[should_panic]` tests have no counterpart, since Zig cannot catch a panic:
//! `test_standard_start_floor_rejects_invalid_finalization` and
//! `test_standard_set_floor_rejects_invalid_finalization` ("floor finalization must verify",
//! `core/actor_ingress.zig`), and `test_standard_restart_rejects_mismatched_genesis_anchor`
//! ("stored genesis block does not match configured anchor"). The actor panics with the same
//! messages.

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
            try testing.expect(try deliver_fetched_block(started.resolver, &floor.block));
            try testing.expectEqual(5, (try created.started.recv()).get());
        }
    }.body);
}

/// Delivers `block` (borrowed) through the resolver for its recorded block fetch and reports
/// whether marshal resolved it completely.
fn deliver_fetched_block(resolver: common.RecordingResolver, block: *const Block) !bool {
    const fetches = try resolver.fetches(gpa);
    defer gpa.free(fetches);
    const key: common.Key = .{ .block = block.digest() };
    const fetch = for (fetches) |item| {
        if (item.key.eql(key)) break item;
    } else return error.BlockFetchMissing;
    var handler = resolver.handler_clone();
    defer handler.deinit();
    const encoded = try @import("codec").encode(harness.B, gpa, block.inner().*);
    defer gpa.free(encoded);
    const subscribers = [_]common.Annotation{fetch.subscriber};
    var response = try handler.deliver(.{ .key = fetch.key, .subscribers = &subscribers }, encoded);
    defer response.deinit();
    const outcome = try response.recv();
    return std.meta.eql(outcome, common.Outcome{ .resolved = .complete });
}

/// Reports the quorum notarization of `block` at `view` over `parent_view`.
fn notarize(
    mailbox: anytype,
    fixture: *const harness.Fixture,
    view: u64,
    parent_view: u64,
    digest: D,
) !void {
    const proposal = harness.Proposal.init(round_at(view), .new(parent_view), digest);
    var value = try harness.make_notarization(gpa, fixture, proposal, harness.quorum);
    defer value.deinit(gpa);
    _ = mailbox.report(.{ .notarization = value });
}

const Pending = struct { application: App, height: u64 };

fn pending_is(state: Pending) bool {
    const heights = state.application.pending_ack_heights(gpa) catch return false;
    defer gpa.free(heights);
    return heights.len == 1 and heights[0].get() == state.height;
}

/// Finalizes block 1 on `parent` and waits until it awaits acknowledgement.
fn dispatch_block_one(
    ctx: Ctx,
    started: *Manual,
    fixture: *const harness.Fixture,
    application: App,
    parent: D,
) !void {
    var block = try block_at(parent, 1, 100);
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
            try dispatch_block_one(ctx, &started, &fixture, application, hash("block1-parent"));

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
            try dispatch_block_one(ctx, &started, &fixture, application, hash("block1-parent"));

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

/// A floor at `height` (view `height` over `height - 1`) on parent `label`, stamped
/// `100 * height`.
fn floor_at(fixture: *const harness.Fixture, label: []const u8, height: u64) !Floor {
    var block = try block_at(hash(label), height, 100 * height);
    errdefer block.deinit();
    return .{ .block = block, .finalization = try finalize(fixture, height, height - 1, &block) };
}

/// Verifies and finalizes a child of `parent` at `height`, then checks it is stored.
fn finalize_child(
    started: anytype,
    fixture: *const harness.Fixture,
    parent: D,
    height: u64,
) !void {
    var next = try block_at(parent, height, 100 * height);
    defer next.deinit();
    try testing.expect(try started.mailbox.verified(round_at(height), next.clone()));
    report(&started.mailbox, try finalize(fixture, height, height - 1, &next));
    var stored = (try started.mailbox.get_finalization(.new(height))).?;
    stored.deinit(gpa);
}

test "standard newer pending floor supersedes older anchor" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            var created = try common.HoldingBlockReporter.init_after(gpa, ctx.io(), .zero());
            defer created.started.deinit();
            var started = try start_holding(
                ctx.child("validator"),
                "set-floor-supersedes-pending",
                &fixture,
                created.reporter,
                try common.RecordingBuffer.init(gpa, ctx.io()),
                try genesis_start(),
            );
            defer started.crash();
            var old: Floor = try floor_at(&fixture, "old-floor-parent", 5);
            defer old.deinit();
            try started.mailbox.set_floor(try old.clone_finalization());
            try wait_block_fetch(ctx, started.resolver, old.block.digest());
            var new: Floor = try floor_at(&fixture, "new-floor-parent", 7);
            defer new.deinit();
            try started.mailbox.set_floor(try new.clone_finalization());
            try wait_block_fetch(ctx, started.resolver, new.block.digest());

            try finalize_child(&started, &fixture, old.block.digest(), 6);
            try finalize_child(&started, &fixture, new.block.digest(), 8);

            // The superseded anchor validates but installs nothing.
            try testing.expect(try deliver_fetched_block(started.resolver, &old.block));
            try ctx.sleep(.fromMilliseconds(100));
            try testing.expectError(error.Empty, created.started.try_recv());

            try testing.expect(try deliver_fetched_block(started.resolver, &new.block));
            try testing.expectEqual(7, (try created.started.recv()).get());
        }
    }.body);
}

test "standard set floor applies buffered anchor on notarization" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            var floor: Floor = try .init(&fixture, "floor-parent");
            defer floor.deinit();
            var created = try common.HoldingBlockReporter.init_after(gpa, ctx.io(), .zero());
            defer created.started.deinit();
            var buffer = try common.RecordingBuffer.init(gpa, ctx.io());
            defer buffer.deinit();
            var started = try start_holding(
                ctx.child("validator"),
                "set-floor-buffered-anchor-notarization",
                &fixture,
                created.reporter,
                buffer.clone(),
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

            // The notarization finds the anchor in the buffer and installs the floor.
            try buffer.insert(floor.block.clone());
            try notarize(&started.mailbox, &fixture, 5, 4, floor.block.digest());
            try testing.expectEqual(5, (try created.started.recv()).get());
        }
    }.body);
}

const Subscriptions = struct { buffer: common.RecordingBuffer, count: usize };

fn subscription_count_is(state: Subscriptions) bool {
    return state.buffer.commitment_subscription_count() == state.count;
}

const Closed = struct { buffer: common.RecordingBuffer, index: usize };

fn subscription_closed(state: Closed) bool {
    return state.buffer.commitment_subscription_closed(state.index);
}

fn wait_subscriptions(ctx: Ctx, buffer: common.RecordingBuffer, count: usize) !void {
    const state: Subscriptions = .{ .buffer = buffer, .count = count };
    try common.wait_until(ctx, 5000, "buffer subscription", state, subscription_count_is);
}

fn wait_closed(ctx: Ctx, buffer: common.RecordingBuffer, index: usize) !void {
    const state: Closed = .{ .buffer = buffer, .index = index };
    try common.wait_until(ctx, 5000, "buffer subscription closed", state, subscription_closed);
}

// A pending floor releases its buffer waiter when a newer floor replaces it, whether or not
// the newer anchor is local, and when its anchor installs through another path.
test "standard pending floor releases buffer waiter" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            var created = try common.HoldingBlockReporter.init_after(gpa, ctx.io(), .zero());
            defer created.started.deinit();
            var buffer = try common.RecordingBuffer.init(gpa, ctx.io());
            defer buffer.deinit();
            var started = try start_holding(
                ctx.child("validator"),
                "pending-floor-releases-waiter",
                &fixture,
                created.reporter,
                buffer.clone(),
                try genesis_start(),
            );
            defer started.crash();

            // The first floor waits on the buffer for its anchor.
            var old: Floor = try floor_at(&fixture, "old-parent", 5);
            defer old.deinit();
            try started.mailbox.set_floor(try old.clone_finalization());
            try wait_subscriptions(ctx, buffer, 1);

            // A newer floor replaces it and releases the first waiter.
            var new: Floor = try floor_at(&fixture, "new-parent", 6);
            defer new.deinit();
            try started.mailbox.set_floor(try new.clone_finalization());
            try wait_closed(ctx, buffer, 0);
            try testing.expectEqual(2, buffer.commitment_subscription_count());
            try testing.expect(!buffer.commitment_subscription_closed(1));

            // A notarization that finds the newer anchor installs the floor and releases the
            // second waiter.
            try buffer.insert(new.block.clone());
            try notarize(&started.mailbox, &fixture, 6, 5, new.block.digest());
            try testing.expectEqual(6, (try created.started.recv()).get());
            try wait_closed(ctx, buffer, 1);

            // A third floor waits on the buffer for its anchor.
            var missing: Floor = try floor_at(&fixture, "missing-parent", 7);
            defer missing.deinit();
            try started.mailbox.set_floor(try missing.clone_finalization());
            try wait_subscriptions(ctx, buffer, 3);

            // A newer floor whose anchor is local replaces it without subscribing and
            // releases the third waiter.
            var local: Floor = try floor_at(&fixture, "local-parent", 8);
            defer local.deinit();
            try buffer.insert(local.block.clone());
            try started.mailbox.set_floor(try local.clone_finalization());
            try wait_closed(ctx, buffer, 2);
            try testing.expectEqual(3, buffer.commitment_subscription_count());
        }
    }.body);
}

/// The digest of `block_at(parent, height, timestamp)`.
fn block_digest(parent: D, height: u64, timestamp: u64) !D {
    var block = try block_at(parent, height, timestamp);
    defer block.deinit();
    return block.digest();
}

/// Verifies and finalizes block 2 on `parent`, then checks its finalization is stored.
fn finalize_block_two(started: *Manual, fixture: *const harness.Fixture, parent: D) !void {
    var block = try block_at(parent, 2, 200);
    defer block.deinit();
    try testing.expect(try started.mailbox.verified(round_at(2), block.clone()));
    report(&started.mailbox, try finalize(fixture, 2, 1, &block));
    var stored = (try started.mailbox.get_finalization(.new(2))).?;
    stored.deinit(gpa);
}

fn expect_pending(application: App, height: u64) !void {
    try testing.expect(pending_is(.{ .application = application, .height = height }));
}

/// The quorum finalization of `digest` at view 5 over view 4.
fn floor_over(fixture: *const harness.Fixture, digest: D) !harness.Finalization {
    const proposal = harness.Proposal.init(round_at(5), .new(4), digest);
    return harness.make_finalization(gpa, fixture, proposal, harness.quorum);
}

fn genesis_digest() !D {
    var genesis = try H.genesis_block(gpa, harness.num_validators);
    defer genesis.deinit();
    return genesis.digest();
}

/// Releases the ack at `height` and waits until the actor processes it.
fn acknowledge_processed(ctx: Ctx, started: *Manual, application: App, height: u64) !void {
    const state: Retains = .{
        .resolver = started.resolver,
        .at_least = started.resolver.retain_count() + 1,
    };
    try testing.expectEqual(height, application.acknowledge_next().?.get());
    try common.wait_until(ctx, 5000, "ack processed", state, retained);
}

test "standard pending floor drops in-flight ack before anchor" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            var application = try App.manual_ack(gpa, ctx.io());
            defer application.deinit();
            var started = try start_manual(
                ctx.child("validator"),
                "pending-floor-drops-in-flight-ack",
                &fixture,
                application.clone(),
                try common.RecordingBuffer.init(gpa, ctx.io()),
            );
            defer started.crash();
            try testing.expectEqual(0, (try application.acknowledged()).get());
            const parent = hash("block1-parent");
            try dispatch_block_one(ctx, &started, &fixture, application, parent);

            // Keep the anchor missing so the floor waits on a fetch while the height 1 ack
            // is in flight.
            var floor_block = try block_at(hash("stale-floor"), 0, 500);
            defer floor_block.deinit();
            try started.mailbox.set_floor(try finalize(&fixture, 5, 4, &floor_block));
            try wait_block_fetch(ctx, started.resolver, floor_block.digest());

            // The successor finalizes but does not dispatch until the anchor is installed.
            try finalize_block_two(&started, &fixture, try block_digest(parent, 1, 100));
            try ctx.sleep(.fromMilliseconds(100));
            try expect_pending(application, 1);

            // The pending floor removed this ack from the active waiters.
            try testing.expectEqual(1, application.acknowledge_next().?.get());
            try ctx.sleep(.fromMilliseconds(100));

            // Once the anchor arrives, dispatch restarts at the floor successor instead of
            // treating the stale ack as progress.
            try testing.expect(try started.mailbox.verified(round_at(5), floor_block.clone()));
            try testing.expectEqual(1, (try application.acknowledged()).get());
            try testing.expectEqual(2, (try application.acknowledged()).get());
        }
    }.body);
}

test "standard local floor below in-flight keeps pending ack" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            var application = try App.manual_ack(gpa, ctx.io());
            defer application.deinit();
            var started = try start_manual(
                ctx.child("validator"),
                "local-floor-below-in-flight-keeps-pending-ack",
                &fixture,
                application.clone(),
                try common.RecordingBuffer.init(gpa, ctx.io()),
            );
            defer started.crash();
            try testing.expectEqual(0, (try application.acknowledged()).get());
            const genesis = try genesis_digest();
            try dispatch_block_one(ctx, &started, &fixture, application, genesis);

            // The genesis anchor is local and below the in-flight height 1 ack, so applying
            // it must not clear or duplicate the pending ack.
            try started.mailbox.set_floor(try floor_over(&fixture, genesis));
            var stored = (try started.mailbox.get_block(.{ .height = .zero() })).?;
            stored.deinit();
            try expect_pending(application, 1);

            try acknowledge_processed(ctx, &started, application, 1);
            const heights = try application.pending_ack_heights(gpa);
            defer gpa.free(heights);
            try testing.expectEqual(0, heights.len);
        }
    }.body);
}

const RoundFetch = struct { resolver: common.RecordingResolver, round: Round, active: bool };

/// Whether a notarized fetch for `round` is active (`active`) or none is (`!active`).
fn round_fetch_is(state: RoundFetch) bool {
    const fetches = state.resolver.active_fetches(gpa) catch return false;
    defer gpa.free(fetches);
    const key: common.Key = .{ .notarized = state.round };
    const found = for (fetches) |fetch| {
        if (fetch.key.eql(key)) break true;
    } else false;
    return found == state.active;
}

fn wait_round_fetch(
    ctx: Ctx,
    resolver: common.RecordingResolver,
    round: Round,
    active: bool,
) !void {
    const state: RoundFetch = .{ .resolver = resolver, .round = round, .active = active };
    try common.wait_until(ctx, 5000, "round-bound fetch", state, round_fetch_is);
}

test "standard set floor below processed height preserves in-flight ack" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            var application = try App.manual_ack(gpa, ctx.io());
            defer application.deinit();
            var started = try start_manual(
                ctx.child("validator"),
                "set-floor-below-processed-height-preserves-in-flight-ack",
                &fixture,
                application.clone(),
                try common.RecordingBuffer.init(gpa, ctx.io()),
            );
            defer started.crash();
            try testing.expectEqual(0, (try application.acknowledged()).get());
            const genesis = try genesis_digest();
            try dispatch_block_one(ctx, &started, &fixture, application, genesis);
            try acknowledge_processed(ctx, &started, application, 1);
            try finalize_block_two(&started, &fixture, try block_digest(genesis, 1, 100));
            const state: Pending = .{ .application = application, .height = 2 };
            try common.wait_until(ctx, 5000, "second block dispatch", state, pending_is);

            // Keep a round-bound request live so the stale floor's round-floor side effect is
            // covered separately from ack handling.
            const stale_round = round_at(5);
            var subscription = try started.mailbox.subscribe_by_commitment(
                hash("missing-before-stale-lower-floor"),
                .{ .fetch_by_round = stale_round },
            );
            defer subscription.deinit();
            try wait_round_fetch(ctx, started.resolver, stale_round, true);

            // This lower local anchor is behind the processed height. It may advance the
            // round floor, but must leave height 2 in flight.
            try started.mailbox.set_floor(try floor_over(&fixture, genesis));
            var stored = (try started.mailbox.get_block(.{ .height = .zero() })).?;
            stored.deinit();
            try expect_pending(application, 2);
            try wait_round_fetch(ctx, started.resolver, stale_round, false);
        }
    }.body);
}

const Processed = @import("../../core/floor.zig").Processed;

/// Polls until the processed position is the stored block at `height`.
fn wait_processed_block(ctx: Ctx, mailbox: anytype, height: u64) !void {
    var waited_ms: u64 = 0;
    while (true) : (waited_ms += 10) {
        const processed = try mailbox.get_processed();
        if (processed != null and std.meta.eql(processed.?, Processed{ .block = .new(height) })) {
            return;
        }
        if (waited_ms > 5000) return error.WaitTimedOut;
        try ctx.sleep(.fromMilliseconds(10));
    }
}

test "standard floor with stored predecessor reports block" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            var application = try App.manual_ack(gpa, ctx.io());
            defer application.deinit();
            var started = try start_manual(
                ctx.child("validator"),
                "floor-stored-predecessor",
                &fixture,
                application.clone(),
                try common.RecordingBuffer.init(gpa, ctx.io()),
            );
            defer started.crash();
            try testing.expectEqual(0, (try application.acknowledged()).get());

            // Finalize and acknowledge block 1.
            var block1 = try block_at(hash("block1-parent"), 1, 100);
            defer block1.deinit();
            try testing.expect(try started.mailbox.verified(round_at(1), block1.clone()));
            report(&started.mailbox, try finalize(&fixture, 1, 0, &block1));
            try testing.expectEqual(1, (try application.acknowledged()).get());
            try wait_processed_block(ctx, &started.mailbox, 1);

            // Install a floor at block 2. Block 1 stays stored, so marshal reports it as the
            // processed block while block 2 awaits acknowledgement.
            var block2 = try block_at(block1.digest(), 2, 200);
            defer block2.deinit();
            try testing.expect(try started.mailbox.verified(round_at(2), block2.clone()));
            try started.mailbox.set_floor(try finalize(&fixture, 2, 1, &block2));
            const state: Pending = .{ .application = application, .height = 2 };
            try common.wait_until(ctx, 5000, "floor block dispatch", state, pending_is);
            const processed = (try started.mailbox.get_processed()).?;
            try testing.expectEqual(Processed{ .block = .new(1) }, processed);
            var anchor = (try started.mailbox.get_anchor()).?;
            defer anchor.block.deinit();
            try testing.expectEqual(Processed{ .block = .new(1) }, anchor.processed);
            try testing.expect(anchor.block.digest().eql(block1.digest()));
        }
    }.body);
}

test "standard same-height floor anchor keeps pending ack" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            var application = try App.manual_ack(gpa, ctx.io());
            defer application.deinit();
            var started = try start_manual(
                ctx.child("validator"),
                "same-height-floor-keeps-pending-ack",
                &fixture,
                application.clone(),
                try common.RecordingBuffer.init(gpa, ctx.io()),
            );
            defer started.crash();
            try testing.expectEqual(0, (try application.acknowledged()).get());
            const parent = hash("block1-parent");
            try dispatch_block_one(ctx, &started, &fixture, application, parent);
            try acknowledge_processed(ctx, &started, application, 1);
            const block1 = try block_digest(parent, 1, 100);
            try finalize_block_two(&started, &fixture, block1);
            const state: Pending = .{ .application = application, .height = 2 };
            try common.wait_until(ctx, 5000, "second block dispatch", state, pending_is);

            // A floor anchored at the processed height 1 must not clear or duplicate the
            // in-flight height 2 ack.
            const proposal = harness.Proposal.init(round_at(5), .zero(), block1);
            const floor = try harness.make_finalization(gpa, &fixture, proposal, harness.quorum);
            try started.mailbox.set_floor(floor);
            var stored = (try started.mailbox.get_block(.{ .height = .new(1) })).?;
            stored.deinit();
            try expect_pending(application, 2);
        }
    }.body);
}

test "standard stale floor anchor advances round floor" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            var application = try App.manual_ack(gpa, ctx.io());
            defer application.deinit();
            var started = try start_manual(
                ctx.child("validator"),
                "stale-floor-anchor-round-floor",
                &fixture,
                application.clone(),
                try common.RecordingBuffer.init(gpa, ctx.io()),
            );
            defer started.crash();
            try testing.expectEqual(0, (try application.acknowledged()).get());
            var block = try block_at(hash("processed-parent"), 1, 100);
            defer block.deinit();
            try testing.expect(try started.mailbox.verified(round_at(1), block.clone()));
            report(&started.mailbox, try finalize(&fixture, 1, 0, &block));
            try testing.expectEqual(1, (try application.acknowledged()).get());

            const floor_round = round_at(5);
            var subscription = try started.mailbox.subscribe_by_commitment(
                hash("missing-before-stale-floor"),
                .{ .fetch_by_round = floor_round },
            );
            defer subscription.deinit();
            try wait_round_fetch(ctx, started.resolver, floor_round, true);

            const proposal = harness.Proposal.init(floor_round, .zero(), block.digest());
            const stale = try harness.make_finalization(gpa, &fixture, proposal, harness.quorum);
            try started.mailbox.set_floor(stale);
            try wait_round_fetch(ctx, started.resolver, floor_round, false);

            // The stale anchor's round floor applies to later fetches: a hint at the floor
            // round fetches nothing, which the barrier request orders after the hint.
            const fetches_before = started.resolver.fetch_count();
            try started.mailbox.hint_notarized(floor_round, hash("missing-after-stale-floor"));
            var barrier = try block_at(block.digest(), 2, 200);
            defer barrier.deinit();
            try testing.expect(try started.mailbox.verified(round_at(2), barrier.clone()));
            try testing.expectEqual(fetches_before, started.resolver.fetch_count());
        }
    }.body);
}

const FetchCount = struct { resolver: common.RecordingResolver };

fn any_fetch(state: FetchCount) bool {
    return state.resolver.fetch_count() > 0;
}

test "standard floor anchor uses parent digest as commitment" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            var application = try App.manual_ack(gpa, ctx.io());
            defer application.deinit();
            var started = try start_manual(
                ctx.child("validator"),
                "standard-floor-parent-digest-commitment",
                &fixture,
                application.clone(),
                try common.RecordingBuffer.init(gpa, ctx.io()),
            );
            defer started.crash();
            const me = fixture.participants[0];
            const genesis_parent = H.genesis_parent_commitment(harness.num_validators);
            const parent_context: harness.Ctx = .{
                .round = round_at(1),
                .leader = me,
                .parent = .{ .zero(), genesis_parent },
            };
            const parent = try harness.B.init(gpa, parent_context, hash(""), .new(1), 100);
            const bad_context: harness.Ctx = .{
                .round = round_at(2),
                .leader = me,
                .parent = .{ .new(1), genesis_parent },
            };
            const floor_block = try harness.B.init(gpa, bad_context, parent.digest(), .new(2), 200);
            try testing.expect(!floor_block.parent().eql(floor_block.context_value.parent[1]));

            // Standard commitments are digests, so the floor-anchor parent check uses the
            // block's parent digest. The standard verification wrappers reject context-parent
            // mismatches.
            const proposal = harness.Proposal.init(round_at(2), .new(1), floor_block.digest());
            const floor = try harness.make_finalization(gpa, &fixture, proposal, harness.quorum);
            const encoded = try @import("codec").encode(harness.B, gpa, floor_block);
            defer gpa.free(encoded);
            try started.resolver.respond_to_next_fetch(encoded);
            try started.mailbox.set_floor(floor);
            const state: FetchCount = .{ .resolver = started.resolver };
            try common.wait_until(ctx, 5000, "floor block fetch", state, any_fetch);
            try testing.expect(try started.resolver.wait_for_delivery_response());

            var stored = (try started.mailbox.get_block(.{ .height = .new(2) })).?;
            stored.deinit();
            var finalization = (try started.mailbox.get_finalization(.new(2))).?;
            finalization.deinit(gpa);
        }
    }.body);
}

const certificate = @import("cryptography").certificate;

/// A provider whose scopes verify but cannot sign (commonware `VerifierProvider`).
const VerifierProvider = struct {
    inner: *const harness.S,

    pub fn scoped(self: VerifierProvider, scope: anytype) ?certificate.Scoped(harness.S) {
        _ = scope;
        return certificate.Scoped(harness.S).verifier(self.inner);
    }

    pub fn scheme(self: VerifierProvider, scope: anytype) ?*const harness.S {
        const handle = self.scoped(scope) orelse return null;
        return handle.into_scheme();
    }
};

/// The concatenated encodings of `first` and `second` (a Rust tuple's encoding).
fn encode_pair(first: anytype, second: anytype) ![]u8 {
    const codec = @import("codec");
    const a = try codec.encode(@TypeOf(first), gpa, first);
    defer gpa.free(a);
    const b = try codec.encode(@TypeOf(second), gpa, second);
    defer gpa.free(b);
    return std.mem.concat(gpa, u8, &.{ a, b });
}

/// Delivers `value` (borrowed) for `key` to one `subscriber` and returns marshal's outcome.
fn deliver(
    resolver: common.RecordingResolver,
    key: common.Key,
    subscriber: common.Annotation,
    value: []const u8,
) !common.Outcome {
    var handler = resolver.handler_clone();
    defer handler.deinit();
    const subscribers = [_]common.Annotation{subscriber};
    var response = try handler.deliver(.{ .key = key, .subscribers = &subscribers }, value);
    defer response.deinit();
    return response.recv();
}

/// The quorum notarization of `block` at `round` over view 0.
fn notarization_of(
    fixture: *const harness.Fixture,
    round: Round,
    block: *const harness.B,
) !harness.Notarization {
    const proposal = harness.Proposal.init(round, .zero(), block.digest());
    return harness.make_notarization(gpa, fixture, proposal, harness.quorum);
}

const RoundRequest = struct { resolver: common.RecordingResolver, round: Round };

/// Whether a notarized fetch for `round` with a notarization subscriber was recorded.
fn round_requested(state: RoundRequest) bool {
    const fetches = state.resolver.fetches(gpa) catch return false;
    defer gpa.free(fetches);
    const key: common.Key = .{ .notarized = state.round };
    const subscriber: common.Annotation = .{ .notarization = state.round };
    for (fetches) |fetch| {
        if (fetch.key.eql(key) and fetch.subscriber.eql(subscriber)) return true;
    }
    return false;
}

test "standard notarized delivery wakes fetch-by-round subscriber" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            const round = round_at(1);
            var block = try harness.make_raw_block(gpa, hash(""), .new(1), 100);
            var notarization = try notarization_of(&fixture, round, &block);
            defer notarization.deinit(gpa);
            var application = try App.manual_ack(gpa, ctx.io());
            defer application.deinit();
            var started = try start_manual(
                ctx.child("validator"),
                "notarized-delivery-wakes-subscriber",
                &fixture,
                application.clone(),
                try common.RecordingBuffer.init(gpa, ctx.io()),
            );
            defer started.crash();
            var subscription = try started.mailbox.subscribe_by_commitment(
                notarization.proposal.payload,
                .{ .fetch_by_round = round },
            );
            defer subscription.deinit();
            const state: RoundRequest = .{ .resolver = started.resolver, .round = round };
            try common.wait_until(ctx, 5000, "fetch-by-round request", state, round_requested);

            const value = try encode_pair(notarization, block);
            defer gpa.free(value);
            const outcome = try deliver(
                started.resolver,
                .{ .notarized = round },
                .{ .notarization = round },
                value,
            );
            try testing.expectEqual(common.Outcome{ .resolved = .complete }, outcome);
            var delivered = try subscription.recv();
            defer delivered.deinit();
            try testing.expect(delivered.digest().eql(block.digest()));
        }
    }.body);
}

test "standard notarized delivery rejects wrong round" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            const requested: Round = .new(.new(1), .new(1));
            const block = try harness.make_raw_block(gpa, hash(""), .new(1), 100);
            var notarization = try notarization_of(&fixture, round_at(1), &block);
            defer notarization.deinit(gpa);
            var application = try App.manual_ack(gpa, ctx.io());
            defer application.deinit();
            var started = try start_manual(
                ctx.child("validator"),
                "notarized-delivery-wrong-round",
                &fixture,
                application.clone(),
                try common.RecordingBuffer.init(gpa, ctx.io()),
            );
            defer started.crash();
            const value = try encode_pair(notarization, block);
            defer gpa.free(value);
            const outcome = try deliver(
                started.resolver,
                .{ .notarized = requested },
                .{ .notarization = requested },
                value,
            );
            try testing.expectEqual(common.Outcome.invalid, outcome);
        }
    }.body);
}

const Verifying = common.Started(VerifierProvider, App, common.RecordingBuffer);

fn start_verifying(
    ctx: Ctx,
    prefix: []const u8,
    fixture: *const harness.Fixture,
    application: App,
) !Verifying {
    return common.start_standard_actor(
        VerifierProvider,
        App,
        common.RecordingBuffer,
        ctx,
        prefix,
        .{ .inner = &fixture.schemes[0] },
        application,
        try common.RecordingBuffer.init(gpa, ctx.io()),
        try genesis_start(),
    );
}

// Without the epoch's full scheme a notarized delivery cannot be validated, so marshal
// retires the key without decoding and without crediting or blaming the peer.
test "standard notarized delivery ignored without full scheme" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            var application = try App.manual_ack(gpa, ctx.io());
            defer application.deinit();
            var started = try start_verifying(
                ctx.child("validator"),
                "notarized-delivery-stale-certificate-only",
                &fixture,
                application.clone(),
            );
            defer started.crash();
            // Undecodable bytes are not attributed to the peer either: nothing can be checked.
            const round = round_at(1);
            const outcome = try deliver(
                started.resolver,
                .{ .notarized = round },
                .{ .notarization = round },
                "unverifiable",
            );
            try testing.expectEqual(common.Outcome.ignored, outcome);
        }
    }.body);
}

/// Delivers `value` (borrowed) for the finalized height 1 to a by-height subscriber.
fn deliver_finalized(resolver: common.RecordingResolver, value: []const u8) !common.Outcome {
    const subscriber: common.Annotation = .{ .finalized = .{ .by_height = .new(1) } };
    return deliver(resolver, .{ .finalized = .new(1) }, subscriber, value);
}

const VerifyOnly = struct {
    const prefix = "finalized-delivery-verify-only";
    fixture: harness.Fixture,
    block: harness.B,
    finalization: harness.Finalization,

    fn deliver_and_stop(ctx: Ctx, self: *const VerifyOnly) anyerror!void {
        var application = try App.manual_ack(gpa, ctx.io());
        defer application.deinit();
        var started = try start_verifying(
            ctx.child("validator"),
            prefix,
            &self.fixture,
            application.clone(),
        );
        defer started.crash();
        const value = try encode_pair(self.finalization, self.block);
        defer gpa.free(value);
        const outcome = try deliver_finalized(started.resolver, value);
        try testing.expectEqual(common.Outcome{ .resolved = .complete }, outcome);
        try testing.expectEqual(0, (try application.acknowledged()).get());
        try testing.expectEqual(1, (try application.acknowledged()).get());
        const entries = try application.blocks(gpa);
        defer App.free_blocks(gpa, entries);
        const last = entries[entries.len - 1];
        try testing.expectEqual(1, last.height.get());
        try testing.expect(last.block.digest().eql(self.block.digest()));
    }

    fn recover(ctx: Ctx, self: *const VerifyOnly) anyerror!void {
        var application = try App.init(gpa, ctx.io());
        defer application.deinit();
        var started = try start_verifying(
            ctx.child("recovered"),
            prefix,
            &self.fixture,
            application.clone(),
        );
        defer started.crash();
        var block = (try started.mailbox.get_block(.{ .height = .new(1) })).?;
        defer block.deinit();
        try testing.expect(block.digest().eql(self.block.digest()));
        var finalization = (try started.mailbox.get_finalization(.new(1))).?;
        defer finalization.deinit(gpa);
        try testing.expect(std.meta.eql(finalization.proposal, self.finalization.proposal));
    }
};

// A finalization verified through a verify-only scope is accepted and durable.
test "standard finalized delivery verifies with verify-only scope" {
    var rng = utils.rng.test_rng();
    var state: VerifyOnly = undefined;
    state.fixture = try harness.fixture(gpa, &rng);
    defer state.fixture.deinit(gpa);
    state.block = try harness.make_raw_block(gpa, hash(""), .new(1), 100);
    const proposal = harness.Proposal.init(round_at(1), .zero(), state.block.digest());
    const quorum = harness.quorum;
    state.finalization = try harness.make_finalization(gpa, &state.fixture, proposal, quorum);
    defer state.finalization.deinit(gpa);

    var runner = try runtime.deterministic.Runner.init(gpa, timed);
    defer runner.deinit();
    try try runner.start_context(VerifyOnly.deliver_and_stop, .{&state});
    // A second start on the same runner recovers its storage (commonware's `Checkpoint`).
    try try runner.start_context(VerifyOnly.recover, .{&state});
}

// A valid certificate only authorizes the bytes whose digest it commits to.
test "standard finalized delivery rejects different block bytes" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            const genesis = try genesis_digest();
            const block = try harness.make_raw_block(gpa, genesis, .new(1), 100);
            const other = try harness.make_raw_block(gpa, genesis, .new(1), 200);
            try testing.expect(!block.digest().eql(other.digest()));
            const proposal = harness.Proposal.init(round_at(1), .zero(), block.digest());
            const quorum = harness.quorum;
            var finalization = try harness.make_finalization(gpa, &fixture, proposal, quorum);
            defer finalization.deinit(gpa);
            var application = try App.manual_ack(gpa, ctx.io());
            defer application.deinit();
            var started = try start_manual(
                ctx.child("validator"),
                "finalized-delivery-different-bytes",
                &fixture,
                application.clone(),
                try common.RecordingBuffer.init(gpa, ctx.io()),
            );
            defer started.crash();
            try testing.expectEqual(0, (try application.acknowledged()).get());
            var subscriber = try started.mailbox.subscribe_by_digest(block.digest(), .wait);
            defer subscriber.deinit();
            var other_subscriber = try started.mailbox.subscribe_by_digest(other.digest(), .wait);
            defer other_subscriber.deinit();

            const wrong = try encode_pair(finalization, other);
            defer gpa.free(wrong);
            const rejected = try deliver_finalized(started.resolver, wrong);
            try testing.expectEqual(common.Outcome.invalid, rejected);
            const mailbox = &started.mailbox;
            try testing.expect(try mailbox.get_block(.{ .height = .new(1) }) == null);
            try testing.expect(try mailbox.get_block(.{ .digest = block.digest() }) == null);
            try testing.expect(try mailbox.get_block(.{ .digest = other.digest() }) == null);
            try testing.expect(try mailbox.get_finalization(.new(1)) == null);
            try testing.expect(application.tip() == null);
            try testing.expectError(error.Empty, subscriber.try_recv());
            try testing.expectError(error.Empty, other_subscriber.try_recv());

            // The same certificate accepts its own block, isolating the rejected byte binding.
            const right = try encode_pair(finalization, block);
            defer gpa.free(right);
            const accepted = try deliver_finalized(started.resolver, right);
            try testing.expectEqual(common.Outcome{ .resolved = .complete }, accepted);
            var delivered = try subscriber.recv();
            defer delivered.deinit();
            try testing.expect(delivered.digest().eql(block.digest()));
            try testing.expectEqual(1, (try application.acknowledged()).get());
            try testing.expectError(error.Empty, other_subscriber.try_recv());
        }
    }.body);
}

/// A signing provider whose scopes each survive a fixed number of lookups and then retire,
/// modeling an application that prunes an epoch between a delivery's admission and its
/// batched verification (commonware `RetiringProvider`). Copies share `scopes`.
const RetiringProvider = struct {
    const Scope = struct {
        epoch: u64,
        scheme: *const harness.S,
        remaining: std.atomic.Value(usize),
    };

    scopes: []Scope,

    pub fn scoped(self: RetiringProvider, epoch: types.Epoch) ?certificate.Scoped(harness.S) {
        const scope = for (self.scopes) |*item| {
            if (item.epoch == epoch.get()) break item;
        } else return null;
        const counter = &scope.remaining;
        var remaining = counter.load(.acquire);
        while (remaining > 0) {
            remaining = counter.cmpxchgWeak(remaining, remaining - 1, .acq_rel, .acquire) orelse
                return certificate.Scoped(harness.S).scheme(scope.scheme);
        }
        return null;
    }

    pub fn scheme(self: RetiringProvider, epoch: types.Epoch) ?*const harness.S {
        const handle = self.scoped(epoch) orelse return null;
        return handle.into_scheme();
    }

    /// Whether `epoch` was looked up as many times as allowed, which confirms the admission
    /// path consulted the provider.
    fn retired(self: RetiringProvider, epoch: u64) bool {
        for (self.scopes) |*item| {
            if (item.epoch == epoch) return item.remaining.load(.acquire) == 0;
        }
        unreachable;
    }
};

const Retiring = common.Started(RetiringProvider, App, common.RecordingBuffer);

fn start_retiring(
    ctx: Ctx,
    prefix: []const u8,
    provider: RetiringProvider,
    application: App,
) !Retiring {
    return common.start_standard_actor(
        RetiringProvider,
        App,
        common.RecordingBuffer,
        ctx,
        prefix,
        provider,
        application,
        try common.RecordingBuffer.init(gpa, ctx.io()),
        try genesis_start(),
    );
}

/// A finalized delivery at height 1 of a block over `hash("")`, finalized by `signers` at
/// `round`, with the block it carries.
const FinalizedDelivery = struct {
    block: harness.B,
    finalization: harness.Finalization,

    fn init(signers: *const harness.Fixture, round: Round) !FinalizedDelivery {
        const block = try harness.make_raw_block(gpa, hash(""), .new(1), 100);
        const proposal = harness.Proposal.init(round, .zero(), block.digest());
        const quorum = harness.quorum;
        const finalization = try harness.make_finalization(gpa, signers, proposal, quorum);
        return .{ .block = block, .finalization = finalization };
    }

    fn deinit(self: *FinalizedDelivery) void {
        self.finalization.deinit(gpa);
    }

    fn send(self: *const FinalizedDelivery, resolver: common.RecordingResolver) !common.Outcome {
        const value = try encode_pair(self.finalization, self.block);
        defer gpa.free(value);
        return deliver_finalized(resolver, value);
    }
};

test "standard finalized delivery rejects epoch mismatch" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            // Height 1 lives in epoch 0, but the finalization claims epoch 1. It decodes
            // against epoch 0's config, so the epoch guard rejects it and blames the peer
            // before any verification.
            var delivery: FinalizedDelivery = try .init(&fixture, .new(.new(1), .new(1)));
            defer delivery.deinit();
            var application = try App.manual_ack(gpa, ctx.io());
            defer application.deinit();
            var started = try start_verifying(
                ctx.child("validator"),
                "finalized-delivery-epoch-mismatch",
                &fixture,
                application.clone(),
            );
            defer started.crash();
            try testing.expectEqual(common.Outcome.invalid, try delivery.send(started.resolver));
        }
    }.body);
}

fn one_scope(scheme: *const harness.S, remaining: usize) [1]RetiringProvider.Scope {
    return .{.{ .epoch = 0, .scheme = scheme, .remaining = .init(remaining) }};
}

test "standard finalized delivery verifies after scope retires" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            var delivery: FinalizedDelivery = try .init(&fixture, round_at(1));
            defer delivery.deinit();
            var application = try App.manual_ack(gpa, ctx.io());
            defer application.deinit();
            // The scope survives exactly the admission lookup, so it is gone by the time the
            // batched verification runs.
            var scopes = one_scope(&fixture.schemes[0], 1);
            const provider: RetiringProvider = .{ .scopes = &scopes };
            var started = try start_retiring(
                ctx.child("validator"),
                "finalized-delivery-scope-retires",
                provider,
                application.clone(),
            );
            defer started.crash();
            try testing.expect(!provider.retired(0));
            const outcome = try delivery.send(started.resolver);
            try testing.expectEqual(common.Outcome{ .resolved = .complete }, outcome);
            try testing.expect(provider.retired(0));
            try testing.expectEqual(0, (try application.acknowledged()).get());
            try testing.expectEqual(1, (try application.acknowledged()).get());
            const entries = try application.blocks(gpa);
            defer App.free_blocks(gpa, entries);
            const last = entries[entries.len - 1];
            try testing.expectEqual(1, last.height.get());
            try testing.expect(last.block.digest().eql(delivery.block.digest()));
        }
    }.body);
}

test "standard notarized delivery verifies after scope retires" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            const round = round_at(1);
            const block = try harness.make_raw_block(gpa, hash(""), .new(1), 100);
            var notarization = try notarization_of(&fixture, round, &block);
            defer notarization.deinit(gpa);
            var application = try App.manual_ack(gpa, ctx.io());
            defer application.deinit();
            var scopes = one_scope(&fixture.schemes[0], 1);
            const provider: RetiringProvider = .{ .scopes = &scopes };
            var started = try start_retiring(
                ctx.child("validator"),
                "notarized-delivery-scope-retires",
                provider,
                application.clone(),
            );
            defer started.crash();
            try testing.expect(!provider.retired(0));
            const value = try encode_pair(notarization, block);
            defer gpa.free(value);
            const outcome = try deliver(
                started.resolver,
                .{ .notarized = round },
                .{ .notarization = round },
                value,
            );
            try testing.expectEqual(common.Outcome{ .resolved = .complete }, outcome);
            try testing.expect(provider.retired(0));
            // The notarized block verified under the admission scope is cached.
            var cached = (try started.mailbox.get_block(.{ .digest = block.digest() })).?;
            defer cached.deinit();
            try testing.expect(cached.digest().eql(block.digest()));
        }
    }.body);
}

test "standard finalized delivery rejects foreign certificate after scope retires" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            var foreign = try harness.fixture(gpa, &rng);
            defer foreign.deinit(gpa);
            // The certificate decodes under epoch 0's scope but was signed by a committee
            // marshal does not know.
            var delivery: FinalizedDelivery = try .init(&foreign, round_at(1));
            defer delivery.deinit();
            var application = try App.manual_ack(gpa, ctx.io());
            defer application.deinit();
            // Retiring the scope after admission must not turn the rejection into an
            // acceptance: the retained scope still verifies the certificate.
            var scopes = one_scope(&fixture.schemes[0], 1);
            const provider: RetiringProvider = .{ .scopes = &scopes };
            var started = try start_retiring(
                ctx.child("validator"),
                "finalized-delivery-foreign-certificate-scope-retires",
                provider,
                application.clone(),
            );
            defer started.crash();
            try testing.expect(!provider.retired(0));
            try testing.expectEqual(common.Outcome.invalid, try delivery.send(started.resolver));
            try testing.expect(provider.retired(0));
        }
    }.body);
}

/// Finalizes block 1 over `hash("")` at view 1, waits for its ack and the processed-round
/// prune, and returns the block (owned).
fn process_block_one(
    ctx: Ctx,
    started: *Manual,
    fixture: *const harness.Fixture,
    application: App,
) !Block {
    var block = try block_at(hash(""), 1, 100);
    errdefer block.deinit();
    try testing.expect(try started.mailbox.verified(round_at(1), block.clone()));
    report(&started.mailbox, try finalize(fixture, 1, 0, &block));
    const state: Retains = .{
        .resolver = started.resolver,
        .at_least = started.resolver.retain_count() + 2,
    };
    try testing.expectEqual(1, (try application.acknowledged()).get());
    try common.wait_until(ctx, 5000, "processed-round pruning", state, retained);
    return block;
}

/// Verifies block 2 on `parent`, which orders the actor's handling of earlier messages.
fn verify_barrier(started: *Manual, parent: D) !void {
    var block = try block_at(parent, 2, 200);
    defer block.deinit();
    try testing.expect(try started.mailbox.verified(round_at(2), block.clone()));
}

test "standard processed round skips fetch and preserves subscription" {
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
                "fetch-notarized-processed-round",
                &fixture,
                application.clone(),
                buffer.clone(),
            );
            defer started.crash();
            try testing.expectEqual(0, (try application.acknowledged()).get());
            var block = try process_block_one(ctx, &started, &fixture, application);
            defer block.deinit();

            const fetches_before = started.resolver.fetch_count();
            const round = round_at(1);
            try started.mailbox.hint_notarized(round, hash("missing-at-processed-round"));
            var missing = try block_at(hash(""), 1, 101);
            defer missing.deinit();
            var subscription = try started.mailbox.subscribe_by_commitment(
                missing.digest(),
                .{ .fetch_by_round = round },
            );
            defer subscription.deinit();
            try verify_barrier(&started, block.digest());
            // The hint must not enqueue the already-pruned processed round.
            try testing.expectEqual(fetches_before, started.resolver.fetch_count());
            try testing.expectError(error.Empty, subscription.try_recv());

            const last = buffer.commitment_subscription_count() - 1;
            try testing.expect(buffer.deliver_commitment_subscription(last, missing.clone()));
            var delivered = try subscription.recv();
            defer delivered.deinit();
            try testing.expect(delivered.digest().eql(missing.digest()));
        }
    }.body);
}

test "standard finalization rejects processed round block fetch" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            var application = try App.manual_ack(gpa, ctx.io());
            defer application.deinit();
            var started = try start_manual(
                ctx.child("validator"),
                "finalization-processed-round-fetch",
                &fixture,
                application.clone(),
                try common.RecordingBuffer.init(gpa, ctx.io()),
            );
            defer started.crash();
            try testing.expectEqual(0, (try application.acknowledged()).get());
            var block = try process_block_one(ctx, &started, &fixture, application);
            defer block.deinit();

            const fetches_before = started.resolver.fetch_count();
            const digest = hash("missing-finalized-at-processed-round");
            const proposal = harness.Proposal.init(round_at(1), .zero(), digest);
            const quorum = harness.quorum;
            const stale = try harness.make_finalization(gpa, &fixture, proposal, quorum);
            report(&started.mailbox, stale);
            try verify_barrier(&started, block.digest());
            // The stale finalization must not enqueue a round-bound block fetch.
            try testing.expectEqual(fetches_before, started.resolver.fetch_count());
        }
    }.body);
}

const seed = @import("seed.zig");

/// Subscribes to `missing` by round 1, verifies the barrier on `parent`, and checks no fetch
/// was enqueued, then delivers `missing` through the buffer and checks the subscription
/// resolves: restored progress controls network acquisition, while local ingress stays a
/// valid source.
fn expect_round_floor_restored(
    started: *Manual,
    buffer: common.RecordingBuffer,
    parent: D,
    missing: *const Block,
) !void {
    const fetches_before = started.resolver.fetch_count();
    var subscription = try started.mailbox.subscribe_by_commitment(
        missing.digest(),
        .{ .fetch_by_round = round_at(1) },
    );
    defer subscription.deinit();
    try verify_barrier(started, parent);
    try testing.expectEqual(fetches_before, started.resolver.fetch_count());
    try testing.expectError(error.Empty, subscription.try_recv());
    const last = buffer.commitment_subscription_count() - 1;
    try testing.expect(buffer.deliver_commitment_subscription(last, missing.clone()));
    var delivered = try subscription.recv();
    defer delivered.deinit();
    try testing.expect(delivered.digest().eql(missing.digest()));
}

test "standard processed round restored after restart" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            const prefix = "processed-round-restart";
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            var application = try App.manual_ack(gpa, ctx.io());
            defer application.deinit();
            var started = try start_manual(
                ctx.child("validator"),
                prefix,
                &fixture,
                application.clone(),
                try common.RecordingBuffer.init(gpa, ctx.io()),
            );
            try testing.expectEqual(0, (try application.acknowledged()).get());
            var block = try process_block_one(ctx, &started, &fixture, application);
            defer block.deinit();
            const info = (try started.mailbox.get_info(.latest)).?;
            try testing.expectEqual(1, info.height.get());
            try testing.expect(info.digest.eql(block.digest()));
            started.crash();

            var restarted_app = try App.manual_ack(gpa, ctx.io());
            defer restarted_app.deinit();
            var buffer = try common.RecordingBuffer.init(gpa, ctx.io());
            defer buffer.deinit();
            var restarted = try start_manual(
                ctx.child("validator_restart"),
                prefix,
                &fixture,
                restarted_app.clone(),
                buffer.clone(),
            );
            defer restarted.crash();
            try restarted.mailbox.hint_notarized(round_at(1), hash("missing-after-restart"));
            var missing = try block_at(hash(""), 1, 101);
            defer missing.deinit();
            try expect_round_floor_restored(&restarted, buffer, block.digest(), &missing);
        }
    }.body);
}

test "standard round floor does not restore missing next block" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            const prefix = "round-floor-missing-next-block";
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            const round = round_at(1);
            const block = try harness.make_raw_block(gpa, hash(""), .new(1), 100);
            var notarization = try notarization_of(&fixture, round, &block);
            defer notarization.deinit(gpa);
            const proposal = harness.Proposal.init(round, .zero(), block.digest());
            const quorum = harness.quorum;
            var finalization = try harness.make_finalization(gpa, &fixture, proposal, quorum);
            defer finalization.deinit(gpa);
            try seed.processed_height(ctx.child("metadata"), prefix, .zero(), null);
            const finalized = [_]seed.FinalizationAt{
                .{ .height = .new(1), .finalization = finalization },
            };
            try seed.inconsistent_restart_state(ctx.child("storage"), prefix, &.{}, &finalized);

            var application = try App.manual_ack(gpa, ctx.io());
            defer application.deinit();
            var started = try start_manual(
                ctx.child("validator"),
                prefix,
                &fixture,
                application.clone(),
                try common.RecordingBuffer.init(gpa, ctx.io()),
            );
            defer started.crash();
            var subscription = try started.mailbox.subscribe_by_commitment(
                block.digest(),
                .{ .fetch_by_round = round },
            );
            defer subscription.deinit();
            try ctx.sleep(.fromMilliseconds(100));
            // The missing next block must not advance the restored round floor.
            try testing.expectError(error.Empty, subscription.try_recv());
            const state: RoundRequest = .{ .resolver = started.resolver, .round = round };
            const label = "fetch-by-round after restart";
            try common.wait_until(ctx, 5000, label, state, round_requested);

            const value = try encode_pair(notarization, block);
            defer gpa.free(value);
            const outcome = try deliver(
                started.resolver,
                .{ .notarized = round },
                .{ .notarization = round },
                value,
            );
            try testing.expectEqual(common.Outcome{ .resolved = .complete }, outcome);
            var delivered = try subscription.recv();
            defer delivered.deinit();
            try testing.expect(delivered.digest().eql(block.digest()));
        }
    }.body);
}

test "standard round floor restores unacknowledged anchor" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            const prefix = "round-floor-before-anchor-ack";
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            var floor: Floor = try .init(&fixture, "floor-parent");
            defer floor.deinit();
            var created = try common.HoldingBlockReporter.init_after(gpa, ctx.io(), .zero());
            defer created.started.deinit();
            var started = try start_holding(
                ctx.child("validator"),
                prefix,
                &fixture,
                created.reporter,
                try common.RecordingBuffer.init(gpa, ctx.io()),
                try genesis_start(),
            );
            try testing.expect(try started.mailbox.verified(round_at(5), floor.block.clone()));
            try started.mailbox.set_floor(try floor.clone_finalization());
            // The floor anchor is delivered before the simulated crash.
            try testing.expectEqual(5, (try created.started.recv()).get());
            started.crash();

            var application = try App.manual_ack(gpa, ctx.io());
            defer application.deinit();
            var restarted = try start_manual(
                ctx.child("validator_restart"),
                prefix,
                &fixture,
                application.clone(),
                try common.RecordingBuffer.init(gpa, ctx.io()),
            );
            defer restarted.crash();
            const fetches_before = restarted.resolver.fetch_count();
            var subscription = try restarted.mailbox.subscribe_by_commitment(
                hash("missing-before-anchor-ack"),
                .{ .fetch_by_round = round_at(5) },
            );
            defer subscription.deinit();
            var next = try block_at(floor.block.digest(), 6, 600);
            defer next.deinit();
            try testing.expect(try restarted.mailbox.verified(round_at(6), next.clone()));
            // The durable floor round suppresses round-bound fetches after restart and
            // preserves local subscriptions.
            try testing.expectEqual(fetches_before, restarted.resolver.fetch_count());
            try testing.expectError(error.Empty, subscription.try_recv());
        }
    }.body);
}

test "standard set floor prunes round-bound fetches" {
    try run(struct {
        fn body(ctx: Ctx) anyerror!void {
            var rng = utils.rng.test_rng();
            var fixture = try harness.fixture(gpa, &rng);
            defer fixture.deinit(gpa);
            var application = try App.manual_ack(gpa, ctx.io());
            defer application.deinit();
            var started = try start_manual(
                ctx.child("validator"),
                "set-floor-round-prune",
                &fixture,
                application.clone(),
                try common.RecordingBuffer.init(gpa, ctx.io()),
            );
            defer started.crash();
            const round = round_at(1);
            var block = try block_at(hash(""), 1, 100);
            defer block.deinit();
            var subscription = try started.mailbox.subscribe_by_commitment(
                hash("missing-before-set-floor"),
                .{ .fetch_by_round = round },
            );
            defer subscription.deinit();
            try wait_round_fetch(ctx, started.resolver, round, true);

            // The processed finalization after `set_floor` prunes the round-bound fetch.
            try started.mailbox.set_floor(try finalize(&fixture, 1, 0, &block));
            try testing.expect(try started.mailbox.verified(round, block.clone()));
            try wait_round_fetch(ctx, started.resolver, round, false);

            // The round floor applies to future fetches too.
            const fetches_before = started.resolver.fetch_count();
            try started.mailbox.hint_notarized(round, hash("missing-after-set-floor"));
            try verify_barrier(&started, block.digest());
            try testing.expectEqual(fetches_before, started.resolver.fetch_count());
        }
    }.body);
}
