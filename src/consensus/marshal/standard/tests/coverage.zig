//! The standard actor's prune, pipelined handoff, reproposal coverage across restarts,
//! closed-epoch floors, and cache retention (commonware `standard/mod.rs`, lines
//! 12605-14905).

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const testing = std.testing;
const runtime = @import("runtime");
const utils = @import("utils");
const parallel = @import("parallel");
const types = @import("../../../types.zig");
const harness = @import("../../mocks/harness.zig");
const mocks_block = @import("../../mocks/block.zig");
const common = @import("common.zig");
const seed = @import("seed.zig");
const codec = @import("codec");
const cryptography = @import("cryptography");
const core = @import("../../core/root.zig");
const handler = @import("../../resolver/handler.zig");

const gpa = testing.allocator;
const H = harness.StandardHarness;
const App = @import("../../mocks/application.zig").Application(harness.B);
const Ctx = runtime.deterministic.Context;
const Height = types.Height;
const Round = types.Round;
const B = harness.B;
const Finalization = harness.Finalization;
const Processed = @import("../../core/floor.zig").Processed;

fn run(comptime body: fn (Ctx) anyerror!void) !void {
    try run_timed(body, 30);
}

/// commonware's `Runner::timed(seconds)`.
fn run_timed(comptime body: fn (Ctx) anyerror!void, seconds: u64) !void {
    const config: runtime.deterministic.Config = .{ .timeout_ns = seconds * std.time.ns_per_s };
    var runner = try runtime.deterministic.Runner.init(gpa, config);
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

/// A provider that holds no epochs (commonware `EmptyProvider`).
const EmptyProvider = struct {
    pub fn scoped(_: EmptyProvider, _: anytype) ?cryptography.certificate.Scoped(harness.S) {
        return null;
    }

    pub fn scheme(_: EmptyProvider, _: anytype) ?*const harness.S {
        return null;
    }
};

const Prunable = common.PrunableStores(B);

/// The blocks 1 through 30 chained from genesis, block `h` stamped `100 * h`.
fn make_chain(out: *[30]B) !void {
    var genesis = try H.genesis_block(gpa, harness.num_validators);
    defer genesis.deinit();
    var parent = genesis.digest();
    for (out, 1..) |*block, height| {
        block.* = try harness.make_raw_block(gpa, parent, .new(height), height * 100);
        parent = block.digest();
    }
}

/// `block` wrapped with its digest, owned.
fn ready(block: B) !common.Block {
    return mocks_block.ready(B, gpa, block);
}

/// The finalization of `block` at `view` of `epoch`, over view `view - 1`.
fn finalize_at(fixture: *const harness.Fixture, epoch: u64, view: u64, block: B) !Finalization {
    const proposal = harness.Proposal.init(
        .new(.new(epoch), .new(view)),
        .new(view - 1),
        block.digest(),
    );
    return harness.make_finalization(gpa, fixture, proposal, harness.quorum);
}

/// The encoded `(finalization, block)` a finalized-by-height response carries.
fn finalized_value(finalization: Finalization, block: B) ![]u8 {
    return codec.encode(struct { Finalization, B }, gpa, .{ finalization, block });
}

/// A marshal actor over prunable finalized stores, started from a configured floor
/// (commonware's `Actor::init` with `configured_floor_config` or `reproposal_floor_config`).
fn Running(comptime Prov: type, comptime Buf: type) type {
    return RunningActor(common.Actor(Prov, App, Buf, Prunable.Certificates, Prunable.Blocks));
}

fn RunningActor(comptime Actor: type) type {
    return struct {
        const Self = @This();
        pub const A = Actor;

        stores: *Prunable,
        prefix: []u8,
        mailbox: A.Mailbox,
        resolver: common.RecordingResolver,
        /// The test's handle on the application (the actor holds a clone).
        application: App,
        restored: core.Floor,
        handle: runtime.context.Handle(anyerror!void),

        /// Aborts the actor and releases its storage so a restart can reopen it.
        fn crash(self: *Self) void {
            const ended = self.handle.abort() catch {};
            ended catch {};
            self.mailbox.deinit();
            self.application.deinit();
            self.resolver.deinit();
            self.stores.deinit();
            gpa.destroy(self.stores);
            gpa.free(self.prefix);
            self.* = undefined;
        }

        fn processed(self: *Self) !?Processed {
            return self.mailbox.get_processed();
        }
    };
}

/// Starts an actor under `prefix` from `floor` (owned) with `epoch_length` epochs and
/// `buffer` (owned; null for an unbuffered actor).
fn start_floor(
    comptime Prov: type,
    comptime Buf: type,
    ctx: Ctx,
    prefix: []const u8,
    provider: Prov,
    epoch_length: u64,
    floor: Finalization,
    buffer: ?Buf,
) !Running(Prov, Buf) {
    const A = Running(Prov, Buf).A;
    var start: Finalization = floor;
    errdefer start.deinit(gpa);
    const owned_prefix = try gpa.dupe(u8, prefix);
    errdefer gpa.free(owned_prefix);
    const stores = try gpa.create(Prunable);
    errdefer gpa.destroy(stores);
    try stores.open(ctx, owned_prefix);
    errdefer stores.deinit();
    var config = try common.test_config(A, gpa, owned_prefix, provider, 1, &stores.cache_ref);
    config.start.genesis.deinit();
    config.start = .{ .floor = start };
    config.epocher = .new(utils.NonZero(u64).init(epoch_length).?);
    const initialized = try A.init(ctx, stores.certificates(), stores.blocks_store(), config);
    const application = try App.manual_ack(gpa, ctx.io());
    var holding = try common.RecordingResolver.holding(gpa, ctx.io(), &ctx.scope.child("mailbox"));
    const actor_buffer: Buf = if (Buf == common.Unbuffered) .{ .gpa = gpa } else buffer.?;
    const handle = try initialized.actor.start(
        application.clone(),
        actor_buffer,
        holding.receiver,
        holding.resolver.clone(),
    );
    return .{
        .stores = stores,
        .prefix = owned_prefix,
        .mailbox = initialized.mailbox,
        .resolver = holding.resolver,
        .application = application,
        .restored = initialized.floor,
        .handle = handle,
    };
}

/// A buffer holding blocks 10 through 30 of `blocks`.
fn buffer_from_ten(ctx: Ctx, blocks: *const [30]B) !common.RecordingBuffer {
    var buffer = try common.RecordingBuffer.init(gpa, ctx.io());
    errdefer buffer.deinit();
    for (blocks[9..]) |block| try buffer.insert(try ready(block));
    return buffer;
}

/// Acknowledges heights `first` through `last`, expecting each in order.
fn expect_acks(application: App, first: u64, last: u64) !void {
    for (first..last + 1) |expected| {
        try testing.expectEqual(Height.new(expected), try application.acknowledged());
    }
}

/// Waits until marshal has processed through `height` after the application acknowledged it.
/// commonware's biased `select_loop!` handles a ready ack before a queued `get_processed`;
/// the Zig actor's inbox is FIFO, so the ack can land one scheduler cycle after the query.
fn wait_processed(ctx: Ctx, mailbox: anytype, height: u64) !void {
    const expected: Processed = .{ .block = .new(height) };
    for (0..1000) |_| {
        const current = try mailbox.get_processed();
        if (current != null and std.meta.eql(current.?, expected)) return;
        try ctx.sleep(.fromMilliseconds(1));
    }
    return expect_processed(mailbox, height);
}

fn expect_processed(mailbox: anytype, height: u64) !void {
    try testing.expectEqual(Processed{ .block = .new(height) }, (try mailbox.get_processed()).?);
}

/// Reports `finalization` (borrowed) through the mailbox.
fn report(mailbox: anytype, finalization: Finalization) void {
    _ = mailbox.report(.{ .finalization = finalization });
}

const Constant = Running(harness.Provider, common.RecordingBuffer);
const ConstantUnbuffered = Running(harness.Provider, common.Unbuffered);
const Retired = Running(EmptyProvider, common.Unbuffered);

fn configured_floor_restart_body(ctx: Ctx) anyerror!void {
    const prefix = "prune-configured-floor-restart";
    var rng = utils.rng.test_rng();
    var fixture = try harness.fixture(gpa, &rng);
    defer fixture.deinit(gpa);
    var blocks: [30]B = undefined;
    try make_chain(&blocks);
    const provider: harness.Provider = .init(&fixture.schemes[0]);
    var first = try start_floor(
        harness.Provider,
        common.RecordingBuffer,
        ctx.child("first"),
        prefix,
        provider,
        100,
        try finalize_at(&fixture, 0, 10, blocks[9]),
        try buffer_from_ten(ctx, &blocks),
    );
    try expect_acks(first.application, 10, 10);
    // Heights 11..=29 are repaired from the buffer without certificates.
    var tip = try finalize_at(&fixture, 0, 30, blocks[29]);
    defer tip.deinit(gpa);
    report(&first.mailbox, tip);
    try expect_acks(first.application, 11, 20);
    try wait_processed(ctx, &first.mailbox, 20);
    try first.mailbox.prune(.new(20));
    try testing.expect(!try has_block(&first.mailbox, .new(10)));
    first.crash();

    // Drop the persisted round floor so the restart recovers the floor's round only from the
    // certificate archive.
    try seed.processed_height(ctx.child("metadata"), prefix, .new(20), null);
    var restarted = try start_floor(
        EmptyProvider,
        common.Unbuffered,
        ctx.child("restarted"),
        prefix,
        .{},
        100,
        try finalize_at(&fixture, 0, 10, blocks[9]),
        null,
    );
    defer restarted.crash();
    try expect_acks(restarted.application, 21, 21);
}

test "standard prune keeps round floor evidence for a configured floor restart" {
    try run(configured_floor_restart_body);
}

/// Makes block 10 the last block of epoch zero, so its re-proposals stay in epoch zero and
/// every later block belongs to a later epoch (commonware `REPROPOSAL_EPOCH_LENGTH`).
const reproposal_epoch_length: u64 = 11;

/// A marshal started by `start_reproposal_processed_through_20`.
const Reproposal = struct {
    fixture: harness.Fixture,
    /// Blocks 1 through 30, chained from genesis.
    blocks: [30]B,
    run: Constant,

    fn block(self: *const Reproposal, height: u64) B {
        return self.blocks[height - 1];
    }

    fn provider(self: *const Reproposal) harness.Provider {
        return .init(&self.fixture.schemes[0]);
    }

    /// Finalizes the block at `height` at `view` of the epoch containing the height.
    fn finalize(self: *const Reproposal, height: u64, view: u64) !Finalization {
        return finalize_in_epoch(&self.fixture, &self.blocks, height, view);
    }

    fn deinit(self: *Reproposal) void {
        self.fixture.deinit(gpa);
    }
};

/// Finalizes `blocks[height - 1]` at `view` of the reproposal epoch containing `height`.
fn finalize_in_epoch(
    fixture: *const harness.Fixture,
    blocks: *const [30]B,
    height: u64,
    view: u64,
) !Finalization {
    const epocher: types.FixedEpocher = .new(utils.NonZero(u64).init(reproposal_epoch_length).?);
    const epoch = epocher.containing(.new(height)).?.epoch;
    return finalize_at(fixture, epoch.get(), view, blocks[height - 1]);
}

/// Starts marshal from the first finalization of block 10, at round (0, 10), with a buffer
/// holding blocks 10 through 30. A finalization at height 30 repairs heights 11 through 29 by
/// walking back through the buffer, and the application acknowledges through height 20.
/// Walkback stores no finalizations, so (0, 10) stays the newest archived at or below 20.
fn start_reproposal_processed_through_20(self: *Reproposal, ctx: Ctx, prefix: []const u8) !void {
    var rng = utils.rng.test_rng();
    self.fixture = try harness.fixture(gpa, &rng);
    errdefer self.fixture.deinit(gpa);
    try make_chain(&self.blocks);
    self.run = try start_floor(
        harness.Provider,
        common.RecordingBuffer,
        ctx.child("first"),
        prefix,
        self.provider(),
        reproposal_epoch_length,
        try self.finalize(10, 10),
        try buffer_from_ten(ctx, &self.blocks),
    );
    errdefer self.run.crash();
    try expect_acks(self.run.application, 10, 10);
    var tip = try self.finalize(30, 30);
    defer tip.deinit(gpa);
    report(&self.run.mailbox, tip);
    try expect_acks(self.run.application, 11, 20);
    try wait_processed(ctx, &self.run.mailbox, 20);
}

/// Restarts marshal under `prefix` with `floor` (owned) configured and a provider holding no
/// epochs. The restored round floor must cover the floor's round and dispatch must resume at
/// `next`: verifying the floor would need its retired epoch.
fn restart_with_retired_floor_resumes_at(
    ctx: Ctx,
    prefix: []const u8,
    floor: Finalization,
    next: u64,
) !void {
    const round = floor.round();
    const child = ctx.child("restarted");
    var restarted = try start_floor(
        EmptyProvider,
        common.Unbuffered,
        child,
        prefix,
        .{},
        reproposal_epoch_length,
        floor,
        null,
    );
    defer restarted.crash();
    try testing.expect(restarted.restored.cutoff.covers(round));
    try expect_acks(restarted.application, next, next);
}

/// Expects the application to hold exactly the acknowledgement of `height`.
fn expect_pending_ack(application: App, height: u64) !void {
    const heights = try application.pending_ack_heights(gpa);
    defer gpa.free(heights);
    try testing.expectEqualSlices(Height, &.{.new(height)}, heights);
}

/// Delivers `value` (borrowed) for `key` with one subscriber through the actor's resolver
/// handler, returning the actor's verdict.
fn deliver(
    resolver: common.RecordingResolver,
    key: common.Key,
    subscriber: handler.Annotation,
    value: []const u8,
) !common.Outcome {
    var sender = resolver.handler_clone();
    defer sender.deinit();
    const subscribers = [_]handler.Annotation{subscriber};
    var response = try sender.deliver(.{ .key = key, .subscribers = &subscribers }, value);
    defer response.deinit();
    return response.recv();
}

const complete: common.Outcome = .{ .resolved = .complete };

fn reproposal_floor_below_processed_body(ctx: Ctx) anyerror!void {
    const prefix = "reproposal-floor-prune-restart";
    var state: Reproposal = undefined;
    try start_reproposal_processed_through_20(&state, ctx, prefix);
    defer state.deinit();
    state.run.crash();

    // Restart with the later finalization of block 10. The round floor already covers epoch
    // zero, so the floor is skipped. Pruning below 20 leaves only the (0, 10) finalization.
    const reproposal = try state.finalize(10, 40);
    var again = try start_floor(
        harness.Provider,
        common.Unbuffered,
        ctx.child("reproposal"),
        prefix,
        state.provider(),
        reproposal_epoch_length,
        try reproposal.clone(gpa),
        null,
    );
    try again.mailbox.prune(.new(20));
    try testing.expect(!try has_block(&again.mailbox, .new(10)));
    try expect_processed(&again.mailbox, 20);
    again.crash();

    // Restart again with the same floor and a provider holding no epochs.
    try restart_with_retired_floor_resumes_at(ctx, prefix, reproposal, 21);
}

test "standard reproposal floor below processed is covered after prune restart" {
    try run(reproposal_floor_below_processed_body);
}

fn reproposal_reported_below_processed_body(ctx: Ctx) anyerror!void {
    const prefix = "reproposal-reported-restart-before-ack";
    var state: Reproposal = undefined;
    try start_reproposal_processed_through_20(&state, ctx, prefix);
    defer state.deinit();
    // The archive already holds block 10's (0, 10) finalization, so the report stores
    // nothing. The test stops before the application acknowledges height 21.
    var reproposal = try state.finalize(10, 40);
    errdefer reproposal.deinit(gpa);
    report(&state.run.mailbox, reproposal);
    try expect_processed(&state.run.mailbox, 20);
    try expect_pending_ack(state.run.application, 21);
    state.run.crash();
    try restart_with_retired_floor_resumes_at(ctx, prefix, reproposal, 21);
}

test "standard reproposal reported below processed survives restart before ack" {
    try run(reproposal_reported_below_processed_body);
}

fn reproposal_delivered_below_processed_body(ctx: Ctx) anyerror!void {
    const prefix = "reproposal-delivered-restart-before-ack";
    var state: Reproposal = undefined;
    try start_reproposal_processed_through_20(&state, ctx, prefix);
    defer state.deinit();
    // Deliver the later finalization of block 10 with its block as a finalized-by-height
    // response. Marshal answers once the certificate verifies, before it ingests it, so the
    // `get_processed` round trip confirms the ingest finished.
    var reproposal = try state.finalize(10, 40);
    errdefer reproposal.deinit(gpa);
    const value = try finalized_value(reproposal, state.block(10));
    defer gpa.free(value);
    const height: Height = .new(10);
    const subscriber: handler.Annotation = .{ .finalized = .{ .by_height = height } };
    const outcome = try deliver(state.run.resolver, .{ .finalized = height }, subscriber, value);
    try testing.expectEqual(complete, outcome);
    try expect_processed(&state.run.mailbox, 20);
    try expect_pending_ack(state.run.application, 21);
    state.run.crash();
    try restart_with_retired_floor_resumes_at(ctx, prefix, reproposal, 21);
}

test "standard reproposal delivered below processed survives restart before ack" {
    try run(reproposal_delivered_below_processed_body);
}

/// Whether `resolver` recorded a fetch of the block `digest` for the finalization at `round`.
fn fetched_block_for_round(
    resolver: common.RecordingResolver,
    digest: harness.D,
    round: Round,
) !bool {
    const fetches = try resolver.fetches(gpa);
    defer gpa.free(fetches);
    const subscriber: handler.Annotation = .{ .finalized = .{ .by_round = round } };
    for (fetches) |fetch| {
        if (fetch.key != .block or !fetch.key.block.eql(digest)) continue;
        if (fetch.subscriber.eql(subscriber)) return true;
    }
    return false;
}

/// Restarts without a buffer from block 10's first finalization, which the restored round
/// floor already supersedes, and prunes below 20: block 11 goes, and block 10's finalization
/// stays as the newest at or below the processed height.
fn restart_pruned(state: *Reproposal, ctx: Ctx, prefix: []const u8) !ConstantUnbuffered {
    var pruned = try start_floor(
        harness.Provider,
        common.Unbuffered,
        ctx.child("pruned"),
        prefix,
        state.provider(),
        reproposal_epoch_length,
        try state.finalize(10, 10),
        null,
    );
    errdefer pruned.crash();
    try testing.expect(pruned.restored.cutoff.covers(.new(.zero(), .new(10))));
    try pruned.mailbox.prune(.new(20));
    try expect_processed(&pruned.mailbox, 20);
    try testing.expect(!try has_block(&pruned.mailbox, .new(11)));
    try testing.expect(!try has_finalization(&pruned.mailbox, .new(11)));
    try testing.expect(try has_finalization(&pruned.mailbox, .new(10)));
    try expect_pending_ack(pruned.application, 21);
    return pruned;
}

fn late_finalization_block_delivered_body(ctx: Ctx) anyerror!void {
    const prefix = "late-finalization-block-delivered-restart-before-ack";
    var state: Reproposal = undefined;
    try start_reproposal_processed_through_20(&state, ctx, prefix);
    defer state.deinit();
    state.run.crash();
    var pruned = try restart_pruned(&state, ctx, prefix);
    var late = try state.finalize(11, 11);
    errdefer late.deinit(gpa);

    // Block 11 is not local, so marshal caches the late finalization and fetches the block by
    // its commitment.
    report(&pruned.mailbox, late);
    try expect_processed(&pruned.mailbox, 20);
    const repaired = state.block(11);
    const round = late.round();
    try testing.expect(try fetched_block_for_round(pruned.resolver, repaired.digest(), round));

    // Delivering the block alone pairs it with the cached finalization and raises the round
    // floor; the pruned block is not stored. The test stops before height 21 is acknowledged.
    const value = try codec.encode(B, gpa, repaired);
    defer gpa.free(value);
    const subscriber: handler.Annotation = .{ .finalized = .{ .by_round = round } };
    const key: common.Key = .{ .block = repaired.digest() };
    try testing.expectEqual(complete, try deliver(pruned.resolver, key, subscriber, value));
    try expect_processed(&pruned.mailbox, 20);
    try testing.expect(!try has_finalization(&pruned.mailbox, .new(11)));
    try expect_pending_ack(pruned.application, 21);
    pruned.crash();
    try restart_with_retired_floor_resumes_at(ctx, prefix, late, 21);
}

test "standard late finalization block delivered below processed survives restart before ack" {
    try run(late_finalization_block_delivered_body);
}

/// The last block of epoch zero under `reproposal_epoch_length`, built without its chain,
/// and the validators that certify it (commonware `BoundaryBlock`).
const Boundary = struct {
    fixture: harness.Fixture,
    block: B,

    fn init(self: *Boundary) !void {
        var rng = utils.rng.test_rng();
        self.fixture = try harness.fixture(gpa, &rng);
        errdefer self.fixture.deinit(gpa);
        const parent = cryptography.Sha256.hash(&.{"parent"});
        self.block = try harness.make_raw_block(gpa, parent, .new(10), 1_000);
    }

    fn deinit(self: *Boundary) void {
        self.fixture.deinit(gpa);
    }

    fn provider(self: *const Boundary) harness.Provider {
        return .init(&self.fixture.schemes[0]);
    }

    /// Finalizes the block at `view` of epoch zero.
    fn finalize(self: *const Boundary, view: u64) !Finalization {
        return finalize_at(&self.fixture, 0, view, self.block);
    }
};

fn expect_no_pending_ack(application: App) !void {
    const heights = try application.pending_ack_heights(gpa);
    defer gpa.free(heights);
    try testing.expectEqual(0, heights.len);
}

fn reproposal_pending_anchor_body(ctx: Ctx) anyerror!void {
    const prefix = "reproposal-delivered-pending-anchor-restart-before-ack";
    var boundary: Boundary = undefined;
    try boundary.init();
    defer boundary.deinit();
    var pending = try boundary.finalize(30);
    defer pending.deinit(gpa);
    var reproposal = try boundary.finalize(40);
    errdefer reproposal.deinit(gpa);

    // Start from the (0, 30) finalization with no block available. The floor verifies and
    // stays pending with a fetch for its block, and dispatch waits for the anchor.
    var first = try start_floor(
        harness.Provider,
        common.Unbuffered,
        ctx.child("pending"),
        prefix,
        boundary.provider(),
        reproposal_epoch_length,
        try pending.clone(gpa),
        null,
    );
    try testing.expectEqual(null, try first.mailbox.get_processed());
    const digest = boundary.block.digest();
    try testing.expect(try fetched_block_for_round(first.resolver, digest, pending.round()));
    try expect_no_pending_ack(first.application);

    // Deliver block 10 with its (0, 40) finalization as a finalized-by-height response. The
    // block anchors the pending floor; the test stops before the application acknowledges it.
    const value = try finalized_value(reproposal, boundary.block);
    defer gpa.free(value);
    const height: Height = .new(10);
    const subscriber: handler.Annotation = .{ .finalized = .{ .by_height = height } };
    const outcome = try deliver(first.resolver, .{ .finalized = height }, subscriber, value);
    try testing.expectEqual(complete, outcome);
    const absent: Processed = .{ .absent = .new(9) };
    try testing.expectEqual(absent, (try first.mailbox.get_processed()).?);
    try expect_pending_ack(first.application, 10);
    first.crash();

    // Marshal skips the later floor and dispatches block 10 from the archive.
    try restart_with_retired_floor_resumes_at(ctx, prefix, reproposal, 10);
}

test "standard reproposal delivered as pending floor anchor survives restart before ack" {
    try run(reproposal_pending_anchor_body);
}

/// Whether `resolver` recorded any fetch keyed by the block `digest`.
fn fetched_block(resolver: common.RecordingResolver, digest: harness.D) !bool {
    const fetches = try resolver.fetches(gpa);
    defer gpa.free(fetches);
    for (fetches) |fetch| {
        if (fetch.key == .block and fetch.key.block.eql(digest)) return true;
    }
    return false;
}

fn reproposal_pruned_block_body(ctx: Ctx) anyerror!void {
    const prefix = "reproposal-reported-pruned-covered";
    var state: Reproposal = undefined;
    try start_reproposal_processed_through_20(&state, ctx, prefix);
    defer state.deinit();
    state.run.crash();
    var reproposal = try state.finalize(10, 40);
    errdefer reproposal.deinit(gpa);

    // Restart without a buffer from block 10's first finalization, and prune below 20 so
    // block 10 is no longer local.
    var pruned = try start_floor(
        harness.Provider,
        common.Unbuffered,
        ctx.child("pruned"),
        prefix,
        state.provider(),
        reproposal_epoch_length,
        try state.finalize(10, 10),
        null,
    );
    try testing.expect(pruned.restored.cutoff.covers(reproposal.round()));
    try pruned.mailbox.prune(.new(20));
    try expect_processed(&pruned.mailbox, 20);
    try testing.expect(!try has_block(&pruned.mailbox, .new(10)));

    // The later finalization's round is covered: no fetch by commitment, and dispatch stays
    // at height 21.
    report(&pruned.mailbox, reproposal);
    try expect_processed(&pruned.mailbox, 20);
    try testing.expect(!try fetched_block(pruned.resolver, state.block(10).digest()));
    try expect_pending_ack(pruned.application, 21);
    pruned.crash();
    try restart_with_retired_floor_resumes_at(ctx, prefix, reproposal, 21);
}

test "standard reproposal reported for pruned block is covered without fetch" {
    try run(reproposal_pruned_block_body);
}

fn pending_ack_is_ten(application: App) bool {
    const heights = application.pending_ack_heights(gpa) catch return false;
    defer gpa.free(heights);
    return heights.len == 1 and heights[0].get() == 10;
}

fn set_floor_installed_anchor_body(ctx: Ctx) anyerror!void {
    const prefix = "set-floor-installed-anchor-covered";
    var boundary: Boundary = undefined;
    try boundary.init();
    defer boundary.deinit();
    var buffer = try common.RecordingBuffer.init(gpa, ctx.io());
    errdefer buffer.deinit();
    try buffer.insert(try ready(boundary.block));

    // Install the (0, 10) finalization as the floor; block 10 is dispatched, not acknowledged.
    var first = try start_floor(
        harness.Provider,
        common.RecordingBuffer,
        ctx.child("first"),
        prefix,
        boundary.provider(),
        reproposal_epoch_length,
        try boundary.finalize(10),
        buffer,
    );
    defer first.crash();
    try common.wait_until(ctx, 5000, "floor dispatch", first.application, pending_ack_is_ten);

    // The later finalization is covered: the pending acknowledgement survives and block 10
    // is not dispatched again.
    try first.mailbox.set_floor(try boundary.finalize(40));
    const absent: Processed = .{ .absent = .new(9) };
    try testing.expectEqual(absent, (try first.mailbox.get_processed()).?);
    try expect_pending_ack(first.application, 10);
}

test "standard set floor for installed anchor is covered" {
    try run(set_floor_installed_anchor_body);
}

/// An epocher that has retired every height at or below `retired`, as an application may do
/// for processed heights (commonware `RetiredThrough`).
const RetiredThrough = struct {
    epocher: types.FixedEpocher,
    retired: Height,

    pub fn containing(self: RetiredThrough, height: Height) ?types.EpochInfo {
        if (height.get() <= self.retired.get()) return null;
        return self.epocher.containing(height);
    }

    pub fn first(self: RetiredThrough, epoch: types.Epoch) ?Height {
        return self.epocher.first(epoch);
    }

    pub fn last(self: RetiredThrough, epoch: types.Epoch) ?Height {
        return self.epocher.last(epoch);
    }
};

/// The marshal actor over prunable stores with provider `Prov` and epocher `E`, unbuffered.
fn EpocherActor(comptime Prov: type, comptime E: type) type {
    const Params = struct {
        pub const Scheme = harness.S;
        pub const Provider = Prov;
        pub const Epocher = E;
        pub const Strategy = parallel.Sequential;
        pub const ApplicationBlock = B;
        pub const Block = common.V.Block;
        pub const Commitment = harness.D;
        pub const Variant = common.V;
        pub const Acknowledgement = harness.Exact;
        pub const Certificates = Prunable.Certificates;
        pub const Blocks = Prunable.Blocks;
        pub const Application = App;
        pub const Buffer = common.Unbuffered;
        pub const Resolver = common.RecordingResolver;
    };
    return core.Actor(Params);
}

/// `from` (taken) rebuilt with `epocher` in place of its fixed-length epocher (commonware
/// `with_epocher`).
fn with_epocher(comptime To: type, from: anytype, epocher: anytype) To {
    var config: To = undefined;
    inline for (@typeInfo(To).@"struct".field_names) |name| {
        if (comptime std.mem.eql(u8, name, "epocher")) {
            config.epocher = epocher;
        } else {
            @field(config, name) = @field(from, name);
        }
    }
    return config;
}

fn reproposal_epocher() types.FixedEpocher {
    return .new(utils.NonZero(u64).init(reproposal_epoch_length).?);
}

/// Opens marshal under `prefix` with `epocher` and `floor` (owned) configured and a provider
/// holding no epochs, without starting it, and returns the floor it restored (commonware's
/// `Actor::init` then a drop, with `with_epocher`).
fn restored_floor(
    comptime E: type,
    ctx: Ctx,
    prefix: []const u8,
    epocher: E,
    floor: Finalization,
) !core.Floor {
    const A = EpocherActor(EmptyProvider, E);
    const Fixed = Running(EmptyProvider, common.Unbuffered).A;
    var start: Finalization = floor;
    errdefer start.deinit(gpa);
    var stores: Prunable = undefined;
    try stores.open(ctx, prefix);
    defer stores.deinit();
    var fixed = try common.test_config(Fixed, gpa, prefix, EmptyProvider{}, 1, &stores.cache_ref);
    fixed.start.genesis.deinit();
    fixed.start = .{ .floor = start };
    const config = with_epocher(A.Config, fixed, epocher);
    const initialized = try A.init(ctx, stores.certificates(), stores.blocks_store(), config);
    var mailbox = initialized.mailbox;
    mailbox.deinit();
    initialized.actor.deinit();
    return initialized.floor;
}

/// Acknowledges through height 20, then restarts from metadata holding that processed height
/// and `round` as the round floor, with no epoch cutoff. The start derives the cutoff for the
/// epoch height 20 closes and writes it back for a start whose epocher retired that height.
fn closed_epoch_floor_written_back(ctx: Ctx, prefix: []const u8, round: ?Round) !void {
    var state: Reproposal = undefined;
    try start_reproposal_processed_through_20(&state, ctx, prefix);
    defer state.deinit();
    state.run.crash();
    var reproposal = try state.finalize(10, 40);
    defer reproposal.deinit(gpa);
    try seed.processed_height(ctx.child("metadata"), prefix, .new(20), round);
    const derived_ctx = ctx.child("derived");
    const derived = try restored_floor(
        types.FixedEpocher,
        derived_ctx,
        prefix,
        reproposal_epocher(),
        try reproposal.clone(gpa),
    );
    try testing.expect(derived.cutoff.covers(reproposal.round()));
    // Only the written-back metadata can supply the floor to an epocher that retired every
    // processed height.
    const retired: RetiredThrough = .{ .epocher = reproposal_epocher(), .retired = .new(20) };
    const persisted_ctx = ctx.child("persisted");
    const persisted = try restored_floor(
        RetiredThrough,
        persisted_ctx,
        prefix,
        retired,
        try reproposal.clone(gpa),
    );
    try testing.expect(persisted.cutoff.covers(reproposal.round()));
}

fn written_back_body(ctx: Ctx) anyerror!void {
    try closed_epoch_floor_written_back(ctx, "closed-epoch-floor-written-back", null);
}

test "standard restored closed epoch floor is written back" {
    try run(written_back_body);
}

fn written_back_over_round_body(ctx: Ctx) anyerror!void {
    const prefix = "closed-epoch-floor-written-back-over-round-floor";
    try closed_epoch_floor_written_back(ctx, prefix, .new(.zero(), .new(10)));
}

test "standard restored closed epoch floor is written back over a round floor" {
    try run(written_back_over_round_body);
}

fn unacknowledged_successor_body(ctx: Ctx) anyerror!void {
    const prefix = "closed-epoch-floor-unacknowledged-successor";
    var state: Reproposal = undefined;
    try start_reproposal_processed_through_20(&state, ctx, prefix);
    defer state.deinit();
    var late = try state.finalize(21, 25);
    defer late.deinit(gpa);
    var reproposal = try state.finalize(21, 50);
    errdefer reproposal.deinit(gpa);
    // Archive block 21's first finalization, then stop before it is acknowledged.
    report(&state.run.mailbox, late);
    try expect_processed(&state.run.mailbox, 20);
    try expect_pending_ack(state.run.application, 21);
    state.run.crash();
    try seed.processed_height(ctx.child("metadata"), prefix, .new(20), null);
    try restart_with_retired_floor_resumes_at(ctx, prefix, reproposal, 21);
}

test "standard closed epoch floor restores from an unacknowledged successor" {
    try run(unacknowledged_successor_body);
}

fn certificate_only_successor_body(ctx: Ctx) anyerror!void {
    const prefix = "certificate-only-successor-closes-no-epoch";
    var boundary: Boundary = undefined;
    try boundary.init();
    defer boundary.deinit();
    var first = try boundary.finalize(10);
    defer first.deinit(gpa);
    const digest = boundary.block.digest();
    // Seed processed height 9 and archive only block 10's finalization above it.
    try seed.processed_height(ctx.child("metadata"), prefix, .new(9), null);
    {
        var stores: Prunable = undefined;
        try stores.open(ctx.child("seed"), prefix);
        defer stores.deinit();
        try stores.certificates().put(.new(10), digest, &first);
        try stores.certificates().sync();
    }
    var restarted = try start_floor(
        harness.Provider,
        common.Unbuffered,
        ctx.child("restarted"),
        prefix,
        boundary.provider(),
        reproposal_epoch_length,
        try first.clone(gpa),
        null,
    );
    defer restarted.crash();
    try testing.expect(!restarted.restored.cutoff.covers(first.round()));
    // The floor is above the restored round floor, so it verifies and fetches its block.
    const absent: Processed = .{ .absent = .new(9) };
    try testing.expectEqual(absent, (try restarted.mailbox.get_processed()).?);
    try testing.expect(try has_finalization(&restarted.mailbox, .new(10)));
    try testing.expect(!try has_block(&restarted.mailbox, .new(10)));
    try testing.expect(try fetched_block_for_round(restarted.resolver, digest, first.round()));
}

test "standard certificate-only successor closes no epoch" {
    try run(certificate_only_successor_body);
}

fn installed_anchor_body(ctx: Ctx) anyerror!void {
    const prefix = "closed-epoch-floor-installed-anchor";
    var boundary: Boundary = undefined;
    try boundary.init();
    defer boundary.deinit();
    var reproposal = try boundary.finalize(40);
    errdefer reproposal.deinit(gpa);
    var buffer = try common.RecordingBuffer.init(gpa, ctx.io());
    errdefer buffer.deinit();
    try buffer.insert(try ready(boundary.block));
    // Install the first finalization as the floor and stop before block 10 is acknowledged.
    var first = try start_floor(
        harness.Provider,
        common.RecordingBuffer,
        ctx.child("first"),
        prefix,
        boundary.provider(),
        reproposal_epoch_length,
        try boundary.finalize(10),
        buffer,
    );
    try common.wait_until(ctx, 5000, "floor dispatch", first.application, pending_ack_is_ten);
    const absent: Processed = .{ .absent = .new(9) };
    try testing.expectEqual(absent, (try first.mailbox.get_processed()).?);
    first.crash();
    // Restart from metadata holding only the processed height: block 10 is dispatched from
    // the archive.
    try seed.processed_height(ctx.child("metadata"), prefix, .new(9), null);
    try restart_with_retired_floor_resumes_at(ctx, prefix, reproposal, 10);
}

test "standard closed epoch floor restores from an installed anchor" {
    try run(installed_anchor_body);
}

/// The finalization indices pruned from the cache of `epoch`, summed over every actor
/// (commonware's `pruned` closure over `context.encode()`).
fn cache_pruned(ctx: Ctx, epoch: u64) !u64 {
    const text = try ctx.encode(gpa);
    defer gpa.free(text);
    var label: [32]u8 = undefined;
    const epoch_label = try std.fmt.bufPrint(&label, "epoch=\"{d}\"", .{epoch});
    var total: u64 = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.indexOf(u8, line, "cache_finalizations_indices_pruned_total") == null) continue;
        if (std.mem.indexOf(u8, line, epoch_label) == null) continue;
        const space = std.mem.lastIndexOfScalar(u8, line, ' ') orelse continue;
        total += std.fmt.parseInt(u64, line[space + 1 ..], 10) catch continue;
    }
    return total;
}

/// Restarts unbuffered from block 10's first finalization (the round floor covers epoch zero
/// and the witnessed round comes back from the archives).
fn restart_from_first(state: *Reproposal, ctx: Ctx, prefix: []const u8) !ConstantUnbuffered {
    return start_floor(
        harness.Provider,
        common.Unbuffered,
        ctx.child("restarted"),
        prefix,
        state.provider(),
        reproposal_epoch_length,
        try state.finalize(10, 10),
        null,
    );
}

fn cache_prunes_behind_reproposals_body(ctx: Ctx) anyerror!void {
    const prefix = "cache-prunes-behind-covered-reproposals";
    var state: Reproposal = undefined;
    try start_reproposal_processed_through_20(&state, ctx, prefix);
    defer state.deinit();
    state.run.crash();
    var restarted = try restart_from_first(&state, ctx, prefix);
    defer restarted.crash();
    // Each re-proposal is cached in epoch zero and becomes the newest witnessed round. The
    // cache prunes behind the previously witnessed round while the round floor stays put:
    // (0, 10) goes at the second report and (0, 40) at the third.
    const before = try cache_pruned(ctx, 0);
    for ([_]u64{ 40, 60, 80 }) |view| {
        var reproposal = try state.finalize(10, view);
        defer reproposal.deinit(gpa);
        report(&restarted.mailbox, reproposal);
    }
    try expect_processed(&restarted.mailbox, 20);
    try testing.expectEqual(before + 2, try cache_pruned(ctx, 0));
}

test "standard cache prunes behind covered reproposals" {
    try run(cache_prunes_behind_reproposals_body);
}

fn restored_witnessed_round_body(ctx: Ctx) anyerror!void {
    const prefix = "restored-witnessed-round-prunes-cache";
    var state: Reproposal = undefined;
    try start_reproposal_processed_through_20(&state, ctx, prefix);
    defer state.deinit();
    // Archive block 11's finalization at (1, 11) and block 21's at (1, 50), then acknowledge
    // block 21: the newest processed round sits a retention window above (1, 11).
    for ([_][2]u64{ .{ 11, 11 }, .{ 21, 50 } }) |at| {
        var finalization = try state.finalize(at[0], at[1]);
        defer finalization.deinit(gpa);
        report(&state.run.mailbox, finalization);
    }
    try testing.expectEqual(Height.new(21), state.run.application.acknowledge_next().?);
    try wait_processed(ctx, &state.run.mailbox, 21);
    state.run.crash();

    // The archives restore (1, 50) as the newest witnessed round, so the first finalization
    // witnessed after the restart, (1, 70), prunes the cached (1, 11) finalization.
    var restarted = try restart_from_first(&state, ctx, prefix);
    defer restarted.crash();
    const before = try cache_pruned(ctx, 1);
    var reproposal = try state.finalize(21, 70);
    defer reproposal.deinit(gpa);
    report(&restarted.mailbox, reproposal);
    try expect_processed(&restarted.mailbox, 21);
    try testing.expectEqual(before + 1, try cache_pruned(ctx, 1));
}

test "standard restored witnessed round prunes cache after restart" {
    try run(restored_witnessed_round_body);
}

/// The round a height finalizes in, under `epoch_length` epochs: epoch zero at the view of the
/// same number, later epochs counting views from one.
fn layout_round(epoch_length: u64, height: Height) Round {
    const layout: types.FixedEpocher = .new(utils.NonZero(u64).init(epoch_length).?);
    const info = layout.containing(height).?;
    const offset = height.get() - info.first.get();
    const view = if (info.epoch.is_zero()) offset else offset + 1;
    return .new(info.epoch, .new(view));
}

/// What `epoch_retention` tracks of the watched epoch's last block.
const Watch = struct {
    round: Round,
    last_kept: ?Round = null,
    gone: bool = false,

    /// Records whether the watched block is still cached after `round` was processed; once
    /// gone it must never return.
    fn observe(self: *Watch, mailbox: anytype, round: Round) !void {
        var verified = (try mailbox.get_verified(self.round)) orelse {
            self.gone = true;
            return;
        };
        verified.deinit();
        try testing.expect(!self.gone);
        self.last_kept = round;
    }
};

/// Verifies `block` (borrowed) at its layout round, finalizes it, and waits until marshal
/// processes it. Processing a finalization prunes the cache behind the previous one.
fn retention_step(
    ctx: Ctx,
    fixture: *const harness.Fixture,
    run_state: anytype,
    round: Round,
    block: B,
) !void {
    const height = block.height();
    try testing.expect(try run_state.mailbox.verified(round, try ready(block)));
    const parent_view = round.view.previous().?;
    const proposal = harness.Proposal.init(round, parent_view, block.digest());
    var finalization = try harness.make_finalization(gpa, fixture, proposal, harness.quorum);
    defer finalization.deinit(gpa);
    report(&run_state.mailbox, finalization);
    try testing.expectEqual(height, try run_state.application.acknowledged());
    try wait_processed(ctx, &run_state.mailbox, height.get());
}

const RetentionParams = struct {
    epoch_length: u64,
    view_retention: u64,
    watched: u64,
    blocks: u64,
};

/// Drives a fresh marshal under `epocher` and `params.view_retention` through
/// `params.blocks` finalized heights laid out in `params.epoch_length` epochs, verifying each
/// block at its finalization round so the cache holds it. Returns the last processed round
/// after which the watched epoch's last block was still cached (commonware `epoch_retention`).
fn epoch_retention(
    ctx: Ctx,
    prefix: []const u8,
    epocher: anytype,
    params: RetentionParams,
) !?Round {
    const A = EpocherActor(harness.Provider, @TypeOf(epocher));
    const Fixed = Running(harness.Provider, common.Unbuffered).A;
    var rng = utils.rng.test_rng();
    var fixture = try harness.fixture(gpa, &rng);
    defer fixture.deinit(gpa);
    const provider: harness.Provider = .init(&fixture.schemes[0]);
    const owned_prefix = try gpa.dupe(u8, prefix);
    errdefer gpa.free(owned_prefix);
    const stores = try gpa.create(Prunable);
    errdefer gpa.destroy(stores);
    try stores.open(ctx, owned_prefix);
    errdefer stores.deinit();
    const fixed = try common.test_config(Fixed, gpa, owned_prefix, provider, 1, &stores.cache_ref);
    var config = with_epocher(A.Config, fixed, epocher);
    config.view_retention = .new(params.view_retention);
    const initialized = try A.init(
        ctx.child("actor"),
        stores.certificates(),
        stores.blocks_store(),
        config,
    );
    const application = try App.manual_ack(gpa, ctx.io());
    var holding = try common.RecordingResolver.holding(gpa, ctx.io(), &ctx.scope.child("mailbox"));
    const handle = try initialized.actor.start(
        application.clone(),
        .{ .gpa = gpa },
        holding.receiver,
        holding.resolver.clone(),
    );
    var state: RunningActor(A) = .{
        .stores = stores,
        .prefix = owned_prefix,
        .mailbox = initialized.mailbox,
        .resolver = holding.resolver,
        .application = application,
        .restored = initialized.floor,
        .handle = handle,
    };
    defer state.crash();
    try testing.expectEqual(Height.zero(), try state.application.acknowledged());
    return retention_chain(ctx, &fixture, &state, params);
}

fn retention_chain(
    ctx: Ctx,
    fixture: *const harness.Fixture,
    state: anytype,
    params: RetentionParams,
) !?Round {
    const layout: types.FixedEpocher = .new(utils.NonZero(u64).init(params.epoch_length).?);
    const boundary = layout.last(.new(params.watched)).?;
    var watch: Watch = .{ .round = layout_round(params.epoch_length, boundary) };
    var genesis = try H.genesis_block(gpa, harness.num_validators);
    defer genesis.deinit();
    var parent = genesis.digest();
    for (1..params.blocks + 1) |index| {
        const height: Height = .new(index);
        const block = try harness.make_raw_block(gpa, parent, height, index * 100);
        parent = block.digest();
        const round = layout_round(params.epoch_length, height);
        try retention_step(ctx, fixture, state, round, block);
        if (height.get() < boundary.get()) continue;
        try watch.observe(&state.mailbox, round);
    }
    return watch.last_kept;
}

fn fixed_epocher(length: u64) types.FixedEpocher {
    return .new(utils.NonZero(u64).init(length).?);
}

fn keeps_previous_epoch_body(ctx: Ctx) anyerror!void {
    // Epoch one spans views 1..=20, so the window of ten views is measurable from its tenth
    // finalization on, and the next one destroys epoch zero.
    const epocher = fixed_epocher(harness.blocks_per_epoch);
    const kept = try epoch_retention(ctx, "cache-keeps-previous-epoch", epocher, .{
        .epoch_length = harness.blocks_per_epoch,
        .view_retention = 10,
        .watched = 0,
        .blocks = 31,
    });
    try testing.expectEqual(Round.new(.new(1), .new(10)), kept.?);
}

test "standard cache keeps previous epoch through retention window" {
    try run_timed(keeps_previous_epoch_body, 60);
}

/// Regression test for https://github.com/commonwarexyz/monorepo/pull/5646: when epochs span
/// fewer views than the retention window, the window reaches through several of them, one
/// view per height, and every epoch below the lowest one it reaches is destroyed.
fn pr_5646_body(ctx: Ctx) anyerror!void {
    for ([_][2]u64{ .{ 0, 10 }, .{ 1, 11 } }) |case| {
        var name: [64]u8 = undefined;
        const prefix = try std.fmt.bufPrint(&name, "cache-retention-short-epochs-{d}", .{case[0]});
        var label: [16]u8 = undefined;
        const child = ctx.child(try std.fmt.bufPrint(&label, "watched_{d}", .{case[0]}));
        const kept = try epoch_retention(child, prefix, fixed_epocher(10), .{
            .epoch_length = 10,
            .view_retention = 100,
            .watched = case[0],
            .blocks = 125,
        });
        try testing.expectEqual(Round.new(.new(case[1]), .new(10)), kept.?);
    }
}

test "standard cache retention reaches through short epochs (pr_5646_regression)" {
    if (builtin.mode == .debug and !build_options.slow_tests) return error.SkipZigTest;
    try run_timed(pr_5646_body, 60);
}

fn retired_epochs_once_body(ctx: Ctx) anyerror!void {
    // The epocher places none of the processed heights. After (8, 3), seven views of the
    // window remain, covered by epochs seven through one, so the next finalization destroys
    // epoch zero.
    const epocher: RetiredThrough = .{ .epocher = fixed_epocher(3), .retired = .new(30) };
    const kept = try epoch_retention(ctx, "cache-retention-retired-heights", epocher, .{
        .epoch_length = 3,
        .view_retention = 10,
        .watched = 0,
        .blocks = 30,
    });
    try testing.expectEqual(Round.new(.new(8), .new(3)), kept.?);
}

test "standard cache retention counts retired epochs once" {
    try run_timed(retired_epochs_once_body, 60);
}
