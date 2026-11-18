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
    return struct {
        const Self = @This();
        pub const A = common.Actor(Prov, App, Buf, Prunable.Certificates, Prunable.Blocks);

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
    try expect_processed(&first.mailbox, 20);
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
    try expect_processed(&self.run.mailbox, 20);
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
