//! commonware `glue/src/stateful/actor/core/syncing.rs` tests: handoff classification, and a
//! syncing actor that state-syncs a fresh `any` database from a populated one over the
//! processor harness, then hands off the finalizations it retained meanwhile.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const actor = @import("actor");
const consensus = @import("consensus");
const runtime = @import("runtime");
const utils = @import("utils");
const db = @import("../../db/mod.zig");
const state_sync = @import("../../db/state_sync.zig");
const harness_mod = @import("../processor/testing.zig");
const syncing_mod = @import("syncing.zig");
const syncer_actor = @import("../syncer/actor.zig");

const gpa = testing.allocator;
const io = testing.io;
const oneshot = utils.channel.oneshot;
const Exact = utils.acknowledgement.Exact;
const metrics = runtime.telemetry.metrics;
const Height = consensus.Height;
const Round = consensus.Round;
const core = consensus.marshal.core;
const Any = harness_mod.Any;
const TestBlock = harness_mod.TestBlock;
const Digested = harness_mod.Digested;

// Classification.

const Block = struct {
    pub const Digest = [32]u8;
    number: u64,
    fork: u8 = 0,

    pub fn digest(self: *const Block) [32]u8 {
        var bytes: [32]u8 = @splat(self.fork);
        std.mem.writeInt(u64, bytes[0..8], self.number, .big);
        return bytes;
    }

    pub fn height(self: *const Block) Height {
        return .new(self.number);
    }

    pub fn context(self: *const Block) struct { round: Round } {
        return .{ .round = .new(.zero(), .new(self.number)) };
    }
};

const Pending = syncing_mod.PendingFinalization(Block);

/// Retained blocks for `blocks`, with their acknowledgements' waiters.
const Retained = struct {
    pending: [8]Pending = undefined,
    waiters: [8]Exact.Waiter = undefined,
    len: usize = 0,

    fn init(blocks: []const Block) !Retained {
        var retained: Retained = .{};
        for (blocks) |block| {
            const handle = try Exact.handle(gpa, io);
            const pending: Pending = .{ .block = block, .acknowledgement = handle.acknowledgement };
            retained.pending[retained.len] = pending;
            retained.waiters[retained.len] = handle.waiter;
            retained.len += 1;
        }
        return retained;
    }

    fn deinit(retained: *Retained) void {
        for (retained.pending[0..retained.len]) |*pending| pending.deinit();
        for (retained.waiters[0..retained.len]) |*waiter| waiter.deinit();
    }

    fn items(retained: *Retained) []Pending {
        return retained.pending[0..retained.len];
    }
};

fn anchor(block: Block) syncer_actor.AnchorOf(Block) {
    return syncer_actor.anchor_of(&block);
}

test "stateful syncing: handoff classification orders a mixed terminal sequence" {
    var retained = try Retained.init(&.{
        .{ .number = 5 }, .{ .number = 3 }, .{ .number = 4 }, .{ .number = 6 }, .{ .number = 5 },
    });
    defer retained.deinit();
    try syncing_mod.classify(Block, anchor(.{ .number = 4 }), retained.items());
    const expected = [_]struct { u64, syncing_mod.Handoff }{
        .{ 3, .covered }, .{ 4, .reflected }, .{ 5, .apply }, .{ 5, .apply }, .{ 6, .apply },
    };
    for (expected, retained.items()) |want, got| {
        try testing.expectEqual(want[0], got.block.number);
        try testing.expectEqual(want[1], got.handoff);
    }
}

test "stateful syncing: a block at the anchor height with another digest fails" {
    var retained = try Retained.init(&.{.{ .number = 4, .fork = 1 }});
    defer retained.deinit();
    const result = syncing_mod.classify(Block, anchor(.{ .number = 4 }), retained.items());
    try testing.expectError(error.ConflictingAnchor, result);
}

test "stateful syncing: a duplicate handoff with another digest fails" {
    var retained = try Retained.init(&.{ .{ .number = 5 }, .{ .number = 5, .fork = 1 } });
    defer retained.deinit();
    const result = syncing_mod.classify(Block, anchor(.{ .number = 4 }), retained.items());
    try testing.expectError(error.ConflictingDuplicate, result);
}

test "stateful syncing: a block that skips a height fails" {
    var retained = try Retained.init(&.{.{ .number = 6 }});
    defer retained.deinit();
    const result = syncing_mod.classify(Block, anchor(.{ .number = 4 }), retained.items());
    try testing.expectError(error.SkippedHeight, result);
}

test "stateful syncing: a block covered by the artifact is retained as covered" {
    var retained = try Retained.init(&.{.{ .number = 2 }});
    defer retained.deinit();
    try syncing_mod.classify(Block, anchor(.{ .number = 4 }), retained.items());
    try testing.expectEqual(syncing_mod.Handoff.covered, retained.items()[0].handoff);
}

// The syncing actor.

const Finalization = struct {
    view: u64,
    proposal: struct { payload: TestBlock.Digest },

    pub fn round(self: *const Finalization) Round {
        return harness_mod.round(self.view);
    }
};

const MockPlan = struct {
    pub const Finalization = syncing_test_Finalization;
    selected: syncing_test_Finalization,
    completed: ?Height = null,

    pub fn floor(self: *const MockPlan) ?*const syncing_test_Finalization {
        return &self.selected;
    }

    pub fn set_completed(self: *MockPlan, height: Height) !void {
        self.completed = height;
    }
};
const syncing_test_Finalization = Finalization;

/// A marshal whose floor block arrives by subscription and holds nothing else.
const MockMarshal = struct {
    floor_block: TestBlock,
    prunes: *std.ArrayList(u64),

    pub const Anchored = struct { processed: core.Processed, block: Digested };

    pub fn get_anchor(_: MockMarshal) error{}!?Anchored {
        return null;
    }

    pub fn get_block(_: MockMarshal, _: core.Identifier(TestBlock.Digest)) error{}!?Digested {
        return null;
    }

    pub fn subscribe_by_commitment(
        self: MockMarshal,
        _: TestBlock.Digest,
        _: core.CommitmentFallback,
    ) !oneshot.Receiver(Digested) {
        var pair = try oneshot.channel(Digested, gpa, io);
        pair.sender.send(try harness_mod.digested(self.floor_block)) catch unreachable;
        return pair.receiver;
    }

    pub fn prune(self: MockMarshal, height: Height) !void {
        try self.prunes.append(gpa, height.get());
    }
};

/// Serves sync requests from the source database once `gate` opens, and records attachment.
const Resolvers = struct {
    const Source = state_sync.SharedSource(Any);
    pub const Family = Source.Family;
    pub const Op = Source.Op;
    pub const Digest = Source.Digest;
    pub const Error = Source.Error;

    source: Source,
    gate: ?oneshot.Receiver(void),
    attached: ?Any.Shared = null,

    pub fn serve(
        self: *Resolvers,
        allocator: std.mem.Allocator,
        request: Source.Request,
    ) (Error || Io.Cancelable)!@import("storage").qmdb.sync.Served(Source.Response) {
        if (self.gate) |*gate| {
            gate.recv() catch {};
            gate.deinit();
            self.gate = null;
        }
        return self.source.serve(allocator, request);
    }

    pub fn attach_database(self: *Resolvers, database: Any.Shared) !void {
        self.attached = database;
    }
};

const SyncP = struct {
    pub const App = harness_mod.TestApp;
    pub const Databases = Any.Shared;
    pub const Provider = harness_mod.TestProvider;
    pub const Marshal = MockMarshal;
    pub const Plan = MockPlan;
    pub const Resolvers = *syncing_test_Resolvers;
};
const syncing_test_Resolvers = Resolvers;
const Syncing = syncing_mod.Syncing(SyncP);
const Mailbox = Syncing.Processing.Mailbox;

/// The destination node's storage, page cache, and metrics.
const Node = struct {
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: metrics.Registry,

    fn init(node: *Node) !void {
        node.* = .{
            .storage = .init(gpa),
            .cache_ref = try .init(gpa, 101, 11),
            .registry = metrics.Registry.init(gpa),
        };
    }

    fn deinit(node: *Node) void {
        node.registry.deinit();
        node.cache_ref.deinit();
        node.storage.deinit();
    }

    fn env(node: *Node) db.Env {
        return .{
            .gpa = gpa,
            .io = io,
            .storage = node.storage.interface(),
            .scope = metrics.Scope.init(&node.registry).child("db"),
        };
    }

    fn config(node: *Node) Any.Config {
        return .{
            .merkle = .{
                .journal_partition = "syncing-journal",
                .metadata_partition = "syncing-metadata",
                .items_per_blob = 11,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .cache_ref = &node.cache_ref,
            },
            .log = .{
                .partition = "syncing-log",
                .items_per_blob = 7,
                .cache_ref = &node.cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
            },
            .translator = .{},
            .init_cache = 1024,
        };
    }
};

/// Builds and finalizes `count` blocks on `source`, newest last.
fn build_chain(source: *harness_mod.Harness, blocks: []TestBlock) !void {
    var parent = TestBlock.genesis();
    for (blocks, 1..) |*block, view| {
        block.*, var merkleized = try source.build_child(&parent, view);
        merkleized.deinit();
        try source.finalize(block);
        parent = block.*;
    }
}

fn run_syncing(syncing: *Syncing) anyerror!?Syncing.Ready {
    return syncing.run();
}

fn report(mailbox: *Mailbox, block: TestBlock) !Exact.Waiter {
    const handle = try Exact.handle(gpa, io);
    const update: Mailbox.Update = .{ .block = .{
        .block = try harness_mod.digested(block),
        .ack = handle.acknowledgement,
    } };
    try testing.expect(mailbox.report(update) != .closed);
    return handle.waiter;
}

test "stateful syncing: state sync hands off the finalizations retained above its anchor" {
    var source: harness_mod.Harness = undefined;
    try source.init();
    defer source.deinit();
    var blocks: [3]TestBlock = undefined;
    try build_chain(&source, &blocks);
    const floor = blocks[1];

    var node: Node = undefined;
    try node.init();
    defer node.deinit();
    var provider_state: harness_mod.ProviderState = .{};
    defer provider_state.deinit();
    for (blocks) |block| try provider_state.insert(block);
    var prunes: std.ArrayList(u64) = .empty;
    defer prunes.deinit(gpa);
    var plan: MockPlan = .{ .selected = .{
        .view = floor.round.view.get(),
        .proposal = .{ .payload = floor.digest() },
    } };
    var gate = try oneshot.channel(void, gpa, io);
    var resolvers: Resolvers = .{
        .source = .{ .shared = source.databases },
        .gate = gate.receiver,
    };
    var pair = try actor.mailbox.new(Syncing.Message, gpa, io, 16);
    defer pair.receiver.deinit();
    var mailbox = Mailbox.init(gpa, io, pair.sender);
    defer mailbox.deinit();

    var syncing = try Syncing.init(.{
        .app = .{},
        .env = node.env(),
        .db_config = node.config(),
        .sync_config = .{
            .fetch_batch_size = 16,
            .apply_batch_size = 16,
            .max_outstanding_requests = 1,
        },
        .resolvers = &resolvers,
        .receiver = &pair.receiver,
        .marshal = .{ .floor_block = floor, .prunes = &prunes },
        .floor = .init(null, .zero()),
        .plan = &plan,
        .provider = .{ .state = &provider_state },
        .max_pending_acks = 8,
    });
    defer syncing.deinit();
    var task = try io.concurrent(run_syncing, .{&syncing});

    // While the sync waits on the gate: a covered, a reflected, and an applied block, a
    // database subscriber, and a verification, then a proposal the actor declines.
    var covered = try report(&mailbox, blocks[0]);
    defer covered.deinit();
    var reflected = try report(&mailbox, blocks[1]);
    defer reflected.deinit();
    var applied = try report(&mailbox, blocks[2]);
    defer applied.deinit();
    var subscriber = try oneshot.channel(Any.Shared, gpa, io);
    defer subscriber.receiver.deinit();
    _ = try mailbox.sender.enqueue(.{ .subscribe_databases = subscriber.sender });
    var verdict = try oneshot.channel(bool, gpa, io);
    defer verdict.receiver.deinit();
    _ = try mailbox.sender.enqueue(.{ .verify = .{
        .ancestry = try source.ancestry(&.{blocks[2]}),
        .verification = verdict.sender,
    } });
    const context: TestBlock.Context = .{ .round = harness_mod.round(9) };
    const declined = try mailbox.propose({}, context, try source.ancestry(&.{blocks[2]}), {});
    try testing.expectEqual(@as(?Mailbox.Digested, null), declined);
    try testing.expectError(error.Empty, subscriber.receiver.try_recv());
    try gate.sender.send({});

    var ready = (try task.await(io)).?;
    defer ready.databases.deinit();
    defer ready.processor.deinit();
    defer ready.deferred.deinit(gpa);
    defer for (ready.deferred.items) |*request| {
        request.ancestry.deinit();
        request.verification.deinit();
    };
    // Every retained block is acknowledged, and the block above the anchor is applied.
    try covered.wait();
    try reflected.wait();
    try applied.wait();
    try testing.expectEqual(@as(u64, 3), plan.completed.?.get());
    try testing.expectEqual(@as(u64, 3), ready.processor.branch_anchor().height.get());
    const reached = try ready.databases.committed_targets();
    try testing.expect(db.targets_eql(Any.SyncTarget, &reached, &blocks[2].target));
    // The databases reach the resolver before the subscriber; the verification waits.
    try testing.expect(resolvers.attached.?.cell == ready.databases.cell);
    const handed = try subscriber.receiver.recv();
    try testing.expect(handed.cell == ready.databases.cell);
    try testing.expectEqual(@as(usize, 1), ready.deferred.items.len);
    try testing.expectEqual(@as(usize, 0), prunes.items.len);
}
