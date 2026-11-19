//! The `Stateful` actor end to end over a fake marshal: recovery opens the databases at the
//! processed block, records completion in the plan, serves proposals and verifications, and
//! acknowledges finalizations once durable; a restart recovers the finalized state.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const utils = @import("utils");
const db = @import("../../db/mod.zig");
const harness_mod = @import("../processor/testing.zig");
const plan_mod = @import("../syncer/plan.zig");
const stateful_mod = @import("stateful.zig");

const gpa = testing.allocator;
const io = testing.io;
const oneshot = utils.channel.oneshot;
const metrics = runtime.telemetry.metrics;
const Exact = utils.acknowledgement.Exact;
const Height = consensus.Height;
const Processed = consensus.marshal.core.Processed;
const Digest = cryptography.Sha256.Digest;
const TestBlock = harness_mod.TestBlock;
const Digested = harness_mod.Processor.Digested;
const Any = harness_mod.Any;

/// What the fake marshal stores: blocks by digest, the finalized chain, and its processed
/// height.
const MarshalState = struct {
    mutex: Io.Mutex = .init,
    blocks: std.AutoHashMapUnmanaged(Digest, TestBlock) = .empty,
    finalized: std.AutoHashMapUnmanaged(u64, TestBlock) = .empty,
    processed: u64 = 0,
    prunes: std.ArrayList(u64) = .empty,

    fn deinit(state: *MarshalState) void {
        state.blocks.deinit(gpa);
        state.finalized.deinit(gpa);
        state.prunes.deinit(gpa);
    }

    fn insert(state: *MarshalState, block: TestBlock) !void {
        state.mutex.lockUncancelable(io);
        defer state.mutex.unlock(io);
        try state.blocks.put(gpa, block.digest(), block);
    }

    fn mark_finalized(state: *MarshalState, block: TestBlock) !void {
        try state.insert(block);
        state.mutex.lockUncancelable(io);
        defer state.mutex.unlock(io);
        try state.finalized.put(gpa, block.height().get(), block);
    }
};

const Identifier = union(enum) { height: Height };

/// The parts of marshal's core mailbox the actor uses.
const FakeMarshal = struct {
    pub const Block = TestBlock;
    pub const ParentReceiver = oneshot.Receiver(Digested);
    pub const Anchor = struct { processed: Processed, block: Digested };
    pub const Info = struct { height: Height, digest: Digest };

    state: *MarshalState,

    pub fn clone(self: FakeMarshal) FakeMarshal {
        return self;
    }

    pub fn deinit(self: *FakeMarshal) void {
        self.* = undefined;
    }

    fn finalized_at(self: FakeMarshal, at: Height) ?TestBlock {
        self.state.mutex.lockUncancelable(io);
        defer self.state.mutex.unlock(io);
        return self.state.finalized.get(at.get());
    }

    pub fn get_anchor(self: FakeMarshal) !?Anchor {
        const processed = self.state.processed;
        const block = self.finalized_at(.new(processed)) orelse return null;
        const handle = try harness_mod.digested(block);
        return .{ .processed = .{ .block = .new(processed) }, .block = handle };
    }

    pub fn get_block(self: FakeMarshal, identifier: Identifier) !?Digested {
        const block = self.finalized_at(identifier.height) orelse return null;
        return try harness_mod.digested(block);
    }

    pub fn get_info(self: FakeMarshal, identifier: Identifier) !?Info {
        const block = self.finalized_at(identifier.height) orelse return null;
        return .{ .height = block.height(), .digest = block.digest() };
    }

    pub fn subscribe_parent(self: FakeMarshal, child: *const Digested) !ParentReceiver {
        const pair = try oneshot.channel(Digested, gpa, io);
        var sender = pair.sender;
        self.state.mutex.lockUncancelable(io);
        const found = self.state.blocks.get(child.inner().parent());
        self.state.mutex.unlock(io);
        const block = found orelse {
            sender.deinit();
            return pair.receiver;
        };
        sender.send(try harness_mod.digested(block)) catch unreachable; // Receiver open.
        return pair.receiver;
    }

    pub fn prune(self: FakeMarshal, height: Height) !void {
        try self.state.prunes.append(gpa, height.get());
    }
};

const TestPlan = plan_mod.SyncPlan(
    consensus.simplex.scheme.ed25519.Scheme(Digest),
    struct {
        pub const Commitment = Digest;
    },
);

const P = struct {
    pub const App = harness_mod.TestApp;
    pub const Databases = Any.Shared;
    pub const Marshal = FakeMarshal;
    pub const Plan = TestPlan;
};

const Stateful = stateful_mod.Stateful(P);
const Mailbox = Stateful.Mailbox;

/// Storage, the plan, and the fake marshal, which outlive actor restarts.
const Node = struct {
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: metrics.Registry,
    marshal: MarshalState = .{},
    plan: TestPlan,

    /// `node` must not move afterwards.
    fn init(node: *Node) !void {
        node.storage = .init(gpa);
        errdefer node.storage.deinit();
        node.cache_ref = try .init(gpa, 101, 11);
        errdefer node.cache_ref.deinit();
        node.registry = metrics.Registry.init(gpa);
        errdefer node.registry.deinit();
        node.marshal = .{};
        errdefer node.marshal.deinit();
        try node.marshal.mark_finalized(TestBlock.genesis());
        node.plan = try TestPlan.init(node.env(), "stateful-test");
    }

    fn deinit(node: *Node) void {
        node.plan.deinit();
        node.marshal.deinit();
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

    fn db_config(node: *Node) Any.Config {
        return .{
            .merkle = .{
                .journal_partition = "stateful-journal",
                .metadata_partition = "stateful-metadata",
                .items_per_blob = 11,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .cache_ref = &node.cache_ref,
            },
            .log = .{
                .partition = "stateful-log",
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

/// A started actor and its mailbox.
const Running = struct {
    actor: *Stateful,
    mailbox: Mailbox,
    future: Io.Future(anyerror!void),

    fn start(node: *Node) !Running {
        const actor, const mailbox = try Stateful.init(gpa, io, .{
            .app = .{},
            .env = node.env(),
            .db_config = node.db_config(),
            .marshal = .{ .state = &node.marshal },
            .mailbox_size = 8,
            .plan = &node.plan,
        });
        return .{ .actor = actor, .mailbox = mailbox, .future = try actor.start() };
    }

    /// Closes the mailbox, which stops the actor, and returns how it ended.
    fn stop(running: *Running) !void {
        running.mailbox.deinit();
        const outcome = running.future.await(io);
        running.actor.deinit();
        try outcome;
    }

    fn propose(running: *Running, parent: TestBlock, view: u64) !?Digested {
        const context: TestBlock.Context = .{ .round = harness_mod.round(view) };
        var handles = [_]Digested{try harness_mod.digested(parent)};
        const ancestry = try Mailbox.Ancestry.from_blocks(gpa, &handles);
        return running.mailbox.propose({}, context, ancestry, {});
    }

    fn verify(running: *Running, blocks: []const TestBlock) !bool {
        var handles: [2]Digested = undefined;
        for (blocks, 0..) |block, index| handles[index] = try harness_mod.digested(block);
        const ancestry = try Mailbox.Ancestry.from_blocks(gpa, handles[0..blocks.len]);
        const context: TestBlock.Context = .{ .round = blocks[0].round };
        return running.mailbox.verify({}, context, ancestry);
    }

    fn finalize(running: *Running, block: TestBlock) !void {
        const handle = try Exact.handle(gpa, io);
        var waiter = handle.waiter;
        defer waiter.deinit();
        const update: Mailbox.Update = .{ .block = .{
            .block = try harness_mod.digested(block),
            .ack = handle.acknowledgement,
        } };
        try testing.expect(running.mailbox.report(update) != .closed);
        try waiter.wait();
    }
};

fn counter(databases: Any.Shared) !?u64 {
    const value = try harness_mod.read_applied(databases.readers(), harness_mod.counter_key());
    return if (value) |digest| harness_mod.digest_u64(digest) else null;
}

test "stateful actor: recovers, proposes, verifies, and finalizes" {
    var node: Node = undefined;
    try node.init();
    defer node.deinit();
    var running = try Running.start(&node);
    var stopped = false;
    defer if (!stopped) running.stop() catch {};

    const genesis = TestBlock.genesis();
    const built = (try running.propose(genesis, 1)).?;
    const block = built.inner().*;
    built.discard();
    try node.marshal.insert(block);
    try testing.expect(try running.verify(&.{ block, genesis }));
    const invalid = block.with_root(harness_mod.u64_digest(9));
    try testing.expect(!try running.verify(&.{ invalid, genesis }));
    // Recovery recorded completion at the processed (genesis) height.
    try testing.expectEqual(@as(?u64, 0), if (node.plan.completed()) |at| at.get() else null);

    try running.finalize(block);
    try node.marshal.mark_finalized(block);
    const databases = try running.mailbox.subscribe_databases();
    try testing.expectEqual(@as(?u64, 1), try counter(databases));
    stopped = true;
    try running.stop();
}

test "stateful actor: a restart recovers the processed state" {
    var node: Node = undefined;
    try node.init();
    defer node.deinit();
    const genesis = TestBlock.genesis();
    var first = try Running.start(&node);
    const built = (try first.propose(genesis, 1)).?;
    const block = built.inner().*;
    built.discard();
    try first.finalize(block);
    try first.stop();

    // Marshal's processed height advanced with the acknowledgement.
    try node.marshal.mark_finalized(block);
    node.marshal.processed = 1;
    var second = try Running.start(&node);
    var stopped = false;
    defer if (!stopped) second.stop() catch {};
    const databases = try second.mailbox.subscribe_databases();
    try testing.expectEqual(@as(?u64, 1), try counter(databases));
    try testing.expectEqual(@as(?u64, 1), if (node.plan.completed()) |at| at.get() else null);
    // The recovered anchor is block 1: proposing on it builds height 2.
    const next = (try second.propose(block, 2)).?;
    defer next.discard();
    try testing.expectEqual(@as(u64, 2), next.inner().height().get());
    stopped = true;
    try second.stop();
}

/// A minimal application over marshal's mock block, so the actor instantiates against the real
/// core mailbox (compile check of the surface the dkg validator uses).
const MarshalApp = struct {
    const marshal_harness = consensus.marshal.mocks.harness;
    pub const Block = marshal_harness.B;
    pub const Context = marshal_harness.Ctx;
    pub const Input = void;
    pub const Merkleized = Any.Merkleized;
    const Built = @import("../processor/processor.zig").Proposed(MarshalApp);

    pub fn sync_targets(_: *const Block) Any.SyncTarget {
        return Any.initial_sync_target();
    }

    pub fn process(
        _: *MarshalApp,
        _: Io,
        _: Context,
        _: anytype,
        batches: Any.Unmerkleized,
        _: anytype,
    ) !?Any.Merkleized {
        var owned = batches;
        return try owned.merkleize();
    }

    pub fn propose(
        _: *MarshalApp,
        _: Io,
        _: Context,
        _: anytype,
        batches: Any.Unmerkleized,
        _: void,
    ) !?Built {
        var owned = batches;
        owned.deinit();
        return null;
    }

    pub fn capture(
        _: *MarshalApp,
        _: Io,
        _: Context,
        _: *const Block,
        _: anytype,
        _: anytype,
    ) !void {}

    pub fn finalized(
        _: *MarshalApp,
        _: Io,
        _: Context,
        _: *const Block,
        _: void,
        _: anytype,
    ) !void {}
};

test "stateful actor: instantiates over marshal's core mailbox" {
    const H = consensus.marshal.mocks.harness.StandardHarness;
    const RealP = struct {
        pub const App = MarshalApp;
        pub const Databases = Any.Shared;
        pub const Marshal = consensus.marshal.core.Mailbox(H.Scheme, H.Variant);
        pub const Plan = TestPlan;
    };
    const RealStateful = stateful_mod.Stateful(RealP);
    _ = &RealStateful.init;
    _ = &RealStateful.run;
    _ = &RealStateful.deinit;
}
