//! commonware `glue/src/stateful/tests/mod.rs`'s targeted multi-database QMDB tests: a real
//! marshal (`actor/marshal_fixture_for.zig` over `multi_db.Block`), the `Stateful` actor over a
//! full and a compact QMDB (`multi_db.Databases`) running commonware's `GatedMultiApp`, and
//! marshal's `Deferred` wrapper, without consensus or a network.
//!
//! zigware differences: `Deferred.certify` returns its verdict rather than a future, so each
//! certification runs as its own concurrent task, started in the order commonware queues them;
//! commonware's `release.is_closed()` (the gated call was dropped) is the gate's
//! `Sender.is_closed`.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const broadcast = @import("broadcast");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const utils = @import("utils");
const multi = @import("multi_db.zig");
const single = @import("single_db.zig");
const targeted = @import("qmdb_targeted_test.zig");
const db = @import("../db/mod.zig");
const actor_mod = @import("../actor/mod.zig");
const fixture_for = @import("../actor/marshal_fixture_for.zig");
const processor_mod = @import("../actor/processor/processor.zig");
const processor_testing = @import("../actor/processor/testing.zig");
const pruning = @import("../actor/processor/pruning.zig");

const Ctx = runtime.deterministic.Context;
const Height = consensus.Height;
const Round = consensus.Round;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const Block = multi.Block;
const Databases = multi.Databases;
const Scheme = single.Scheme;
const Digested = broadcast.Digested(Block);
const ExactWaiter = utils.acknowledgement.ExactWaiter;
const Gate = processor_testing.Gate;
const GateHandles = processor_testing.GateHandles;
const CacheRef = runtime.buffer.paged.CacheRef;

/// The marshal fixture's types over the multi-database block and the mock scheme.
const Types = struct {
    pub const B = Block;
    pub const D = Digest;
    pub const K = single.Key;
    pub const S = Scheme;
    pub const Finalization = consensus.simplex.types.Finalization(S, D);
    pub const Validators = cryptography.certificate.mocks.Fixture(S);
    pub const Provider = cryptography.certificate.ConstantProvider(S);
    pub const Application = consensus.marshal.mocks.Application(B);

    pub fn genesis(gpa: Allocator) !Digested {
        const raw = Block.genesis();
        return Digested.precomputed(gpa, raw, raw.digest());
    }
};
const Marshal = fixture_for.FixtureFor(Types);
const MarshalFixture = Marshal.Fixture(Marshal.PrunableStores);
const Plan = actor_mod.SyncPlan(Scheme, Marshal.V);
const Stateful = actor_mod.Stateful(struct {
    pub const App = GatedMultiApp;
    pub const Databases = multi.Databases;
    pub const Marshal = MarshalFixture.Mailbox;
    pub const Plan = multi_targeted.Plan;
});
const StatefulMailbox = Stateful.Mailbox;
const multi_targeted = @This();

/// commonware `ApplicationGate`s for one application hook, taken one per call in call order;
/// a call with no gate left passes.
const Gates = struct {
    gpa: Allocator,
    io: Io,
    mutex: Io.Mutex = .init,
    queue: std.ArrayList(Gate) = .empty,

    fn deinit(gates: *Gates) void {
        for (gates.queue.items) |*gate| {
            gate.started.deinit();
            gate.release.deinit();
        }
        gates.queue.deinit(gates.gpa);
        gates.* = undefined;
    }

    /// Installs a gate for the next ungated call.
    fn add(gates: *Gates) !Held {
        const started = try utils.channel.oneshot.channel(void, gates.gpa, gates.io);
        errdefer {
            var sender = started.sender;
            sender.deinit();
            var receiver = started.receiver;
            receiver.deinit();
        }
        const release = try utils.channel.oneshot.channel(void, gates.gpa, gates.io);
        const gate: Gate = .{ .started = started.sender, .release = release.receiver };
        gates.mutex.lockUncancelable(gates.io);
        defer gates.mutex.unlock(gates.io);
        gates.queue.append(gates.gpa, gate) catch |err| {
            var sender = release.sender;
            sender.deinit();
            var receiver = release.receiver;
            receiver.deinit();
            return err;
        };
        return .{ .handles = .{ .started = started.receiver, .release = release.sender } };
    }

    /// Holds the call on the next gate, if any, until the test releases or drops it.
    fn pass(gates: *Gates) Io.Cancelable!void {
        gates.mutex.lockUncancelable(gates.io);
        const next: ?Gate = if (gates.queue.items.len > 0) gates.queue.orderedRemove(0) else null;
        gates.mutex.unlock(gates.io);
        var gate = next orelse return;
        defer gate.release.deinit();
        // The test may already have dropped its handles; the call then just passes.
        gate.started.send({}) catch {};
        gate.release.recv() catch |err| switch (err) {
            error.Closed => {},
            error.Canceled => return error.Canceled,
        };
    }
};

/// The test's side of one gate.
const Held = struct {
    handles: GateHandles,
    released: bool = false,

    /// Waits until a call reaches the gate.
    fn started(held: *Held) !void {
        try held.handles.started.recv();
    }

    fn reached(held: *const Held) bool {
        return held.handles.started.is_ready();
    }

    /// Whether the gated call is still alive (commonware `!release.is_closed()`).
    fn retained(held: *const Held) bool {
        assert(!held.released);
        return !held.handles.release.is_closed();
    }

    /// Releases the gated call; fails when the call was dropped.
    fn open(held: *Held) !void {
        assert(!held.released);
        held.released = true;
        try held.handles.release.send({});
    }

    fn deinit(held: *Held) void {
        if (!held.released) held.handles.release.deinit();
        held.handles.started.deinit();
        held.* = undefined;
    }
};

const AppGates = struct {
    propose: Gates,
    process: Gates,
    finalize: Gates,

    fn init(gpa: Allocator, io: Io) AppGates {
        return .{
            .propose = .{ .gpa = gpa, .io = io },
            .process = .{ .gpa = gpa, .io = io },
            .finalize = .{ .gpa = gpa, .io = io },
        };
    }

    fn deinit(gates: *AppGates) void {
        gates.propose.deinit();
        gates.process.deinit();
        gates.finalize.deinit();
    }
};

fn deinit_batches(batches: Databases.Unmerkleized) void {
    var owned = batches;
    inline for (&owned) |*batch| batch.deinit();
}

/// `multi_db.App` with gates before each build and execution and after each finalization
/// hook (commonware `GatedMultiApp`).
const GatedMultiApp = struct {
    pub const Block = multi.Block;
    pub const Context = multi.Block.Context;
    pub const Input = void;
    pub const Merkleized = Databases.Merkleized;
    const Built = processor_mod.Proposed(GatedMultiApp);

    inner: multi.App = .{},
    gates: *AppGates,

    pub fn sync_targets(block: *const multi.Block) Databases.SyncTargets {
        return multi.App.sync_targets(block);
    }

    pub fn propose(
        app: *GatedMultiApp,
        io: Io,
        context: GatedMultiApp.Context,
        ancestry: anytype,
        batches: Databases.Unmerkleized,
        input: void,
    ) !?Built {
        app.gates.propose.pass() catch |err| {
            deinit_batches(batches);
            return err;
        };
        const built = try app.inner.propose(io, context, ancestry, batches, input) orelse
            return null;
        return .{ .block = built.block, .merkleized = built.merkleized };
    }

    pub fn process(
        app: *GatedMultiApp,
        io: Io,
        context: GatedMultiApp.Context,
        ancestry: anytype,
        batches: Databases.Unmerkleized,
        finality: anytype,
    ) !?Databases.Merkleized {
        app.gates.process.pass() catch |err| {
            deinit_batches(batches);
            return err;
        };
        return app.inner.process(io, context, ancestry, batches, finality);
    }

    pub fn capture(
        app: *GatedMultiApp,
        io: Io,
        context: GatedMultiApp.Context,
        block: *const multi.Block,
        batches: anytype,
        readers: anytype,
    ) !void {
        return app.inner.capture(io, context, block, batches, readers);
    }

    pub fn finalized(
        app: *GatedMultiApp,
        io: Io,
        context: GatedMultiApp.Context,
        block: *const multi.Block,
        captured: void,
        readers: anytype,
    ) !void {
        try app.inner.finalized(io, context, block, captured, readers);
        try app.gates.finalize.pass();
    }
};

/// The stateful mailbox as `Deferred`'s application (which passes no upstream input).
const Adapter = struct {
    mailbox: StatefulMailbox,

    pub fn propose(
        self: *Adapter,
        ctx: anytype,
        context: Block.Context,
        ancestry: anytype,
    ) anyerror!?Digested {
        return self.mailbox.propose(ctx, context, ancestry, {});
    }

    pub fn verify(
        self: *Adapter,
        ctx: anytype,
        context: Block.Context,
        ancestry: anytype,
    ) anyerror!bool {
        return self.mailbox.verify(ctx, context, ancestry);
    }

    pub fn clone(self: *const Adapter) Adapter {
        return .{ .mailbox = self.mailbox.clone() };
    }

    pub fn deinit(self: *Adapter) void {
        self.mailbox.deinit();
        self.* = undefined;
    }
};
const Wrapper = consensus.marshal.standard.Deferred(
    Ctx,
    Scheme,
    Adapter,
    Block,
    consensus.types.FixedEpocher,
);

fn ranged_targets(batches: *const Databases.Merkleized) [2]multi.QmdbA.SyncTarget {
    const bounds_a = &batches[0].inner.bounds;
    const bounds_b = batches[1].bounds();
    return .{
        .init(batches[0].root(), bounds_a.inactivity_floor, bounds_a.tip.size),
        .init(batches[1].root(), bounds_b.inactivity_floor, bounds_b.tip.size),
    };
}

/// Blocks `1..=count` over genesis, each executed on scratch QMDBs from its parent's
/// speculative batches, in view `height` (commonware `build_multi_chain`).
fn build_multi_chain(ctx: Ctx, blocks: []Block) !void {
    const gpa = ctx.gpa();
    var cache: CacheRef = try .init(gpa, targeted.page_size, targeted.page_cache_size);
    defer cache.deinit();
    var config: multi.Spec.DbConfig = try .init(gpa, "certify-multi-chain-builder", &cache);
    defer config.deinit(gpa);
    const builder_env = targeted.env(ctx, "multi_chain_builder");
    var databases = try Databases.open(builder_env, config.config(), null);
    defer databases.deinit();
    // Descendant batches read their uncommitted ancestry, so the whole chain stays alive.
    const speculative = try gpa.alloc(Databases.Merkleized, blocks.len);
    defer gpa.free(speculative);
    var made: usize = 0;
    defer for (speculative[0..made]) |*batches| {
        db.deinit_merkleized(Databases.Merkleized, batches);
    };
    var batches = try databases.new_batches();
    var parent = Block.genesis();
    const leader = cryptography.ed25519.PrivateKey.from_seed(0).public_key();
    for (blocks, 1..) |*block, height| {
        const at: Height = .new(height);
        speculative[made] = try multi.App.execute(batches, at);
        made += 1;
        const targets = ranged_targets(&speculative[made - 1]);
        const context: Block.Context = .{
            .round = .new(.zero(), .new(height)),
            .leader = leader,
            .parent = .{ parent.context().round.view, parent.digest() },
        };
        block.* = .init(context, parent.digest(), at, targets[0], targets[1]);
        parent = block.*;
        if (height < blocks.len) batches = try Databases.fork_batches(&speculative[made - 1]);
    }
    assert(made == blocks.len);
}

const NodeOptions = struct {
    prefix: []const u8,
    namespace: []const u8,
    prune_config: ?pruning.PruneConfig = null,
};

/// Marshal, the gated stateful actor, and the deferred wrapper over them (commonware's test
/// body setup). Must not move once started.
const Node = struct {
    gpa: Allocator,
    validators: Types.Validators,
    cache: CacheRef,
    marshal: MarshalFixture,
    plan: Plan,
    db_config: multi.Spec.DbConfig,
    gates: AppGates,
    prng: std.Random.DefaultPrng,
    actor: *Stateful,
    mailbox: StatefulMailbox,
    future: Io.Future(anyerror!void),
    /// Served once recovery has opened them (commonware's startup `subscribe_databases`).
    databases: Databases,
    wrapper: *Wrapper,

    fn start(node: *Node, ctx: Ctx, comptime options: NodeOptions) !void {
        const gpa = ctx.gpa();
        node.gpa = gpa;
        var rng = utils.rng.test_rng();
        const namespace = options.namespace;
        const fixture = consensus.simplex.mocks.scheme.fixture;
        node.validators = try fixture(Digest, gpa, &rng, namespace, 1);
        errdefer node.validators.deinit(gpa);
        node.cache = try .init(gpa, targeted.page_size, targeted.page_cache_size);
        errdefer node.cache.deinit();
        const prefix = options.prefix;
        node.marshal = try .init(ctx.child("marshal"), prefix ++ "-marshal", &node.validators, .{});
        errdefer node.marshal.abort();
        node.plan = try .init(targeted.env(ctx, "plan"), prefix ++ "-stateful");
        errdefer node.plan.deinit();
        node.db_config = try .init(gpa, prefix ++ "-stateful", &node.cache);
        errdefer node.db_config.deinit(gpa);
        node.gates = .init(gpa, ctx.io());
        errdefer node.gates.deinit();
        node.prng = .init(0);
        try node.start_actor(ctx, options.prune_config);
    }

    fn start_actor(node: *Node, ctx: Ctx, prune_config: ?pruning.PruneConfig) !void {
        node.actor, node.mailbox = try Stateful.init(node.gpa, ctx.io(), .{
            .app = .{ .gates = &node.gates },
            .env = targeted.env(ctx, "stateful"),
            .db_config = node.db_config.config(),
            .marshal = node.marshal.mailbox.clone(),
            .mailbox_size = 1,
            .plan = &node.plan,
            .prune_config = prune_config,
            .random = node.prng.random(),
            .floor = node.marshal.floor,
        });
        node.future = try node.actor.start();
        node.databases = try node.mailbox.subscribe_databases();
        const length = utils.NonZero(u64).init(std.math.maxInt(u64)).?;
        const adapter: Adapter = .{ .mailbox = node.mailbox.clone() };
        const marshal = node.marshal.mailbox.clone();
        node.wrapper = try Wrapper.create(ctx.child("deferred"), adapter, marshal, .new(length));
    }

    fn stop(node: *Node) void {
        node.wrapper.destroy();
        node.mailbox.deinit();
        const outcome = node.future.await(node.actor.io);
        node.actor.deinit();
        outcome catch {};
        node.gates.deinit();
        node.db_config.deinit(node.gpa);
        node.plan.deinit();
        node.marshal.abort();
        node.cache.deinit();
        node.validators.deinit(node.gpa);
        node.* = undefined;
    }

    /// Marks every block verified in marshal.
    fn verify_all(node: *Node, blocks: []const Block) !void {
        for (blocks) |*block| {
            const digested = try Digested.precomputed(node.gpa, block.*, block.digest());
            try testing.expect(try node.marshal.mailbox.verified(block.context().round, digested));
        }
    }

    /// Certifies `blocks` one at a time, so their batches are cached (commonware's priming).
    fn prime(node: *Node, io: Io, blocks: []const Block) !void {
        for (blocks) |*block| {
            const verdict = try node.wrapper.certify(io, block.context().round, block.digest());
            try testing.expectEqual(@as(?bool, true), verdict);
        }
    }

    /// Reports `blocks` as finalized to the stateful actor, returning their acknowledgements.
    fn report_finalized(node: *Node, blocks: []const Block, waiters: []ExactWaiter) !void {
        assert(blocks.len == waiters.len);
        for (blocks, waiters) |*block, *waiter| {
            const handle = try utils.acknowledgement.Exact.handle(node.gpa, node.actor.io);
            waiter.* = handle.waiter;
            const update: StatefulMailbox.Update = .{ .block = .{
                .block = try Digested.precomputed(node.gpa, block.*, block.digest()),
                .ack = handle.acknowledgement,
            } };
            try testing.expect(node.mailbox.report(update) != .closed);
        }
    }

    /// Reports `blocks` as finalized and waits until each is durable.
    fn finalize_durably(node: *Node, blocks: []const Block) !void {
        var waiters: [8]ExactWaiter = undefined;
        assert(blocks.len <= waiters.len);
        try node.report_finalized(blocks, waiters[0..blocks.len]);
        defer for (waiters[0..blocks.len]) |*waiter| waiter.deinit();
        for (waiters[0..blocks.len]) |*waiter| try waiter.wait();
    }

    /// Both committed targets equal `block`'s sync targets.
    fn expect_committed(node: *Node, block: *const Block) !void {
        const committed = try node.databases.committed_targets();
        const expected = GatedMultiApp.sync_targets(block);
        const TargetA = @TypeOf(expected[0]);
        const TargetB = @TypeOf(expected[1]);
        try testing.expect(db.targets_eql(TargetA, &committed[0], &expected[0]));
        try testing.expect(db.targets_eql(TargetB, &committed[1], &expected[1]));
    }
};

/// One certification run beside the test, recording when it returns.
const Certification = struct {
    done: bool = false,
    verdict: ?bool = null,

    fn run(
        self: *Certification,
        wrapper: *Wrapper,
        io: Io,
        block: *const Block,
    ) Io.Cancelable!void {
        defer self.done = true;
        self.verdict = try wrapper.certify(io, block.context().round, block.digest());
    }
};

/// Certifications of `blocks[order[i]]`, started concurrently in `order`.
const Certifications = struct {
    slots: [4]Certification = @splat(.{}),
    futures: [4]Io.Future(Io.Cancelable!void) = undefined,
    started: usize = 0,

    fn start(
        self: *Certifications,
        io: Io,
        wrapper: *Wrapper,
        blocks: []const Block,
        order: []const usize,
    ) !void {
        assert(self.started + order.len <= self.futures.len);
        for (order) |index| {
            const args = .{ &self.slots[self.started], wrapper, io, &blocks[index] };
            self.futures[self.started] = try io.concurrent(Certification.run, args);
            self.started += 1;
        }
    }

    fn any_done(self: *const Certifications) bool {
        for (self.slots[0..self.started]) |slot| if (slot.done) return true;
        return false;
    }

    /// Awaits every certification and expects each verdict to be true.
    fn expect_all_true(self: *Certifications, io: Io) !void {
        var results: [4]Io.Cancelable!void = undefined;
        const count = self.started;
        for (self.futures[0..count], results[0..count]) |*future, *result| {
            result.* = future.await(io);
        }
        self.started = 0;
        for (results[0..count], self.slots[0..count]) |result, slot| {
            try result;
            try testing.expectEqual(@as(?bool, true), slot.verdict);
        }
    }

    fn cancel(self: *Certifications, io: Io) void {
        for (self.futures[0..self.started]) |*future| future.cancel(io) catch {};
        self.started = 0;
    }
};

pub fn run(comptime body: fn (Ctx) anyerror!void) !void {
    return targeted.run(body);
}

/// Holds `blocks[3]`'s execution under certifications of 5, 3, and 4 (only block 3 can run
/// before block 3's state exists), then runs the first finalization into its gate.
fn overlapping_finalizations(ctx: Ctx) !void {
    const io = ctx.io();
    var blocks: [6]Block = undefined;
    try build_multi_chain(ctx, &blocks);
    var node: Node = undefined;
    try node.start(ctx, .{
        .prefix = "certify-multi-qmdb",
        .namespace = "_COMMONWARE_GLUE_MULTI_QMDB_OVERLAPPING_FINALIZATION",
    });
    defer node.stop();
    try node.verify_all(&blocks);
    // Cache the batches that will be finalized, so the held descendant verification does not
    // own their replay.
    try node.prime(io, blocks[0..3]);
    var process = try node.gates.process.add();
    defer process.deinit();
    var finalize = try node.gates.finalize.add();
    defer finalize.deinit();
    var certifications: Certifications = .{};
    defer certifications.cancel(io);
    try certifications.start(io, node.wrapper, &blocks, &.{ 5, 3, 4 });
    try process.started();
    try testing.expect(!certifications.any_done());
    var waiters: [3]ExactWaiter = undefined;
    try node.report_finalized(blocks[0..1], waiters[0..1]);
    var reported: usize = 1;
    defer for (waiters[0..reported]) |*waiter| waiter.deinit();
    try finalize.started();
    try testing.expect(process.retained());
    // Finalizations queued behind the active one must not stop descendant processing:
    // releasing the process gate succeeds only while that processing is still alive.
    try node.report_finalized(blocks[1..3], waiters[1..3]);
    reported = 3;
    try finalize.open();
    for (&waiters) |*waiter| try waiter.wait();
    try process.open();
    try certifications.expect_all_true(io);
    try node.finalize_durably(blocks[3..]);
    try node.expect_committed(&blocks[5]);
}

// commonware `overlapping_finalizations_complete_on_multi_qmdb`: on a full and a compact QMDB,
// finalizations queued behind a gated finalization keep a held descendant verification alive;
// every finalization becomes durable, every certification passes, and both committed targets
// converge on the tip.
test "stateful tests: overlapping finalizations complete on multi qmdb" {
    try run(overlapping_finalizations);
}

/// An ancestry yielding one block (commonware `ancestry::from_iter([block])`).
const OneAncestry = struct {
    pub const Block = multi.Block;
    block: ?Digested,

    pub fn peek(self: *const OneAncestry) ?*const Digested {
        return if (self.block) |*block| block else null;
    }

    pub fn next(self: *OneAncestry) !?Digested {
        const block = self.block;
        self.block = null;
        return block;
    }

    pub fn clone(self: *const OneAncestry) !OneAncestry {
        return .{ .block = if (self.block) |block| block.clone() else null };
    }

    pub fn deinit(self: *OneAncestry) void {
        if (self.block) |*block| block.deinit();
        self.* = undefined;
    }
};

/// A proposal run beside the test until cancelled.
fn propose_on(mailbox: *StatefulMailbox, context: Block.Context, parent: Digested) void {
    var built = (mailbox.propose({}, context, OneAncestry{ .block = parent }, {}) catch
        return) orelse return;
    built.deinit();
}

/// A build on `blocks[2]`'s cached state holds its gate while the first three finalizations
/// queue behind it and descendant verifications start.
fn deferred_finalizations(ctx: Ctx) !void {
    const io = ctx.io();
    const gpa = ctx.gpa();
    var blocks: [6]Block = undefined;
    try build_multi_chain(ctx, &blocks);
    var node: Node = undefined;
    try node.start(ctx, .{
        .prefix = "deferred-multi-qmdb",
        .namespace = "_COMMONWARE_GLUE_MULTI_QMDB_DEFERRED_FINALIZATION",
    });
    defer node.stop();
    try node.verify_all(&blocks);
    try node.prime(io, blocks[0..3]);
    var propose = try node.gates.propose.add();
    defer propose.deinit();
    var process = try node.gates.process.add();
    defer process.deinit();
    var finalize = try node.gates.finalize.add();
    defer finalize.deinit();
    var proposer = node.mailbox.clone();
    defer proposer.deinit();
    const parent = try Digested.precomputed(gpa, blocks[2], blocks[2].digest());
    var proposal = try io.concurrent(propose_on, .{ &proposer, blocks[3].context(), parent });
    var proposing = true;
    defer if (proposing) proposal.cancel(io);
    try propose.started();
    var waiters: [3]ExactWaiter = undefined;
    try node.report_finalized(blocks[0..3], &waiters);
    defer for (&waiters) |*waiter| waiter.deinit();
    // Descendant verifications queued after them start during the proposal; only `blocks[3]`
    // can be processed while the gate holds it.
    var certifications: Certifications = .{};
    defer certifications.cancel(io);
    try certifications.start(io, node.wrapper, &blocks, &.{ 5, 3, 4 });
    try process.started();
    for (&waiters) |*waiter| try testing.expect(waiter.poll() == null);
    try deferred_finalizations_finish(&node, &blocks, .{
        .proposal = &proposal,
        .proposing = &proposing,
        .process = &process,
        .finalize = &finalize,
        .waiters = &waiters,
        .certifications = &certifications,
    }, io);
}

const DeferredState = struct {
    proposal: *Io.Future(void),
    proposing: *bool,
    process: *Held,
    finalize: *Held,
    waiters: *[3]ExactWaiter,
    certifications: *Certifications,
};

/// Ending the proposal runs the first finalization, which keeps the compatible descendant
/// verifications alive through every finalization.
fn deferred_finalizations_finish(
    node: *Node,
    blocks: *const [6]Block,
    state: DeferredState,
    io: Io,
) !void {
    state.proposing.* = false;
    state.proposal.cancel(io);
    try state.finalize.started();
    try testing.expect(state.process.retained());
    try state.finalize.open();
    for (state.waiters) |*waiter| try waiter.wait();
    try state.process.open();
    try state.certifications.expect_all_true(io);
    // The verified descendants finalize as well.
    try node.finalize_durably(blocks[3..]);
    try node.expect_committed(&blocks[5]);
}

// commonware `deferred_finalizations_keep_verifications_on_multi_qmdb`: on a full and a
// compact QMDB, descendant verifications queued behind finalizations that a proposal build
// defers start during the build; once it ends, the first finalization keeps them active,
// every finalization becomes durable, every certification passes, and both targets converge.
test "stateful tests: deferred finalizations keep verifications on multi qmdb" {
    try run(deferred_finalizations);
}

/// DB-A's retained log range.
fn full_bounds(databases: Databases) !struct { u64, u64 } {
    var guard = try databases.members[0].read();
    defer guard.deinit();
    const bounds = guard.get().inner.bounds();
    return .{ bounds.start, bounds.end };
}

/// Block 5's held execution and block 4's held finalization overlap the prune the latter
/// schedules; a second process gate catches a repeated execution of block 5.
fn pruning_joins_verification(ctx: Ctx) !void {
    const io = ctx.io();
    var blocks: [5]Block = undefined;
    try build_multi_chain(ctx, &blocks);
    var node: Node = undefined;
    // The first prune runs at block 4 and targets block 3's floor, which crosses the full
    // QMDB's first journal blob.
    try node.start(ctx, .{
        .prefix = "prune-overlap-multi-qmdb",
        .namespace = "_COMMONWARE_GLUE_MULTI_QMDB_PRUNE_OVERLAP",
        .prune_config = .{
            .maintenance_interval = 1,
            .retained_marshal_blocks = 2,
            .retained_qmdb_blocks = 0,
        },
    });
    defer node.stop();
    try node.verify_all(&blocks);
    // Keep the first four batches available, so block 5's verification executes only block 5.
    try node.prime(io, blocks[0..4]);
    for (blocks[0..3]) |*block| try node.finalize_durably(block[0..1]);
    const expected_floor = blocks[2].target_a.start;
    try testing.expect(expected_floor > 0);
    var first = try node.gates.process.add();
    defer first.deinit();
    var duplicate = try node.gates.process.add();
    defer duplicate.deinit();
    var finalize = try node.gates.finalize.add();
    defer finalize.deinit();
    var certification: Certifications = .{};
    defer certification.cancel(io);
    try certification.start(io, node.wrapper, &blocks, &.{4});
    try first.started();
    try testing.expect(!certification.any_done());
    var finalized: [1]ExactWaiter = undefined;
    try node.report_finalized(blocks[3..4], &finalized);
    defer finalized[0].deinit();
    try finalize.started();
    try testing.expect(first.retained());
    try pruning_joins_finish(&node, &blocks, .{
        .first = &first,
        .duplicate = &duplicate,
        .finalize = &finalize,
        .finalized = &finalized[0],
        .certification = &certification,
    }, io);
}

const PruneState = struct {
    first: *Held,
    duplicate: *Held,
    finalize: *Held,
    finalized: *ExactWaiter,
    certification: *Certifications,
};

/// Pruning waits for both the held execution and a held DB-A reader before removing history,
/// and block 5 executes once.
fn pruning_joins_finish(node: *Node, blocks: *const [5]Block, state: PruneState, io: Io) !void {
    var reader = try node.databases.members[0].read();
    var reading = true;
    defer if (reading) reader.deinit();
    const before = reader.get().inner.bounds();
    try testing.expectEqual(@as(u64, 0), before.start);
    try state.finalize.open();
    // Block 4's acknowledgement follows its barrier, after which the prune is the actor's next
    // step; the held execution keeps it from running.
    try state.finalized.wait();
    try testing.expect(state.first.retained());
    const held = reader.get().inner.bounds();
    try testing.expectEqual(before.start, held.start);
    try testing.expectEqual(before.end, held.end);
    try testing.expect(!state.certification.any_done());
    // Beyond commonware, which releases the execution before the reader: with only the
    // execution held, the prune still waits (a prune that ignored it would run once the reader
    // is gone, as the database lock is all that holds it).
    reading = false;
    reader.deinit();
    try io.sleep(.fromMilliseconds(10), .awake);
    try testing.expectEqual(.{ before.start, before.end }, try full_bounds(node.databases));
    try state.first.open();
    try state.certification.expect_all_true(io);
    try testing.expect(!state.duplicate.reached());
    // The verification answers only once the prune has run and admission reopens.
    const after_start, const after_end = try full_bounds(node.databases);
    try testing.expect(after_start > before.start);
    try testing.expect(after_start <= blocks[2].target_a.start);
    try testing.expectEqual(before.end, after_end);
    try node.expect_committed(&blocks[3]);
}

// commonware `pruning_joins_verification_on_real_qmdbs`: a prune scheduled by a finalization
// waits for a same-branch verification's held execution and for a held reader, keeps the full
// QMDB's history until both end, then discards history up to the requested floor, preserving
// the tip, while block 5 executes exactly once.
test "stateful tests: pruning joins verification on real qmdbs" {
    try run(pruning_joins_verification);
}
