//! commonware `glue/src/stateful/tests/mod.rs`'s targeted single-database QMDB tests: a real
//! marshal (`actor/marshal_fixture_for.zig` over the e2e `Block`), the `Stateful` actor over a
//! real QMDB, and marshal's `Deferred` wrapper, without consensus or a network.
//!
//! zigware differences: `Deferred.certify` returns its verdict rather than a future, so each
//! certification runs as its own concurrent task, started in the order commonware queues them.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Io = std.Io;
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const utils = @import("utils");
const single = @import("single_db.zig");
const db = @import("../db/mod.zig");
const actor_mod = @import("../actor/mod.zig");
const fixture_for = @import("../actor/marshal_fixture_for.zig");
const wait_until = @import("../actor/marshal_fixture.zig").wait_until;

const Ctx = runtime.deterministic.Context;
const Height = consensus.Height;
const Round = consensus.Round;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const Block = single.Block;
const Any = single.Any;
const Scheme = single.Scheme;
const Digested = single.Digested;

/// The marshal fixture's types over the e2e block and the mock scheme.
pub const Types = struct {
    pub const B = Block;
    pub const D = Digest;
    pub const K = single.Key;
    pub const S = Scheme;
    pub const Finalization = consensus.simplex.types.Finalization(S, D);
    pub const Validators = cryptography.certificate.mocks.Fixture(S);
    pub const Provider = cryptography.certificate.ConstantProvider(S);
    pub const Application = consensus.marshal.mocks.Application(B);

    pub fn genesis(gpa: std.mem.Allocator) !Digested {
        const raw = Block.genesis();
        return Digested.precomputed(gpa, raw, raw.digest());
    }
};
pub const Marshal = fixture_for.FixtureFor(Types);
pub const MarshalFixture = Marshal.Fixture(Marshal.PrunableStores);
pub const Plan = actor_mod.SyncPlan(Scheme, Marshal.V);
pub const Stateful = actor_mod.Stateful(struct {
    pub const App = single.App;
    pub const Databases = Any.Shared;
    pub const Marshal = MarshalFixture.Mailbox;
    pub const Plan = qmdb_targeted.Plan;
});
pub const StatefulMailbox = Stateful.Mailbox;
const qmdb_targeted = @This();

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

pub const page_size: u16 = 1024;
pub const page_cache_size: u32 = 10;
const io_buffer_size: usize = 2048;

pub fn env(ctx: Ctx, label: []const u8) db.Env {
    return .{
        .gpa = ctx.gpa(),
        .io = ctx.io(),
        .storage = ctx.storage,
        .scope = ctx.scope.child(label),
    };
}

/// The QMDB configuration over partitions named `prefix ++ suffix` (commonware `qmdb_config`).
pub fn qmdb_config(comptime prefix: []const u8, cache: *runtime.buffer.paged.CacheRef) Any.Config {
    return .{
        .merkle = .{
            .journal_partition = prefix ++ "-qmdb-mmr-journal",
            .metadata_partition = prefix ++ "-qmdb-mmr-metadata",
            .items_per_blob = 11,
            .write_buffer = io_buffer_size,
            .replay_buffer = io_buffer_size,
            .cache_ref = cache,
        },
        .log = .{
            .partition = prefix ++ "-qmdb-log-journal",
            .items_per_blob = 7,
            .cache_ref = cache,
            .write_buffer = io_buffer_size,
            .replay_buffer = io_buffer_size,
        },
        .translator = .{},
        .init_cache = 1024,
    };
}

/// `single.App`'s block execution: increment `counter` and write `height -> height`.
fn execute(batches: Any.Unmerkleized, at: Height) !Any.Merkleized {
    var batch = batches;
    errdefer batch.deinit();
    const key = single.counter_key();
    const current = if (try batch.get(&key)) |value| single.digest_to_u64(value) else 0;
    try batch.write(key, single.u64_to_digest(current + 1));
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, at.get(), .big);
    try batch.write(Sha256.hash(&.{&bytes}), single.u64_to_digest(at.get()));
    return batch.merkleize();
}

/// Blocks `1..=count` over genesis, each executed on a scratch QMDB from its parent's
/// speculative batch, in view `height` (commonware `build_chain`).
pub fn build_chain(ctx: Ctx, blocks: []Block) !void {
    const gpa = ctx.gpa();
    var cache: runtime.buffer.paged.CacheRef = try .init(gpa, page_size, page_cache_size);
    defer cache.deinit();
    const databases = try Any.Shared.open(env(ctx, "chain_builder"), qmdb_config(
        "certify-chain-builder",
        &cache,
    ), null);
    defer databases.deinit();
    // Descendant batches read their uncommitted ancestry, so the whole chain stays alive.
    const speculative = try gpa.alloc(Any.Merkleized, blocks.len);
    defer gpa.free(speculative);
    var made: usize = 0;
    defer for (speculative[0..made]) |*batch| batch.deinit();
    var batches = try databases.new_batches();
    var parent = Block.genesis();
    const leader = cryptography.ed25519.PrivateKey.from_seed(0).public_key();
    for (blocks, 1..) |*block, height| {
        const at: Height = .new(height);
        speculative[made] = try execute(batches, at);
        made += 1;
        const merkleized = &speculative[made - 1];
        const bounds = &merkleized.inner.bounds;
        const target: Any.SyncTarget =
            .init(merkleized.root(), bounds.inactivity_floor, bounds.tip.size);
        const context: Block.Context = .{
            .round = .new(.zero(), .new(height)),
            .leader = leader,
            .parent = .{ parent.context().round.view, parent.digest() },
        };
        block.* = .init(context, parent.digest(), at, target);
        parent = block.*;
        if (height < blocks.len) batches = try Any.Shared.fork_batches(merkleized);
    }
    assert(made == blocks.len);
}

/// Marshal, the stateful actor, and the deferred wrapper over them (commonware's test body
/// setup). Must not move once started.
const Node = struct {
    gpa: std.mem.Allocator,
    validators: Types.Validators,
    cache: runtime.buffer.paged.CacheRef,
    marshal: MarshalFixture,
    plan: Plan,
    actor: *Stateful,
    mailbox: StatefulMailbox,
    future: Io.Future(anyerror!void),
    wrapper: *Wrapper,

    fn start(node: *Node, ctx: Ctx, comptime prefix: []const u8) !void {
        const gpa = ctx.gpa();
        node.gpa = gpa;
        var rng = utils.rng.test_rng();
        node.validators = try consensus.simplex.mocks.scheme.fixture(Digest, gpa, &rng, prefix, 1);
        errdefer node.validators.deinit(gpa);
        node.cache = try .init(gpa, page_size, page_cache_size);
        errdefer node.cache.deinit();
        node.marshal = try .init(ctx.child("marshal"), prefix ++ "-marshal", &node.validators, .{});
        errdefer node.marshal.abort();
        node.plan = try .init(env(ctx, "plan"), prefix ++ "-stateful");
        errdefer node.plan.deinit();
        node.actor, node.mailbox = try Stateful.init(gpa, ctx.io(), .{
            .app = .{},
            .env = env(ctx, "stateful"),
            .db_config = qmdb_config(prefix ++ "-stateful", &node.cache),
            .marshal = node.marshal.mailbox.clone(),
            .mailbox_size = 1,
            .plan = &node.plan,
            .floor = node.marshal.floor,
        });
        node.future = try node.actor.start();
        // Recovery has opened the databases once they are served.
        _ = try node.mailbox.subscribe_databases();
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
        node.plan.deinit();
        node.marshal.abort();
        node.cache.deinit();
        node.validators.deinit(node.gpa);
        node.* = undefined;
    }
};

fn certify(wrapper: *Wrapper, io: Io, round: Round, digest: Digest) Io.Cancelable!?bool {
    return wrapper.certify(io, round, digest);
}

/// Certifies `blocks[order[i]]` concurrently in `order`, expecting every verdict to be true.
fn certify_all(io: Io, wrapper: *Wrapper, blocks: []const Block, order: []const usize) !void {
    var futures: [8]Io.Future(Io.Cancelable!?bool) = undefined;
    assert(order.len <= futures.len);
    var started: usize = 0;
    defer for (futures[0..started]) |*future| {
        _ = future.cancel(io) catch {};
    };
    for (order) |index| {
        const block = &blocks[index];
        const args = .{ wrapper, io, block.context().round, block.digest() };
        futures[started] = try io.concurrent(certify, args);
        started += 1;
    }
    var verdicts: [8]?bool = undefined;
    for (futures[0..started], verdicts[0..started]) |*future, *verdict| {
        verdict.* = try future.await(io);
    }
    started = 0;
    for (verdicts[0..order.len]) |verdict| try testing.expectEqual(@as(?bool, true), verdict);
}

pub fn run(comptime body: fn (Ctx) anyerror!void) !void {
    try runtime.deterministic.soak(testing.allocator, .{
        .timeout_ns = 10 * std.time.ns_per_s,
    }, {}, struct {
        fn run_round(_: void, runner: *runtime.deterministic.Runner) anyerror!void {
            try try runner.start_context(body, .{});
        }
    }.run_round);
}

fn out_of_order_certifications(ctx: Ctx) !void {
    var blocks: [6]Block = undefined;
    try build_chain(ctx, &blocks);
    var node: Node = undefined;
    try node.start(ctx, "certify-qmdb");
    defer node.stop();
    for (&blocks) |*block| {
        const digested = try Digested.precomputed(ctx.gpa(), block.*, block.digest());
        try testing.expect(try node.marshal.mailbox.verified(block.context().round, digested));
    }
    try certify_all(ctx.io(), node.wrapper, &blocks, &.{ 5, 1, 4, 0, 3, 2 });
}

// commonware `out_of_order_certifications_complete_on_qmdb`: certifications of a verified
// six-block chain, requested out of height order, all complete with a true verdict.
test "stateful tests: out-of-order certifications complete on qmdb" {
    try run(out_of_order_certifications);
}

/// An ancestry that never yields a block (commonware `PendingAncestry`): the proposal it
/// carries waits for its parent until cancelled.
const PendingAncestry = struct {
    pub const Block = qmdb_targeted.Block;
    io: Io,

    pub fn peek(_: *const PendingAncestry) ?*const Digested {
        return null;
    }

    pub fn next(self: *PendingAncestry) !?Digested {
        // Each pass sleeps an hour; only cancellation ends the loop.
        while (true) try self.io.sleep(.fromSeconds(3_600), .awake);
    }

    pub fn clone(self: *const PendingAncestry) !PendingAncestry {
        return self.*;
    }

    pub fn deinit(_: *PendingAncestry) void {}
};

/// A proposal run beside the test, recording when it returns.
const Proposal = struct {
    done: bool = false,

    fn run(self: *Proposal, mailbox: *StatefulMailbox, io: Io, context: Block.Context) void {
        defer self.done = true;
        var built = (mailbox.propose({}, context, PendingAncestry{ .io = io }, {}) catch
            return) orelse return;
        built.deinit();
    }
};

/// A finalization of `block` signed by the node's validator (commonware `finalization`).
pub fn finalization_of(
    gpa: std.mem.Allocator,
    validators: *const Types.Validators,
    block: *const Block,
) !Types.Finalization {
    const Vote = consensus.simplex.types.Finalize(Scheme, Digest);
    const context = block.context();
    const proposal = consensus.simplex.types.Proposal(Digest).init(
        context.round,
        context.parent[0],
        block.digest(),
    );
    const scheme = &validators.schemes[0];
    var votes = [1]Vote{(try Vote.sign(gpa, scheme, proposal)).?};
    const sequential = @import("parallel").sequential;
    return Types.Finalization.from_votes(gpa, scheme, &votes, sequential);
}

fn dispatched_through(reporter: Types.Application, count: usize) !bool {
    return reporter.block_count() >= count;
}

/// Reports finalizations of `blocks` to marshal and waits until it dispatches genesis and
/// each of them, in height order, with its finalization stored.
fn marshal_finalizes(ctx: Ctx, node: *Node, blocks: []const Block) !void {
    const gpa = ctx.gpa();
    for (blocks) |*block| {
        var certificate = try finalization_of(gpa, &node.validators, block);
        defer certificate.deinit(gpa);
        _ = node.marshal.mailbox.report(.{ .finalization = certificate });
    }
    const reporter = node.marshal.reporter.?;
    try wait_until(ctx, 1000, dispatched_through, .{ reporter, blocks.len + 1 });
    const entries = try reporter.blocks(gpa);
    defer Types.Application.free_blocks(gpa, entries);
    try testing.expectEqual(blocks.len + 1, entries.len);
    for (entries, 0..) |entry, height| try testing.expectEqual(height, entry.height.get());
    for (blocks) |*block| {
        var stored = try node.marshal.mailbox.get_finalization(block.height()) orelse
            return error.TestFinalizationMissing;
        stored.deinit(gpa);
    }
}

/// Reports `blocks` as finalized to the stateful actor, returning their acknowledgements.
fn report_finalized(
    node: *Node,
    blocks: []const Block,
    waiters: []utils.acknowledgement.ExactWaiter,
) !void {
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

fn during_parent_lookup(ctx: Ctx) !void {
    const gpa = ctx.gpa();
    const io = ctx.io();
    var blocks: [6]Block = undefined;
    try build_chain(ctx, &blocks);
    var node: Node = undefined;
    try node.start(ctx, "deferred-qmdb");
    defer node.stop();
    for (&blocks) |*block| {
        const digested = try Digested.precomputed(gpa, block.*, block.digest());
        try testing.expect(try node.marshal.mailbox.verified(block.context().round, digested));
    }
    // Marshal finalizes the first three blocks before the actor applies them, so a
    // certification below the applied tip can look up the canonical block.
    try marshal_finalizes(ctx, &node, blocks[0..3]);
    // A proposal whose parent never arrives, then the first three finalized blocks.
    var proposal: Proposal = .{};
    var proposer = node.mailbox.clone();
    defer proposer.deinit();
    const args = .{ &proposal, &proposer, io, blocks[5].context() };
    var pending = try io.concurrent(Proposal.run, args);
    defer pending.cancel(io);
    try ctx.sleep(.fromMilliseconds(10));
    try testing.expect(!proposal.done);
    var waiters: [3]utils.acknowledgement.ExactWaiter = undefined;
    try report_finalized(&node, blocks[0..3], &waiters);
    defer for (&waiters) |*waiter| waiter.deinit();
    // Out-of-order certifications queued after them complete as well.
    try certify_all(io, node.wrapper, &blocks, &.{ 5, 1, 4, 0, 3, 2 });
    for (&waiters) |*waiter| try waiter.wait();
    // The proposal still waits for its parent until its caller cancels it.
    try testing.expect(!proposal.done);
    const databases = try node.mailbox.subscribe_databases();
    const committed = try databases.committed_targets();
    const expected = single.App.sync_targets(&blocks[2]);
    try testing.expect(db.targets_eql(Any.SyncTarget, &committed, &expected));
}

// commonware `finalizations_and_certifications_complete_during_proposal_parent_lookup_on_qmdb`:
// on a real QMDB, finalizations and the out-of-order certifications queued after them
// complete while a proposal still waits for a parent that never arrives.
test "stateful tests: finalizations and certifications complete during a parent lookup" {
    try run(during_parent_lookup);
}
