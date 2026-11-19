//! commonware `glue/src/stateful/actor/core/processing.rs`'s
//! `parent_certification_overtakes_deferred_finalization`, over a real marshal and its
//! `Deferred` wrapper (deployer's `FixtureFor` through qmdb_targeted_test's types), since the
//! handoff build, the optimistic verify, and the certification all run through `Deferred`.
//!
//! zigware differences: the whole `Stateful` actor runs (commonware spawns `Processing`
//! alone), recovering at genesis from marshal; `Deferred`'s calls block, so the handoff runs
//! on a concurrent task; and the gates block on the deterministic runtime's io (the processor
//! harness's `Probe` blocks on `testing.io`, which would stall the runtime).

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Io = std.Io;
const Allocator = std.mem.Allocator;
const consensus = @import("consensus");
const runtime = @import("runtime");
const utils = @import("utils");
const targeted = @import("../../tests/qmdb_targeted_test.zig");
const single = @import("../../tests/single_db.zig");
const actor_mod = @import("../mod.zig");
const processor_mod = @import("../processor/processor.zig");

const Ctx = runtime.deterministic.Context;
const Block = single.Block;
const Digested = single.Digested;
const Any = single.Any;
const Digest = @TypeOf(Block.genesis().digest());
const oneshot = utils.channel.oneshot;
const Exact = utils.acknowledgement.Exact;

/// Gates application calls in call order on the runtime's io (commonware `application_gate`
/// queues); calls past the last gate pass at once.
const Gates = struct {
    const capacity = 4;

    io: Io,
    mutex: Io.Mutex = .init,
    calls: u32 = 0,
    count: u32 = 0,
    next: u32 = 0,
    started: [capacity]oneshot.Sender(void) = undefined,
    release: [capacity]oneshot.Receiver(void) = undefined,

    const Handles = struct { started: oneshot.Receiver(void), release: oneshot.Sender(void) };

    fn add(gates: *Gates, gpa: Allocator) !Handles {
        assert(gates.count < capacity);
        assert(gates.next == 0); // Gates are added before any call.
        const started = try oneshot.channel(void, gpa, gates.io);
        const release = try oneshot.channel(void, gpa, gates.io);
        gates.started[gates.count] = started.sender;
        gates.release[gates.count] = release.receiver;
        gates.count += 1;
        return .{ .started = started.receiver, .release = release.sender };
    }

    fn call(gates: *Gates) Io.Cancelable!void {
        gates.mutex.lockUncancelable(gates.io);
        gates.calls += 1;
        const index: ?u32 = if (gates.next < gates.count) gates.next else null;
        if (index != null) gates.next += 1;
        gates.mutex.unlock(gates.io);
        const at = index orelse return;
        gates.started[at].send({}) catch {}; // A test that stopped waiting needs no signal.
        defer gates.release[at].deinit();
        gates.release[at].recv() catch |err| switch (err) {
            error.Closed => {},
            error.Canceled => return error.Canceled,
        };
    }

    fn deinit(gates: *Gates) void {
        for (gates.next..gates.count) |at| {
            gates.started[at].deinit();
            gates.release[at].deinit();
        }
        gates.* = undefined;
    }
};

/// single_db's application with gates on processing and proposals (commonware `GatedApp`):
/// each processed block passes `process` first, and a build passes `propose`, then declines.
const GatedApp = struct {
    pub const Block = single.App.Block;
    pub const Context = single.App.Context;
    pub const Input = void;
    pub const Merkleized = Any.Merkleized;
    const Built = processor_mod.Proposed(GatedApp);

    process_gates: *Gates,
    propose_gates: *Gates,

    pub fn sync_targets(block: *const single.Block) Any.SyncTarget {
        return single.App.sync_targets(block);
    }

    pub fn process(
        app: *GatedApp,
        io: Io,
        context: GatedApp.Context,
        ancestry: anytype,
        batches: Any.Unmerkleized,
        mode: anytype,
    ) !?Any.Merkleized {
        var owned = batches;
        app.process_gates.call() catch |err| {
            owned.deinit();
            return err;
        };
        var inner: single.App = .{};
        return inner.process(io, context, ancestry, owned, mode);
    }

    pub fn propose(
        app: *GatedApp,
        _: Io,
        _: GatedApp.Context,
        _: anytype,
        batches: Any.Unmerkleized,
        _: void,
    ) !?Built {
        var owned = batches;
        defer owned.deinit();
        try app.propose_gates.call();
        return null; // commonware's GatedApp builds nothing.
    }

    pub fn prepare(
        app: *GatedApp,
        io: Io,
        context: GatedApp.Context,
        ancestry: anytype,
        batches: Any.Unmerkleized,
        input: void,
    ) !consensus.Handoff(Built) {
        const built = try app.propose(io, context, ancestry, batches, input) orelse return .wait;
        return .{ .vote = built };
    }

    pub fn capture(
        _: *GatedApp,
        _: Io,
        _: GatedApp.Context,
        _: *const single.Block,
        _: anytype,
        _: anytype,
    ) !void {}

    pub fn finalized(
        _: *GatedApp,
        _: Io,
        _: GatedApp.Context,
        _: *const single.Block,
        _: void,
        _: anytype,
    ) !void {}
};

const Stateful = actor_mod.Stateful(struct {
    pub const App = GatedApp;
    pub const Databases = Any.Shared;
    pub const Marshal = targeted.MarshalFixture.Mailbox;
    pub const Plan = targeted.Plan;
});
const StatefulMailbox = Stateful.Mailbox;

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

    pub fn prepare(
        self: *Adapter,
        ctx: anytype,
        context: Block.Context,
        ancestry: anytype,
    ) anyerror!consensus.Handoff(Digested) {
        return self.mailbox.prepare(ctx, context, ancestry, {});
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
    single.Scheme,
    Adapter,
    Block,
    consensus.types.FixedEpocher,
);

/// Marshal, the stateful actor over `GatedApp`, and the deferred wrapper over them. Must not
/// move once started.
const Node = struct {
    gpa: Allocator,
    validators: targeted.Types.Validators,
    cache: runtime.buffer.paged.CacheRef,
    marshal: targeted.MarshalFixture,
    plan: targeted.Plan,
    actor: *Stateful,
    mailbox: StatefulMailbox,
    future: Io.Future(anyerror!void),
    wrapper: *Wrapper,

    fn start(node: *Node, ctx: Ctx, comptime prefix: []const u8, app: GatedApp) !void {
        const gpa = ctx.gpa();
        node.gpa = gpa;
        var rng = utils.rng.test_rng();
        node.validators = try consensus.simplex.mocks.scheme.fixture(Digest, gpa, &rng, prefix, 1);
        errdefer node.validators.deinit(gpa);
        node.cache = try .init(gpa, targeted.page_size, targeted.page_cache_size);
        errdefer node.cache.deinit();
        node.marshal = try .init(ctx.child("marshal"), prefix ++ "-marshal", &node.validators, .{});
        errdefer node.marshal.abort();
        node.plan = try .init(targeted.env(ctx, "plan"), prefix ++ "-stateful");
        errdefer node.plan.deinit();
        node.actor, node.mailbox = try Stateful.init(gpa, ctx.io(), .{
            .app = app,
            .env = targeted.env(ctx, "stateful"),
            .db_config = targeted.qmdb_config(prefix ++ "-stateful", &node.cache),
            .marshal = node.marshal.mailbox.clone(),
            .mailbox_size = 8,
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

fn digested(gpa: Allocator, block: Block) !Digested {
    return Digested.precomputed(gpa, block, block.digest());
}

fn verify_task(
    mailbox: *StatefulMailbox,
    context: Block.Context,
    ancestry: consensus.marshal.ancestry.Bounded(Block),
) anyerror!bool {
    return mailbox.verify({}, context, ancestry);
}

fn prepare_task(
    wrapper: *Wrapper,
    io: Io,
    context: Block.Context,
) Io.Cancelable!?consensus.Handoff(Digest) {
    return wrapper.prepare(io, context);
}

/// Verifies `block` (on genesis) through the stateful mailbox, releasing `gate` once its
/// processing starts, and expects it valid.
fn verify_held(gpa: Allocator, io: Io, node: *Node, block: Block, gate: *Gates.Handles) !void {
    var verifier = node.mailbox.clone();
    defer verifier.deinit();
    const ancestry = try consensus.marshal.ancestry.from_iter(Block, gpa, &.{
        try digested(gpa, block),
        try digested(gpa, Block.genesis()),
    });
    var verification = try io.concurrent(verify_task, .{ &verifier, block.context(), ancestry });
    try gate.started.recv();
    try gate.release.send({});
    try testing.expect(try verification.await(io));
}

fn overtakes(ctx: Ctx) !void {
    const gpa = ctx.gpa();
    const io = ctx.io();
    var blocks: [2]Block = undefined; // The outgoing term's block, then the parent.
    try targeted.build_chain(ctx, &blocks);
    const outgoing = blocks[0];
    const parent = blocks[1];

    var process: Gates = .{ .io = io };
    defer process.deinit();
    var outgoing_gate = try process.add(gpa);
    defer outgoing_gate.started.deinit();
    var parent_gate = try process.add(gpa);
    defer parent_gate.started.deinit();
    var propose: Gates = .{ .io = io };
    defer propose.deinit();
    var proposal_gate = try propose.add(gpa);
    defer proposal_gate.started.deinit();
    var node: Node = undefined;
    try node.start(ctx, "handoff-parent-certification", .{
        .process_gates = &process,
        .propose_gates = &propose,
    });
    defer node.stop();
    for (&blocks) |*block| {
        const handle = try digested(gpa, block.*);
        try testing.expect(try node.marshal.mailbox.verified(block.context().round, handle));
    }

    // The proposer has already verified the outgoing term's earlier block.
    try verify_held(gpa, io, &node, outgoing, &outgoing_gate);

    // The handoff build on the uncertified parent processes the parent and is then held, and
    // a finalization report queues behind it ahead of the parent's verification.
    const child_context: Block.Context = .{
        .round = .new(.zero(), .new(3)),
        .leader = outgoing.context().leader,
        .parent = .{ parent.context().round.view, parent.digest() },
    };
    var handoff = try io.concurrent(prepare_task, .{ node.wrapper, io, child_context });
    var handoff_done = false;
    defer if (!handoff_done) {
        _ = handoff.cancel(io) catch {};
    };
    try parent_gate.started.recv();
    try parent_gate.release.send({});
    try proposal_gate.started.recv();
    const handle = try Exact.handle(gpa, io);
    var waiter = handle.waiter;
    defer waiter.deinit();
    const update: StatefulMailbox.Update = .{ .block = .{
        .block = try digested(gpa, outgoing),
        .ack = handle.acknowledgement,
    } };
    try testing.expect(node.mailbox.report(update) != .closed);

    // The parent verifies and certifies from its processed state while the build is held.
    const optimistic = try node.wrapper.verify(io, parent.context(), parent.digest());
    try testing.expectEqual(@as(?bool, true), optimistic);
    const certified = try node.wrapper.certify(io, parent.context().round, parent.digest());
    try testing.expectEqual(@as(?bool, true), certified);
    try testing.expect(waiter.poll() == null);

    // The deferred finalization applies once the build ends, and the handoff declines.
    try proposal_gate.release.send({});
    try waiter.wait();
    const outcome = try handoff.await(io);
    handoff_done = true;
    try testing.expect(outcome.?.is_wait());
}

// commonware `parent_certification_overtakes_deferred_finalization`: a handoff build on an
// uncertified parent processes the parent and is held, and a finalization report queues
// behind it; the parent still verifies and certifies from its processed state during the
// build, and the deferred finalization applies once the build ends.
test "stateful processing: parent certification overtakes a deferred finalization" {
    try targeted.run(overtakes);
}
