//! commonware `glue/src/stateful/actor/core/mod.rs` tests on `stateful_test.zig`'s fake
//! marshal and node: `prepare` under each application decision, and startup recovery
//! releasing the ancestries of verifications cancelled while it was held (skipped; see the
//! test).

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Io = std.Io;
const consensus = @import("consensus");
const utils = @import("utils");
const fixtures = @import("stateful_test.zig");
const harness_mod = @import("../processor/testing.zig");
const processor_mod = @import("../processor/processor.zig");
const stateful_mod = @import("stateful.zig");
const state_sync = @import("../../db/state_sync.zig");
const qmdb_sync = @import("storage").qmdb.sync;

const gpa = testing.allocator;
const io = testing.io;
const oneshot = utils.channel.oneshot;
const Exact = utils.acknowledgement.Exact;
const Handoff = consensus.Handoff;
const TestApp = harness_mod.TestApp;
const TestBlock = harness_mod.TestBlock;
const Digested = harness_mod.Processor.Digested;
const Any = harness_mod.Any;

/// The harness application answering `prepare` with `decision` (commonware's
/// `TestApp::with_handoff`): a vote or stage carries the block it builds, and a wait
/// declines even when it would build one.
const DecisionApp = struct {
    pub const Block = TestBlock;
    pub const Context = TestApp.Context;
    pub const Input = void;
    pub const Merkleized = TestApp.Merkleized;
    pub const Captured = TestApp.Captured;
    const Built = processor_mod.Proposed(DecisionApp);

    inner: TestApp = .{},
    decision: std.meta.Tag(Handoff(void)) = .vote,

    pub fn sync_targets(block: *const TestBlock) Any.SyncTarget {
        return TestApp.sync_targets(block);
    }

    pub fn process(
        app: *DecisionApp,
        io_: Io,
        context: Context,
        ancestry: anytype,
        batches: Any.Unmerkleized,
        finality: anytype,
    ) !?Merkleized {
        return app.inner.process(io_, context, ancestry, batches, finality);
    }

    pub fn propose(
        app: *DecisionApp,
        io_: Io,
        context: Context,
        ancestry: anytype,
        batches: Any.Unmerkleized,
        input: void,
    ) !?Built {
        const built = try app.inner.propose(
            io_,
            context,
            ancestry,
            batches,
            input,
        ) orelse return null;
        return .{ .block = built.block, .merkleized = built.merkleized };
    }

    pub fn prepare(
        app: *DecisionApp,
        io_: Io,
        context: Context,
        ancestry: anytype,
        batches: Any.Unmerkleized,
        input: void,
    ) !Handoff(Built) {
        var built = try app.propose(io_, context, ancestry, batches, input) orelse return .wait;
        return switch (app.decision) {
            .vote => .{ .vote = built },
            .stage => .{ .stage = built },
            .wait => {
                built.merkleized.deinit();
                return .wait;
            },
        };
    }

    pub fn capture(
        app: *DecisionApp,
        io_: Io,
        context: Context,
        block: *const TestBlock,
        batch: *const Merkleized,
        readers: anytype,
    ) !Captured {
        return app.inner.capture(io_, context, block, batch, readers);
    }

    pub fn finalized(
        app: *DecisionApp,
        io_: Io,
        context: Context,
        block: *const TestBlock,
        captured: Captured,
        readers: anytype,
    ) !void {
        return app.inner.finalized(io_, context, block, captured, readers);
    }
};

/// The fake marshal with the floor subscription the state sync path compiles against; no
/// test here selects a floor.
const SyncMarshal = struct {
    pub const Block = fixtures.FakeMarshal.Block;
    pub const ParentReceiver = fixtures.FakeMarshal.ParentReceiver;
    pub const Anchor = fixtures.FakeMarshal.Anchor;
    pub const Info = fixtures.FakeMarshal.Info;

    inner: fixtures.FakeMarshal,

    pub fn clone(self: SyncMarshal) SyncMarshal {
        return self;
    }

    pub fn deinit(self: *SyncMarshal) void {
        self.* = undefined;
    }

    pub fn get_anchor(self: SyncMarshal) !?Anchor {
        return self.inner.get_anchor();
    }

    pub fn get_block(self: SyncMarshal, identifier: fixtures.Identifier) !?Digested {
        return self.inner.get_block(identifier);
    }

    pub fn get_info(self: SyncMarshal, identifier: fixtures.Identifier) !?Info {
        return self.inner.get_info(identifier);
    }

    pub fn subscribe_parent(
        self: SyncMarshal,
        child: *const Digested,
        bound: ?consensus.types.Round,
    ) !ParentReceiver {
        return self.inner.subscribe_parent(child, bound);
    }

    pub fn prune(self: SyncMarshal, height: consensus.Height) !void {
        return self.inner.prune(height);
    }

    pub fn subscribe_by_commitment(
        _: SyncMarshal,
        _: TestBlock.Digest,
        _: consensus.marshal.core.CommitmentFallback,
    ) !oneshot.Receiver(Digested) {
        var pair = try oneshot.channel(Digested, gpa, io);
        pair.sender.deinit();
        return pair.receiver;
    }
};

/// Resolvers whose database attachment holds startup until released (commonware's
/// `NoopResolver::gated`). They serve nothing.
const GatedResolvers = struct {
    const Source = state_sync.SharedSource(Any);
    pub const Family = Source.Family;
    pub const Op = Source.Op;
    pub const Digest = Source.Digest;
    pub const Error = Source.Error;

    started: ?oneshot.Sender(void) = null,
    release: ?oneshot.Receiver(void) = null,

    pub fn serve(
        _: *GatedResolvers,
        _: std.mem.Allocator,
        _: Source.Request,
    ) (Error || Io.Cancelable)!qmdb_sync.Served(Source.Response) {
        return error.Canceled;
    }

    pub fn attach_database(self: *GatedResolvers, _: Any.Shared) !void {
        if (self.started) |*started| started.send({}) catch {};
        self.started = null;
        var release = self.release orelse return;
        self.release = null;
        defer release.deinit();
        release.recv() catch {};
    }
};

const Stateful = stateful_mod.Stateful(struct {
    pub const App = DecisionApp;
    pub const Databases = Any.Shared;
    pub const Marshal = SyncMarshal;
    pub const Plan = fixtures.TestPlan;
    pub const Resolvers = *GatedResolvers;
});
const Mailbox = Stateful.Mailbox;

/// A started actor over `node` with `resolvers`.
const Running = struct {
    actor: *Stateful,
    mailbox: Mailbox,
    future: Io.Future(anyerror!void),

    fn start(
        node: *fixtures.Node,
        app: DecisionApp,
        resolvers: *GatedResolvers,
        size: u32,
    ) !Running {
        const actor, const mailbox = try Stateful.init(gpa, io, .{
            .app = app,
            .env = node.env(),
            .db_config = node.db_config(),
            .marshal = .{ .inner = .{ .state = &node.marshal } },
            .mailbox_size = size,
            .plan = &node.plan,
            .resolvers = resolvers,
        });
        return .{ .actor = actor, .mailbox = mailbox, .future = try actor.start() };
    }

    fn stop(running: *Running) !void {
        running.mailbox.deinit();
        const outcome = running.future.await(io);
        running.actor.deinit();
        try outcome;
    }
};

/// Prepares a child of genesis at view 1 under `decision`.
fn prepare_case(decision: std.meta.Tag(Handoff(void))) !void {
    var node: fixtures.Node = undefined;
    try node.init();
    defer node.deinit();
    var resolvers: GatedResolvers = .{};
    var running = try Running.start(&node, .{ .decision = decision }, &resolvers, 8);
    var stopped = false;
    defer if (!stopped) running.stop() catch {};
    const context: TestBlock.Context = .{ .round = harness_mod.round(1) };
    var handles = [_]Digested{try harness_mod.digested(TestBlock.genesis())};
    const ancestry = try Mailbox.Ancestry.from_blocks(gpa, &handles);
    var prepared = try running.mailbox.prepare({}, context, ancestry, {});
    try testing.expectEqualStrings(@tagName(decision), @tagName(std.meta.activeTag(prepared)));
    switch (prepared) {
        .wait => {},
        inline .vote, .stage => |*block| {
            defer block.deinit();
            // The built block extends genesis at height 1 in the requested round.
            try testing.expectEqual(@as(u64, 1), block.inner().height().get());
            try testing.expect(block.inner().parent().eql(TestBlock.genesis().digest()));
            try testing.expectEqual(@as(u64, 1), block.inner().round.view.get());
        },
    }
    stopped = true;
    try running.stop();
}

test "stateful actor: prepare declines on a wait decision" {
    try prepare_case(.wait);
}

test "stateful actor: prepare attaches the application's decision to the built block" {
    try prepare_case(.vote);
    try prepare_case(.stage);
}

/// One verification caller on its own task.
const Verify = struct {
    mailbox: Mailbox,
    owner: Digested,
    result: anyerror!bool = error.Canceled,

    fn run(verify: *Verify) void {
        var handles = [_]Digested{verify.owner.clone()};
        const ancestry = Mailbox.Ancestry.from_blocks(gpa, &handles) catch |err| {
            verify.result = err;
            return;
        };
        const context: TestBlock.Context = .{ .round = verify.owner.inner().round };
        verify.result = verify.mailbox.verify({}, context, ancestry);
    }
};

fn references(handle: Digested) u32 {
    return handle.shared.references.load(.acquire);
}

/// Waits up to a second for every owner's ancestry clone to be released.
fn wait_released(owners: []const Digested) !void {
    for (0..1000) |_| {
        var held: usize = 0;
        for (owners) |owner| held += @intFromBool(references(owner) > 1);
        if (held == 0) return;
        try io.sleep(.fromMilliseconds(1), .awake);
    }
    return error.TestAncestryRetained;
}

test "stateful actor: startup recovery releases cancelled verify ancestries" {
    var node: fixtures.Node = undefined;
    try node.init();
    defer node.deinit();
    // Hold startup after database recovery, before processing reads the mailbox.
    var started = try oneshot.channel(void, gpa, io);
    defer started.receiver.deinit();
    var release = try oneshot.channel(void, gpa, io);
    var resolvers: GatedResolvers = .{ .started = started.sender, .release = release.receiver };
    var running = try Running.start(&node, .{}, &resolvers, 1);
    try started.receiver.recv();

    // Fill the single ready slot and the overflow with independently owned ancestries.
    var owners: [3]Digested = undefined;
    var verifies: [3]Verify = undefined;
    var futures: [3]Io.Future(void) = undefined;
    for (&owners, &verifies, &futures, 2..) |*owner, *verify, *future, height| {
        const parent = TestBlock.genesis().digest();
        const block = TestBlock.init(
            parent,
            .new(height),
            harness_mod.round(height),
            Any.initial_sync_target(),
        );
        owner.* = try harness_mod.digested(block);
        verify.* = .{ .mailbox = running.mailbox.clone(), .owner = owner.* };
        future.* = try io.concurrent(Verify.run, .{verify});
    }
    defer for (&owners) |*owner| owner.deinit();
    // Each caller's ancestry clone is queued.
    for (0..1000) |_| {
        var queued: usize = 0;
        for (owners) |owner| queued += @intFromBool(references(owner) > 1);
        if (queued == owners.len) break;
        try io.sleep(.fromMilliseconds(1), .awake);
    } else return error.TestVerificationsNotQueued;

    // Queue a finalization behind the verifications, then cancel every caller.
    var source: harness_mod.Harness = undefined;
    try source.init();
    defer source.deinit();
    const finalized, var merkleized = try source.build_child(&TestBlock.genesis(), 1);
    merkleized.deinit();
    try node.marshal.insert(finalized);
    const handle = try Exact.handle(gpa, io);
    var waiter = handle.waiter;
    defer waiter.deinit();
    const update: Mailbox.Update = .{ .block = .{
        .block = try harness_mod.digested(finalized),
        .ack = handle.acknowledgement,
    } };
    _ = running.mailbox.report(update);
    for (&futures, &verifies) |*future, *verify| {
        future.cancel(io);
        verify.mailbox.deinit();
    }

    // Startup stays held while cancellation releases every ancestry block.
    try wait_released(&owners);
    try testing.expect(waiter.poll() == null);

    // Resuming startup drains the queue; processing then reaches the finalization.
    try release.sender.send({});
    try waiter.wait();
    try running.stop();
}
