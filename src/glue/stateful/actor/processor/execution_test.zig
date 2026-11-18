//! commonware `glue/src/stateful/actor/processor/mod.rs` execution tests: forking, replay,
//! and the flight registry, over an unordered fixed `any` database (commonware's
//! `ExecutionApp` and `MapProvider` harness).

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const broadcast = @import("broadcast");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const storage = @import("storage");
const utils = @import("utils");
const db = @import("../../db/mod.zig");
const any_mod = @import("../../db/any.zig");
const execution_mod = @import("execution.zig");

const gpa = testing.allocator;
const io = testing.io;
const oneshot = utils.channel.oneshot;
const qmdb = storage.qmdb;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const Family = storage.mmr.Family;
const Height = consensus.Height;
const Round = consensus.Round;
const Encoding = qmdb.value.Fixed(Digest);
const Journal = storage.journal.contiguous.fixed.Journal(
    qmdb.any.operation.Unordered(Family, Digest, Encoding),
);
const Update = qmdb.any.operation.update.Unordered(Digest, Encoding);
const Index = storage.index.unordered.Index(storage.translator.TwoCap, u64);
const Any = any_mod.Any(qmdb.any.Db(Family, Update, Journal, Index, Sha256, 64), Sha256);
const metrics = runtime.telemetry.metrics;

/// commonware's test block: it commits to its state through `target`.
const TestBlock = struct {
    pub const Digest = Sha256.Digest;
    pub const Context = struct { round: Round };

    round: Round,
    parent_digest: Sha256.Digest,
    height_value: Height,
    target: Any.SyncTarget,
    digest_value: Sha256.Digest,

    fn init(
        parent_digest: Sha256.Digest,
        at: Height,
        at_round: Round,
        target: Any.SyncTarget,
    ) TestBlock {
        const values = [_]u64{
            at.get(), at_round.epoch.get(), at_round.view.get(), target.start, target.end,
        };
        var fields: [8 * values.len]u8 = undefined;
        for (values, 0..) |value, index| {
            std.mem.writeInt(u64, fields[index * 8 ..][0..8], value, .big);
        }
        const digest_value = Sha256.hash(&.{
            parent_digest.as_slice(), &fields, target.root.as_slice(),
        });
        return .{
            .round = at_round,
            .parent_digest = parent_digest,
            .height_value = at,
            .target = target,
            .digest_value = digest_value,
        };
    }

    fn genesis() TestBlock {
        return init(.fill(0), .zero(), .zero(), Any.initial_sync_target());
    }

    pub fn digest(self: TestBlock) Sha256.Digest {
        return self.digest_value;
    }

    pub fn parent(self: TestBlock) Sha256.Digest {
        return self.parent_digest;
    }

    pub fn height(self: TestBlock) Height {
        return self.height_value;
    }

    pub fn context(self: TestBlock) Context {
        return .{ .round = self.round };
    }

    /// The same block claiming a different state root.
    fn with_root(self: TestBlock, root: Sha256.Digest) TestBlock {
        var target = self.target;
        target.root = root;
        return init(self.parent_digest, self.height_value, self.round, target);
    }
};
const Digested = broadcast.Digested(TestBlock);

fn digested(block: TestBlock) !Digested {
    return Digested.compute(gpa, block);
}

fn round(view: u64) Round {
    return .new(.zero(), .new(view));
}

/// Blocks by digest, served as parents (commonware `MapProvider`).
const ProviderState = struct {
    mutex: Io.Mutex = .init,
    blocks: std.AutoHashMapUnmanaged(Sha256.Digest, TestBlock) = .empty,
    fetches: u32 = 0,

    fn deinit(state: *ProviderState) void {
        state.blocks.deinit(gpa);
    }

    fn insert(state: *ProviderState, block: TestBlock) !void {
        try state.blocks.put(gpa, block.digest(), block);
    }
};

const TestProvider = struct {
    pub const Block = TestBlock;

    state: *ProviderState,

    pub fn subscribe_parent(
        self: *TestProvider,
        child: *const Digested,
    ) !oneshot.Receiver(Digested) {
        const pair = try oneshot.channel(Digested, gpa, io);
        var sender = pair.sender;
        self.state.mutex.lockUncancelable(io);
        self.state.fetches += 1;
        const found = self.state.blocks.get(child.inner().parent());
        self.state.mutex.unlock(io);
        const block = found orelse {
            sender.deinit();
            return pair.receiver;
        };
        const handle = try digested(block);
        sender.send(handle) catch unreachable; // The receiver is still open.
        return pair.receiver;
    }
};

/// Holds `process` on a target block until released (commonware `ApplyGate`).
const Gate = struct { started: oneshot.Sender(void), release: oneshot.Receiver(void) };

const GateHandles = struct { started: oneshot.Receiver(void), release: oneshot.Sender(void) };

/// Counts `process` calls on `target` and holds each on the next gate (commonware
/// `ApplicationProbe`).
const Probe = struct {
    mutex: Io.Mutex = .init,
    target: Sha256.Digest,
    calls: u32 = 0,
    gates: std.ArrayList(Gate) = .empty,

    fn deinit(probe: *Probe) void {
        for (probe.gates.items) |*gate| {
            gate.started.deinit();
            gate.release.deinit();
        }
        probe.gates.deinit(gpa);
    }

    fn add_gate(probe: *Probe) !GateHandles {
        const started = try oneshot.channel(void, gpa, io);
        const release = try oneshot.channel(void, gpa, io);
        try probe.gates.append(gpa, .{ .started = started.sender, .release = release.receiver });
        return .{ .started = started.receiver, .release = release.sender };
    }

    fn call(probe: *Probe, digest: Sha256.Digest) !void {
        if (!digest.eql(probe.target)) return;
        probe.mutex.lockUncancelable(io);
        probe.calls += 1;
        const next: ?Gate = if (probe.gates.items.len > 0) probe.gates.orderedRemove(0) else null;
        probe.mutex.unlock(io);
        var gate = next orelse return;
        defer gate.release.deinit();
        gate.started.send({}) catch unreachable; // The test awaits each start.
        gate.release.recv() catch |err| switch (err) {
            error.Closed => {},
            error.Canceled => return error.Canceled,
        };
    }
};

fn counter_key() Sha256.Digest {
    return Sha256.hash(&.{"processor_harness_counter"});
}

fn height_key(at: Height) Sha256.Digest {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, at.get(), .big);
    return Sha256.hash(&.{&bytes});
}

fn u64_digest(value: u64) Sha256.Digest {
    var result: Sha256.Digest = .fill(0);
    std.mem.writeInt(u64, result.bytes[0..8], value, .big);
    return result;
}

fn digest_u64(value: Sha256.Digest) u64 {
    return std.mem.readInt(u64, value.bytes[0..8], .big);
}

/// commonware's `ExecutionApp`: bumps a counter and records each height's view.
const TestApp = struct {
    pub const Block = TestBlock;

    probe: ?*Probe = null,

    pub fn sync_targets(block: *const TestBlock) Any.SyncTarget {
        return block.target;
    }

    fn execute(batches: Any.Unmerkleized, at: Height, view: u64) !Any.Merkleized {
        var batch = batches;
        errdefer batch.deinit();
        const counter = if (try batch.get(&counter_key())) |value| digest_u64(value) else 0;
        try batch.write(counter_key(), u64_digest(counter + 1));
        try batch.write(height_key(at), u64_digest(view));
        return batch.merkleize();
    }

    pub fn process(
        app: *TestApp,
        _: Io,
        context: TestBlock.Context,
        ancestry: *Execution.Ancestry,
        batches: Any.Unmerkleized,
        _: execution_mod.Finality,
    ) !?Any.Merkleized {
        var owned = batches;
        var block = (ancestry.next() catch |err| {
            owned.deinit();
            return err;
        }) orelse {
            owned.deinit();
            return null;
        };
        defer block.deinit();
        if (app.probe) |probe| probe.call(block.digest()) catch |err| {
            owned.deinit();
            return err;
        };
        return try execute(owned, block.inner().height(), context.round.view.get());
    }
};

const Execution = execution_mod.Execution(struct {
    pub const App = TestApp;
    pub const Databases = Any.Shared;
    pub const Provider = TestProvider;
});

/// Storage, a page cache, metrics, the database, its execution, and a block provider.
const Harness = struct {
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: metrics.Registry,
    databases: Any.Shared,
    execution: Execution,
    provider_state: ProviderState = .{},
    app: TestApp = .{},

    /// `harness` must not move afterwards: flights point at its execution.
    fn init(harness: *Harness) !void {
        harness.storage = .init(gpa);
        errdefer harness.storage.deinit();
        harness.cache_ref = try .init(gpa, 101, 11);
        errdefer harness.cache_ref.deinit();
        harness.registry = metrics.Registry.init(gpa);
        errdefer harness.registry.deinit();
        const env: db.Env = .{
            .gpa = gpa,
            .io = io,
            .storage = harness.storage.interface(),
            .scope = metrics.Scope.init(&harness.registry).child("db"),
        };
        harness.databases = try Any.Shared.open(env, harness.config(), null);
        const genesis = TestBlock.genesis();
        const anchor: Execution.Anchor = .{
            .height = .zero(),
            .round = genesis.round,
            .digest = genesis.digest(),
        };
        harness.execution = .init(gpa, io, harness.databases, anchor);
        harness.provider_state = .{};
        harness.app = .{};
    }

    fn deinit(harness: *Harness) void {
        harness.execution.deinit();
        harness.databases.deinit();
        harness.provider_state.deinit();
        harness.registry.deinit();
        harness.cache_ref.deinit();
        harness.storage.deinit();
    }

    fn config(harness: *Harness) Any.Config {
        return .{
            .merkle = .{
                .journal_partition = "processor-journal",
                .metadata_partition = "processor-metadata",
                .items_per_blob = 11,
                .write_buffer = 1024,
                .replay_buffer = 1024,
                .cache_ref = &harness.cache_ref,
            },
            .log = .{
                .partition = "processor-log",
                .items_per_blob = 7,
                .cache_ref = &harness.cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
            },
            .translator = .{},
            .init_cache = 1024,
        };
    }

    fn provider(harness: *Harness) TestProvider {
        return .{ .state = &harness.provider_state };
    }

    /// A child of `parent` at `view` built on `parent`'s state, with that state.
    fn build_child(harness: *Harness, parent: *const TestBlock, view: u64) !struct {
        TestBlock,
        Any.Merkleized,
    } {
        const batches = try harness.execution.fork_batches(parent.digest());
        const at = parent.height().next();
        var merkleized = try TestApp.execute(batches, at, view);
        errdefer merkleized.deinit();
        const bounds = &merkleized.inner.bounds;
        const target: Any.SyncTarget = .init(
            merkleized.root(),
            bounds.inactivity_floor,
            bounds.tip.size,
        );
        return .{ TestBlock.init(parent.digest(), at, round(view), target), merkleized };
    }

    /// Builds a child of `parent`, caches its state, and makes it fetchable.
    fn stage_pending_child(harness: *Harness, parent: *const TestBlock, view: u64) !TestBlock {
        const block, const merkleized = try harness.build_child(parent, view);
        const entry: Execution.Entry = .{
            .round = block.round,
            .parent = parent.digest(),
            .merkleized = merkleized,
        };
        try testing.expect(try harness.execution.cache_pending(block.digest(), entry));
        try harness.provider_state.insert(block);
        return block;
    }

    /// Applies the cached state of `block`, the branch anchor's child, durably.
    fn finalize(harness: *Harness, block: *const TestBlock) !void {
        const execution = &harness.execution;
        var batch = execution.state.get(block.digest()).?.merkleized.clone();
        defer batch.deinit();
        const anchor: Execution.Anchor = .{
            .height = block.height(),
            .round = block.round,
            .digest = block.digest(),
        };
        _ = try execution.retain_branch(anchor, block.parent(), &batch);
        try harness.databases.apply(&batch);
        const barrier = try harness.databases.finalize();
        try barrier.durable();
        try testing.expect(execution.state.remove(block.digest()));
    }

    /// An ancestry over `blocks`, newest first.
    fn ancestry(harness: *Harness, blocks: []const TestBlock) !Execution.Ancestry {
        var handles: [4]Digested = undefined;
        assert(blocks.len <= handles.len);
        for (blocks, 0..) |block, index| handles[index] = try digested(block);
        return Execution.Ancestry.init(gpa, io, harness.provider(), handles[0..blocks.len], null);
    }
};

test "stateful execution: fork_batches rejects an unknown parent" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    try testing.expectError(error.Invalid, harness.execution.fork_batches(u64_digest(999)));
}

test "stateful execution: rebuild_pending restores a missing chain" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const block1 = try harness.stage_pending_child(&genesis, 1);
    try harness.finalize(&block1);
    const block2 = try harness.stage_pending_child(&block1, 2);
    const block3 = try harness.stage_pending_child(&block2, 3);
    harness.execution.state.clear();

    var provider = harness.provider();
    try harness.execution.rebuild_pending(harness.app, &provider, try digested(block3));
    try testing.expect(harness.execution.pending_contains(block2.digest()));
    try testing.expect(harness.execution.pending_contains(block3.digest()));
    // block3's parent was fetched, then block2's parent (the anchor) ended the walk.
    try testing.expectEqual(2, harness.provider_state.fetches);
    try testing.expect(harness.execution.flights_idle());
}

/// The candidate block 1 on genesis, claiming a bad root unless `valid`.
fn candidate(harness: *Harness, valid: bool) !TestBlock {
    const genesis = TestBlock.genesis();
    const block, var merkleized = try harness.build_child(&genesis, 1);
    merkleized.deinit();
    return if (valid) block else block.with_root(u64_digest(999));
}

/// A completing flight leaves the registry, caches the block only after a success, and answers
/// every joined request with the same result (commonware
/// `flight_completion_removes_entry_and_shares_result` and `flight_shares_terminal_result`).
fn check_shared_result(valid: bool, joiner_count: u32) !void {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const block = try candidate(&harness, valid);
    var probe: Probe = .{ .target = block.digest() };
    defer probe.deinit();
    var gate = try probe.add_gate();
    defer gate.started.deinit();
    const app: TestApp = .{ .probe = &probe };
    const execution = &harness.execution;

    // The gate holds the processing while the other requests join it.
    const first = (try execution.join_flight(app, try harness.ancestry(&.{ block, genesis }))).?;
    try gate.started.recv();
    for (0..joiner_count) |_| {
        const joined = try execution.join_flight(app, try harness.ancestry(&.{ block, genesis }));
        try testing.expectEqual(first, joined.?);
    }
    try testing.expectEqual(1 + joiner_count, first.joiners);
    try gate.release.send({});

    const expected: anyerror!void = if (valid) {} else error.Invalid;
    try testing.expectEqual(expected, first.wait());
    try testing.expect(!execution.flights.contains(block.digest()));
    try testing.expectEqual(valid, execution.pending_contains(block.digest()));
    for (0..joiner_count) |_| {
        try testing.expectEqual(expected, first.wait());
        execution.release(first);
    }
    execution.release(first);
    try testing.expect(execution.flights_idle());
    try testing.expectEqual(1, probe.calls);
}

test "stateful execution: a flight shares its terminal result" {
    try check_shared_result(true, 0);
    try check_shared_result(true, 1);
    try check_shared_result(true, 16);
    try check_shared_result(false, 1);
    try check_shared_result(false, 16);
}

test "stateful execution: a flight ends with its last request" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const block = try candidate(&harness, true);
    var probe: Probe = .{ .target = block.digest() };
    defer probe.deinit();
    var gate = try probe.add_gate();
    defer gate.started.deinit();
    defer gate.release.deinit();
    var fresh_gate = try probe.add_gate();
    defer fresh_gate.started.deinit();
    const app: TestApp = .{ .probe = &probe };
    const execution = &harness.execution;

    const first = (try execution.join_flight(app, try harness.ancestry(&.{ block, genesis }))).?;
    try gate.started.recv();
    // Releasing another request leaves the flight active.
    const other = (try execution.join_flight(app, try harness.ancestry(&.{ block, genesis }))).?;
    execution.release(other);
    try testing.expect(!execution.flights_idle());

    // A later request joins the same flight and keeps it alive once the first leaves.
    const late = (try execution.join_flight(app, try harness.ancestry(&.{ block, genesis }))).?;
    try testing.expectEqual(first, late);
    execution.release(first);
    try testing.expect(!execution.flights_idle());
    try testing.expect(!gate.release.is_closed());

    // The last request cancels the processing and removes the entry.
    execution.release(late);
    try testing.expect(execution.flights_idle());
    try testing.expect(gate.release.is_closed());
    try testing.expect(!execution.pending_contains(block.digest()));

    // A new request starts a new flight and processes the block again.
    const fresh = (try execution.join_flight(app, try harness.ancestry(&.{ block, genesis }))).?;
    defer execution.release(fresh);
    try fresh_gate.started.recv();
    try testing.expect(!execution.flights_idle());
    try fresh_gate.release.send({});
    try fresh.wait();
    try testing.expect(execution.pending_contains(block.digest()));
    try testing.expectEqual(2, probe.calls);
}

test "stateful execution: a cached or anchored block needs no flight" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const block = try harness.stage_pending_child(&genesis, 1);
    const execution = &harness.execution;
    try testing.expectEqual(null, try execution.join_flight(.{}, try harness.ancestry(&.{block})));
    const anchored = try harness.ancestry(&.{genesis});
    try testing.expectEqual(null, try execution.join_flight(.{}, anchored));
    try execution.process_shared(.{}, try harness.ancestry(&.{block}));
    try testing.expect(execution.flights_idle());
}

test "stateful execution: replay rejects a fork at or below the anchor's height" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const block1 = try harness.stage_pending_child(&genesis, 1);
    // A sibling of block1 at its height, and a child of the sibling.
    const sibling = try harness.stage_pending_child(&genesis, 2);
    const child = try harness.stage_pending_child(&sibling, 3);
    try harness.finalize(&block1);
    try testing.expect(!harness.execution.pending_contains(sibling.digest()));

    var provider = harness.provider();
    const fetches = harness.provider_state.fetches;
    const result = harness.execution.rebuild_pending(harness.app, &provider, try digested(child));
    try testing.expectError(error.Invalid, result);
    // The walk stops at the sibling without fetching below the anchor's height.
    try testing.expectEqual(fetches + 1, harness.provider_state.fetches);
}

test "stateful execution: replay rejects non-contiguous and missing ancestry" {
    var harness: Harness = undefined;
    try harness.init();
    defer harness.deinit();
    const genesis = TestBlock.genesis();
    const block1 = try harness.stage_pending_child(&genesis, 1);
    harness.execution.state.clear();
    var provider = harness.provider();

    // A block at height 3 naming block1 (height 1) as its parent skips height 2.
    const skipping = TestBlock.init(block1.digest(), .new(3), round(3), block1.target);
    const execution = &harness.execution;
    const skipped = execution.rebuild_pending(harness.app, &provider, try digested(skipping));
    try testing.expectError(error.Invalid, skipped);

    // A parent the provider does not have leaves the replay incomplete.
    const orphan = TestBlock.init(u64_digest(7), .new(2), round(2), block1.target);
    const missing = execution.rebuild_pending(harness.app, &provider, try digested(orphan));
    try testing.expectError(error.Incomplete, missing);
    try testing.expect(!execution.pending_contains(block1.digest()));
}
