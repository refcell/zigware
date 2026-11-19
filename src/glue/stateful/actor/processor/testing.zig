//! The processor tests' harness (commonware `glue/src/stateful/actor/processor/mod.rs`'s
//! `ExecutionApp`, `ApplicationProbe`, `MapProvider`, and `Harness`), over an unordered fixed
//! `any` database. Only tests import it.

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
const processor_mod = @import("processor.zig");

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
pub const Any = any_mod.Any(qmdb.any.Db(Family, Update, Journal, Index, Sha256, 64), Sha256);
const metrics = runtime.telemetry.metrics;

/// commonware's test block: it commits to its state through `target`.
pub const TestBlock = struct {
    pub const Digest = Sha256.Digest;
    pub const Context = struct { round: Round };

    round: Round,
    parent_digest: Sha256.Digest,
    height_value: Height,
    target: Any.SyncTarget,
    digest_value: Sha256.Digest,

    pub fn init(
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

    pub fn genesis() TestBlock {
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
    pub fn with_root(self: TestBlock, root: Sha256.Digest) TestBlock {
        var target = self.target;
        target.root = root;
        return init(self.parent_digest, self.height_value, self.round, target);
    }
};
pub const Digested = broadcast.Digested(TestBlock);

pub fn digested(block: TestBlock) !Digested {
    return Digested.compute(gpa, block);
}

pub fn round(view: u64) Round {
    return .new(.zero(), .new(view));
}

/// Blocks by digest, served as parents (commonware `MapProvider`).
pub const ProviderState = struct {
    mutex: Io.Mutex = .init,
    blocks: std.AutoHashMapUnmanaged(Sha256.Digest, TestBlock) = .empty,
    /// Finalized blocks by height (marshal's local store).
    canonical: std.AutoHashMapUnmanaged(u64, Sha256.Digest) = .empty,
    fetches: u32 = 0,
    /// The bound of each parent request, in order (commonware `MapProvider::bounds`).
    bounds: std.ArrayList(?Round) = .empty,

    pub fn deinit(state: *ProviderState) void {
        state.bounds.deinit(gpa);
        state.blocks.deinit(gpa);
        state.canonical.deinit(gpa);
    }

    pub fn insert(state: *ProviderState, block: TestBlock) !void {
        try state.blocks.put(gpa, block.digest(), block);
    }
};

pub const TestProvider = struct {
    pub const Block = TestBlock;

    state: *ProviderState,

    pub fn subscribe_parent(
        self: *TestProvider,
        child: *const Digested,
        bound: ?consensus.types.Round,
    ) !oneshot.Receiver(Digested) {
        const pair = try oneshot.channel(Digested, gpa, io);
        var sender = pair.sender;
        self.state.mutex.lockUncancelable(io);
        self.state.fetches += 1;
        self.state.bounds.append(gpa, bound) catch {
            self.state.mutex.unlock(io);
            sender.deinit();
            return error.OutOfMemory;
        };
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

    pub fn canonical_digest(self: *TestProvider, at: Height) !?Sha256.Digest {
        self.state.mutex.lockUncancelable(io);
        defer self.state.mutex.unlock(io);
        return self.state.canonical.get(at.get());
    }
};

/// Holds `process` on a target block until released (commonware `ApplyGate`).
pub const Gate = struct { started: oneshot.Sender(void), release: oneshot.Receiver(void) };

pub const GateHandles = struct { started: oneshot.Receiver(void), release: oneshot.Sender(void) };

/// Counts `process` calls on `target` and holds each on the next gate (commonware
/// `ApplicationProbe`).
pub const Probe = struct {
    mutex: Io.Mutex = .init,
    /// The gated block, or null to gate every processed block in call order.
    target: ?Sha256.Digest,
    calls: u32 = 0,
    gates: std.ArrayList(Gate) = .empty,

    pub fn deinit(probe: *Probe) void {
        for (probe.gates.items) |*gate| {
            gate.started.deinit();
            gate.release.deinit();
        }
        probe.gates.deinit(gpa);
    }

    pub fn add_gate(probe: *Probe) !GateHandles {
        const started = try oneshot.channel(void, gpa, io);
        const release = try oneshot.channel(void, gpa, io);
        try probe.gates.append(gpa, .{ .started = started.sender, .release = release.receiver });
        return .{ .started = started.receiver, .release = release.sender };
    }

    pub fn call(probe: *Probe, digest: Sha256.Digest) !void {
        if (probe.target) |target| if (!digest.eql(target)) return;
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

pub fn counter_key() Sha256.Digest {
    return Sha256.hash(&.{"processor_harness_counter"});
}

pub fn height_key(at: Height) Sha256.Digest {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, at.get(), .big);
    return Sha256.hash(&.{&bytes});
}

pub fn u64_digest(value: u64) Sha256.Digest {
    var result: Sha256.Digest = .fill(0);
    std.mem.writeInt(u64, result.bytes[0..8], value, .big);
    return result;
}

pub fn digest_u64(value: Sha256.Digest) u64 {
    return std.mem.readInt(u64, value.bytes[0..8], .big);
}

/// commonware's `ExecutionApp`: bumps a counter and records each height's view.
pub const TestApp = struct {
    pub const Block = TestBlock;

    probe: ?*Probe = null,
    capture_probe: ?*Probe = null,
    finalized_probe: ?*Probe = null,
    /// Gates each build on the parent's digest (commonware's proposal gate).
    propose_probe: ?*Probe = null,
    /// Records each `process` call's finality and first ancestry digests (commonware
    /// `process_ancestry`).
    process_log: ?*std.ArrayList(ProcessRecord) = null,
    observations: ?*std.ArrayList(Observation) = null,

    /// One `process` call: its finality and up to three ancestry digests, newest first.
    pub const ProcessRecord = struct {
        finality: execution_mod.Finality,
        digests: [3]Sha256.Digest,
        len: u32,
    };

    /// Pre-apply reads (commonware `Captured`).
    pub const Captured = struct { prior_counter: ?u64, batch_counter: u64, batch_view: u64 };

    /// What the finalized hook saw (commonware `FinalizedObservation`).
    pub const Observation = struct { captured: Captured, post_counter: u64, post_view: u64 };

    pub const Context = TestBlock.Context;
    pub const Input = void;
    pub const Merkleized = Any.Merkleized;
    const Built = processor_mod.Proposed(TestApp);

    pub fn sync_targets(block: *const TestBlock) Any.SyncTarget {
        return block.target;
    }

    pub fn execute(batches: Any.Unmerkleized, at: Height, view: u64) !Any.Merkleized {
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
        finality: execution_mod.Finality,
    ) !?Any.Merkleized {
        var owned = batches;
        if (app.process_log) |log| record_process(log, ancestry, finality) catch |err| {
            owned.deinit();
            return err;
        };
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

    /// Appends `ancestry`'s first three digests, read from a clone, to `log`.
    fn record_process(
        log: *std.ArrayList(ProcessRecord),
        ancestry: *const Execution.Ancestry,
        finality: execution_mod.Finality,
    ) !void {
        var record: ProcessRecord = .{ .finality = finality, .digests = undefined, .len = 0 };
        var copy = try ancestry.clone();
        defer copy.deinit();
        while (record.len < record.digests.len) : (record.len += 1) {
            var block = (copy.next() catch |err| {
                if (err == error.Canceled) return err; // Propagated, never swallowed.
                break;
            }) orelse break;
            defer block.deinit();
            record.digests[record.len] = block.digest();
        }
        try log.append(gpa, record);
    }

    /// Builds the next block on the parent at the head of `ancestry` (commonware
    /// `ExecutionApp::propose`).
    pub fn propose(
        app: *TestApp,
        _: Io,
        context: TestBlock.Context,
        ancestry: *Execution.Ancestry,
        batches: Any.Unmerkleized,
        _: void,
    ) !?Built {
        var owned = batches;
        var parent = (ancestry.next() catch |err| {
            owned.deinit();
            return err;
        }) orelse {
            owned.deinit();
            return null;
        };
        defer parent.deinit();
        if (app.propose_probe) |probe| probe.call(parent.digest()) catch |err| {
            owned.deinit();
            return err;
        };
        const at = parent.inner().height().next();
        var merkleized = try execute(owned, at, context.round.view.get());
        errdefer merkleized.deinit();
        const bounds = &merkleized.inner.bounds;
        const floor = bounds.inactivity_floor;
        const target: Any.SyncTarget = .init(merkleized.root(), floor, bounds.tip.size);
        const block = TestBlock.init(parent.digest(), at, context.round, target);
        return .{ .block = block, .merkleized = merkleized };
    }

    /// Votes on every block it builds.
    pub fn prepare(
        app: *TestApp,
        io_: Io,
        context: TestBlock.Context,
        ancestry: *Execution.Ancestry,
        batches: Any.Unmerkleized,
        input: void,
    ) !consensus.Handoff(Built) {
        const built = try app.propose(io_, context, ancestry, batches, input) orelse return .wait;
        return .{ .vote = built };
    }

    pub fn capture(
        app: *TestApp,
        _: Io,
        _: TestBlock.Context,
        block: *const TestBlock,
        batch: *const Any.Merkleized,
        readers: Any.Shared.Readers,
    ) !Captured {
        if (app.capture_probe) |probe| try probe.call(block.digest());
        const prior = try read_applied(readers, counter_key());
        const counter = (try batch.get(&counter_key())).?; // Every batch bumps the counter.
        const view = (try batch.get(&height_key(block.height()))).?;
        return .{
            .prior_counter = if (prior) |value| digest_u64(value) else null,
            .batch_counter = digest_u64(counter),
            .batch_view = digest_u64(view),
        };
    }

    pub fn finalized(
        app: *TestApp,
        _: Io,
        _: TestBlock.Context,
        block: *const TestBlock,
        captured: Captured,
        readers: Any.Shared.Readers,
    ) !void {
        if (app.finalized_probe) |probe| try probe.call(block.digest());
        const observations = app.observations orelse return;
        const view = (try read_applied(readers, height_key(block.height()))).?;
        const counter = (try read_applied(readers, counter_key())).?;
        try observations.append(gpa, .{
            .captured = captured,
            .post_counter = digest_u64(counter),
            .post_view = digest_u64(view),
        });
    }
};

/// Reads `key` from the applied state.
pub fn read_applied(readers: Any.Shared.Readers, key: Sha256.Digest) !?Sha256.Digest {
    var guard = try readers.read();
    defer guard.deinit();
    return guard.get().inner.get(&key);
}

/// A proposal waiting for its parent's state (the core actor's `Recover` contract).
pub const TestRecover = struct {
    ancestry: Execution.Ancestry,
    /// Receives false when the proposal declines.
    response: oneshot.Sender(bool),

    pub fn is_cancelled(self: *const TestRecover) bool {
        return self.response.is_closed();
    }

    pub fn closed(self: *const TestRecover) Io.Cancelable!void {
        return self.response.closed();
    }

    pub fn decline(self: *TestRecover) void {
        self.ancestry.deinit();
        self.response.send(false) catch {}; // A caller that left needs no answer.
        self.* = undefined;
    }

    pub fn deinit(self: *TestRecover) void {
        self.ancestry.deinit();
        self.response.deinit();
        self.* = undefined;
    }
};

/// The test's hold on barriers (commonware's `FlushControl`): while armed, each barrier the
/// harness's database set starts persists inline as usual, but its completion stays pending
/// until the test finishes it, so later finalizations apply behind a pending barrier.
pub const FlushControl = struct {
    pub const capacity = 8;

    mutex: Io.Mutex = .init,
    armed: bool = false,
    /// The producer's reference to each held barrier's completion, oldest first.
    held: [capacity]runtime.storage.Completion = undefined,
    count: usize = 0,
    /// Barriers started while armed.
    flushes: u32 = 0,

    pub fn deinit(control: *FlushControl) void {
        control.release_all();
        control.* = undefined;
    }

    /// Finishes every held barrier successfully and holds no more: a held barrier would never
    /// complete, so tests defer this ahead of stopping the processing loop.
    pub fn release_all(control: *FlushControl) void {
        control.mutex.lockUncancelable(io);
        control.armed = false;
        control.mutex.unlock(io);
        while (control.pending() > 0) control.release_next({});
    }

    pub fn arm(control: *FlushControl) void {
        control.mutex.lockUncancelable(io);
        defer control.mutex.unlock(io);
        control.armed = true;
    }

    /// A new held completion when armed, else null.
    fn hold(control: *FlushControl) !?runtime.storage.Completion {
        control.mutex.lockUncancelable(io);
        defer control.mutex.unlock(io);
        if (!control.armed) return null;
        assert(control.count < capacity);
        const completion = try runtime.storage.Completion.init_pending(gpa, io);
        control.held[control.count] = completion;
        control.count += 1;
        control.flushes += 1;
        return completion.retain();
    }

    pub fn pending(control: *FlushControl) usize {
        control.mutex.lockUncancelable(io);
        defer control.mutex.unlock(io);
        return control.count;
    }

    /// Waits (bounded) until a barrier is held (commonware `next_flush`).
    pub fn next_flush(control: *FlushControl) !void {
        // Each pass sleeps 1 ms; the bound is a hang guard.
        for (0..10_000) |_| {
            if (control.pending() > 0) return;
            try io.sleep(.fromMilliseconds(1), .awake);
        }
        return error.TestTimedOut;
    }

    /// Completes the oldest held barrier with `result` (commonware's `release.send`).
    pub fn release_next(control: *FlushControl, result: runtime.storage.Error!void) void {
        control.mutex.lockUncancelable(io);
        assert(control.count > 0);
        const completion = control.held[0];
        std.mem.copyForwards(
            runtime.storage.Completion,
            control.held[0 .. control.count - 1],
            control.held[1..control.count],
        );
        control.count -= 1;
        control.mutex.unlock(io);
        completion.finish(result);
        completion.release();
    }
};

/// `Any.Shared` with barriers the harness's `FlushControl` can hold; it delegates every other
/// call, and behaves as `Any.Shared` while the control is unarmed.
pub const HeldShared = struct {
    pub const Unmerkleized = Any.Shared.Unmerkleized;
    pub const Merkleized = Any.Shared.Merkleized;
    pub const Readers = Any.Shared.Readers;
    pub const Config = Any.Shared.Config;
    pub const SyncTargets = Any.Shared.SyncTargets;

    inner: Any.Shared,
    control: *FlushControl,

    pub fn deinit(self: HeldShared) void {
        self.inner.deinit();
    }

    pub fn initial_sync_targets() SyncTargets {
        return Any.Shared.initial_sync_targets();
    }

    pub fn new_batches(self: HeldShared) !Unmerkleized {
        return self.inner.new_batches();
    }

    pub fn fork_batches(parent: *const Merkleized) !Unmerkleized {
        return Any.Shared.fork_batches(parent);
    }

    pub fn matches_sync_targets(batches: *const Merkleized, targets: *const SyncTargets) bool {
        return Any.Shared.matches_sync_targets(batches, targets);
    }

    pub fn readers(self: HeldShared) Readers {
        return self.inner.readers();
    }

    pub fn apply(self: HeldShared, batches: *const Merkleized) !void {
        return self.inner.apply(batches);
    }

    /// The inner barrier, or, while the control is armed, the inner state persisted at once
    /// and a barrier over a completion the test finishes.
    pub fn finalize(self: HeldShared) !db.Barrier {
        var barrier = try self.inner.finalize();
        const held = self.control.hold() catch |err| {
            barrier.deinit();
            return err;
        } orelse return barrier;
        barrier.durable() catch |err| {
            held.release();
            return err;
        };
        return db.Barrier.from_completions("held", &.{held});
    }

    pub fn prune(self: HeldShared, targets: *const SyncTargets) !void {
        return self.inner.prune(targets);
    }

    pub fn committed_targets(self: HeldShared) !SyncTargets {
        return self.inner.committed_targets();
    }
};

pub const TestP = struct {
    pub const App = TestApp;
    pub const Databases = HeldShared;
    pub const Provider = TestProvider;
    pub const Recover = TestRecover;
};

pub const Processor = processor_mod.Processor(TestP);
pub const Execution = Processor.Execution;

/// Storage, a page cache, metrics, the database, its execution, and a block provider.
pub const Harness = struct {
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: metrics.Registry,
    databases: HeldShared,
    /// Holds the database set's barriers once armed.
    flushes: FlushControl = .{},
    processor: Processor,
    /// The processor's execution.
    execution: *Execution,
    provider_state: ProviderState = .{},
    app: TestApp = .{},

    /// `harness` must not move afterwards: its provider points at its state.
    pub fn init(harness: *Harness) !void {
        harness.init_storage();
        errdefer harness.storage.deinit();
        try harness.init_with(harness.storage.interface());
    }

    /// Creates the backing storage only, for a test that wraps `storage.interface()` (for
    /// example in `runtime.storage.mocks.DelayedSynced`) and then calls `init_with`.
    pub fn init_storage(harness: *Harness) void {
        harness.storage = .init(gpa);
    }

    /// Opens everything but the backing storage (created by `init_storage`, released by
    /// `deinit` either way) over `over`, which must outlive the harness.
    pub fn init_with(harness: *Harness, over: runtime.storage.Storage) !void {
        harness.cache_ref = try .init(gpa, 101, 11);
        errdefer harness.cache_ref.deinit();
        harness.registry = metrics.Registry.init(gpa);
        errdefer harness.registry.deinit();
        const env: db.Env = .{
            .gpa = gpa,
            .io = io,
            .storage = over,
            .scope = metrics.Scope.init(&harness.registry).child("db"),
        };
        harness.flushes = .{};
        const shared = try Any.Shared.open(env, harness.config(), null);
        harness.databases = .{ .inner = shared, .control = &harness.flushes };
        const genesis = TestBlock.genesis();
        const anchor: Execution.Anchor = .{
            .height = .zero(),
            .round = genesis.round,
            .digest = genesis.digest(),
        };
        errdefer harness.databases.deinit();
        harness.processor = try .init(gpa, io, .{}, harness.databases, anchor, null);
        harness.execution = harness.processor.execution;
        harness.provider_state = .{};
        errdefer harness.provider_state.deinit();
        try harness.provider_state.insert(genesis);
        harness.app = .{};
    }

    pub fn deinit(harness: *Harness) void {
        harness.flushes.deinit();
        harness.processor.deinit();
        harness.databases.deinit();
        harness.provider_state.deinit();
        harness.registry.deinit();
        harness.cache_ref.deinit();
        harness.storage.deinit();
    }

    pub fn config(harness: *Harness) Any.Config {
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

    pub fn provider(harness: *Harness) TestProvider {
        return .{ .state = &harness.provider_state };
    }

    /// A child of `parent` at `view` built on `parent`'s state, with that state.
    pub fn build_child(harness: *Harness, parent: *const TestBlock, view: u64) !struct {
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
    pub fn stage_pending_child(harness: *Harness, parent: *const TestBlock, view: u64) !TestBlock {
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

    /// Finalizes `block`, the branch anchor's child, through the processor and waits for its
    /// barrier.
    pub fn finalize(harness: *Harness, block: *const TestBlock) !void {
        var handle = try digested(block.*);
        defer handle.deinit();
        try testing.expect(!harness.processor.redelivered(&handle));
        const provider_value = harness.provider();
        const applied = try harness.processor.finalize(&provider_value, &handle, true);
        try applied.barrier.?.durable();
        try harness.provider_state.canonical.put(gpa, block.height().get(), block.digest());
    }

    /// A fixed ancestry over `blocks`, newest first (commonware `from_iter`).
    pub fn ancestry(_: *Harness, blocks: []const TestBlock) !Execution.Ancestry {
        var handles: [4]Digested = undefined;
        assert(blocks.len <= handles.len);
        for (blocks, 0..) |block, index| handles[index] = try digested(block);
        return Execution.Ancestry.from_blocks(gpa, handles[0..blocks.len]);
    }
};
