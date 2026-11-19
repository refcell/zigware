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

    pub fn deinit(state: *ProviderState) void {
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
    target: Sha256.Digest,
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
    observations: ?*std.ArrayList(Observation) = null,

    /// Pre-apply reads (commonware `Captured`).
    pub const Captured = struct { prior_counter: ?u64, batch_counter: u64, batch_view: u64 };

    /// What the finalized hook saw (commonware `FinalizedObservation`).
    pub const Observation = struct { captured: Captured, post_counter: u64, post_view: u64 };

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

pub const Processor = processor_mod.Processor(struct {
    pub const App = TestApp;
    pub const Databases = Any.Shared;
    pub const Provider = TestProvider;
});
pub const Execution = Processor.Execution;

/// Storage, a page cache, metrics, the database, its execution, and a block provider.
pub const Harness = struct {
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: metrics.Registry,
    databases: Any.Shared,
    processor: Processor,
    /// The processor's execution.
    execution: *Execution,
    provider_state: ProviderState = .{},
    app: TestApp = .{},

    /// `harness` must not move afterwards: its provider points at its state.
    pub fn init(harness: *Harness) !void {
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
        errdefer harness.databases.deinit();
        harness.processor = try .init(gpa, io, .{}, harness.databases, anchor, null);
        harness.execution = harness.processor.execution;
        harness.provider_state = .{};
        errdefer harness.provider_state.deinit();
        try harness.provider_state.insert(genesis);
        harness.app = .{};
    }

    pub fn deinit(harness: *Harness) void {
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
