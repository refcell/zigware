//! commonware `glue/src/stateful/db/compact.rs`'s state-sync tests, each for keyless and
//! immutable: the update forwarder stops with the sync, a queued target is adopted before the
//! initial one is reached, progress gauges from compact and full sources, and superseding an
//! in-flight stale target from compact and full sources. They run on the deterministic
//! runtime, so a sync that never finishes fails instead of hanging.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const storage = @import("storage");
const utils = @import("utils");
const db = @import("mod.zig");
const state_sync = @import("state_sync.zig");
const keyless = @import("keyless.zig");
const immutable = @import("immutable.zig");
const compact = @import("compact.zig");

const gpa = testing.allocator;
const qmdb = storage.qmdb;
const ring = utils.channel.ring;
const mpsc = utils.channel.mpsc;
const metrics = runtime.telemetry.metrics;
const contiguous = storage.journal.contiguous;
const Sha256 = cryptography.Sha256;
const Digest = Sha256.Digest;
const Mmr = storage.mmr.Family;
const U64 = utils.sequence.U64;

const engine_config: state_sync.SyncEngineConfig = .{
    .fetch_batch_size = 1,
    .apply_batch_size = 1,
    .max_outstanding_requests = 1,
};

/// One operation family: its compact adapter, its full database, and its mutation.
fn Case(comptime keyed: bool) type {
    return struct {
        const Encoding = if (keyed) qmdb.value.Fixed(Digest) else qmdb.value.Fixed(U64);
        const Op = if (keyed)
            qmdb.immutable.Operation(Mmr, Digest, Encoding)
        else
            qmdb.keyless.Operation(Mmr, Encoding);
        const Journal = contiguous.fixed.Journal(Op);
        pub const Compact = compact.Compact(Mmr, Op, Sha256);
        pub const Full = if (keyed)
            immutable.Immutable(Mmr, Digest, Encoding, Journal, Sha256, storage.translator.TwoCap)
        else
            keyless.Keyless(Mmr, Encoding, Journal, Sha256);
        pub const Value = Compact.Value;

        /// commonware's `commit_metadata(seed)`.
        pub fn metadata(seed: u64) Value {
            if (!keyed) return U64.init(seed);
            var bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &bytes, seed, .little);
            return Sha256.hash(&.{ "metadata", &bytes });
        }

        /// commonware's `mutate(batch, seed)` with its commit metadata.
        pub fn fill(batch: anytype, seed: u64) !void {
            if (keyed) {
                var bytes: [8]u8 = undefined;
                std.mem.writeInt(u64, &bytes, seed, .big);
                try batch.set(Sha256.hash(&.{&bytes}), Sha256.hash(&.{ "value", &bytes }));
            } else {
                try batch.append(U64.init(seed));
            }
            batch.with_metadata(metadata(seed));
        }
    };
}

const cases = .{ Case(false), Case(true) };

/// One node's storage, page cache, and metrics.
const Node = struct {
    io: Io,
    storage: runtime.buffer.mocks.Storage,
    cache_ref: runtime.buffer.paged.CacheRef,
    registry: metrics.Registry,

    fn init(node: *Node, io: Io) !void {
        node.* = .{
            .io = io,
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
            .io = node.io,
            .storage = node.storage.interface(),
            .scope = metrics.Scope.init(&node.registry).child("client"),
        };
    }

    fn compact_config(node: *Node, comptime A: type) A.Config {
        return .{
            .witness = .{
                .partition = "compact-sync-witness",
                .items_per_section = 64,
                .codec_config = {},
                .cache_ref = &node.cache_ref,
                .write_buffer = 1024,
                .replay_buffer = 1024,
            },
            .codec_config = {},
        };
    }

    fn full_config(node: *Node, comptime Full: type) Full.Config {
        var config: Full.Config = undefined;
        config.merkle = .{
            .journal_partition = "compact-sync-full-journal",
            .metadata_partition = "compact-sync-full-metadata",
            .items_per_blob = 11,
            .write_buffer = 1024,
            .replay_buffer = 1024,
            .cache_ref = &node.cache_ref,
        };
        config.log = .{
            .partition = "compact-sync-full-log",
            .items_per_blob = 7,
            .cache_ref = &node.cache_ref,
            .write_buffer = 1024,
            .replay_buffer = 1024,
        };
        if (@hasField(Full.Config, "translator")) config.translator = .{};
        if (@hasField(Full.Config, "io")) config.io = null; // Untimed.
        return config;
    }

    /// Whether this node's metrics hold `name` at `value`.
    fn has_metric(node: *Node, name: []const u8, value: u64) !bool {
        const text = try node.registry.encode(gpa);
        defer gpa.free(text);
        return metrics.has_metric_value(text, name, value);
    }
};

/// A populated source database of `DB` with one commit per seed, and its targets as compact
/// targets.
fn Populated(comptime C: type, comptime DB: type) type {
    return struct {
        const Self = @This();
        node: Node,
        shared: DB.Shared,
        source: state_sync.SharedSource(DB),
        targets: [2]C.Compact.SyncTarget,

        fn init(self: *Self, io: Io, seeds: [2]u64) !void {
            try self.node.init(io);
            errdefer self.node.deinit();
            const config = if (DB == C.Compact)
                self.node.compact_config(DB)
            else
                self.node.full_config(DB);
            self.shared = try DB.Shared.open(self.node.env(), config, null);
            errdefer self.shared.deinit();
            for (seeds, &self.targets) |seed, *target| {
                var batch = try self.shared.new_batches();
                errdefer batch.deinit();
                try C.fill(&batch, seed);
                var merkleized = try batch.merkleize();
                defer merkleized.deinit();
                try self.shared.apply(&merkleized);
                const barrier = try self.shared.finalize();
                try barrier.durable();
                const committed = try self.shared.committed_targets();
                target.* = if (DB == C.Compact)
                    committed
                else
                    .{ .root = committed.root, .size = committed.end };
            }
            self.source = .{ .shared = self.shared };
        }

        fn deinit(self: *Self) void {
            self.shared.deinit();
            self.node.deinit();
        }
    };
}

/// Serves through `inner`, except that a request at `stale_size` signals `stale_requests`
/// and then never completes (commonware's `SupersedingSource`).
fn SupersedingSource(comptime Inner: type) type {
    return struct {
        const Self = @This();
        pub const Family = Inner.Family;
        pub const Op = Inner.Op;
        pub const Digest = Inner.Digest;
        pub const Error = Inner.Error;
        const Response = qmdb.sync.Response(Family, Op, Self.Digest);

        io: Io,
        inner: *Inner,
        stale_size: u64,
        stale_requests: mpsc.Sender(void),

        pub fn serve(
            self: *Self,
            allocator: std.mem.Allocator,
            request: qmdb.sync.Request(Family),
        ) (Error || Io.Cancelable)!qmdb.sync.Served(Response) {
            if (request.size() != self.stale_size) return self.inner.serve(allocator, request);
            self.stale_requests.try_send({}) catch {}; // One signal is enough.
            try self.io.sleep(.fromSeconds(3600), .awake);
            unreachable; // The runner's timeout fires first.
        }
    };
}

/// Runs `body` on a deterministic runtime that fails after 10 simulated seconds.
fn run(comptime body: fn (Io) anyerror!void) !void {
    const timeout_ns = 10 * std.time.ns_per_s;
    var runner = try runtime.deterministic.Runner.init(gpa, .{ .timeout_ns = timeout_ns });
    defer runner.deinit();
    try try runner.start(body, .{runner.io()});
}

/// Syncs `C.Compact` from `source`, as a task function.
fn Sync(comptime C: type, comptime S: type) type {
    return struct {
        const A = C.Compact;
        /// The task's arguments, passed by pointer to keep its closure small.
        const Args = struct {
            env: db.Env,
            config: A.Config,
            source: *S,
            target: A.SyncTarget,
            channels: state_sync.Channels(A.SyncTarget),
            /// The synced database, set when the sync succeeds.
            synced: ?A = null,

            fn close(args: *Args) void {
                if (args.synced) |*database| database.deinit();
                args.synced = null;
            }
        };
        /// Results are written to `args.synced` to keep the task's result small.
        fn run(args: *Args) anyerror!void {
            const a = args;
            const config = engine_config;
            a.synced = try A.sync_db(a.env, a.config, a.source, a.target, a.channels, config);
        }
    };
}

fn expect_synced(
    comptime C: type,
    synced: *C.Compact,
    target: C.Compact.SyncTarget,
    seed: u64,
) !void {
    try testing.expect(synced.sync_target().eql(target));
    try testing.expectEqual(C.metadata(seed), (try synced.inner.get_metadata()).?);
}

fn forwarder_stops(comptime C: type) fn (Io) anyerror!void {
    return struct {
        fn body(io: Io) anyerror!void {
            const A = C.Compact;
            var source: Populated(C, A) = undefined;
            try source.init(io, .{ 7, 8 });
            defer source.deinit();
            var node: Node = undefined;
            try node.init(io);
            defer node.deinit();
            var tips = try ring.channel(A.SyncTarget, gpa, io, 1);
            defer tips.sender.deinit();
            defer tips.receiver.deinit();
            const config = node.compact_config(A);
            var synced = try A.sync_db(node.env(), config, &source.source, source.targets[0], .{
                .tip_updates = &tips.receiver,
            }, engine_config);
            defer synced.deinit();
            // The forwarder ended with the sync: a later tip stays queued for its owner.
            try testing.expect(tips.sender.send_lossy(source.targets[1]));
            try io.sleep(.fromMilliseconds(10), .awake);
            const queued = try tips.receiver.try_recv();
            try testing.expect(queued.eql(source.targets[1]));
        }
    }.body;
}

fn adopts_queued_target(comptime C: type) fn (Io) anyerror!void {
    return struct {
        fn body(io: Io) anyerror!void {
            const A = C.Compact;
            var source: Populated(C, C.Full) = undefined;
            try source.init(io, .{ 7, 8 });
            defer source.deinit();
            var node: Node = undefined;
            try node.init(io);
            defer node.deinit();
            var tips = try ring.channel(A.SyncTarget, gpa, io, 1);
            defer tips.sender.deinit();
            defer tips.receiver.deinit();
            try testing.expect(tips.sender.send_lossy(source.targets[1]));
            // Room for two reports, but the initial target is never reached on its own.
            var reached = try ring.channel(A.SyncTarget, gpa, io, 2);
            defer reached.receiver.deinit();
            const config = node.compact_config(A);
            var synced = try A.sync_db(node.env(), config, &source.source, source.targets[0], .{
                .tip_updates = &tips.receiver,
                .reached_target = reached.sender,
            }, engine_config);
            defer synced.deinit();
            const first = (try reached.receiver.recv()).?;
            try testing.expect(first.eql(source.targets[1]));
            try testing.expectEqual(null, try reached.receiver.recv());
            try expect_synced(C, &synced, source.targets[1], 8);
        }
    }.body;
}

fn reports_progress(comptime C: type, comptime DB: type) fn (Io) anyerror!void {
    return struct {
        fn body(io: Io) anyerror!void {
            const A = C.Compact;
            const Source = SupersedingSource(state_sync.SharedSource(DB));
            var populated: Populated(C, DB) = undefined;
            try populated.init(io, .{ 7, 8 });
            defer populated.deinit();
            const target = populated.targets[0];
            // A larger target the source never serves, so the gauges can be read diverging.
            const unservable: A.SyncTarget = .{
                .root = Sha256.hash(&.{&.{0xFF}}),
                .size = target.size + 1,
            };
            var stale = try mpsc.channel(void, gpa, io, 1);
            defer stale.receiver.deinit();
            var source: Source = .{
                .io = io,
                .inner = &populated.source,
                .stale_size = unservable.size,
                .stale_requests = stale.sender,
            };
            defer source.stale_requests.deinit();
            var node: Node = undefined;
            try node.init(io);
            defer node.deinit();
            var tips = try ring.channel(A.SyncTarget, gpa, io, 1);
            defer tips.sender.deinit();
            defer tips.receiver.deinit();
            var finish = try mpsc.channel(void, gpa, io, 1);
            defer finish.sender.deinit();
            defer finish.receiver.deinit();
            var reached = try ring.channel(A.SyncTarget, gpa, io, 1);
            defer reached.receiver.deinit();
            const channels: state_sync.Channels(A.SyncTarget) = .{
                .tip_updates = &tips.receiver,
                .finish = &finish.receiver,
                .reached_target = reached.sender,
            };
            const T = Sync(C, Source);
            var args: T.Args = .{
                .env = node.env(),
                .config = node.compact_config(A),
                .source = &source,
                .target = target,
                .channels = channels,
            };
            var future = try io.concurrent(T.run, .{&args});
            defer args.close();
            defer future.cancel(io) catch {};

            try testing.expect((try reached.receiver.recv()).?.eql(target));
            try testing.expect(try node.has_metric("sync_target_size", target.size));
            try testing.expect(try node.has_metric("sync_size", target.size));
            // The target gauge advances to the superseding target while the synced gauge
            // still reports the reached one.
            try testing.expect(tips.sender.send_lossy(unservable));
            _ = try stale.receiver.recv();
            try testing.expect(try node.has_metric("sync_target_size", unservable.size));
            try testing.expect(try node.has_metric("sync_size", target.size));
        }
    }.body;
}

fn supersedes_stale_target(comptime C: type, comptime DB: type) fn (Io) anyerror!void {
    return struct {
        fn body(io: Io) anyerror!void {
            const A = C.Compact;
            const Source = SupersedingSource(state_sync.SharedSource(DB));
            var populated: Populated(C, DB) = undefined;
            try populated.init(io, .{ 7, 8 });
            defer populated.deinit();
            var stale = try mpsc.channel(void, gpa, io, 1);
            defer stale.receiver.deinit();
            var source: Source = .{
                .io = io,
                .inner = &populated.source,
                .stale_size = populated.targets[0].size,
                .stale_requests = stale.sender,
            };
            defer source.stale_requests.deinit();
            var node: Node = undefined;
            try node.init(io);
            defer node.deinit();
            var tips = try ring.channel(A.SyncTarget, gpa, io, 1);
            defer tips.sender.deinit();
            defer tips.receiver.deinit();
            const channels: state_sync.Channels(A.SyncTarget) = .{ .tip_updates = &tips.receiver };
            const target = populated.targets[0];
            const T = Sync(C, Source);
            var args: T.Args = .{
                .env = node.env(),
                .config = node.compact_config(A),
                .source = &source,
                .target = target,
                .channels = channels,
            };
            var future = try io.concurrent(T.run, .{&args});
            defer args.close();
            var done = false;
            defer if (!done) future.cancel(io) catch {};
            // The sync requests the stale target first, then switches to the latest.
            _ = try stale.receiver.recv();
            try testing.expect(tips.sender.send_lossy(populated.targets[1]));
            done = true;
            try future.await(io);
            try expect_synced(C, &args.synced.?, populated.targets[1], 8);
        }
    }.body;
}

test "stateful compact sync: the update forwarder stops after completion" {
    inline for (cases) |C| try run(forwarder_stops(C));
}

test "stateful compact sync: a queued target is adopted before reaching the initial one" {
    inline for (cases) |C| try run(adopts_queued_target(C));
}

test "stateful compact sync: progress gauges from a compact source" {
    inline for (cases) |C| try run(reports_progress(C, C.Compact));
}

test "stateful compact sync: progress gauges from a full source" {
    inline for (cases) |C| try run(reports_progress(C, C.Full));
}

test "stateful compact sync: an in-flight stale target is superseded from a compact source" {
    inline for (cases) |C| try run(supersedes_stale_target(C, C.Compact));
}

test "stateful compact sync: an in-flight stale target is superseded from a full source" {
    inline for (cases) |C| try run(supersedes_stale_target(C, C.Full));
}
