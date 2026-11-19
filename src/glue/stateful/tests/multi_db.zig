//! The multi-database stateful e2e app (commonware `glue/src/stateful/tests/multi_db_app.rs`).
//!
//! `MultiDbEngine` runs `engine.StatefulEngine` over two QMDBs per validator: DB-A, a full
//! unordered fixed QMDB that mirrors the single-database app (a counter and a height marker per
//! block), and DB-B, a compact immutable QMDB that keeps only its witness and records the height
//! marker. Every block commits to both roots. Both QMDB sync resolvers share the sync channel
//! through a muxer (subchannels 0 and 1), as commonware's do.
//!
//! Differences from commonware: DB-B's sync target is zigware's `CompactTarget` (its root and
//! size) where commonware's is the ranged `Target` over the last commit (`size - 1..size`); both
//! name the same state.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const p2p = @import("p2p");
const runtime = @import("runtime");
const storage = @import("storage");
const engine = @import("engine.zig");
const db = @import("../db/mod.zig");
const compact = @import("../db/compact.zig");
const processor_mod = @import("../actor/processor/processor.zig");
const testing_mod = @import("../actor/processor/testing.zig");

const Height = consensus.Height;
const Sha256 = cryptography.Sha256;
const Digest = engine.Digest;
const qmdb = storage.qmdb;
const mux = p2p.utils.mux;
const Family = storage.mmr.Family;
const CacheRef = runtime.buffer.paged.CacheRef;

/// DB-A: the full (journaled) QMDB.
pub const QmdbA = testing_mod.Any;
/// DB-B: the compact (witness-only) immutable QMDB.
pub const QmdbB = compact.Compact(
    Family,
    qmdb.immutable.Operation(Family, Digest, qmdb.value.Fixed(Digest)),
    Sha256,
);
pub const Databases = db.Tuple(.{ QmdbA, QmdbB });
const RangedTarget = QmdbA.SyncTarget;

pub const MultiDbEngine = engine.StatefulEngine(Spec);

/// A block carrying state from two QMDBs (commonware `Block`):
/// `context || parent || height || root_a || range_a || root_b || range_b`, hashed with SHA-256.
pub const Block = struct {
    pub const Digest = Sha256.Digest;
    pub const Context = engine.BlockContext;
    pub const Cfg = void;

    context_value: Block.Context,
    parent_value: Sha256.Digest,
    height_value: Height,
    /// DB-A's root and its range: inactivity floor to size.
    target_a: RangedTarget,
    /// DB-B's root and its range: inactivity floor to size.
    target_b: RangedTarget,
    /// The hash of the encoding above (not encoded).
    digest_value: Sha256.Digest,

    pub const max_encode_size: usize = codec.max_encode_size(Block.Context).? +
        Sha256.Digest.fixed_size + Height.max_encode_size +
        2 * (Sha256.Digest.fixed_size + 2 * codec.varint.max_size(u64));

    pub fn init(
        context_value: Block.Context,
        parent_digest: Sha256.Digest,
        at: Height,
        target_a: RangedTarget,
        target_b: RangedTarget,
    ) Block {
        var block: Block = .{
            .context_value = context_value,
            .parent_value = parent_digest,
            .height_value = at,
            .target_a = target_a,
            .target_b = target_b,
            .digest_value = undefined,
        };
        var buffer: [max_encode_size]u8 = undefined;
        var writer = codec.Writer.init(&buffer);
        block.write(&writer);
        block.digest_value = Sha256.hash(&.{writer.written()});
        assert(writer.written().len == block.encode_size());
        return block;
    }

    /// The height-zero block over both empty databases (commonware `Block::genesis`).
    pub fn genesis() Block {
        const empty: Sha256.Digest = .fill(0);
        const initial_b = QmdbB.initial_sync_target();
        const target_b: RangedTarget = .init(initial_b.root, 0, initial_b.size);
        const target_a = QmdbA.initial_sync_target();
        return init(engine.genesis_context(), empty, .zero(), target_a, target_b);
    }

    pub fn digest(self: Block) Sha256.Digest {
        return self.digest_value;
    }

    pub fn parent(self: Block) Sha256.Digest {
        return self.parent_value;
    }

    pub fn height(self: Block) Height {
        return self.height_value;
    }

    pub fn context(self: Block) Block.Context {
        return self.context_value;
    }

    pub fn write(self: Block, writer: *codec.Writer) void {
        codec.write(Block.Context, self.context_value, writer);
        self.parent_value.write(writer);
        self.height_value.write(writer);
        self.target_a.write(writer);
        self.target_b.write(writer);
    }

    pub fn encode_size(self: Block) usize {
        const size = codec.encode_size(Block.Context, self.context_value) +
            Sha256.Digest.fixed_size + self.height_value.encode_size() +
            self.target_a.encode_size() + self.target_b.encode_size();
        assert(size <= max_encode_size);
        return size;
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Block {
        const context_value = try codec.read(Block.Context, gpa, reader);
        const parent_digest = try Sha256.Digest.read(gpa, reader, {});
        const at = try Height.read(gpa, reader, {});
        const target_a = try RangedTarget.read(gpa, reader, {});
        const target_b = try RangedTarget.read(gpa, reader, {});
        return init(context_value, parent_digest, at, target_a, target_b);
    }
};

/// The application (commonware `App`): DB-A increments `counter` and writes
/// `height -> height`; DB-B writes `height -> height`.
pub const App = struct {
    pub const Block = multi.Block;
    pub const Context = multi.Block.Context;
    pub const Input = void;
    pub const Merkleized = Databases.Merkleized;
    const Built = processor_mod.Proposed(App);

    pub fn sync_targets(block: *const multi.Block) Databases.SyncTargets {
        const target_b = block.target_b;
        assert(target_b.end > target_b.start);
        // DB-B is compact, so its target covers only the last commit.
        return .{ block.target_a, .{ .root = target_b.root, .size = target_b.end } };
    }

    /// Executes a block against both databases (commonware `App::execute`).
    pub fn execute(batches: Databases.Unmerkleized, at: Height) !Databases.Merkleized {
        var batch_a = batches[0];
        var batch_b = batches[1];
        var a_owned = true;
        errdefer if (a_owned) batch_a.deinit();
        errdefer batch_b.deinit();
        const key = engine.counter_key();
        const current = if (try batch_a.get(&key)) |value| engine.digest_to_u64(value) else 0;
        try batch_a.write(key, engine.u64_to_digest(current + 1));
        const marker = engine.height_key(at);
        try batch_a.write(marker, engine.u64_to_digest(at.get()));
        try batch_b.set(marker, engine.u64_to_digest(at.get()));
        var merkleized_a = try batch_a.merkleize();
        a_owned = false;
        errdefer merkleized_a.deinit();
        const merkleized_b = try batch_b.merkleize();
        return .{ merkleized_a, merkleized_b };
    }

    pub fn process(
        _: *App,
        _: Io,
        _: App.Context,
        ancestry: anytype,
        batches: Databases.Unmerkleized,
        _: anytype,
    ) !?Databases.Merkleized {
        var owned = batches;
        var block = (ancestry.next() catch |err| {
            inline for (&owned) |*batch| batch.deinit();
            return err;
        }) orelse {
            inline for (&owned) |*batch| batch.deinit();
            return null;
        };
        defer block.deinit();
        var merkleized = try execute(owned, block.inner().height());
        // DB-B's sync target covers its root and last commit but not its inactivity floor,
        // so the floor is checked here.
        const bounds_b = merkleized[1].bounds();
        const range_b = block.inner().target_b;
        if (bounds_b.inactivity_floor != range_b.start or bounds_b.tip.size != range_b.end) {
            inline for (&merkleized) |*batch| batch.deinit();
            return null;
        }
        return merkleized;
    }

    pub fn propose(
        _: *App,
        _: Io,
        context: App.Context,
        ancestry: anytype,
        batches: Databases.Unmerkleized,
        _: void,
    ) !?Built {
        var owned = batches;
        var parent = (ancestry.next() catch |err| {
            inline for (&owned) |*batch| batch.deinit();
            return err;
        }) orelse {
            inline for (&owned) |*batch| batch.deinit();
            return null;
        };
        defer parent.deinit();
        const at = parent.inner().height().next();
        var merkleized = try execute(owned, at);
        errdefer inline for (&merkleized) |*batch| batch.deinit();
        const bounds_a = &merkleized[0].inner.bounds;
        const target_a: RangedTarget =
            .init(merkleized[0].root(), bounds_a.inactivity_floor, bounds_a.tip.size);
        const bounds_b = merkleized[1].bounds();
        const target_b: RangedTarget =
            .init(merkleized[1].root(), bounds_b.inactivity_floor, bounds_b.tip.size);
        const block: multi.Block = .init(context, parent.digest(), at, target_a, target_b);
        return .{ .block = block, .merkleized = merkleized };
    }

    pub fn capture(
        _: *App,
        _: Io,
        _: App.Context,
        _: *const multi.Block,
        _: anytype,
        _: anytype,
    ) !void {
        // The app captures nothing before applying.
    }

    pub fn finalized(
        _: *App,
        _: Io,
        _: App.Context,
        _: *const multi.Block,
        _: void,
        _: anytype,
    ) !void {
        // The app has no finalization hook.
    }
};

/// The app's databases, their configuration, and their muxed resolvers (see `engine`).
pub const Spec = struct {
    pub const Block = multi.Block;
    pub const App = multi.App;
    pub const Databases = multi.Databases;
    pub const Resolvers = ResolverSet;

    /// Commonware `qmdb_config`: DB-A as the single-database app's, and DB-B with one
    /// witness entry per section so periodic pruning drops entries.
    pub const DbConfig = struct {
        names: [4][]u8,
        cache: *CacheRef,

        pub fn init(gpa: Allocator, prefix: []const u8, cache: *CacheRef) !DbConfig {
            const parts = [_][]const u8{
                "-qmdb-a-mmr-journal",
                "-qmdb-a-mmr-metadata",
                "-qmdb-a-log-journal",
                "-qmdb-b-witness",
            };
            var names: [parts.len][]u8 = undefined;
            var made: usize = 0;
            errdefer for (names[0..made]) |name| gpa.free(name);
            for (&names, parts) |*name, suffix| {
                name.* = try std.mem.concat(gpa, u8, &.{ prefix, suffix });
                made += 1;
            }
            assert(made == parts.len);
            return .{ .names = names, .cache = cache };
        }

        pub fn config(self: *const DbConfig) multi.Databases.Config {
            const config_a: QmdbA.Config = .{
                .merkle = .{
                    .journal_partition = self.names[0],
                    .metadata_partition = self.names[1],
                    .items_per_blob = 11,
                    .write_buffer = engine.io_buffer_size,
                    .replay_buffer = engine.io_buffer_size,
                    .cache_ref = self.cache,
                },
                .log = .{
                    .partition = self.names[2],
                    .items_per_blob = 7,
                    .cache_ref = self.cache,
                    .write_buffer = engine.io_buffer_size,
                    .replay_buffer = engine.io_buffer_size,
                },
                .translator = .{},
                .init_cache = 1024,
            };
            const config_b: QmdbB.Config = .{
                .witness = .{
                    .partition = self.names[3],
                    .items_per_section = 1,
                    .codec_config = {},
                    .cache_ref = self.cache,
                    .write_buffer = engine.io_buffer_size,
                    .replay_buffer = engine.io_buffer_size,
                },
                .codec_config = {},
            };
            return .{ config_a, config_b };
        }

        pub fn deinit(self: *DbConfig, gpa: Allocator) void {
            for (self.names) |name| gpa.free(name);
            self.* = undefined;
        }
    };

    /// DB-A's oldest retained operation; the compact DB-B keeps no history to observe.
    pub fn oldest_retained(databases: multi.Databases) !u64 {
        var guard = try databases.members[0].read();
        defer guard.deinit();
        return guard.get().inner.bounds().start;
    }
};

/// Two resolvers, one per database, on subchannels 0 and 1 of the muxed sync channel.
const ResolverSet = struct {
    const Mux = mux.Muxer(engine.Net.Sender, engine.Net.Receiver);
    const SubSender = mux.SubSender(engine.Net.Sender);
    const SubReceiver = mux.SubReceiver(engine.Key);
    const ResolverA = engine.QmdbResolver(QmdbA, SubSender, SubReceiver);
    const ResolverB = engine.QmdbResolver(QmdbB, SubSender, SubReceiver);
    pub const Handles = struct { *ResolverA.Mailbox, *ResolverB.Mailbox };
    /// Both actors share one channel, so its bound is the wider sync payload plus the
    /// subchannel prefix.
    pub const payload_size = mux.prefixed(@max(ResolverA.payload_size, ResolverB.payload_size));

    io: Io,
    handle: Mux.Handle,
    demux: Io.Future(Mux.RunError!void),
    resolver_a: ResolverA,
    resolver_b: ResolverB,

    pub fn init(self: *ResolverSet, args: engine.ResolverArgs) !void {
        const ctx = args.ctx;
        const channel = args.channel;
        const built = try Mux.init(ctx.gpa(), ctx.io(), channel.sender, channel.receiver);
        self.io = ctx.io();
        self.handle = built.handle;
        errdefer self.handle.deinit();
        self.demux = try built.muxer.start();
        errdefer _ = self.demux.cancel(self.io) catch {};
        const sub_a = try self.handle.register(0);
        try self.resolver_a.init(&args, "qmdb_a", sub_a.sender, sub_a.receiver);
        errdefer self.resolver_a.deinit();
        const sub_b = try self.handle.register(1);
        try self.resolver_b.init(&args, "qmdb_b", sub_b.sender, sub_b.receiver);
        assert(self.resolver_a.task != null and self.resolver_b.task != null);
    }

    pub fn handles(self: *ResolverSet) Handles {
        return .{ &self.resolver_a.mailbox, &self.resolver_b.mailbox };
    }

    pub fn stop(self: *ResolverSet) void {
        self.resolver_a.stop();
        self.resolver_b.stop();
        assert(self.resolver_a.task == null and self.resolver_b.task == null);
    }

    pub fn deinit(self: *ResolverSet) void {
        self.resolver_a.deinit();
        self.resolver_b.deinit();
        _ = self.demux.cancel(self.io) catch {};
        self.handle.deinit();
        self.* = undefined;
    }
};

const multi = @This();
