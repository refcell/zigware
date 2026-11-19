//! The single-database stateful e2e app (commonware `glue/src/stateful/tests/single_db_app.rs`).
//!
//! `SingleDbEngine` runs `engine.StatefulEngine` over one unordered fixed QMDB per validator. Its
//! `App` bumps a counter and records each height, and every block commits to the resulting
//! state through its sync target.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const consensus = @import("consensus");
const cryptography = @import("cryptography");
const runtime = @import("runtime");
const engine = @import("engine.zig");
const processor_mod = @import("../actor/processor/processor.zig");
const testing_mod = @import("../actor/processor/testing.zig");

const Height = consensus.Height;
const Sha256 = cryptography.Sha256;
const Key = engine.Key;
pub const Any = testing_mod.Any;
const SyncTarget = Any.SyncTarget;
const u64_to_digest = engine.u64_to_digest;
const digest_to_u64 = engine.digest_to_u64;
const counter_key = engine.counter_key;
const height_key = engine.height_key;

pub const SingleDbEngine = engine.StatefulEngine(Spec);

/// A block carrying its consensus context and the state it commits to (commonware `Block`):
/// `context || parent || height || state_root || range`, hashed with SHA-256.
pub const Block = struct {
    pub const Digest = Sha256.Digest;
    pub const Context = engine.BlockContext;
    pub const Cfg = void;

    context_value: Block.Context,
    parent_value: Sha256.Digest,
    height_value: Height,
    target: SyncTarget,
    /// The hash of the encoding above (not encoded).
    digest_value: Sha256.Digest,

    pub const max_encode_size: usize = codec.max_encode_size(Block.Context).? +
        Sha256.Digest.fixed_size + Height.max_encode_size + Sha256.Digest.fixed_size +
        2 * codec.varint.max_size(u64);

    pub fn init(
        context_value: Block.Context,
        parent_digest: Sha256.Digest,
        at: Height,
        target: SyncTarget,
    ) Block {
        var block: Block = .{
            .context_value = context_value,
            .parent_value = parent_digest,
            .height_value = at,
            .target = target,
            .digest_value = undefined,
        };
        var buffer: [max_encode_size]u8 = undefined;
        var writer = codec.Writer.init(&buffer);
        block.write(&writer);
        block.digest_value = Sha256.hash(&.{writer.written()});
        assert(writer.written().len == block.encode_size());
        return block;
    }

    /// The height-zero block over the empty database (commonware `Block::genesis`).
    pub fn genesis() Block {
        const empty: Sha256.Digest = .fill(0);
        return init(engine.genesis_context(), empty, .zero(), Any.initial_sync_target());
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
        self.target.write(writer);
    }

    pub fn encode_size(self: Block) usize {
        const size = codec.encode_size(Block.Context, self.context_value) +
            Sha256.Digest.fixed_size + self.height_value.encode_size() +
            self.target.encode_size();
        assert(size <= max_encode_size);
        return size;
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Block {
        const context_value = try codec.read(Block.Context, gpa, reader);
        const parent_digest = try Sha256.Digest.read(gpa, reader, {});
        const at = try Height.read(gpa, reader, {});
        const target = try SyncTarget.read(gpa, reader, {});
        return init(context_value, parent_digest, at, target);
    }
};

/// The application: each block increments `counter` and writes `height -> height` (commonware
/// `App`).
pub const App = struct {
    pub const Block = single.Block;
    pub const Context = single.Block.Context;
    pub const Input = void;
    pub const Merkleized = Any.Merkleized;
    const Built = processor_mod.Proposed(App);

    pub fn sync_targets(block: *const single.Block) SyncTarget {
        return block.target;
    }

    fn execute(batches: Any.Unmerkleized, at: Height) !Any.Merkleized {
        var batch = batches;
        errdefer batch.deinit();
        const key = counter_key();
        const current = if (try batch.get(&key)) |value| digest_to_u64(value) else 0;
        try batch.write(key, u64_to_digest(current + 1));
        try batch.write(height_key(at), u64_to_digest(at.get()));
        return batch.merkleize();
    }

    pub fn process(
        _: *App,
        _: Io,
        _: App.Context,
        ancestry: anytype,
        batches: Any.Unmerkleized,
        _: anytype,
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
        return try execute(owned, block.inner().height());
    }

    pub fn propose(
        _: *App,
        _: Io,
        context: App.Context,
        ancestry: anytype,
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
        const at = parent.inner().height().next();
        var merkleized = try execute(owned, at);
        errdefer merkleized.deinit();
        const bounds = &merkleized.inner.bounds;
        const floor = bounds.inactivity_floor;
        const target: SyncTarget = .init(merkleized.root(), floor, bounds.tip.size);
        return .{ .block = .init(context, parent.digest(), at, target), .merkleized = merkleized };
    }

    pub fn capture(
        _: *App,
        _: Io,
        _: App.Context,
        _: *const single.Block,
        _: anytype,
        _: anytype,
    ) !void {
        // The app captures nothing before applying.
    }

    pub fn finalized(
        _: *App,
        _: Io,
        _: App.Context,
        _: *const single.Block,
        _: void,
        _: anytype,
    ) !void {
        // The app has no finalization hook.
    }
};

/// The app's databases, their configuration, and their one resolver (see `engine`).
const Spec = struct {
    pub const Block = single.Block;
    pub const App = single.App;
    pub const Databases = Any.Shared;
    pub const Resolvers = ResolverSet;

    pub const DbConfig = struct {
        names: [3][]u8,
        cache: *runtime.buffer.paged.CacheRef,

        pub fn init(
            gpa: Allocator,
            prefix: []const u8,
            cache: *runtime.buffer.paged.CacheRef,
        ) !DbConfig {
            const parts = [_][]const u8{
                "-qmdb-mmr-journal",
                "-qmdb-mmr-metadata",
                "-qmdb-log-journal",
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

        pub fn config(self: *const DbConfig) Any.Config {
            return .{
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
        }

        pub fn deinit(self: *DbConfig, gpa: Allocator) void {
            for (self.names) |name| gpa.free(name);
            self.* = undefined;
        }
    };

    pub fn oldest_retained(databases: Any.Shared) !u64 {
        var guard = try databases.read();
        defer guard.deinit();
        return guard.get().inner.bounds().start;
    }
};

/// One resolver on the QMDB sync channel.
const ResolverSet = struct {
    const Resolver = engine.QmdbResolver(Any, engine.Net.Sender, engine.Net.Receiver);
    pub const Handles = *Resolver.Mailbox;
    pub const payload_size = Resolver.payload_size;

    resolver: Resolver,

    pub fn init(self: *ResolverSet, args: engine.ResolverArgs) !void {
        const channel = args.channel;
        try self.resolver.init(&args, "qmdb", channel.sender, channel.receiver);
        assert(self.resolver.task != null);
    }

    pub fn handles(self: *ResolverSet) Handles {
        return &self.resolver.mailbox;
    }

    pub fn stop(self: *ResolverSet) void {
        self.resolver.stop();
    }

    pub fn deinit(self: *ResolverSet) void {
        self.resolver.deinit();
        self.* = undefined;
    }
};

const single = @This();
