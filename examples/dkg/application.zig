//! Stateful application that records each block's height in QMDB (commonware
//! `examples/dkg/src/application.rs`).
//!
//! Every non-genesis block writes its height to one fixed key. Epoch validation (`Deferred`),
//! QMDB root and range validation (`stateful::Application`), and reshare payload validation
//! (`reshare::Application`) belong to the layers above, as in commonware; this module only
//! executes blocks. `App` meets glue.stateful's application contract (`Processor`): `propose`
//! and `process` take the ancestry stream; `build` and `execute` are their cores.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const zigware = @import("zigware");
const types = @import("types.zig");

const storage = zigware.storage;
const qmdb = storage.qmdb;
const any = zigware.glue.stateful.db.any;
const U64 = zigware.utils.sequence.U64;
const Sha256 = zigware.cryptography.Sha256;

const Encoding = qmdb.value.Fixed(U64);
const Journal = storage.journal.contiguous.fixed.Journal(
    qmdb.any.operation.Unordered(types.Family, U64, Encoding),
);
const Update = qmdb.any.operation.update.Unordered(U64, Encoding);
const Index = storage.index.unordered.Index(storage.translator.TwoCap, u64);
/// The QMDB holding the application state (commonware's `Qmdb`: an unordered fixed `any`
/// database of `U64` keys and values over a `TwoCap` index).
pub const Qmdb = qmdb.any.Db(types.Family, Update, Journal, Index, Sha256, 64);
pub const Managed = any.Any(Qmdb, Sha256);
/// Shared handle to the application QMDB (commonware's `Database`).
pub const Database = Managed.Shared;
pub const Unmerkleized = Managed.Unmerkleized;
pub const Merkleized = Managed.Merkleized;

/// The one key every block writes.
pub const height_key: U64 = .init(0);

/// Application QMDB config with partitions derived from `prefix` (commonware's `db_config`).
/// The partition names are allocated in `arena` and must outlive the database.
pub fn db_config(
    arena: Allocator,
    prefix: []const u8,
    cache_ref: *zigware.runtime.buffer.paged.CacheRef,
) Allocator.Error!Managed.Config {
    assert(prefix.len > 0);
    const io_buffer_size = types.io_buffer_size;
    return .{
        .merkle = .{
            .journal_partition = try std.fmt.allocPrint(arena, "{s}-qmdb-mmr-journal", .{prefix}),
            .metadata_partition = try std.fmt.allocPrint(arena, "{s}-qmdb-mmr-metadata", .{
                prefix,
            }),
            .items_per_blob = 11,
            .write_buffer = io_buffer_size,
            .replay_buffer = io_buffer_size,
            .cache_ref = cache_ref,
        },
        .log = .{
            .partition = try std.fmt.allocPrint(arena, "{s}-qmdb-log-journal", .{prefix}),
            .items_per_blob = 7,
            .cache_ref = cache_ref,
            .write_buffer = io_buffer_size,
            .replay_buffer = io_buffer_size,
        },
        .translator = .{},
        .init_cache = 1024,
    };
}

/// The sync target a merkleized batch reaches: its root over `[inactivity floor, tip)`.
pub fn target_of(merkleized: *const Merkleized) types.Target {
    const bounds = &merkleized.inner.bounds;
    assert(bounds.inactivity_floor < bounds.tip.size);
    return .init(merkleized.root(), bounds.inactivity_floor, bounds.tip.size);
}

/// A proposed block and the state it reaches (glue.stateful's `Proposed(App)`).
pub const Proposed = zigware.glue.stateful.actor.processor.Proposed(App);

/// Application logic: every non-genesis block writes its height to one fixed key. A cheap
/// handle: the stateful actor copies it into each call.
pub const App = struct {
    gpa: Allocator,
    genesis_block: *const types.Block,

    pub const Block = types.Block;
    pub const Context = types.Context;
    pub const Merkleized = Managed.Merkleized;
    /// The reshare payload the `reshare.Application` wrapper selected (commonware's
    /// `ReshareInput`), with the allocator that frees it.
    pub const Input = zigware.glue.dkg.reshare.application.InputOf(types.Payload);
    /// Nothing is read before a finalized block applies.
    pub const Captured = void;

    pub fn init(gpa: Allocator, genesis_block: *const types.Block) App {
        assert(genesis_block.height().get() == 0);
        return .{ .gpa = gpa, .genesis_block = genesis_block };
    }

    /// Frees an unused input.
    pub fn deinit_input(input: *Input) void {
        input.deinit();
        assert(input.payload == null);
    }

    /// The genesis block, copied for the caller.
    pub fn genesis(app: *const App, gpa: Allocator) Allocator.Error!types.Block {
        return app.genesis_block.clone(gpa);
    }

    /// Writes `height` and merkleizes; consumes `batches`, also on error.
    pub fn execute(height: types.Height, batches: *Unmerkleized) !Managed.Merkleized {
        errdefer batches.deinit();
        assert(height.get() > 0);
        try batches.write(height_key, .init(height.get()));
        return batches.merkleize();
    }

    /// Builds the child of `parent` carrying `payload` (owned by the block on success), which
    /// the reshare wrapper selected. Consumes `batches`.
    pub fn build(
        gpa: Allocator,
        context: types.Context,
        parent: *const types.Block,
        batches: *Unmerkleized,
        payload: ?types.Payload,
    ) !Proposed {
        const height = parent.height().next();
        var merkleized = try execute(height, batches);
        errdefer merkleized.deinit();
        const target = target_of(&merkleized);
        const block = try types.Block.init(gpa, context, parent.digest(), height, target, payload);
        assert(block.height().get() == parent.height().get() + 1);
        return .{ .block = block, .merkleized = merkleized };
    }

    /// Builds on the parent at the head of `ancestry` with the wrapper's `input` (commonware
    /// `propose`); null when the parent is gone. Consumes `batches` and `input`.
    pub fn propose(
        app: *App,
        _: Io,
        context: types.Context,
        ancestry: anytype,
        batches: Unmerkleized,
        input: Input,
    ) !?Proposed {
        var owned = batches;
        var payload = input;
        errdefer deinit_input(&payload);
        var parent = (ancestry.next() catch |err| {
            owned.deinit();
            return err;
        }) orelse {
            owned.deinit();
            deinit_input(&payload);
            return null;
        };
        defer parent.deinit();
        const payload_gpa = payload.gpa;
        const taken = payload.take();
        errdefer if (taken) |owned_payload| {
            var dropped = owned_payload;
            dropped.deinit(payload_gpa);
        };
        return try build(app.gpa, context, parent.inner(), &owned, taken);
    }

    /// Re-executes the block at the head of `ancestry` (commonware `process`); null when it is
    /// gone. Consumes `batches`.
    pub fn process(
        _: *App,
        _: Io,
        _: types.Context,
        ancestry: anytype,
        batches: Unmerkleized,
        _: zigware.glue.stateful.actor.Finality,
    ) !?Managed.Merkleized {
        var owned = batches;
        const head = ancestry.peek() orelse {
            owned.deinit();
            return null;
        };
        return try execute(head.inner().height(), &owned);
    }

    /// Reads nothing before a finalized block applies (commonware's empty `capture`).
    pub fn capture(
        _: *App,
        _: Io,
        _: types.Context,
        _: *const Block,
        _: *const Managed.Merkleized,
        _: anytype,
    ) !Captured {}

    /// Does nothing once a block is finalized (commonware's empty `finalized`).
    pub fn finalized(
        _: *App,
        _: Io,
        _: types.Context,
        _: *const Block,
        _: Captured,
        _: anytype,
    ) !void {}

    /// The state a block claims to reach.
    pub fn sync_targets(block: *const types.Block) types.Target {
        assert(block.target.start < block.target.end);
        return block.target;
    }
};
