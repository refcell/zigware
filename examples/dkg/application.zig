//! Stateful application that records each block's height in QMDB (commonware
//! `examples/dkg/src/application.rs`).
//!
//! Every non-genesis block writes its height to one fixed key. Epoch validation (`Deferred`),
//! QMDB root and range validation (`stateful::Application`), and reshare payload validation
//! (`reshare::Application`) belong to the layers above, as in commonware; this module only
//! executes blocks. Until glue's stateful `Application` contract lands, the hooks take what
//! commonware's ancestry stream yields (the parent block, or the block's height) directly.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
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

/// A proposed block and the state it reaches.
pub const Proposed = struct { block: types.Block, merkleized: Merkleized };

/// Application logic: every non-genesis block writes its height to one fixed key.
pub const App = struct {
    genesis_block: *const types.Block,

    pub fn init(genesis_block: *const types.Block) App {
        assert(genesis_block.height().get() == 0);
        return .{ .genesis_block = genesis_block };
    }

    /// The genesis block, copied for the caller.
    pub fn genesis(app: *const App, gpa: Allocator) Allocator.Error!types.Block {
        return app.genesis_block.clone(gpa);
    }

    /// Writes `height` and merkleizes; consumes `batches`, also on error.
    pub fn execute(height: types.Height, batches: *Unmerkleized) !Merkleized {
        errdefer batches.deinit();
        assert(height.get() > 0);
        try batches.write(height_key, .init(height.get()));
        return batches.merkleize();
    }

    /// Builds the child of `parent` carrying `payload` (owned by the block on success), which
    /// the reshare wrapper selected. Consumes `batches`.
    pub fn propose(
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

    /// Re-executes a block at `height` (the ancestry's head); consumes `batches`.
    pub fn process(height: types.Height, batches: *Unmerkleized) !Merkleized {
        return execute(height, batches);
    }

    /// The state a block claims to reach.
    pub fn sync_targets(block: *const types.Block) types.Target {
        assert(block.target.start < block.target.end);
        return block.target;
    }
};
