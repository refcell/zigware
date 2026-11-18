//! The sync `Database` interface for the compact db (commonware's `qmdb/compact/sync.rs`).
//!
//! `Db` re-exports these declarations, so `sync.database.assert_database(Db)` holds. Compact
//! sync fetches only the commit at the start of the target's range, into an in-memory journal;
//! the db is built from that commit and the pinned nodes, and the configured witness partition
//! stays untouched until `persist_sync_result` journals the import.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const runtime = @import("runtime");
const merkle = @import("../../merkle/mod.zig");
const sync_journal = @import("../sync/journal.zig");
const target_mod = @import("../sync/target.zig");

const Storage = runtime.storage.Storage;
const Scope = runtime.telemetry.metrics.Scope;

/// The sync declarations of compact db `D`.
pub fn Sync(comptime D: type) type {
    return struct {
        pub const Journal = sync_journal.Memory(D.Operation);
        pub const Target = target_mod.Target(D.Family, D.Digest);
        /// Compact sync writes no journal of its own (commonware's `JournalConfig = ()`).
        pub const JournalConfig = void;

        pub fn journal_config(_: D.Cfg) JournalConfig {}

        /// The engine's sync journal: an empty in-memory journal at `range.start`.
        pub fn open_journal(gpa: Allocator, _: Storage, _: D.Cfg, range: merkle.Range) !Journal {
            assert(range.start < range.end);
            return Journal.init(gpa, .{ .start = range.start, .end = range.end });
        }

        /// Builds a compact db from the synced journal, which must hold exactly the commit at
        /// `range.start`. Takes `journal` and `pinned_nodes`, also on error.
        pub fn from_sync_result(
            gpa: Allocator,
            storage: Storage,
            _: Scope,
            cfg: D.Cfg,
            journal: Journal,
            pinned_nodes: ?[]D.Digest,
            range: merkle.Range,
            _: u64,
        ) !D {
            assert(range.start < range.end);
            var log = journal;
            defer log.deinit();
            defer if (pinned_nodes) |pins| gpa.free(pins);
            const last_commit_loc = range.start;
            if (log.ops.items.len != 1 or log.start != last_commit_loc) {
                for (log.ops.items) |op| codec.free(D.Operation, gpa, op);
                log.ops.clearRetainingCapacity();
                return error.UnexpectedData;
            }
            const op = log.ops.items[0];
            log.ops.clearRetainingCapacity(); // `init_from_sync` takes the op, also on error.
            assert(log.ops.items.len == 0);
            // Null only at genesis, where nothing is pinned.
            const pins: []const D.Digest = pinned_nodes orelse &.{};
            return D.init_from_sync(gpa, storage, cfg, last_commit_loc, pins, op);
        }

        /// Journals the pending import and syncs the witness journal.
        pub fn persist_sync_result(db: *D) !void {
            try db.sync();
        }

        /// Nothing to discard: the sync journal lives in memory, and the stored witnesses are
        /// never read to build the synced state.
        pub fn discard_local_state(_: Allocator, _: Storage, _: D.Cfg) !void {}

        /// Compact dbs keep no pins a sync could reuse.
        pub fn local_pinned_nodes(
            _: Allocator,
            _: Storage,
            _: D.Cfg,
            target: Target,
            journal: *const Journal,
        ) !?[]D.Digest {
            assert(target.start < target.end);
            assert(journal.start <= journal.size());
            return null;
        }

        pub fn ops_root(db: *const D) D.Digest {
            return db.root();
        }
    };
}
