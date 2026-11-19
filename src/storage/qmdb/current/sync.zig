//! State sync for `current` databases (commonware's `qmdb/current/sync/mod.rs`), covering every
//! variant: unordered and ordered, fixed and variable.
//!
//! The engine syncs and verifies against the **ops root** (`any`'s root), exactly as `any`
//! sync does; `ops_root` returns it, not the canonical root. Once the operations are in, the
//! activity bitmap and grafted tree are rebuilt deterministically from them
//! (`current.Db.init_from_sync`), so the canonical root follows. Callers that must
//! authenticate the synced ops root against a trusted canonical root check it themselves.
//! A source serves through `any`'s log (`sync.JournalSource` over `db.any.log`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const runtime = @import("runtime");
const merkle = @import("../../merkle/mod.zig");
const qmdb = @import("../mod.zig");
const sync = @import("../sync/mod.zig");

const Storage = runtime.storage.Storage;
const Scope = runtime.telemetry.metrics.Scope;

/// The sync adapter of `current.Db` `D` hashed with `H` (`D`'s hasher, which `D` does not
/// export).
pub fn Database(comptime D: type, comptime H: type) type {
    comptime assert(D.Digest == H.Digest);
    return struct {
        const Self = @This();
        const F = D.Family;
        const C = @FieldType(D.Any.Log, "journal");
        pub const Db = D;
        pub const Family = F;
        pub const Op = D.Operation;
        pub const Digest = H.Digest;
        pub const Hasher = H;
        pub const Journal = C;
        pub const Config = D.Cfg;
        pub const Target = sync.Target(F, Digest);

        db: D,

        pub fn deinit(self: *Self) void {
            self.db.deinit();
            self.* = undefined;
        }

        pub fn journal_config(cfg: Config) C.BackingConfig {
            return cfg.log;
        }

        /// Builds the database over the filled sync journal `log`: the ops tree is opened for
        /// `range` with `pinned_nodes`, missing leaves are replayed from the log, the bitmap
        /// and grafted tree are rebuilt, and the result (with its grafted metadata) is
        /// synced. Takes ownership of `log` and `pinned_nodes`.
        pub fn from_sync_result(
            gpa: Allocator,
            storage: Storage,
            scope: Scope,
            cfg: Config,
            log: C,
            pinned_nodes: ?[]Digest,
            range: merkle.Range,
            apply_batch_size: u64,
        ) !Self {
            assert(range.start < range.end);
            var owned_log = log;
            const structure = structure: {
                defer if (pinned_nodes) |pins| gpa.free(pins);
                errdefer owned_log.deinit();
                break :structure try D.Any.Log.Merkle.init_sync(gpa, storage, .{
                    .config = cfg.merkle,
                    .range = range,
                    .pinned_nodes = pinned_nodes,
                });
            };
            const hasher = qmdb.hasher(H);
            const from = D.Any.Log.from_components;
            const journal = try from(gpa, structure, owned_log, hasher, apply_batch_size);
            var self: Self = .{ .db = try D.init_from_sync(gpa, storage, scope, cfg, journal) };
            errdefer self.deinit();
            try self.db.sync();
            assert(self.db.any.log.size() == range.end);
            return self;
        }

        pub fn persist_sync_result(_: *Self) !void {}

        /// Empties the ops tree and the grafted metadata recording chunks pruned from its
        /// operations.
        pub fn discard_local_state(gpa: Allocator, storage: Storage, cfg: Config) !void {
            try sync.database.discard_local_state(F, H, gpa, storage, cfg.merkle);
            try D.discard_grafted_metadata(gpa, storage, cfg);
        }

        pub fn local_pinned_nodes(
            gpa: Allocator,
            storage: Storage,
            cfg: Config,
            wanted: Target,
            log: *C,
        ) !?[]Digest {
            const span = log.get_bounds();
            const bounds: merkle.Range = .{ .start = span.start, .end = span.end };
            const range: merkle.Range = .{ .start = wanted.start, .end = wanted.end };
            if (wanted.start == 0 or !sync.database.journal_covers_range(bounds, range)) {
                return null;
            }
            // The inactivity floor is the last commit's, not the wanted's start.
            var reader: LogReader = .{ .log = log };
            const floor = try qmdb.find_inactivity_floor_at(gpa, &reader, wanted.end);
            return sync.database.local_pinned_nodes(F, H, gpa, storage, cfg.merkle, wanted, floor);
        }

        /// The target reaching the applied state. Its root is the ops root (not the canonical
        /// root), which the engine verifies batches against.
        pub fn target(self: *const Self) Target {
            const end = self.db.bounds().end;
            return .init(self.db.ops_root(), self.db.sync_boundary(), end);
        }

        /// Prunes the history below the start of a reached `target`.
        pub fn prune_to_target(self: *Self, reached: Target) !void {
            assert(reached.start < reached.end);
            try self.db.prune(reached.start);
        }

        const LogReader = struct {
            log: *C,

            pub fn bounds(reader: *const LogReader) merkle.Range {
                const span = reader.log.get_bounds();
                return .{ .start = span.start, .end = span.end };
            }

            pub fn read(reader: *LogReader, _: Allocator, location: u64) !Op {
                return reader.log.read(location);
            }
        };
    };
}

test {
    _ = @import("sync_test.zig");
}
