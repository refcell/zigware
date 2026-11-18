//! State sync for keyless databases (commonware's `qmdb/keyless/sync/mod.rs`).
//!
//! commonware implements `sync::Database` on keyless's `Db`; here `Database(F, E, C, H)` is an
//! adapter that holds the `Db` and provides the interface `sync/database.zig` describes. The
//! sync journal is the backing contiguous journal `C`, opened over the config's `log`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const runtime = @import("runtime");
const merkle = @import("../../merkle/mod.zig");
const qmdb = @import("../mod.zig");
const sync = @import("../sync/mod.zig");
const db_mod = @import("db.zig");

const Storage = runtime.storage.Storage;
const Scope = runtime.telemetry.metrics.Scope;

pub fn Database(comptime F: type, comptime E: type, comptime C: type, comptime H: type) type {
    return struct {
        const Self = @This();
        pub const Db = db_mod.Db(F, E, C, H);
        pub const Family = F;
        pub const Op = Db.Operation;
        pub const Digest = H.Digest;
        pub const Hasher = H;
        pub const Journal = C;
        pub const Config = Db.Cfg;
        pub const Target = sync.Target(F, Digest);

        db: Db,

        pub fn deinit(self: *Self) void {
            self.db.deinit();
            self.* = undefined;
        }

        pub fn journal_config(cfg: Config) C.BackingConfig {
            return cfg.log;
        }

        /// Builds the database over the filled sync journal `log`: the Merkle structure is
        /// opened for `range` with `pinned_nodes`, missing leaves are replayed from the log,
        /// and the result is synced. Takes ownership of `log` and `pinned_nodes`.
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
                break :structure try Db.Journal.Merkle.init_sync(gpa, storage, .{
                    .config = cfg.merkle,
                    .range = range,
                    .pinned_nodes = pinned_nodes,
                });
            };
            const hasher = qmdb.hasher(H);
            const journal =
                try Db.Journal.from_components(gpa, structure, owned_log, hasher, apply_batch_size);
            var self: Self = .{ .db = try Db.init_from_log(gpa, scope, journal) };
            errdefer self.deinit();
            try self.db.sync();
            return self;
        }

        pub fn persist_sync_result(_: *Self) !void {}

        pub fn discard_local_state(gpa: Allocator, storage: Storage, cfg: Config) !void {
            try sync.database.discard_local_state(F, H, gpa, storage, cfg.merkle);
        }

        pub fn local_pinned_nodes(
            gpa: Allocator,
            storage: Storage,
            cfg: Config,
            target: Target,
            log: *C,
        ) !?[]Digest {
            const span = log.get_bounds();
            const bounds: merkle.Range = .{ .start = span.start, .end = span.end };
            const range: merkle.Range = .{ .start = target.start, .end = target.end };
            if (target.start == 0 or !sync.database.journal_covers_range(bounds, range)) {
                return null;
            }
            // The inactivity floor is the last commit's, not the target's start.
            var reader: LogReader = .{ .log = log };
            const floor = try qmdb.find_inactivity_floor_at(gpa, &reader, target.end);
            return sync.database.local_pinned_nodes(F, H, gpa, storage, cfg.merkle, target, floor);
        }

        pub fn ops_root(self: *const Self) Digest {
            return self.db.root();
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
