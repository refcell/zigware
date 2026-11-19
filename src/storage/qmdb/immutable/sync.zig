//! State sync for immutable databases (commonware's `qmdb/immutable/sync/mod.rs`): the sync
//! database adapter over immutable's `Db` (`sync.database.Persisted`), which rebuilds the
//! index from the last commit's floor with the config's translator.

const std = @import("std");
const Allocator = std.mem.Allocator;
const runtime = @import("runtime");
const sync = @import("../sync/mod.zig");
const db_mod = @import("db.zig");

const Scope = runtime.telemetry.metrics.Scope;

pub fn Database(
    comptime F: type,
    comptime K: type,
    comptime E: type,
    comptime C: type,
    comptime H: type,
    comptime T: type,
) type {
    const DbAlias = db_mod.Db(F, K, E, C, H, T);
    const V = struct {
        pub const Db = DbAlias;
        pub const Backing = C;
        pub const Hasher = H;
        pub fn build(
            gpa: Allocator,
            scope: Scope,
            cfg: DbAlias.Cfg,
            log: DbAlias.Journal,
        ) anyerror!DbAlias {
            return DbAlias.init_from_log(gpa, scope, log, cfg.translator);
        }
    };
    return sync.database.Persisted(F, V);
}

test {
    _ = @import("sync_test.zig");
}
