//! State sync for keyless databases (commonware's `qmdb/keyless/sync/mod.rs`): the sync
//! database adapter over keyless's `Db` (`sync.database.Persisted`), whose sync journal is
//! the backing contiguous journal `C`, opened over the config's `log`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const runtime = @import("runtime");
const sync = @import("../sync/mod.zig");
const db_mod = @import("db.zig");

const Scope = runtime.telemetry.metrics.Scope;

pub fn Database(comptime F: type, comptime E: type, comptime C: type, comptime H: type) type {
    const DbAlias = db_mod.Db(F, E, C, H);
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
            var db = try DbAlias.init_from_log(gpa, scope, log);
            // Times the synced db's operations as `init` does (`init_from_log` does not).
            db.metrics.io = cfg.io;
            return db;
        }
    };
    return sync.database.Persisted(F, V);
}

test {
    _ = @import("sync_test.zig");
}
