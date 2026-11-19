//! State sync for `any` databases (commonware's `qmdb/any/sync/mod.rs`), covering every
//! variant: unordered and ordered, fixed and variable. The sync database adapter over `any.Db`
//! `D` hashed with `H` (`sync.database.Persisted`) rebuilds the snapshot and activity bitmap
//! from the last commit's inactivity floor with the config's translator and init cache.

const std = @import("std");
const Allocator = std.mem.Allocator;
const runtime = @import("runtime");
const sync = @import("../sync/mod.zig");

const Scope = runtime.telemetry.metrics.Scope;

/// The sync adapter of `any.Db` `D` hashed with `H` (`D`'s hasher, which `D` does not export).
pub fn Database(comptime D: type, comptime H: type) type {
    comptime std.debug.assert(D.Digest == H.Digest);
    const V = struct {
        pub const Db = D;
        pub const Backing = @FieldType(D.Log, "journal");
        pub const Hasher = H;
        pub fn build(gpa: Allocator, scope: Scope, cfg: D.Cfg, log: D.Log) anyerror!D {
            return D.init_from_log(gpa, scope, log, cfg.translator, cfg.init_cache);
        }
    };
    return sync.database.Persisted(D.Family, V);
}

test {
    _ = @import("sync_test.zig");
    _ = @import("sync_fuzz_test.zig");
}
