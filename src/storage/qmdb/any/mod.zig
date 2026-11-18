//! Authenticated databases of keyed values that may be updated and deleted (qmdb/any).

const std = @import("std");

pub const operation = @import("operation.zig");
pub const Operation = operation.Operation;
pub const diff = @import("diff.zig");
pub const batch = @import("batch.zig");
pub const db = @import("db.zig");
pub const Db = db.Db;
pub const Config = db.Config;
pub const initial_root = db.initial_root;

test {
    std.testing.refAllDecls(@This());
    _ = @import("conformance_test.zig");
    _ = @import("floor_conformance_test.zig");
    _ = @import("db_test.zig");
    _ = @import("range.zig");
    _ = @import("variable_test.zig");
}
