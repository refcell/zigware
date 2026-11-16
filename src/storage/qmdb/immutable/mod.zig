//! An authenticated database of keyed values that are set once and never change
//! (qmdb/immutable).

const std = @import("std");

pub const operation = @import("operation.zig");
pub const Operation = operation.Operation;
pub const db = @import("db.zig");
pub const Db = db.Db;
pub const Config = db.Config;
pub const initial_root = db.initial_root;

test {
    std.testing.refAllDecls(@This());
    _ = @import("conformance_test.zig");
    _ = @import("db_test.zig");
    _ = @import("variable_test.zig");
}
