//! An authenticated database of unkeyed values (qmdb/keyless).
//!
//! Values are appended to an operation log and read back by location; the Merkle root of the
//! log authenticates them.

const std = @import("std");

pub const operation = @import("operation.zig");
pub const Operation = operation.Operation;
pub const db = @import("db.zig");
pub const Db = db.Db;
pub const Config = db.Config;
pub const initial_root = db.initial_root;

test {
    std.testing.refAllDecls(@This());
    _ = @import("db_test.zig");
    _ = @import("variable_test.zig");
    _ = @import("fuzz_test.zig");
    _ = @import("conformance_test.zig");
}
