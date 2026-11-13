//! An authenticated database of unkeyed values (qmdb/keyless).
//!
//! Values are appended to an operation log and read back by location; the Merkle root of the
//! log authenticates them.

const std = @import("std");

pub const operation = @import("operation.zig");
pub const Operation = operation.Operation;

test {
    std.testing.refAllDecls(@This());
}
