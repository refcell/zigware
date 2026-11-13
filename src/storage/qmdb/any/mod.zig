//! Authenticated databases of keyed values that may be updated and deleted (qmdb/any).

const std = @import("std");

pub const operation = @import("operation.zig");
pub const Operation = operation.Operation;

test {
    std.testing.refAllDecls(@This());
}
