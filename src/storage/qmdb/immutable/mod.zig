//! An authenticated database of keyed values that are set once and never change
//! (qmdb/immutable).

const std = @import("std");

pub const operation = @import("operation.zig");
pub const Operation = operation.Operation;

test {
    std.testing.refAllDecls(@This());
}
