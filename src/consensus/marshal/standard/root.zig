//! Marshal's standard variant: whole blocks over `broadcast.buffered` (commonware
//! `marshal/standard`).

const std = @import("std");

pub const variant = @import("variant.zig");
pub const Standard = variant.Standard;

test {
    std.testing.refAllDecls(@This());
}
