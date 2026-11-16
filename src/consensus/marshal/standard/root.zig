//! Marshal's standard variant: whole blocks over `broadcast.buffered` (commonware
//! `marshal/standard`).

const std = @import("std");

pub const variant = @import("variant.zig");
pub const Standard = variant.Standard;
pub const validation = @import("validation.zig");
pub const inline_wrapper = @import("inline.zig");
pub const Inline = inline_wrapper.Inline;
pub const deferred = @import("deferred.zig");
pub const Deferred = deferred.Deferred;

test {
    std.testing.refAllDecls(@This());
}
