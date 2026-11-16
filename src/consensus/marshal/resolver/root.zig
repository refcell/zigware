//! Marshal's backfill over a resolver (commonware `marshal/resolver`).

const std = @import("std");

pub const handler = @import("handler.zig");
pub const Key = handler.Key;
pub const Annotation = handler.Annotation;
pub const Finalized = handler.Finalized;
pub const Request = handler.Request;

test {
    std.testing.refAllDecls(@This());
}
