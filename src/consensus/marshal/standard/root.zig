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
pub const buffer = @import("buffer.zig");
pub const Buffer = buffer.Buffer;

test {
    std.testing.refAllDecls(@This());
}

test {
    _ = @import("tests/restart.zig");
    _ = @import("tests/late_finalization.zig");
    _ = @import("tests/common.zig");
    _ = @import("tests/floor.zig");
    _ = @import("tests/coverage.zig");
    _ = @import("tests/dispatch.zig");
    _ = @import("tests/cache_epoch.zig");
    _ = @import("tests/scenarios.zig");
    _ = @import("tests/wrappers.zig");
    _ = @import("tests/queries.zig");
}
