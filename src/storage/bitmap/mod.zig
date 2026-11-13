//! Authenticated bitmaps (port of commonware's `storage/src/bitmap`).

pub const authenticated = @import("authenticated.zig");
pub const BitMap = authenticated.BitMap;

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("tests.zig");
}
