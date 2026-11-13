//! A 64-bit roaring compressed bitmap (commonware `utils/src/bitmap/roaring`): values split
//! into a 48-bit container key and a 16-bit index, each container an `Array`, `Bitmap`, or
//! `Run`.

const std = @import("std");

pub const array = @import("roaring/array.zig");
pub const Array = array.Array;

test {
    std.testing.refAllDecls(@This());
}
