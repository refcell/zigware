//! Bitmaps (commonware `utils/src/bitmap`): `BitMap(N)` with `N`-byte chunks, the shared
//! `readable` interface and its set-bit iterator.

const std = @import("std");

const bitmap = @import("bitmap/bitmap.zig");
pub const readable = @import("bitmap/readable.zig");
pub const BitMap = bitmap.BitMap;
pub const DEFAULT_CHUNK_SIZE = bitmap.DEFAULT_CHUNK_SIZE;
/// `BitMap` with commonware's default chunk size of 8 bytes.
pub const DefaultBitMap = BitMap(DEFAULT_CHUNK_SIZE);

test {
    std.testing.refAllDecls(@This());
    _ = @import("bitmap/bitmap_test.zig");
}
