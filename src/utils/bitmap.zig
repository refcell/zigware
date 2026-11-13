//! Bitmaps (commonware `utils/src/bitmap`): `BitMap(N)` with `N`-byte chunks, `Prunable(N)`,
//! the shared `readable` interface and its set-bit iterator.

const std = @import("std");

const bitmap = @import("bitmap/bitmap.zig");
pub const readable = @import("bitmap/readable.zig");
pub const BitMap = bitmap.BitMap;
pub const prunable = @import("bitmap/prunable.zig");
pub const Prunable = prunable.Prunable;
/// The historical bitmap: `historical.BitMap(N)` with its `Dirty` view.
pub const historical = @import("bitmap/historical.zig");
pub const DEFAULT_CHUNK_SIZE = bitmap.DEFAULT_CHUNK_SIZE;
/// `BitMap` with commonware's default chunk size of 8 bytes.
pub const DefaultBitMap = BitMap(DEFAULT_CHUNK_SIZE);

test {
    std.testing.refAllDecls(@This());
    _ = @import("bitmap/bitmap_test.zig");
    _ = @import("bitmap/prunable_test.zig");
    _ = @import("bitmap/historical_test.zig");
}
