//! commonware's `#[should_panic]` tests of `storage/src/bitmap/authenticated.rs`, as death
//! tests (`utils.death`), with commonware's expected panic substrings. The panics come from the
//! `utils.bitmap.Prunable` the authenticated bitmap wraps.

const std = @import("std");
const testing = std.testing;
const cryptography = @import("cryptography");
const death = @import("utils").death;
const merkle = @import("../merkle/mod.zig");
const authenticated = @import("authenticated.zig");
const memory = @import("runtime").storage.memory;

const Sha256 = cryptography.Sha256;
const H = merkle.hasher.Standard(Sha256);
const Map = authenticated.BitMap(Sha256.Digest, 32);
const gpa = testing.allocator;

/// `sha256(s)`, one chunk (commonware's `test_chunk`).
fn test_chunk(s: []const u8) [32]u8 {
    return Sha256.hash(&.{s}).bytes;
}

/// An empty bitmap in `storage`, opened for mutation (commonware's `into_dirty`).
fn open_dirty(storage: *memory.Storage, hasher: *const H) !Map {
    var bitmap = try Map.init(gpa, storage.storage(), "test", hasher);
    bitmap.into_dirty();
    return bitmap;
}

// commonware `test_bitmap_build_chunked_panic`.
test "bitmap push_chunk panics when not chunk aligned" {
    try death.expect_panic(@src(), "cannot add chunk", struct {
        fn body() !void {
            const hasher = H.init(.forward_fold);
            var storage = memory.Storage.init(gpa);
            defer storage.deinit();
            var bitmap = try open_dirty(&storage, &hasher);
            defer bitmap.deinit();
            try bitmap.push_chunk(&test_chunk("test"));
            try bitmap.push(true);
            try bitmap.push_chunk(&test_chunk("panic"));
        }
    }.body);
}

// commonware `test_bitmap_build_byte_panic`.
test "bitmap push_byte panics when not byte aligned" {
    try death.expect_panic(@src(), "cannot add byte", struct {
        fn body() !void {
            const hasher = H.init(.forward_fold);
            var storage = memory.Storage.init(gpa);
            defer storage.deinit();
            var bitmap = try open_dirty(&storage, &hasher);
            defer bitmap.deinit();
            try bitmap.push_chunk(&test_chunk("test"));
            try bitmap.push(true);
            try bitmap.push_byte(0x01);
        }
    }.body);
}

// commonware `test_bitmap_get_out_of_bounds_bit_panic`.
test "bitmap get_bit panics out of bounds" {
    try death.expect_panic(@src(), "out of bounds", struct {
        fn body() !void {
            const hasher = H.init(.forward_fold);
            var storage = memory.Storage.init(gpa);
            defer storage.deinit();
            var bitmap = try open_dirty(&storage, &hasher);
            defer bitmap.deinit();
            try bitmap.push_chunk(&test_chunk("test"));
            std.mem.doNotOptimizeAway(bitmap.get_bit(256));
        }
    }.body);
}

// commonware `test_bitmap_get_pruned_bit_panic`.
test "bitmap get_bit panics on a pruned bit" {
    try death.expect_panic(@src(), "pruned", struct {
        fn body() !void {
            const hasher = H.init(.forward_fold);
            var storage = memory.Storage.init(gpa);
            defer storage.deinit();
            var bitmap = try open_dirty(&storage, &hasher);
            defer bitmap.deinit();
            try bitmap.push_chunk(&test_chunk("test"));
            try bitmap.push_chunk(&test_chunk("test2"));
            try bitmap.merkleize(&hasher);
            try bitmap.prune_to_bit(256);
            std.mem.doNotOptimizeAway(bitmap.get_bit(255));
        }
    }.body);
}
