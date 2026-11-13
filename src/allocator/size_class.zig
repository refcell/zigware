//! mimalloc's size classes (`mi_bin` in page-queue.c and the bin table in init.c, for a
//! release build: no padding, no `MI_ALIGN2W`/`MI_ALIGN4W`), so `good_size` and the bytes a
//! heap hands out match commonware's mimalloc block for block.
//!
//! Sizes up to eight words get one class per word; above that, the top three bits of the word
//! count pick one of four classes per power of two (at most 12.5% internal fragmentation).

const std = @import("std");
const assert = std.debug.assert;
const config = @import("config.zig");

const word_size: usize = @sizeOf(usize);

/// The bin of blocks above `large_object_limit`, each on a page of its own.
pub const bin_huge: usize = 73;

/// Largest block of a size class: `large_object_limit`.
pub const large_max_object_size: usize = config.large_object_limit;
const large_max_object_words: usize = large_max_object_size / word_size;

/// Bytes the OS page size is assumed to be when rounding huge blocks, as mimalloc's default.
pub const os_page_size: usize = 4096;

/// Block sizes of bins `0..bin_huge` in words (bin 0 is the empty queue's one word).
const bin_words = [_]usize{
    1,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    10,
    12,
    14,
    16,
    20,
    24,
    28,
    32,
    40,
    48,
    56,
    64,
    80,
    96,
    112,
    128,
    160,
    192,
    224,
    256,
    320,
    384,
    448,
    512,
    640,
    768,
    896,
    1024,
    1280,
    1536,
    1792,
    2048,
    2560,
    3072,
    3584,
    4096,
    5120,
    6144,
    7168,
    8192,
    10240,
    12288,
    14336,
    16384,
    20480,
    24576,
    28672,
    32768,
    40960,
    49152,
    57344,
    65536,
    81920,
    98304,
    114688,
    131072,
    163840,
    196608,
    229376,
    262144,
    327680,
    393216,
    458752,
    524288,
};

comptime {
    assert(bin_words.len == bin_huge);
    assert(word_size != 8 or bin_words[bin_huge - 1] * word_size == 4 << 20);
}

/// The bin of a `size`-byte request (`mi_bin`). Bins `1..bin_huge` are size classes.
pub fn bin(size: usize) usize {
    const words = (size +| (word_size - 1)) / word_size;
    if (words <= 8) return if (words == 0) 1 else words;
    if (words > large_max_object_words) return bin_huge;
    const value = words - 1;
    const top_bit: usize = @bitSizeOf(usize) - 1 - @clz(value);
    assert(top_bit >= 3);
    const result = ((top_bit << 2) + ((value >> @intCast(top_bit - 2)) & 0x03)) - 3;
    assert(result > 0 and result < bin_huge);
    return result;
}

/// The block size of size-class bin `index`.
pub fn bin_size(index: usize) usize {
    assert(index > 0 and index < bin_huge);
    return bin_words[index] * word_size;
}

/// The block size a heap allocates for `size` bytes: its size class, or above the largest
/// class, `size` rounded up to an OS page (`mi_good_size`).
pub fn good_size(size: usize) usize {
    if (size <= large_max_object_size) {
        const block = bin_size(bin(size));
        assert(block >= size);
        return block;
    }
    if (size <= std.math.maxInt(isize)) return std.mem.alignForward(usize, size, os_page_size);
    return size;
}

/// mimalloc aligns large blocks in a page to OS pages (`MI_PAGE_OSPAGE_BLOCK_ALIGN2`).
const ospage_block_align: usize = 4096;
/// The largest block of a small page (64 KiB): `(page - 4 KiB) / 6`, 10 KiB.
pub const small_max_object_size: usize = (config.arena_slice_size - ospage_block_align) / 6;
/// The largest block of a medium page (512 KiB): about 84 KiB.
pub const medium_max_object_size: usize = (8 * config.arena_slice_size - ospage_block_align) / 6;

/// The size of the page that holds blocks of `block_size` bytes: one slice for small blocks,
/// eight for medium, and `word_size * 8` (4 MiB on 64-bit) for large ones.
pub fn page_size(block_size: usize) usize {
    assert(block_size <= large_max_object_size);
    if (block_size <= small_max_object_size) return config.arena_slice_size;
    if (block_size <= medium_max_object_size) return 8 * config.arena_slice_size;
    return word_size * 8 * config.arena_slice_size;
}

const testing = std.testing;

test "good_size matches mimalloc's size classes" {
    try testing.expectEqual(@as(usize, 4096), good_size(4096));
    try testing.expectEqual(@as(usize, 5120), good_size(4096 + 32));
    try testing.expectEqual(@as(usize, word_size), good_size(0));
    try testing.expectEqual(@as(usize, word_size), good_size(1));
    try testing.expectEqual(@as(usize, 8 * word_size), good_size(8 * word_size));
    try testing.expectEqual(@as(usize, 10 * word_size), good_size(8 * word_size + 1));
    try testing.expectEqual(large_max_object_size, good_size(large_max_object_size));
    const above = large_max_object_size + 1;
    try testing.expectEqual(large_max_object_size + os_page_size, good_size(above));
}

test "bins round up to the next class and never down" {
    var previous: usize = 0;
    for (1..large_max_object_size + 1) |size| {
        const index = bin(size);
        const block = bin_size(index);
        try testing.expect(block >= size);
        // The class below is too small, so the bin is the tightest.
        if (index > 1) try testing.expect(bin_size(index - 1) < size);
        try testing.expect(index >= previous);
        previous = index;
    }
    try testing.expectEqual(bin_huge, bin(large_max_object_size + 1));
}

test "page sizes hold at least six blocks of small and medium classes" {
    try testing.expectEqual(config.arena_slice_size, page_size(8));
    try testing.expect(page_size(small_max_object_size) / small_max_object_size >= 6);
    try testing.expect(page_size(medium_max_object_size) / medium_max_object_size >= 6);
    const largest_page = word_size * 8 * config.arena_slice_size;
    try testing.expectEqual(largest_page, page_size(large_max_object_size));
}
