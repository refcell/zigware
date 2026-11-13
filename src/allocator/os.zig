//! The operating-system memory a heap uses: aligned anonymous mappings, unmapping, purging
//! (decommit with `MADV_DONTNEED` on Linux, a fixed zero-fill remap on Darwin), and
//! prefaulting. Like commonware's allocator, this is the one layer below the runtime that maps
//! memory itself.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const posix = std.posix;

pub const page_size_min = std.heap.page_size_min;

pub const Region = []align(page_size_min) u8;

/// Maps `len` bytes aligned to `alignment` (a power of two, at least a page), or null when the
/// system refuses. The mapping includes slack for the alignment, trimmed at both ends.
pub fn map(len: usize, alignment: usize) ?Region {
    assert(len > 0 and len % page_size_min == 0);
    assert(std.math.isPowerOfTwo(alignment) and alignment >= page_size_min);
    const slack = alignment - page_size_min;
    const total = std.math.add(usize, len, slack) catch return null;
    const mapping = posix.mmap(
        null,
        total,
        .{ .READ = true, .WRITE = true },
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    ) catch return null;
    const base = @intFromPtr(mapping.ptr);
    const start = std.mem.alignForward(usize, base, alignment);
    const head = start - base;
    const tail = total - head - len;
    if (head > 0) posix.munmap(mapping[0..head]);
    if (tail > 0) posix.munmap(@alignCast(mapping[head + len ..]));
    const region: Region = @alignCast(@as([*]u8, @ptrFromInt(start))[0..len]);
    assert(@intFromPtr(region.ptr) % alignment == 0);
    return region;
}

/// Unmaps a region returned by `map`, whole.
pub fn unmap(region: Region) void {
    assert(region.len > 0);
    posix.munmap(region);
}

/// Releases the physical pages behind `region`; its contents read as zero afterwards. Returns
/// whether the system purged it.
pub fn purge(region: Region) bool {
    assert(region.len % page_size_min == 0);
    if (builtin.os.tag == .linux) {
        posix.madvise(region.ptr, region.len, posix.MADV.DONTNEED) catch return false;
        return true;
    }
    if (!builtin.os.tag.isDarwin()) return false;
    // Darwin's MADV_DONTNEED keeps the old contents, so replace the pages with fresh
    // zero-fill ones in place instead.
    const remapped = posix.mmap(
        region.ptr,
        region.len,
        .{ .READ = true, .WRITE = true },
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true, .FIXED = true },
        -1,
        0,
    ) catch return false;
    assert(remapped.ptr == region.ptr);
    return true;
}

/// Touches every page of `region` so first use never faults.
pub fn prefault(region: Region) void {
    var offset: usize = 0;
    while (offset < region.len) : (offset += page_size_min) {
        const byte: *volatile u8 = &region[offset];
        byte.* = 0;
    }
}

test "map aligns, purge zeroes, unmap releases" {
    const alignment = 1 << 20;
    const region = map(2 * page_size_min, alignment) orelse return error.SkipZigTest;
    defer unmap(region);
    try std.testing.expectEqual(@as(usize, 0), @intFromPtr(region.ptr) % alignment);
    @memset(region, 0xaa);
    prefault(region);
    if (purge(region)) {
        for (region) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    }
}
