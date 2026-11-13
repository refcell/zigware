//! An arena: a mapped region carved into `arena_slice_size` slices, holding pages of one or
//! more slices. Its own first slices hold its metadata (mimalloc's page metadata table): the
//! `Arena` header, one `Page` per slice (meaningful at a page's first slice), the first slice
//! of the page each slice belongs to, and bitmaps of free, dirty (freed but not yet purged),
//! and committed (ever used) slices.
//!
//! A transient arena holds exactly one page and is unmapped when that page is freed, which is
//! how a heap maps a page from the operating system on its own.

const std = @import("std");
const assert = std.debug.assert;
const config = @import("config.zig");
const os = @import("os.zig");

const slice_size = config.arena_slice_size;

pub const Kind = enum {
    /// Reserved on demand or as an unpinned reservation; purged by the heap's policy.
    normal,
    /// A pinned reservation, never purged.
    pinned,
    /// Holds one page and is unmapped when it is freed.
    transient,
};

/// A free block, linked through its first word.
pub const Block = struct {
    next: ?*Block,
};

pub const Page = struct {
    arena: *Arena,
    /// Slices in the page; zero when no page starts at this slice.
    slices: u32 = 0,
    /// Size-class bin, or `bin_huge` for a page holding one block of its own.
    bin: u8 = 0,
    block_size: usize = 0,
    /// Blocks the page holds.
    capacity: u32 = 0,
    /// Blocks handed out at least once, from the front of the page.
    carved: u32 = 0,
    /// Blocks currently allocated.
    used: u32 = 0,
    free: ?*Block = null,
    /// Links in the heap's queue of pages with free blocks for this bin.
    next: ?*Page = null,
    prev: ?*Page = null,
    queued: bool = false,

    pub fn start(page: *const Page) usize {
        const arena = page.arena;
        const index = (@intFromPtr(page) - @intFromPtr(arena.pages.ptr)) / @sizeOf(Page);
        assert(index < arena.slices);
        return arena.base + index * slice_size;
    }

    pub fn bytes(page: *const Page) usize {
        assert(page.slices > 0);
        return @as(usize, page.slices) * slice_size;
    }
};

pub const Arena = struct {
    region: os.Region,
    base: usize,
    kind: Kind,
    slices: usize,
    /// Slices taken by the metadata at the front.
    meta_slices: usize,
    pages: []Page,
    page_of: []u32,
    free_bits: []u64,
    dirty_bits: []u64,
    committed_bits: []u64,
    /// Nanoseconds on the heap's clock after which dirty slices may be purged, if any.
    purge_deadline_ns: ?u64 = null,
    /// Slices in live pages.
    used_slices: usize = 0,

    const Layout = struct { pages: usize, page_of: usize, bits: usize, words: usize, meta: usize };

    fn layout(slices: usize, meta_align: usize) Layout {
        const pages = std.mem.alignForward(usize, @sizeOf(Arena), @alignOf(Page));
        const page_of = pages + slices * @sizeOf(Page);
        const bits = std.mem.alignForward(usize, page_of + slices * @sizeOf(u32), @alignOf(u64));
        const words = (slices + 63) / 64;
        const meta = std.mem.alignForward(usize, bits + 3 * words * @sizeOf(u64), meta_align);
        return .{ .pages = pages, .page_of = page_of, .bits = bits, .words = words, .meta = meta };
    }

    /// The region size an arena needs to hold a page of `page_bytes` whose start is aligned
    /// to `page_align`: the page plus the metadata in front of it.
    pub fn transient_size(page_bytes: usize, page_align: usize) usize {
        assert(page_bytes % slice_size == 0);
        var slices = page_bytes / slice_size + 1;
        // The metadata grows with the slice count, so iterate to a fixed point (twice suffices).
        for (0..4) |_| {
            const meta = layout(slices, @max(page_align, slice_size)).meta;
            const needed = (meta + page_bytes) / slice_size;
            if (needed <= slices) break;
            slices = needed;
        }
        return slices * slice_size;
    }

    /// Places an arena's metadata at the front of `region`, whose length is a multiple of the
    /// slice size and whose start is slice-aligned, aligning the first page to `page_align`.
    pub fn create(region: os.Region, kind: Kind, page_align: usize) ?*Arena {
        assert(region.len % slice_size == 0);
        assert(@intFromPtr(region.ptr) % slice_size == 0);
        const slices = region.len / slice_size;
        const plan = layout(slices, @max(page_align, slice_size));
        const meta_slices = plan.meta / slice_size;
        if (meta_slices >= slices) return null;
        const arena: *Arena = @ptrCast(region.ptr);
        const at = @intFromPtr(region.ptr);
        const bits: [*]u64 = @ptrFromInt(at + plan.bits);
        arena.* = .{
            .region = region,
            .base = at,
            .kind = kind,
            .slices = slices,
            .meta_slices = meta_slices,
            .pages = @as([*]Page, @ptrFromInt(at + plan.pages))[0..slices],
            .page_of = @as([*]u32, @ptrFromInt(at + plan.page_of))[0..slices],
            .free_bits = bits[0..plan.words],
            .dirty_bits = bits[plan.words .. 2 * plan.words],
            .committed_bits = bits[2 * plan.words .. 3 * plan.words],
        };
        @memset(arena.free_bits, 0);
        @memset(arena.dirty_bits, 0);
        @memset(arena.committed_bits, 0);
        for (meta_slices..slices) |slice| set_bit(arena.free_bits, slice);
        for (0..meta_slices) |slice| set_bit(arena.committed_bits, slice);
        assert(arena.free_count() == slices - meta_slices);
        return arena;
    }

    pub fn contains(arena: *const Arena, address: usize) bool {
        return address >= arena.base and address < arena.base + arena.region.len;
    }

    /// The page holding `address`, which must lie in a live page of this arena.
    pub fn page_at(arena: *Arena, address: usize) *Page {
        assert(arena.contains(address));
        const slice = (address - arena.base) / slice_size;
        assert(slice >= arena.meta_slices);
        const first = arena.page_of[slice];
        const page = &arena.pages[first];
        assert(page.slices > 0 and first + page.slices > slice);
        return page;
    }

    pub fn free_count(arena: *const Arena) usize {
        var count: usize = 0;
        for (arena.free_bits) |word| count += @popCount(word);
        return count;
    }

    pub const Taken = struct { page: *Page, committed_slices: usize };

    /// Takes the first run of `slices` free slices as a page, or null if there is none.
    pub fn alloc_page(arena: *Arena, slices: usize) ?Taken {
        assert(slices > 0);
        const first = arena.find_run(slices) orelse return null;
        var committed: usize = 0;
        for (first..first + slices) |slice| {
            assert(get_bit(arena.free_bits, slice));
            clear_bit(arena.free_bits, slice);
            clear_bit(arena.dirty_bits, slice);
            if (!get_bit(arena.committed_bits, slice)) committed += 1;
            set_bit(arena.committed_bits, slice);
            arena.page_of[slice] = @intCast(first);
        }
        arena.used_slices += slices;
        const page = &arena.pages[first];
        page.* = .{ .arena = arena, .slices = @intCast(slices) };
        assert(page.start() == arena.base + first * slice_size);
        return .{ .page = page, .committed_slices = committed };
    }

    fn find_run(arena: *const Arena, slices: usize) ?usize {
        var run: usize = 0;
        var slice = arena.meta_slices;
        while (slice < arena.slices) : (slice += 1) {
            const word = arena.free_bits[slice / 64];
            // Skip a full word of used slices at once.
            if (word == 0 and slice % 64 == 0) {
                run = 0;
                slice += 63;
                continue;
            }
            if (get_bit(arena.free_bits, slice)) {
                run += 1;
                if (run == slices) return slice + 1 - slices;
            } else {
                run = 0;
            }
        }
        return null;
    }

    /// Returns `page`'s slices to the arena; they become dirty until purged.
    pub fn free_page(arena: *Arena, page: *Page) void {
        assert(page.arena == arena);
        assert(page.slices > 0 and page.used == 0);
        const first = (page.start() - arena.base) / slice_size;
        for (first..first + page.slices) |slice| {
            assert(!get_bit(arena.free_bits, slice));
            set_bit(arena.free_bits, slice);
            if (arena.kind != .pinned) set_bit(arena.dirty_bits, slice);
        }
        arena.used_slices -= page.slices;
        page.slices = 0;
    }

    pub const Purged = struct { bytes: usize, calls: usize };

    /// Purges every run of free, dirty slices.
    pub fn purge(arena: *Arena) Purged {
        assert(arena.kind != .pinned);
        var purged: Purged = .{ .bytes = 0, .calls = 0 };
        var slice: usize = arena.meta_slices;
        while (slice < arena.slices) {
            if (!get_bit(arena.dirty_bits, slice)) {
                slice += 1;
                continue;
            }
            const first = slice;
            while (slice < arena.slices and get_bit(arena.dirty_bits, slice)) : (slice += 1) {
                assert(get_bit(arena.free_bits, slice));
                clear_bit(arena.dirty_bits, slice);
            }
            const start = arena.base + first * slice_size;
            const len = (slice - first) * slice_size;
            const region: os.Region = @alignCast(@as([*]u8, @ptrFromInt(start))[0..len]);
            if (os.purge(region)) {
                purged.bytes += len;
                purged.calls += 1;
            }
        }
        arena.purge_deadline_ns = null;
        return purged;
    }
};

fn get_bit(bits: []const u64, index: usize) bool {
    return bits[index / 64] & (@as(u64, 1) << @intCast(index % 64)) != 0;
}

fn set_bit(bits: []u64, index: usize) void {
    bits[index / 64] |= @as(u64, 1) << @intCast(index % 64);
}

fn clear_bit(bits: []u64, index: usize) void {
    bits[index / 64] &= ~(@as(u64, 1) << @intCast(index % 64));
}

const testing = std.testing;

test "arena carves, frees, and purges pages" {
    const len = 64 * slice_size;
    const region = os.map(len, slice_size) orelse return error.SkipZigTest;
    defer os.unmap(region);
    const arena = Arena.create(region, .normal, slice_size).?;
    try testing.expectEqual(@as(usize, 1), arena.meta_slices);
    const a = arena.alloc_page(8).?;
    const b = arena.alloc_page(1).?;
    try testing.expectEqual(arena.base + slice_size, a.page.start());
    try testing.expectEqual(a.page.start() + 8 * slice_size, b.page.start());
    try testing.expectEqual(a.page, arena.page_at(a.page.start() + 3 * slice_size + 17));
    a.page.used = 0;
    arena.free_page(a.page);
    // A smaller page reuses the freed run first.
    const c = arena.alloc_page(4).?;
    try testing.expectEqual(arena.base + slice_size, c.page.start());
    try testing.expectEqual(@as(usize, 0), c.committed_slices);
    try testing.expect(arena.alloc_page(len) == null);
    const purged = arena.purge();
    try testing.expectEqual(@as(usize, 4 * slice_size), purged.bytes);
}

test "transient arenas fit one aligned page after their metadata" {
    const page_bytes = 3 * slice_size;
    const size = Arena.transient_size(page_bytes, 4 * slice_size);
    const region = os.map(size, 4 * slice_size) orelse return error.SkipZigTest;
    defer os.unmap(region);
    const arena = Arena.create(region, .transient, 4 * slice_size).?;
    const taken = arena.alloc_page(3).?;
    try testing.expectEqual(@as(usize, 0), taken.page.start() % (4 * slice_size));
}
