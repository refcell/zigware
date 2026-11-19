//! A page cache for _logical_ pages of blob data (commonware's `paged/cache.rs`).
//!
//! The cache holds at most `capacity` full logical pages keyed by `(blob id, page number)`,
//! all allocated at init. It is unaware of the physical page format, which the writer owns.
//!
//! Like commonware's, eviction is Clock2Q+ (`utils.Cache`): new pages enter a small probation
//! queue and earn a place in the main ring only by a later hit, so a scan cannot flush the
//! working set. commonware also shares in-flight page reads between concurrent async readers;
//! zigware's misses are plain validated page reads (in the writer).
//!
//! Like commonware's, one cache may be shared by blobs that tasks on different threads use
//! (on `std.Io.Threaded`, a sync engine's fetch task reads a source while the caller writes
//! its destination), so every operation holds `lock`. A critical section copies at most a
//! caller's buffer and does no I/O, so the lock spins; the deterministic runtime never
//! preempts a fiber inside one, so there it is never contended.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const utils = @import("utils");

const Key = struct { blob_id: u64, page: u64 };

/// Each resident's value is its slot number, the index of its bytes in `CacheRef.pages`;
/// `prefill` numbers the slots once and the replacement policy reuses them in place.
const Slots = utils.Cache(Key, u32);

pub const CacheRef = struct {
    gpa: Allocator,
    /// Logical payload bytes per page (excluding the on-disk CRC record).
    page_size: u16,
    /// The next id handed to a blob using this cache.
    id_next: u64 = 0,
    /// `capacity * page_size` bytes of page slots.
    pages: []u8,
    /// Which page each slot holds, under Clock2Q+ replacement.
    slots: Slots,
    /// Held by every operation; see the file comment.
    lock: std.atomic.Value(bool) = .init(false),

    fn acquire(self: *CacheRef) void {
        while (self.lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
        assert(self.lock.load(.monotonic));
    }

    fn release(self: *CacheRef) void {
        assert(self.lock.load(.monotonic));
        self.lock.store(false, .release);
    }

    const Numbering = struct {
        next: u32 = 0,

        pub fn make(numbering: *Numbering) u32 {
            defer numbering.next += 1;
            return numbering.next;
        }
    };

    /// A cache of `capacity` pages of `page_size` bytes, allocated now.
    pub fn init(gpa: Allocator, page_size: u16, capacity: u32) Allocator.Error!CacheRef {
        assert(page_size > 0);
        assert(capacity > 0);
        const pages = try gpa.alloc(u8, @as(usize, capacity) * page_size);
        errdefer gpa.free(pages);
        @memset(pages, 0);
        var slots = try Slots.init(gpa, capacity);
        errdefer slots.deinit(gpa);
        var numbering: Numbering = .{};
        slots.prefill(&numbering);
        assert(numbering.next == capacity);
        return .{ .gpa = gpa, .page_size = page_size, .pages = pages, .slots = slots };
    }

    pub fn deinit(self: *CacheRef) void {
        self.slots.deinit(self.gpa);
        self.gpa.free(self.pages);
        self.* = undefined;
    }

    /// A unique id for the next blob that uses this cache.
    pub fn next_id(self: *CacheRef) u64 {
        self.acquire();
        defer self.release();
        const id = self.id_next;
        self.id_next += 1;
        return id;
    }

    /// The page holding logical `offset` and the offset within it.
    pub fn offset_to_page(self: *const CacheRef, offset: u64) struct { u64, u64 } {
        return .{ offset / self.page_size, offset % self.page_size };
    }

    fn slot_bytes(self: *const CacheRef, slot: u32) []u8 {
        assert(@as(usize, slot) * self.page_size < self.pages.len);
        return self.pages[@as(usize, slot) * self.page_size ..][0..self.page_size];
    }

    /// The number of cached pages.
    pub fn count(self: *CacheRef) usize {
        self.acquire();
        defer self.release();
        return self.slots.len();
    }

    /// The cached page `page` of blob `blob_id`, marking it recently used. The slice stays
    /// valid only until the next insert, so only a test that owns the cache may hold it.
    pub fn get_page(self: *CacheRef, blob_id: u64, page: u64) ?[]const u8 {
        self.acquire();
        defer self.release();
        return self.find_page(blob_id, page);
    }

    fn find_page(self: *CacheRef, blob_id: u64, page: u64) ?[]const u8 {
        const slot = self.slots.get(.{ .blob_id = blob_id, .page = page }) orelse return null;
        return self.slot_bytes(slot.*);
    }

    /// Copy cached bytes starting at `offset` into `buf`, stopping at the first missing page.
    /// Returns the bytes copied.
    pub fn read_cached(self: *CacheRef, blob_id: u64, buf: []u8, offset: u64) usize {
        self.acquire();
        defer self.release();
        var done: usize = 0;
        while (done < buf.len) {
            const page, const in_page = self.offset_to_page(offset + done);
            const bytes = self.find_page(blob_id, page) orelse break;
            const count_copied = @min(buf.len - done, bytes.len - in_page);
            @memcpy(buf[done..][0..count_copied], bytes[@intCast(in_page)..][0..count_copied]);
            done += count_copied;
        }
        assert(done <= buf.len);
        return done;
    }

    /// Cache the whole pages of `buf`, which starts at page-aligned logical `offset`. Returns
    /// the trailing bytes that do not fill a page (not cached).
    pub fn cache(self: *CacheRef, blob_id: u64, buf: []const u8, offset: u64) usize {
        self.acquire();
        defer self.release();
        var page, const in_page = self.offset_to_page(offset);
        assert(in_page == 0);
        var start: usize = 0;
        while (buf.len - start >= self.page_size) : (start += self.page_size) {
            self.insert(.{ .blob_id = blob_id, .page = page }, buf[start..][0..self.page_size]);
            page += 1;
        }
        return buf.len - start;
    }

    /// Insert or overwrite one page; a miss takes a free slot or evicts one.
    fn insert(self: *CacheRef, key: Key, page: []const u8) void {
        assert(page.len == self.page_size);
        const resident = self.slots.get_or_insert_mut(key, no_growth);
        assert(resident.value.* == resident.slot);
        @memcpy(self.slot_bytes(resident.value.*), page);
        assert(self.slots.len() <= self.slots.capacity);
    }

    const no_growth = struct {
        pub fn make() u32 {
            unreachable; // `init` prefilled every slot, so the cache never grows.
        }
    };

    const keep_none = struct {
        pub fn keep(_: Key, _: *const u32) bool {
            return false;
        }
    };

    /// Drop every cached page, keeping each slot's numbering (commonware `retain(|_, _| false)`).
    pub fn clear(self: *CacheRef) void {
        self.acquire();
        defer self.release();
        self.slots.retain(keep_none);
        assert(self.slots.is_empty());
    }
};

const testing = std.testing;

test "cache basic reads, partial tails, and eviction" {
    var cache_ref = try CacheRef.init(testing.allocator, 4, 2);
    defer cache_ref.deinit();
    try testing.expectEqual(@as(u64, 0), cache_ref.next_id());
    try testing.expectEqual(@as(u64, 1), cache_ref.next_id());

    // Two pages and a trailing partial page that is not cached.
    try testing.expectEqual(@as(usize, 2), cache_ref.cache(7, "abcdefghij", 4));
    var buf: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 8), cache_ref.read_cached(7, &buf, 4));
    try testing.expectEqualStrings("abcdefgh", &buf);
    try testing.expectEqual(@as(usize, 6), cache_ref.read_cached(7, &buf, 6));
    try testing.expectEqual(@as(usize, 0), cache_ref.read_cached(7, &buf, 0));
    try testing.expectEqual(@as(usize, 0), cache_ref.read_cached(8, &buf, 4));

    // A third page evicts one of the first two.
    _ = cache_ref.cache(7, "wxyz", 12);
    try testing.expectEqual(@as(usize, 2), cache_ref.count());
    try testing.expectEqualStrings("wxyz", cache_ref.get_page(7, 3).?);
    const resident = @as(u32, @intFromBool(cache_ref.get_page(7, 1) != null)) +
        @intFromBool(cache_ref.get_page(7, 2) != null);
    try testing.expectEqual(@as(u32, 1), resident);

    // Overwriting a cached page updates it in place.
    _ = cache_ref.cache(7, "WXYZ", 12);
    try testing.expectEqualStrings("WXYZ", cache_ref.get_page(7, 3).?);
    cache_ref.clear();
    try testing.expect(cache_ref.get_page(7, 3) == null);
}

fn hammer(cache_ref: *CacheRef, blob_id: u64, rounds: u32) void {
    var page: [4]u8 = undefined;
    var buf: [8]u8 = undefined;
    for (0..rounds) |round| {
        const at: u64 = (round % 16) * 4;
        std.mem.writeInt(u32, &page, @intCast(round), .little);
        _ = cache_ref.cache(blob_id, &page, at);
        _ = cache_ref.read_cached(blob_id, &buf, at);
    }
}

test "cache shared by threads keeps its slot map consistent" {
    // Two threads insert, evict, and read one small cache at once, as a sync engine's fetch
    // task and its caller do on std.Io.Threaded. Without the lock the slot map and the slot
    // keys diverge and an assertion fails.
    var cache_ref = try CacheRef.init(testing.allocator, 4, 3);
    defer cache_ref.deinit();
    const rounds = 20_000;
    const other = try std.Thread.spawn(.{}, hammer, .{ &cache_ref, 1, rounds });
    hammer(&cache_ref, 2, rounds);
    other.join();
    try testing.expect(cache_ref.count() <= 3);
    for (cache_ref.slots.slots.items, 0..) |*entry, slot| {
        try testing.expectEqual(@as(u32, @intCast(slot)), entry.value);
        if (entry.live) try testing.expect(cache_ref.slots.peek(entry.key).? == &entry.value);
    }
}

test "clear does not orphan a recached page" {
    // commonware `test_clear_does_not_orphan_recached_page`.
    var cache_ref = try CacheRef.init(testing.allocator, 4, 2);
    defer cache_ref.deinit();
    _ = cache_ref.cache(0, "aaaa", 0);
    _ = cache_ref.cache(0, "bbbb", 4);
    cache_ref.clear();
    _ = cache_ref.cache(0, "cccc", 4);
    var buf: [4]u8 = undefined;
    try testing.expectEqual(@as(usize, 4), cache_ref.read_cached(0, &buf, 4));
    try testing.expectEqualStrings("cccc", &buf);
    // A new page takes the other freed slot instead of evicting live page 1.
    _ = cache_ref.cache(0, "dddd", 8);
    try testing.expectEqual(@as(usize, 4), cache_ref.read_cached(0, &buf, 4));
    try testing.expectEqualStrings("cccc", &buf);
    try testing.expectEqual(@as(usize, 4), cache_ref.read_cached(0, &buf, 8));
    try testing.expectEqualStrings("dddd", &buf);
}

test "cache pages at the highest aligned offsets" {
    // commonware `test_cache_max_page` (page size 1024) and `test_cache_at_high_offset` (the
    // minimum page size, 13).
    const max = std.math.maxInt(u64);
    var one = try CacheRef.init(testing.allocator, 1024, 2);
    defer one.deinit();
    const page: [1024]u8 = @splat(42);
    const max_offset = max - max % 1024;
    try testing.expectEqual(@as(usize, 0), one.cache(0, &page, max_offset));
    var buf: [1024]u8 = undefined;
    try testing.expectEqual(@as(usize, 1024), one.read_cached(0, &buf, max_offset));
    try testing.expectEqualSlices(u8, &page, &buf);

    var small = try CacheRef.init(testing.allocator, 13, 2);
    defer small.deinit();
    const two: [26]u8 = @splat(1);
    const high = (max - max % 13) - 26;
    try testing.expectEqual(@as(usize, 0), small.cache(0, &two, high));
    var page_buf: [13]u8 = undefined;
    for ([_]u64{ high, high + 13 }) |offset| {
        try testing.expectEqual(@as(usize, 13), small.read_cached(0, &page_buf, offset));
        try testing.expectEqualSlices(u8, two[0..13], &page_buf);
    }
}
