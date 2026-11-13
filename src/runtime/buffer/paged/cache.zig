//! A page cache for _logical_ pages of blob data (commonware's `paged/cache.rs`).
//!
//! The cache holds at most `capacity` full logical pages keyed by `(blob id, page number)`,
//! all allocated at init. It is unaware of the physical page format, which the writer owns.
//!
//! commonware evicts with Clock2Q+ and shares in-flight page reads between concurrent async
//! readers. zigware's readers are single-owner fibers, so a miss is a plain validated page read
//! (in the writer), and eviction is CLOCK (second chance). The replacement policy changes hit
//! rates, never contents.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const Key = struct { blob_id: u64, page: u64 };

pub const CacheRef = struct {
    gpa: Allocator,
    /// Logical payload bytes per page (excluding the on-disk CRC record).
    page_size: u16,
    /// The next id handed to a blob using this cache.
    id_next: u64 = 0,
    /// `capacity * page_size` bytes of page slots.
    pages: []u8,
    /// The key in each slot, or null for an empty slot.
    keys: []?Key,
    /// CLOCK reference bits, one per slot.
    referenced: std.DynamicBitSetUnmanaged,
    /// The slot holding each cached page.
    slots: std.AutoHashMapUnmanaged(Key, u32) = .empty,
    /// Next slot the CLOCK hand examines.
    hand: u32 = 0,

    /// A cache of `capacity` pages of `page_size` bytes, allocated now.
    pub fn init(gpa: Allocator, page_size: u16, capacity: u32) Allocator.Error!CacheRef {
        assert(page_size > 0);
        assert(capacity > 0);
        const pages = try gpa.alloc(u8, @as(usize, capacity) * page_size);
        errdefer gpa.free(pages);
        @memset(pages, 0);
        const keys = try gpa.alloc(?Key, capacity);
        errdefer gpa.free(keys);
        @memset(keys, null);
        var referenced = try std.DynamicBitSetUnmanaged.initEmpty(gpa, capacity);
        errdefer referenced.deinit(gpa);
        var result: CacheRef = .{
            .gpa = gpa,
            .page_size = page_size,
            .pages = pages,
            .keys = keys,
            .referenced = referenced,
        };
        try result.slots.ensureTotalCapacity(gpa, capacity);
        return result;
    }

    pub fn deinit(self: *CacheRef) void {
        self.slots.deinit(self.gpa);
        self.referenced.deinit(self.gpa);
        self.gpa.free(self.keys);
        self.gpa.free(self.pages);
        self.* = undefined;
    }

    /// A unique id for the next blob that uses this cache.
    pub fn next_id(self: *CacheRef) u64 {
        const id = self.id_next;
        self.id_next += 1;
        return id;
    }

    /// The page holding logical `offset` and the offset within it.
    pub fn offset_to_page(self: *const CacheRef, offset: u64) struct { u64, u64 } {
        return .{ offset / self.page_size, offset % self.page_size };
    }

    fn slot_bytes(self: *const CacheRef, slot: u32) []u8 {
        return self.pages[@as(usize, slot) * self.page_size ..][0..self.page_size];
    }

    /// The cached page `page` of blob `blob_id`, marking it recently used.
    pub fn get_page(self: *CacheRef, blob_id: u64, page: u64) ?[]const u8 {
        const slot = self.slots.get(.{ .blob_id = blob_id, .page = page }) orelse return null;
        self.referenced.set(slot);
        return self.slot_bytes(slot);
    }

    /// Copy cached bytes starting at `offset` into `buf`, stopping at the first missing page.
    /// Returns the bytes copied.
    pub fn read_cached(self: *CacheRef, blob_id: u64, buf: []u8, offset: u64) usize {
        var done: usize = 0;
        while (done < buf.len) {
            const page, const in_page = self.offset_to_page(offset + done);
            const bytes = self.get_page(blob_id, page) orelse break;
            const count = @min(buf.len - done, bytes.len - in_page);
            @memcpy(buf[done..][0..count], bytes[@intCast(in_page)..][0..count]);
            done += count;
        }
        assert(done <= buf.len);
        return done;
    }

    /// Cache the whole pages of `buf`, which starts at page-aligned logical `offset`. Returns
    /// the trailing bytes that do not fill a page (not cached).
    pub fn cache(self: *CacheRef, blob_id: u64, buf: []const u8, offset: u64) usize {
        var page, const in_page = self.offset_to_page(offset);
        assert(in_page == 0);
        var start: usize = 0;
        while (buf.len - start >= self.page_size) : (start += self.page_size) {
            self.insert(.{ .blob_id = blob_id, .page = page }, buf[start..][0..self.page_size]);
            page += 1;
        }
        return buf.len - start;
    }

    /// Insert or overwrite one page.
    fn insert(self: *CacheRef, key: Key, page: []const u8) void {
        assert(page.len == self.page_size);
        const slot = self.slots.get(key) orelse self.evict(key);
        @memcpy(self.slot_bytes(slot), page);
        self.referenced.set(slot);
        assert(self.slots.count() <= self.keys.len);
    }

    /// Claim a slot for `key` with the CLOCK hand: skip and clear referenced slots, take the
    /// first unreferenced one. Two passes always find one.
    fn evict(self: *CacheRef, key: Key) u32 {
        const capacity: u32 = @intCast(self.keys.len);
        var steps: u32 = 0;
        while (steps < 2 * capacity + 1) : (steps += 1) {
            const slot = self.hand;
            self.hand = (self.hand + 1) % capacity;
            if (self.keys[slot] != null and self.referenced.isSet(slot)) {
                self.referenced.unset(slot);
                continue;
            }
            if (self.keys[slot]) |old| assert(self.slots.remove(old));
            self.keys[slot] = key;
            self.slots.putAssumeCapacity(key, slot);
            return slot;
        }
        unreachable; // Proof: the first pass clears every reference bit it passes.
    }

    /// Drop every cached page.
    pub fn clear(self: *CacheRef) void {
        @memset(self.keys, null);
        self.slots.clearRetainingCapacity();
        self.referenced.unsetAll();
        self.hand = 0;
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
    try testing.expectEqual(@as(u32, 2), cache_ref.slots.count());
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
