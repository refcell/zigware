//! A page cache for _logical_ pages of blob data (commonware's `paged/cache.rs`).
//!
//! The cache holds at most `capacity` full logical pages keyed by `(blob id, page number)`,
//! all allocated at init. It is unaware of the physical page format, which the writer owns.
//!
//! Like commonware's, eviction is Clock2Q+ (`utils.Cache`): new pages enter a small probation
//! queue and earn a place in the main ring only by a later hit, so a scan cannot flush the
//! working set.
//!
//! Shared reads (commonware's `page_fetches` and batches): once `share_reads` gives the cache an
//! `Io` to wait with, a reader that misses a page another reader is fetching joins that fetch
//! instead of reading the page again. A fetch lives in one of `fetch_slots_max` slots with a page
//! buffer of its own, so a joiner gets the page even if the cache evicts it first. A fetch whose
//! reader is canceled resolves as abandoned: its joiners read the page again, the first of them
//! as a new fetch the others join, so a cancel never fails other readers. Without `share_reads`,
//! or with every slot taken, a miss reads alone.
//!
//! Like commonware's, lookups first try `hints`, a direct-mapped array from `hint_index` to the
//! `Slots` slot a page was last cached in: one array load instead of a hash probe chain. Hints
//! are best-effort: `Slots.get_at` resolves a slot only while it still holds the page's key, so
//! hints staled by eviction, clearing, or collisions miss and fall back to `Slots.get`. They
//! need no upkeep on eviction, and their memory is fixed at init.
//!
//! Like commonware's, one cache may be shared by blobs that tasks on different threads use
//! (on `std.Io.Threaded`, a sync engine's fetch task reads a source while the caller writes
//! its destination), so every operation holds `lock`. A critical section copies at most a
//! caller's buffer and does no I/O, so the lock spins; the deterministic runtime never
//! preempts a fiber inside one, so there it is never contended.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const utils = @import("utils");

pub const FetchError = @import("mod.zig").Error;

/// One page fetch shared by its reader and the readers that joined it.
const Fetch = struct {
    key: Key = undefined,
    state: enum { free, reading, done, failed, abandoned } = .free,
    /// The fetch's reader until it resolves, plus each joiner still to collect the result.
    refs: u32 = 0,
    /// Bumped when the fetch resolves; joiners wait for it to change.
    resolved: std.atomic.Value(u32) = .init(0),
    failure: FetchError = error.Io,
};

/// A reader's part in a fetch: its slot and, for a joiner, `resolved` when it joined.
pub const Ticket = struct { slot: u32, seen: u32 };

/// How a reader gets a missed page (`CacheRef.begin_fetch`).
pub const Claim = union(enum) {
    /// The page was cached after all; it is in the caller's buffer.
    cached,
    /// Another reader is fetching it: collect it with `wait_fetch`.
    joined: Ticket,
    /// The caller fetches it for every joiner and resolves it with `finish_fetch`.
    claimed: Ticket,
    /// The caller reads it alone.
    private,
};

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
    /// `Slots` slot hints by `hint_index`, `hint_none` until set. A power of two (so the index
    /// wraps with a mask) of at least twice the capacity, so a full cache rarely collides.
    hints: []usize,
    /// Held by every operation; see the file comment.
    lock: std.atomic.Value(bool) = .init(false),
    /// Set by `share_reads`: what joiners wait with. Null keeps every miss a private read.
    io: ?Io = null,
    /// Shared fetches in flight or still being collected, with one page buffer per slot.
    fetch_slots: []Fetch = &.{},
    fetch_pages: []u8 = &.{},

    /// The most page fetches shared at once.
    pub const fetch_slots_max = 64;

    const hint_none = std.math.maxInt(usize);

    /// Ranges `read_cached_many` resolves before copying any of them (commonware's
    /// `RESOLVE_CHUNK`): long enough to overlap several lookups' memory latency.
    const resolve_chunk = 32;

    /// A range `read_cached_many` reads: `buf` at logical `offset`, and the caller's `index`.
    pub const Pending = struct { buf: []u8, offset: u64, index: usize };

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
        const hints = try gpa.alloc(usize, std.math.ceilPowerOfTwoAssert(usize, 2 * capacity));
        @memset(hints, hint_none);
        return .{
            .gpa = gpa,
            .page_size = page_size,
            .pages = pages,
            .slots = slots,
            .hints = hints,
        };
    }

    pub fn deinit(self: *CacheRef) void {
        for (self.fetch_slots) |*fetch| assert(fetch.state == .free);
        self.gpa.free(self.fetch_slots);
        self.gpa.free(self.fetch_pages);
        self.gpa.free(self.hints);
        self.slots.deinit(self.gpa);
        self.gpa.free(self.pages);
        self.* = undefined;
    }

    /// Lets readers that miss the same page share one blob read, waiting with `io`.
    pub fn share_reads(self: *CacheRef, io: Io) Allocator.Error!void {
        assert(self.io == null);
        const fetch_slots = try self.gpa.alloc(Fetch, fetch_slots_max);
        errdefer self.gpa.free(fetch_slots);
        const fetch_pages = try self.gpa.alloc(u8, fetch_slots_max * @as(usize, self.page_size));
        @memset(fetch_slots, .{});
        self.fetch_slots = fetch_slots;
        self.fetch_pages = fetch_pages;
        self.io = io;
        assert(self.fetch_slots.len == fetch_slots_max);
    }

    fn fetch_page_bytes(self: *const CacheRef, slot: u32) []u8 {
        assert(slot < self.fetch_slots.len);
        return self.fetch_pages[@as(usize, slot) * self.page_size ..][0..self.page_size];
    }

    /// For a reader that missed page `page` of `blob_id`: copy it into `dest` if it is cached
    /// now, join the fetch in flight for it (unless `may_join` is false), or claim a new fetch.
    pub fn begin_fetch(
        self: *CacheRef,
        blob_id: u64,
        page: u64,
        dest: []u8,
        may_join: bool,
    ) Claim {
        assert(dest.len == self.page_size);
        self.acquire();
        defer self.release();
        if (self.find_page(blob_id, page)) |bytes| {
            @memcpy(dest, bytes);
            return .cached;
        }
        const key: Key = .{ .blob_id = blob_id, .page = page };
        var free: ?u32 = null;
        for (self.fetch_slots, 0..) |*fetch, index| {
            if (fetch.state == .free) {
                if (free == null) free = @intCast(index);
                continue;
            }
            if (fetch.state != .reading or !std.meta.eql(fetch.key, key)) continue;
            if (!may_join) return .private;
            fetch.refs += 1;
            return .{ .joined = .{ .slot = @intCast(index), .seen = fetch.resolved.raw } };
        }
        const slot = free orelse return .private;
        const fetch = &self.fetch_slots[slot];
        assert(fetch.refs == 0);
        fetch.key = key;
        fetch.state = .reading;
        fetch.refs = 1;
        return .{ .claimed = .{ .slot = slot, .seen = fetch.resolved.raw } };
    }

    /// Resolves a claimed fetch with the page's logical bytes or why reading it failed, caching
    /// a page read: joiners get the page, the error, or (for `Canceled`) a retry.
    pub fn finish_fetch(self: *CacheRef, ticket: Ticket, result: FetchError![]const u8) void {
        const fetch = &self.fetch_slots[ticket.slot];
        {
            self.acquire();
            defer self.release();
            assert(fetch.state == .reading and fetch.refs > 0);
            if (result) |page| {
                @memcpy(self.fetch_page_bytes(ticket.slot), page);
                self.insert(fetch.key, page);
                fetch.state = .done;
            } else |err| switch (err) {
                error.Canceled => fetch.state = .abandoned,
                else => {
                    fetch.state = .failed;
                    fetch.failure = err;
                },
            }
            _ = fetch.resolved.fetchAdd(1, .release);
            drop_ref(fetch);
        }
        self.io.?.futexWake(u32, &fetch.resolved.raw, std.math.maxInt(u32));
    }

    /// Waits for a joined fetch: true with the page in `dest`, false if its reader was canceled
    /// (read the page again), or the fetch's error.
    pub fn wait_fetch(self: *CacheRef, ticket: Ticket, dest: []u8) FetchError!bool {
        assert(dest.len == self.page_size);
        const fetch = &self.fetch_slots[ticket.slot];
        while (fetch.resolved.load(.acquire) == ticket.seen) {
            self.io.?.futexWait(u32, &fetch.resolved.raw, ticket.seen) catch |err| {
                self.leave_fetch(ticket);
                return err;
            };
        }
        self.acquire();
        defer self.release();
        defer drop_ref(fetch);
        return switch (fetch.state) {
            .done => {
                @memcpy(dest, self.fetch_page_bytes(ticket.slot));
                return true;
            },
            .abandoned => false,
            .failed => fetch.failure,
            .free, .reading => unreachable, // `resolved` changed, and this joiner holds a ref.
        };
    }

    /// Gives up a joined fetch without its result.
    pub fn leave_fetch(self: *CacheRef, ticket: Ticket) void {
        self.acquire();
        defer self.release();
        drop_ref(&self.fetch_slots[ticket.slot]);
    }

    fn drop_ref(fetch: *Fetch) void {
        assert(fetch.refs > 0 and fetch.state != .free);
        fetch.refs -= 1;
        if (fetch.refs > 0) return;
        // The fetch's reader holds a ref until it resolves the fetch.
        assert(fetch.state != .reading);
        fetch.state = .free;
    }

    /// The fetches not yet free (resolved fetches still being collected included).
    pub fn fetches_active(self: *CacheRef) usize {
        self.acquire();
        defer self.release();
        var active: usize = 0;
        for (self.fetch_slots) |fetch| active += @intFromBool(fetch.state != .free);
        return active;
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

    /// The hint entry for `(blob_id, page)`: the page number offset by a per-blob salt, so a
    /// blob's consecutive pages take consecutive entries and blobs' ranges spread apart.
    pub fn hint_index(self: *const CacheRef, blob_id: u64, page: u64) usize {
        const salted = page +% blob_id *% utils.GOLDEN_RATIO;
        return @intCast(salted & (self.hints.len - 1));
    }

    fn find_page(self: *CacheRef, blob_id: u64, page: u64) ?[]const u8 {
        const key: Key = .{ .blob_id = blob_id, .page = page };
        const hinted = self.hints[self.hint_index(blob_id, page)];
        const slot = self.slots.get_at(hinted, key) orelse self.slots.get(key) orelse return null;
        return self.slot_bytes(slot.*);
    }

    /// Copy the cached bytes of each of `pending`'s ranges into its `buf`, under one lock
    /// (commonware's `read_cached_many`). Returns how many ranges are left unread; they move
    /// to the front of `pending` in order, each past its cached prefix (already copied).
    pub fn read_cached_many(self: *CacheRef, blob_id: u64, pending: []Pending) usize {
        self.acquire();
        defer self.release();
        var left: usize = 0;
        var start: usize = 0;
        while (start < pending.len) : (start += resolve_chunk) {
            const chunk = pending[start..@min(pending.len, start + resolve_chunk)];
            // Resolve the chunk's first pages before copying any, so the independent lookups
            // overlap; consecutive ranges on one page share its lookup.
            var sources: [resolve_chunk]?[]const u8 = undefined;
            var previous: ?struct { u64, ?[]const u8 } = null;
            for (chunk, sources[0..chunk.len]) |range, *source| {
                const page, const in_page = self.offset_to_page(range.offset);
                const bytes = if (previous != null and previous.?[0] == page)
                    previous.?[1]
                else
                    self.find_page(blob_id, page);
                previous = .{ page, bytes };
                const count_first = @min(range.buf.len, self.page_size - in_page);
                source.* = if (bytes) |b| b[@intCast(in_page)..][0..count_first] else null;
            }
            for (chunk, sources[0..chunk.len]) |range, source| {
                var done: usize = 0;
                if (source) |bytes| {
                    @memcpy(range.buf[0..bytes.len], bytes);
                    done = bytes.len;
                    done += self.copy_cached(blob_id, range.buf[done..], range.offset + done);
                }
                if (done == range.buf.len) continue;
                pending[left] = .{
                    .buf = range.buf[done..],
                    .offset = range.offset + done,
                    .index = range.index,
                };
                left += 1;
            }
        }
        assert(left <= pending.len);
        return left;
    }

    /// Copy cached bytes starting at `offset` into `buf`, stopping at the first missing page.
    /// Returns the bytes copied.
    pub fn read_cached(self: *CacheRef, blob_id: u64, buf: []u8, offset: u64) usize {
        self.acquire();
        defer self.release();
        return self.copy_cached(blob_id, buf, offset);
    }

    fn copy_cached(self: *CacheRef, blob_id: u64, buf: []u8, offset: u64) usize {
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
        self.hints[self.hint_index(key.blob_id, key.page)] = resident.slot;
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

/// Runs `read_cached_many` over `bufs` at `offsets`; returns the unread ranges' offsets.
fn read_many(
    cache_ref: *CacheRef,
    blob_id: u64,
    bufs: []const []u8,
    offsets: []const u64,
    pending: []CacheRef.Pending,
) []const CacheRef.Pending {
    for (bufs, offsets, pending[0..bufs.len], 0..) |buf, offset, *range, index| {
        range.* = .{ .buf = buf, .offset = offset, .index = index };
    }
    return pending[0..cache_ref.read_cached_many(blob_id, pending[0..bufs.len])];
}

// commonware `test_read_cached_many_across_chunks`.
test "read_cached_many across resolve chunks" {
    const per_page = 5;
    comptime assert(CacheRef.resolve_chunk % per_page != 0);
    const pages = CacheRef.resolve_chunk + 1;
    const ranges_count = pages * per_page;
    comptime assert(ranges_count > 3 * CacheRef.resolve_chunk);
    comptime assert(ranges_count % CacheRef.resolve_chunk != 0);
    for ([_]u16{ 1024, 100 }) |width| {
        var cache_ref = try CacheRef.init(testing.allocator, width, 64);
        defer cache_ref.deinit();
        const blob_id = cache_ref.next_id();
        var page_bytes: [1024]u8 = undefined;
        // Cache every page but each third one.
        for (0..pages) |page| {
            if (page % 3 == 1) continue;
            for (page_bytes[0..width], 0..) |*byte, at| byte.* = @truncate(page * 7 + at);
            _ = cache_ref.cache(blob_id, page_bytes[0..width], page * width);
        }
        // Five short ranges from each page: some pages' ranges straddle a chunk boundary, and
        // the last chunk is short.
        const len = width / (2 * per_page);
        var storage: [ranges_count * 1024 / (2 * per_page)]u8 = @splat(0);
        var bufs: [ranges_count][]u8 = undefined;
        var offsets: [ranges_count]u64 = undefined;
        for (&bufs, &offsets, 0..) |*buf, *offset, index| {
            buf.* = storage[index * len ..][0..len];
            offset.* = index / per_page * width + index % per_page * 2 * len;
        }
        var pending: [ranges_count]CacheRef.Pending = undefined;
        const unread = read_many(&cache_ref, blob_id, &bufs, &offsets, &pending);
        var expected_unread: usize = 0;
        for (bufs, offsets, 0..) |buf, offset, index| {
            const page = offset / width;
            if (page % 3 == 1) {
                try testing.expectEqual(index, unread[expected_unread].index);
                try testing.expectEqual(offset, unread[expected_unread].offset);
                expected_unread += 1;
                for (buf) |byte| try testing.expectEqual(0, byte);
                continue;
            }
            for (buf, offset % width..) |byte, at| {
                try testing.expectEqual(@as(u8, @truncate(page * 7 + at)), byte);
            }
        }
        try testing.expectEqual(expected_unread, unread.len);
    }
}

// commonware `test_read_cached_many_stale_hint_after_eviction`.
test "a stale hint after eviction reads as a miss" {
    // Page 0 is evicted and its slot reused for page 2, so page 0's hint names a slot holding
    // page 2's key.
    var cache_ref = try CacheRef.init(testing.allocator, 4, 2);
    defer cache_ref.deinit();
    const blob_id = cache_ref.next_id();
    for (0..3) |page| {
        const bytes: [4]u8 = @splat(@intCast(page + 1));
        _ = cache_ref.cache(blob_id, &bytes, page * 4);
    }
    var storage: [3][4]u8 = @splat(@splat(0));
    const bufs: [3][]u8 = .{ &storage[0], &storage[1], &storage[2] };
    var pending: [3]CacheRef.Pending = undefined;
    const unread = read_many(&cache_ref, blob_id, &bufs, &.{ 0, 4, 8 }, &pending);
    try testing.expectEqual(1, unread.len);
    try testing.expectEqual(0, unread[0].offset);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, &storage[0]);
    try testing.expectEqualSlices(u8, &.{ 2, 2, 2, 2 }, &storage[1]);
    try testing.expectEqualSlices(u8, &.{ 3, 3, 3, 3 }, &storage[2]);
}

// commonware `test_read_cached_many_cross_blob_hint_collision`.
test "blobs sharing a hint read their own pages" {
    var cache_ref = try CacheRef.init(testing.allocator, 4, 4);
    defer cache_ref.deinit();
    const blob_a = cache_ref.next_id();
    const blob_b = cache_ref.next_id();
    const page_a: u64 = 5;
    // Solve hint_index(blob_b, page_b) == hint_index(blob_a, page_a) for page_b.
    const mask: u64 = cache_ref.hints.len - 1;
    const page_b = (page_a +% blob_a *% utils.GOLDEN_RATIO -% blob_b *% utils.GOLDEN_RATIO) & mask;
    try testing.expectEqual(
        cache_ref.hint_index(blob_a, page_a),
        cache_ref.hint_index(blob_b, page_b),
    );
    _ = cache_ref.cache(blob_a, &.{ 0xaa, 0xaa, 0xaa, 0xaa }, page_a * 4);
    _ = cache_ref.cache(blob_b, &.{ 0xbb, 0xbb, 0xbb, 0xbb }, page_b * 4);
    for ([_]u64{ blob_a, blob_b }, [_]u64{ page_a, page_b }, [_]u8{ 0xaa, 0xbb }) |blob, page, b| {
        var buf: [4]u8 = @splat(0);
        var pending: [1]CacheRef.Pending = undefined;
        const unread = read_many(&cache_ref, blob, &.{&buf}, &.{page * 4}, &pending);
        try testing.expectEqual(0, unread.len);
        try testing.expectEqualSlices(u8, &.{ b, b, b, b }, &buf);
    }
}

// commonware `test_read_cached_many_sparse_page_number_keeps_hints_fixed`.
test "a sparse page number keeps hints fixed" {
    var cache_ref = try CacheRef.init(testing.allocator, 4, 2);
    defer cache_ref.deinit();
    const blob_id = cache_ref.next_id();
    const hints = cache_ref.hints.len;
    const offset = (std.math.maxInt(u64) / 4 - 1) * 4;
    _ = cache_ref.cache(blob_id, &.{ 0x5a, 0x5a, 0x5a, 0x5a }, offset);
    try testing.expectEqual(hints, cache_ref.hints.len);
    var buf: [4]u8 = @splat(0);
    var pending: [1]CacheRef.Pending = undefined;
    try testing.expectEqual(0, read_many(&cache_ref, blob_id, &.{&buf}, &.{offset}, &pending).len);
    try testing.expectEqualSlices(u8, &.{ 0x5a, 0x5a, 0x5a, 0x5a }, &buf);
}

// commonware `test_read_cached_many_evicted_page_is_a_miss`.
test "a reused slot serves its new page through the hint" {
    var cache_ref = try CacheRef.init(testing.allocator, 4, 1);
    defer cache_ref.deinit();
    const blob_id = cache_ref.next_id();
    const Read = struct {
        fn page(cache: *CacheRef, blob: u64, number: u64) ?[4]u8 {
            var buf: [4]u8 = @splat(0);
            var pending: [1]CacheRef.Pending = undefined;
            const unread = read_many(cache, blob, &.{&buf}, &.{number * 4}, &pending);
            return if (unread.len == 0) buf else null;
        }
    };
    _ = cache_ref.cache(blob_id, &.{ 1, 1, 1, 1 }, 0);
    try testing.expectEqual([4]u8{ 1, 1, 1, 1 }, Read.page(&cache_ref, blob_id, 0).?);
    _ = cache_ref.cache(blob_id, &.{ 2, 2, 2, 2 }, 4);
    try testing.expectEqual(null, Read.page(&cache_ref, blob_id, 0));
    try testing.expectEqual([4]u8{ 2, 2, 2, 2 }, Read.page(&cache_ref, blob_id, 1).?);
    _ = cache_ref.cache(blob_id, &.{ 0xcc, 0xcc, 0xcc, 0xcc }, 0);
    try testing.expectEqual([4]u8{ 0xcc, 0xcc, 0xcc, 0xcc }, Read.page(&cache_ref, blob_id, 0).?);
    try testing.expectEqual(null, Read.page(&cache_ref, blob_id, 1));
}
