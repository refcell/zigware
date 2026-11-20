//! A borrowed read view over a paged blob: full pages on the blob (through the page cache)
//! followed by an in-memory tail (commonware's `buffer/paged/view.rs`). `Writer` reads
//! through a view of its write buffer and `Sealed` through a view of its frozen partial page.

const std = @import("std");
const assert = std.debug.assert;
const paged = @import("mod.zig");
const Blob = @import("../../storage.zig").Blob;
const cache_mod = @import("cache.zig");
const CacheRef = cache_mod.CacheRef;
const Claim = cache_mod.Claim;

pub const Error = paged.Error;

/// A read range: `len` bytes at `offset`.
pub const Range = struct { offset: u64, len: usize };

pub const View = struct {
    blob: Blob,
    cache_ref: *CacheRef,
    /// The blob's id in the page cache.
    id: u64,
    /// The logical size of the view.
    size: u64,
    /// The logical offset of the first tail byte; bytes below it are full pages on the blob.
    tail_offset: u64,
    /// The logical bytes `[tail_offset, size)`.
    tail: []const u8,

    /// Read exactly `buf.len` bytes at logical `offset`.
    pub fn read_into(self: View, buf: []u8, offset: u64) Error!void {
        const end = std.math.add(u64, offset, buf.len) catch return error.OffsetOverflow;
        if (end > self.size) return error.BlobInsufficientLength;
        const prefix_len = self.copy_tail_overlap(buf, offset);
        if (prefix_len > 0) try self.read_blob(buf[0..prefix_len], offset);
    }

    /// Read exactly `buf.len` bytes at logical `offset` (the `Blob.read_at` argument order).
    pub fn read_at(self: View, offset: u64, buf: []u8) Error!void {
        return self.read_into(buf, offset);
    }

    /// Read up to `buf.len` bytes at `offset`, returning how many were available. Fails if
    /// none are.
    pub fn read_up_to(self: View, offset: u64, buf: []u8) Error!usize {
        if (offset >= self.size) return error.BlobInsufficientLength;
        const len: usize = @intCast(@min(buf.len, self.size - offset));
        try self.read_into(buf[0..len], offset);
        return len;
    }

    /// Read into `buf` only from the tail and page cache. Returns false (leaving
    /// `buf` unspecified) if any byte needs a blob read.
    pub fn try_read_sync_into(self: View, buf: []u8, offset: u64) bool {
        const end = std.math.add(u64, offset, buf.len) catch return false;
        if (end > self.size) return false;
        const prefix_len = self.copy_tail_overlap(buf, offset);
        if (prefix_len == 0) return true;
        return self.cache_ref.read_cached(self.id, buf[0..prefix_len], offset) == prefix_len;
    }

    /// Check `ranges` are sorted, non-overlapping, within the writer, and fill `buf` exactly
    /// (commonware's `validate_read_ranges`; unsorted ranges or a wrong `buf` are a bug).
    fn validate_ranges(self: View, buf_len: usize, ranges: []const Range) Error!void {
        var expected: usize = 0;
        var previous_end: u64 = 0;
        for (ranges, 0..) |range, index| {
            expected += range.len;
            const end = std.math.add(u64, range.offset, range.len) catch
                return error.OffsetOverflow;
            if (index > 0) assert(range.offset >= previous_end);
            if (end > self.size) return error.BlobInsufficientLength;
            previous_end = end;
        }
        assert(expected == buf_len);
    }

    /// Read `ranges` into consecutive slots of `buf`. Returns how many were served from the
    /// tail and page cache without a blob read (empty ranges count as served). Missed ranges
    /// whose pages touch or overlap coalesce into runs, and each run is one blob read of its
    /// physical pages (at most `max_run_pages` at a time), not one read per page or range.
    pub fn read_ranges_into(self: View, buf: []u8, ranges: []const Range) Error!usize {
        try self.validate_ranges(buf.len, ranges);
        const gpa = self.cache_ref.gpa;
        var missed = try std.DynamicBitSetUnmanaged.initEmpty(gpa, ranges.len);
        defer missed.deinit(gpa);
        // Like commonware, every range tries the tail, then the cache under one lock, before
        // any blob read, so the count does not depend on pages an earlier miss brought in.
        const pending = try gpa.alloc(CacheRef.Pending, ranges.len);
        defer gpa.free(pending);
        var pending_count: usize = 0;
        var start: usize = 0;
        for (ranges, 0..) |range, index| {
            const slot = buf[start..][0..range.len];
            start += range.len;
            const below = self.copy_tail_overlap(slot, range.offset);
            if (below == 0) continue;
            pending[pending_count] = .{
                .buf = slot[0..below],
                .offset = range.offset,
                .index = index,
            };
            pending_count += 1;
        }
        assert(start == buf.len);
        const left = self.cache_ref.read_cached_many(self.id, pending[0..pending_count]);
        for (pending[0..left]) |range| missed.set(range.index);
        const served = ranges.len - left;
        if (left == 0) return served;
        // One page buffer serves every run; no run spans more pages than the missed ranges.
        const physical: usize = @intCast(@as(u64, self.cache_ref.page_size) +
            paged.checksum_size);
        // Shared reads assemble a run's logical pages apart from the physical pages they read.
        const run_pages = self.run_pages_bound(ranges, &missed);
        const shared = self.cache_ref.io != null;
        const logical_len = if (shared) run_pages * self.page_size_bytes() else 0;
        const bytes = try gpa.alloc(u8, run_pages * physical + logical_len);
        defer gpa.free(bytes);
        var run: ?Run = null;
        start = 0;
        for (ranges, 0..) |range, index| {
            const slot_start = start;
            start += range.len;
            if (!missed.isSet(index)) continue;
            // The tail part was copied by the probe; only the part below the tail is missing.
            const below = self.copy_tail_overlap(buf[slot_start..][0..range.len], range.offset);
            assert(below > 0); // A range wholly in the tail never misses.
            const first, _ = self.cache_ref.offset_to_page(range.offset);
            const last, _ = self.cache_ref.offset_to_page(range.offset + below - 1);
            if (run) |*current| {
                if (first <= current.last + 1 and @max(current.last, last) - current.first <
                    max_run_pages)
                {
                    current.last = @max(current.last, last);
                    current.end = index + 1;
                    continue;
                }
                try self.read_run(buf, bytes, ranges, &missed, current.*);
            }
            run = .{
                .first = first,
                .last = last,
                .begin = index,
                .end = index + 1,
                .slot_start = slot_start,
            };
        }
        if (run) |current| try self.read_run(buf, bytes, ranges, &missed, current);
        return served;
    }

    /// The most physical pages one coalesced blob read covers. Eight 4 KiB pages make a
    /// 32 KiB run buffer, the general-purpose allocator's largest size class: a larger buffer
    /// is mapped and faulted in afresh by every call.
    const max_run_pages: u64 = 8;

    /// The most pages one run of the missed `ranges` reads at a time: the pages between the
    /// first and last missed byte, capped at `max_run_pages`.
    fn run_pages_bound(
        self: View,
        ranges: []const Range,
        missed: *const std.DynamicBitSetUnmanaged,
    ) usize {
        const first_index = missed.findFirstSet().?;
        const last_index = missed.findLastSet().?;
        assert(first_index <= last_index and last_index < ranges.len);
        const first, _ = self.cache_ref.offset_to_page(ranges[first_index].offset);
        const last_range = ranges[last_index];
        assert(last_range.len > 0);
        const last, _ = self.cache_ref.offset_to_page(last_range.offset + last_range.len - 1);
        return @intCast(@min(last - first + 1, max_run_pages));
    }

    /// Missed ranges `[begin, end)` whose pages span `[first, last]`; the first range's slot
    /// starts at `slot_start` in the caller's buffer.
    const Run = struct { first: u64, last: u64, begin: usize, end: usize, slot_start: usize };

    /// Read `run`'s pages from the blob in reads of at most `max_run_pages`, validate and
    /// cache them, and copy each missed range's bytes below the tail into its slot.
    fn read_run(
        self: View,
        buf: []u8,
        bytes: []u8,
        ranges: []const Range,
        missed: *const std.DynamicBitSetUnmanaged,
        run: Run,
    ) Error!void {
        assert(run.first <= run.last and run.begin < run.end);
        const page_size_value: u64 = self.cache_ref.page_size;
        const physical: usize = @intCast(page_size_value + paged.checksum_size);
        const chunk_pages = @min(run.last - run.first + 1, max_run_pages);
        assert(bytes.len >= chunk_pages * physical);
        const shared = self.cache_ref.io != null;
        var page = run.first;
        while (page <= run.last) {
            const count: usize = @intCast(@min(run.last - page + 1, max_run_pages));
            const span = bytes[0 .. count * physical];
            const logical = if (shared)
                try self.read_pages_shared(span, bytes[chunk_pages * physical ..], page, count)
            else
                try self.read_pages(span, page, count);
            const span_start = page * page_size_value;
            var slot_start = run.slot_start;
            for (ranges[run.begin..run.end], run.begin..) |range, index| {
                const slot = buf[slot_start..][0..range.len];
                slot_start += range.len;
                if (!missed.isSet(index)) continue;
                const below_end = @min(range.offset + range.len, self.tail_offset);
                const lo = @max(range.offset, span_start);
                const hi = @min(below_end, span_start + logical.len);
                if (lo >= hi) continue;
                const len: usize = @intCast(hi - lo);
                const from: usize = @intCast(lo - span_start);
                @memcpy(slot[@intCast(lo - range.offset)..][0..len], logical[from..][0..len]);
            }
            page += count;
        }
        assert(page == run.last + 1);
    }

    /// Read `count` consecutive physical pages starting at `first` into `bytes` with one blob
    /// read, validate each, compact their logical bytes to the front, cache them, and return
    /// the logical bytes. Pages below the tail are full; a shorter one is a bad checksum.
    fn read_pages(self: View, bytes: []u8, first: u64, count: usize) Error![]const u8 {
        const page_size_value: usize = self.cache_ref.page_size;
        const start, const physical = try paged.physical_page(first, page_size_value);
        assert(bytes.len == count * physical);
        try self.blob.read_at(start, bytes);
        for (0..count) |k| {
            const page_bytes = bytes[k * physical ..][0..physical];
            const active = paged.Checksum.validate_page(page_bytes) orelse
                return error.InvalidChecksum;
            if (active.len != page_size_value) return error.InvalidChecksum;
            // Moving left never overruns a later page's unread bytes; `@memmove` is a block
            // copy, where `copyForwards` copies byte by byte.
            if (k > 0) @memmove(
                bytes[k * page_size_value ..][0..page_size_value],
                page_bytes[0..page_size_value],
            );
        }
        const logical = bytes[0 .. count * page_size_value];
        assert(self.cache_ref.cache(self.id, logical, first * page_size_value) == 0);
        return logical;
    }

    fn page_size_bytes(self: View) usize {
        return self.cache_ref.page_size;
    }

    /// `read_pages` sharing reads with other readers through the cache: each page is copied
    /// if cached, joined if another reader is fetching it, and otherwise claimed, and the
    /// claimed pages are read in contiguous runs into `bytes`. The logical pages land in
    /// `logical`. Every claimed page is resolved before any joined one is awaited, since two
    /// readers waiting on each other's pages first would wait forever.
    fn read_pages_shared(
        self: View,
        bytes: []u8,
        logical: []u8,
        first: u64,
        count: usize,
    ) Error![]const u8 {
        const page_size_value = self.page_size_bytes();
        assert(count <= max_run_pages and logical.len >= count * page_size_value);
        var claims: [max_run_pages]Claim = undefined;
        for (claims[0..count], 0..) |*claim, k| {
            const dest = logical[k * page_size_value ..][0..page_size_value];
            claim.* = self.cache_ref.begin_fetch(self.id, first + k, dest, true);
        }
        var failure: ?Error = null;
        var k: usize = 0;
        while (k < count) {
            if (!owns(claims[k])) {
                k += 1;
                continue;
            }
            var end = k + 1;
            while (end < count and owns(claims[end])) end += 1;
            if (self.read_owned(bytes, logical, first, claims[k..end], k)) |err| failure = err;
            k = end;
        }
        // Every claimed page is resolved, so `bytes` is free for re-reads of abandoned pages.
        const physical = page_size_value + paged.checksum_size;
        for (claims[0..count], 0..) |claim, index| switch (claim) {
            .joined => |ticket| {
                if (failure != null) {
                    self.cache_ref.leave_fetch(ticket);
                    continue;
                }
                const dest = logical[index * page_size_value ..][0..page_size_value];
                const got = self.cache_ref.wait_fetch(ticket, dest) catch |err| {
                    failure = err;
                    continue;
                };
                if (got) continue;
                self.fetch_page(first + index, dest, bytes[0..physical]) catch |err| {
                    failure = err;
                };
            },
            .cached, .claimed, .private => {},
        };
        if (failure) |err| return err;
        return logical[0 .. count * page_size_value];
    }

    fn owns(claim: Claim) bool {
        return claim == .claimed or claim == .private;
    }

    /// Read the pages `claims` (claimed or private, starting at run index `begin`) with one
    /// blob read, copy each valid page into `logical`, and resolve every claim. Returns the
    /// first failure.
    fn read_owned(
        self: View,
        bytes: []u8,
        logical: []u8,
        first: u64,
        claims: []const Claim,
        begin: usize,
    ) ?Error {
        const page_size_value = self.page_size_bytes();
        const physical = page_size_value + paged.checksum_size;
        const start, _ = paged.physical_page(first + begin, page_size_value) catch |err| {
            for (claims, begin..) |claim, k| self.resolve(claim, first + k, err);
            return err;
        };
        const span = bytes[begin * physical ..][0 .. claims.len * physical];
        self.blob.read_at(start, span) catch |err| {
            for (claims, begin..) |claim, k| self.resolve(claim, first + k, err);
            return err;
        };
        var failure: ?Error = null;
        for (claims, begin..) |claim, k| {
            const page_bytes = span[(k - begin) * physical ..][0..physical];
            const result = full_page(page_bytes, page_size_value);
            if (result) |page| {
                @memcpy(logical[k * page_size_value ..][0..page_size_value], page);
            } else |err| failure = err;
            self.resolve(claim, first + k, result);
        }
        return failure;
    }

    /// The logical bytes of a full physical page, or `InvalidChecksum`.
    fn full_page(page_bytes: []const u8, page_size_value: usize) Error![]const u8 {
        const active = paged.Checksum.validate_page(page_bytes) orelse
            return error.InvalidChecksum;
        // Pages below the tip are full; a shorter one fell back to a partial checksum.
        if (active.len != page_size_value) return error.InvalidChecksum;
        return page_bytes[0..page_size_value];
    }

    /// Resolve an owned page: a claimed fetch for its joiners; a private page read is cached.
    fn resolve(self: View, claim: Claim, page: u64, result: Error![]const u8) void {
        switch (claim) {
            .claimed => |ticket| self.cache_ref.finish_fetch(ticket, result),
            .private => if (result) |bytes| {
                const offset = page * self.page_size_bytes();
                assert(self.cache_ref.cache(self.id, bytes, offset) == 0);
            } else |_| {},
            .cached, .joined => unreachable,
        }
    }

    /// Fetch full page `page` into `dest`, sharing the read through the cache. A joined fetch
    /// whose reader was canceled is tried again, joining once more; the third try reads alone.
    /// `scratch` holds one physical page.
    fn fetch_page(self: View, page: u64, dest: []u8, scratch: []u8) Error!void {
        const page_size_value = self.page_size_bytes();
        assert(dest.len == page_size_value);
        assert(scratch.len == page_size_value + paged.checksum_size);
        for (0..3) |attempt| {
            const claim = self.cache_ref.begin_fetch(self.id, page, dest, attempt < 2);
            switch (claim) {
                .cached => return,
                .joined => |ticket| if (try self.cache_ref.wait_fetch(ticket, dest)) return,
                .claimed, .private => {
                    const result = self.read_page_alone(page, scratch);
                    self.resolve(claim, page, result);
                    @memcpy(dest, try result);
                    return;
                },
            }
        }
        unreachable; // The last try never joins, so it returns.
    }

    fn read_page_alone(self: View, page: u64, scratch: []u8) Error![]const u8 {
        const page_size_value = self.page_size_bytes();
        const logical, _ = try paged.read_page_with_checksum(
            self.blob,
            page,
            page_size_value,
            scratch,
            .{},
        );
        if (logical.len != page_size_value) return error.InvalidChecksum;
        return logical;
    }

    /// Read `item_size`-byte items at sorted `offsets` into consecutive slots of `buf`.
    /// Returns how many were served without a blob read.
    pub fn read_many_into(
        self: View,
        buf: []u8,
        offsets: []const u64,
        item_size: usize,
    ) Error!usize {
        assert(item_size > 0);
        assert(buf.len == offsets.len * item_size);
        var served: usize = 0;
        for (offsets, 0..) |offset, index| {
            if (index > 0) assert(offset >= offsets[index - 1] +| item_size);
            const end = std.math.add(u64, offset, item_size) catch return error.OffsetOverflow;
            if (end > self.size) return error.BlobInsufficientLength;
        }
        for (offsets, 0..) |offset, index| {
            const slot = buf[index * item_size ..][0..item_size];
            if (self.try_read_sync_into(slot, offset)) served += 1;
        }
        if (served == offsets.len) return served;
        for (offsets, 0..) |offset, index| {
            const slot = buf[index * item_size ..][0..item_size];
            if (!self.try_read_sync_into(slot, offset)) try self.read_into(slot, offset);
        }
        assert(served <= offsets.len);
        return served;
    }

    /// Cache-only `read_ranges_into`: writes the indices of ranges that need a blob read into
    /// `misses` (one slot per range) and returns how many there are. Every index misses when
    /// the ranges extend past the writer; missed slots in `buf` hold unspecified bytes.
    pub fn try_read_ranges_sync_into(
        self: View,
        buf: []u8,
        ranges: []const Range,
        misses: []usize,
    ) usize {
        assert(misses.len >= ranges.len);
        var count: usize = 0;
        self.validate_ranges(buf.len, ranges) catch {
            for (misses[0..ranges.len], 0..) |*miss, index| miss.* = index;
            return ranges.len;
        };
        var start: usize = 0;
        for (ranges, 0..) |range, index| {
            const slot = buf[start..][0..range.len];
            start += range.len;
            if (self.try_read_sync_into(slot, range.offset)) continue;
            misses[count] = index;
            count += 1;
        }
        assert(count <= ranges.len);
        return count;
    }

    /// Cache-only `read_many_into`: writes the indices of items that need a blob read into
    /// `misses` (one slot per item) and returns how many there are. Every index misses when
    /// an item extends past the view; missed slots in `buf` hold unspecified bytes.
    pub fn try_read_many_sync_into(
        self: View,
        buf: []u8,
        offsets: []const u64,
        item_size: usize,
        misses: []usize,
    ) usize {
        assert(item_size > 0);
        assert(buf.len == offsets.len * item_size and misses.len >= offsets.len);
        var count: usize = 0;
        for (offsets, 0..) |offset, index| {
            if (index > 0) assert(offset >= offsets[index - 1] +| item_size);
            const slot = buf[index * item_size ..][0..item_size];
            if (self.try_read_sync_into(slot, offset)) continue;
            misses[count] = index;
            count += 1;
        }
        assert(count <= offsets.len);
        return count;
    }

    /// Copy the part of `[offset, offset + buf.len)` held in the tail; returns the
    /// length of the prefix below it.
    fn copy_tail_overlap(self: View, buf: []u8, offset: u64) usize {
        const tail_start = @max(self.tail_offset, offset);
        const end = offset + buf.len;
        if (tail_start >= end) return buf.len;
        const prefix_len: usize = @intCast(tail_start - offset);
        const from: usize = @intCast(tail_start - self.tail_offset);
        @memcpy(buf[prefix_len..], self.tail[from..][0 .. buf.len - prefix_len]);
        return prefix_len;
    }

    /// Read full pages below the tail through the page cache.
    /// Physical pages up to this size are read into a stack buffer; larger ones allocate.
    const stack_page_bytes = 4096;

    /// Reads `buf` at `offset` from the page cache, fetching missed pages from the blob
    /// (commonware's `read_after_miss`): shared with other readers once the cache shares reads,
    /// otherwise each into a buffer of this call's own.
    fn read_blob(self: View, buf: []u8, offset: u64) Error!void {
        const done = self.cache_ref.read_cached(self.id, buf, offset);
        if (done == buf.len) return;
        if (self.cache_ref.io != null) return self.read_blob_shared(buf, offset, done);
        return self.read_blob_alone(buf, offset, done);
    }

    fn read_blob_shared(self: View, buf: []u8, offset: u64, cached: usize) Error!void {
        const page_size_value = self.page_size_bytes();
        const physical = page_size_value + paged.checksum_size;
        var stack: [2 * stack_page_bytes]u8 = undefined;
        const heap = physical + page_size_value > stack.len;
        const gpa = self.cache_ref.gpa;
        const scratch = if (heap)
            try gpa.alloc(u8, physical + page_size_value)
        else
            stack[0 .. physical + page_size_value];
        defer if (heap) gpa.free(scratch);
        const page_bytes = scratch[physical..];
        var done = cached;
        while (done < buf.len) {
            const page, const in_page = self.cache_ref.offset_to_page(offset + done);
            try self.fetch_page(page, page_bytes, scratch[0..physical]);
            const count = @min(buf.len - done, page_size_value - in_page);
            @memcpy(buf[done..][0..count], page_bytes[@intCast(in_page)..][0..count]);
            done += count;
            done += self.cache_ref.read_cached(self.id, buf[done..], offset + done);
        }
        assert(done == buf.len);
    }

    fn read_blob_alone(self: View, buf: []u8, offset: u64, cached: usize) Error!void {
        const page_size_value = self.cache_ref.page_size;
        var done = cached;
        const physical: usize = @intCast(page_size_value + paged.checksum_size);
        var stack: [stack_page_bytes]u8 = undefined;
        const heap = physical > stack.len;
        const gpa = self.cache_ref.gpa;
        const page_bytes = if (heap) try gpa.alloc(u8, physical) else stack[0..physical];
        defer if (heap) gpa.free(page_bytes);
        assert(page_bytes.len == physical);
        while (done < buf.len) {
            const page, const in_page = self.cache_ref.offset_to_page(offset + done);
            const logical, _ = try paged.read_page_with_checksum(
                self.blob,
                page,
                page_size_value,
                page_bytes,
                .{},
            );
            // Pages below the tip are full; a shorter one fell back to a partial checksum.
            if (logical.len != page_size_value) return error.InvalidChecksum;
            assert(self.cache_ref.cache(self.id, logical, page * page_size_value) == 0);
            const count = @min(buf.len - done, page_size_value - in_page);
            @memcpy(buf[done..][0..count], logical[@intCast(in_page)..][0..count]);
            done += count;
            done += self.cache_ref.read_cached(self.id, buf[done..], offset + done);
        }
        assert(done == buf.len);
    }
};

test "validate_ranges: in bounds, empty, zero-length, overflow, and past the end" {
    // mod.rs's `test_validate_read_ranges` cases over a 16-byte view; mismatched buffers and
    // unsorted ranges are asserts here (commonware's should_panic cases).
    const view: View = .{
        .blob = undefined,
        .cache_ref = undefined,
        .id = 0,
        .size = 16,
        .tail_offset = 16,
        .tail = &.{},
    };
    try view.validate_ranges(12, &.{ .{ .offset = 0, .len = 4 }, .{ .offset = 4, .len = 8 } });
    try view.validate_ranges(0, &.{});
    try view.validate_ranges(4, &.{ .{ .offset = 0, .len = 0 }, .{ .offset = 0, .len = 4 } });
    try view.validate_ranges(4, &.{.{ .offset = 12, .len = 4 }});
    const max = std.math.maxInt(u64);
    try std.testing.expectError(
        error.OffsetOverflow,
        view.validate_ranges(4, &.{.{ .offset = max, .len = 4 }}),
    );
    try std.testing.expectError(
        error.BlobInsufficientLength,
        view.validate_ranges(4, &.{.{ .offset = 14, .len = 4 }}),
    );
}
