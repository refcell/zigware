//! A borrowed read view over a paged blob: full pages on the blob (through the page cache)
//! followed by an in-memory tail (commonware's `buffer/paged/view.rs`). `Writer` reads
//! through a view of its write buffer and `Sealed` through a view of its frozen partial page.

const std = @import("std");
const assert = std.debug.assert;
const paged = @import("mod.zig");
const Blob = @import("../../storage.zig").Blob;
const CacheRef = @import("cache.zig").CacheRef;

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
    /// One physical page for reads.
    page_scratch: []u8,

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
    /// tail and page cache without a blob read (empty ranges count as served).
    pub fn read_ranges_into(self: View, buf: []u8, ranges: []const Range) Error!usize {
        try self.validate_ranges(buf.len, ranges);
        // Like commonware, every range tries the cache before any blob read, so the count
        // does not depend on pages an earlier miss brought in.
        var served: usize = 0;
        var start: usize = 0;
        for (ranges) |range| {
            if (self.try_read_sync_into(buf[start..][0..range.len], range.offset)) served += 1;
            start += range.len;
        }
        if (served == ranges.len) return served;
        start = 0;
        for (ranges) |range| {
            const slot = buf[start..][0..range.len];
            start += range.len;
            if (self.try_read_sync_into(slot, range.offset)) continue;
            try self.read_into(slot, range.offset);
        }
        assert(start == buf.len and served <= ranges.len);
        return served;
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
    fn read_blob(self: View, buf: []u8, offset: u64) Error!void {
        const page_size_value = self.cache_ref.page_size;
        var done = self.cache_ref.read_cached(self.id, buf, offset);
        while (done < buf.len) {
            const page, const in_page = self.cache_ref.offset_to_page(offset + done);
            const logical, _ = try paged.read_page_with_checksum(
                self.blob,
                page,
                page_size_value,
                self.page_scratch,
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
        .page_scratch = &.{},
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
