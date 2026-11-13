//! Append-only buffering for the page-oriented writer (commonware's `paged/tip.rs`).
//!
//! commonware chains page-aligned allocations so full pages can be handed to I/O without
//! copying. zigware keeps one contiguous allocation of `capacity + page_size` bytes made at
//! init: the writer flushes once the buffer exceeds `capacity` and appends that would overflow
//! it by a page or more bypass the buffer, so a buffered append always ends below
//! `capacity + page_size` (see `writer.too_big_for_buffer`). Hot paths never allocate.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");

pub const Buffer = struct {
    /// Backing storage, `capacity + page_size` bytes.
    data: []u8,
    /// Buffered logical bytes at the front of `data`.
    len: usize,
    /// Logical blob offset of the first buffered byte. Always page-aligned.
    offset: u64,
    /// Logical flush threshold, a whole number of pages.
    capacity: usize,
    /// Logical payload bytes per page.
    page_size: usize,

    /// A buffer at `offset` seeded with less than one page of existing logical data.
    pub fn init(
        gpa: Allocator,
        offset: u64,
        seed: []const u8,
        capacity: usize,
        page_size: usize,
    ) Allocator.Error!Buffer {
        assert(page_size > 0);
        assert(capacity % page_size == 0 and capacity >= page_size);
        assert(seed.len < page_size);
        assert(offset % page_size == 0);
        const data = try gpa.alloc(u8, capacity + page_size);
        @memcpy(data[0..seed.len], seed);
        return .{
            .data = data,
            .len = seed.len,
            .offset = offset,
            .capacity = capacity,
            .page_size = page_size,
        };
    }

    pub fn deinit(self: *Buffer, gpa: Allocator) void {
        gpa.free(self.data);
        self.* = undefined;
    }

    /// The logical size of the blob including buffered data.
    pub fn size(self: *const Buffer) u64 {
        return self.offset + self.len;
    }

    pub fn is_empty(self: *const Buffer) bool {
        return self.len == 0;
    }

    /// The buffered bytes.
    pub fn bytes(self: *const Buffer) []const u8 {
        return self.data[0..self.len];
    }

    /// The sole partial page once complete pages have been drained.
    pub fn partial(self: *const Buffer) []const u8 {
        assert(self.len < self.page_size);
        return self.data[0..self.len];
    }

    /// Bytes of complete pages at the front of the buffer.
    pub fn full_len(self: *const Buffer) usize {
        return self.len / self.page_size * self.page_size;
    }

    /// Append `bytes`, reporting whether the flush threshold was exceeded.
    pub fn append(self: *Buffer, data: []const u8) bool {
        const end = self.len + data.len;
        assert(end <= self.data.len); // Callers bypass the buffer for larger appends.
        @memcpy(self.data[self.len..end], data);
        self.len = end;
        return end > self.capacity;
    }

    /// Append `bytes` within the flush threshold, returning their logical offset, or null
    /// without changing the buffer if they do not fit.
    pub fn try_append(self: *Buffer, data: []const u8) ?u64 {
        if (self.len + data.len > self.capacity) return null;
        const offset = self.size();
        const exceeded = self.append(data);
        assert(!exceeded);
        return offset;
    }

    /// Encode `value` within the flush threshold, returning its logical offset, or null
    /// without encoding if it does not fit.
    pub fn try_append_value(self: *Buffer, comptime T: type, value: T) ?u64 {
        const value_size = codec.encode_size(T, value);
        if (self.len + value_size > self.capacity) return null;
        const offset = self.size();
        var writer = codec.Writer.init(self.data[self.len..][0..value_size]);
        codec.write(T, value, &writer);
        assert(writer.end == value_size);
        self.len += value_size;
        return offset;
    }

    /// Drop the complete pages at the front (after they were written), keeping the partial
    /// page at its logical position.
    pub fn consume_full_pages(self: *Buffer) void {
        const full = self.full_len();
        const partial_len = self.len - full;
        std.mem.copyForwards(u8, self.data[0..partial_len], self.data[full..self.len]);
        self.len = partial_len;
        self.offset += full;
        assert(self.len < self.page_size);
        assert(self.offset % self.page_size == 0);
    }

    /// Replace the buffer with less than one page of data at `offset`.
    pub fn replace(self: *Buffer, offset: u64, data: []const u8) void {
        assert(data.len < self.page_size);
        assert(offset % self.page_size == 0);
        std.mem.copyForwards(u8, self.data[0..data.len], data);
        self.len = data.len;
        self.offset = offset;
    }
};

const testing = std.testing;

test "append, threshold, and drain keep logical offsets" {
    var buffer = try Buffer.init(testing.allocator, 32, "ab", 16, 8);
    defer buffer.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 34), buffer.size());
    try testing.expectEqual(@as(?u64, 34), buffer.try_append("cdefghij"));
    try testing.expectEqual(@as(?u64, null), buffer.try_append("1234567"));
    try testing.expect(!buffer.append("123456"));
    try testing.expect(buffer.append("7"));
    try testing.expectEqual(@as(usize, 16), buffer.full_len());
    buffer.consume_full_pages();
    try testing.expectEqual(@as(u64, 48), buffer.offset);
    try testing.expectEqualStrings("7", buffer.partial());
    try testing.expectEqual(@as(?u64, 49), buffer.try_append_value(u16, 0x4142));
    try testing.expectEqualStrings("7AB", buffer.bytes());
    buffer.replace(8, "xy");
    try testing.expectEqual(@as(u64, 10), buffer.size());
}
