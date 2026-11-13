//! A buffer for data written to the tip of a blob (commonware's `buffer/tip.rs`).
//!
//! The buffer holds logical bytes `[offset, offset + len)` of the blob. commonware hands
//! drained bytes to I/O without copying and reallocates on the next write; zigware keeps one
//! allocation of `capacity` bytes made at init, and `take` returns a view into it that stays
//! valid until the next `merge` or `resize`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

pub const Buffer = struct {
    data: []u8,
    /// Number of logical buffered bytes in `data`.
    len: usize = 0,
    /// The blob offset of `data[0]`.
    offset: u64,
    /// The maximum number of buffered bytes.
    capacity: usize,

    pub fn init(gpa: Allocator, offset: u64, capacity: usize) Allocator.Error!Buffer {
        assert(capacity > 0);
        const data = try gpa.alloc(u8, capacity);
        assert(data.len == capacity);
        return .{ .data = data, .offset = offset, .capacity = capacity };
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
        assert(self.len <= self.capacity);
        return self.data[0..self.len];
    }

    /// Adjust the buffer to a blob resized to `len`. Growing past the buffered data returns
    /// the buffered bytes and their offset (as `take` would) for the caller to flush; shrinking
    /// within the buffer truncates it; shrinking below it empties it at `len`.
    pub fn resize(self: *Buffer, len: u64) ?struct { []const u8, u64 } {
        if (self.is_empty()) {
            self.offset = len;
            return null;
        }
        if (len >= self.size()) {
            const previous = self.take().?;
            self.offset = len;
            return previous;
        }
        if (len >= self.offset) {
            self.len = @intCast(len - self.offset);
        } else {
            self.len = 0;
            self.offset = len;
        }
        assert(self.size() == len);
        return null;
    }

    /// Return the buffered bytes and their offset, emptying the buffer at the end of the
    /// drained range. Null if the buffer is empty.
    pub fn take(self: *Buffer) ?struct { []const u8, u64 } {
        if (self.is_empty()) return null;
        const len = self.len;
        const offset = self.offset;
        self.len = 0;
        self.offset += len;
        assert(self.size() == offset + len);
        return .{ self.data[0..len], offset };
    }

    /// Merge `data` at blob `offset` if it lies within `[self.offset, self.offset + capacity)`,
    /// zero-filling any gap. Returns false (leaving the buffer unchanged) otherwise.
    pub fn merge(self: *Buffer, data: []const u8, offset: u64) bool {
        // unreachable: `Write` rejects ranges whose end overflows before merging.
        const end_offset = std.math.add(u64, offset, data.len) catch unreachable;
        const limit = std.math.add(u64, self.offset, self.capacity) catch std.math.maxInt(u64);
        if (offset < self.offset or end_offset > limit) return false;
        const start: usize = @intCast(offset - self.offset);
        const end = start + data.len;
        if (end > self.len) @memset(self.data[self.len..end], 0);
        @memcpy(self.data[start..end], data);
        self.len = @max(self.len, end);
        assert(self.len <= self.capacity);
        return true;
    }
};

const testing = std.testing;

test "tip take" {
    var buffer = try Buffer.init(testing.allocator, 50, 100);
    defer buffer.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 50), buffer.size());
    try testing.expect(buffer.is_empty());
    try testing.expect(buffer.take() == null);
    try testing.expect(buffer.merge(&.{ 1, 2, 3 }, 50));
    try testing.expectEqual(@as(u64, 53), buffer.size());
    const data, const offset = buffer.take().?;
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, data);
    try testing.expectEqual(@as(u64, 50), offset);
    try testing.expectEqual(@as(u64, 53), buffer.size());
    try testing.expect(buffer.take() == null);
    const fill: [100]u8 = @splat(42);
    try testing.expect(buffer.merge(&fill, 53));
    try testing.expect(!buffer.merge(&.{43}, 153));
    const big, const big_offset = buffer.take().?;
    try testing.expectEqualSlices(u8, &fill, big);
    try testing.expectEqual(@as(u64, 53), big_offset);
}

test "tip resize" {
    var buffer = try Buffer.init(testing.allocator, 50, 100);
    defer buffer.deinit(testing.allocator);
    try testing.expect(buffer.merge(&.{ 1, 2, 3 }, buffer.size()));
    // Growing past the buffer returns what `take` would.
    const resized, const offset = buffer.resize(60).?;
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, resized);
    try testing.expectEqual(@as(u64, 50), offset);
    try testing.expectEqual(@as(u64, 60), buffer.size());
    try testing.expect(buffer.take() == null);
    try testing.expect(buffer.merge(&.{ 4, 5, 6 }, buffer.size()));
    try testing.expectEqual(@as(u64, 63), buffer.size());
    // Shrinking within the buffer truncates it.
    try testing.expect(buffer.resize(61) == null);
    try testing.expectEqual(@as(u64, 61), buffer.size());
    const taken, const taken_offset = buffer.take().?;
    try testing.expectEqualSlices(u8, &.{4}, taken);
    try testing.expectEqual(@as(u64, 60), taken_offset);
    try testing.expect(buffer.merge(&.{ 7, 8, 9 }, buffer.size()));
    // Shrinking below the buffer resets it at the new size.
    try testing.expect(buffer.resize(59) == null);
    try testing.expectEqual(@as(u64, 59), buffer.size());
    try testing.expect(buffer.take() == null);
}

test "tip merge appends after truncate and take" {
    var buffer = try Buffer.init(testing.allocator, 50, 8);
    defer buffer.deinit(testing.allocator);
    try testing.expect(buffer.merge("abcdefgh", 50));
    try testing.expect(buffer.resize(53) == null);
    try testing.expect(buffer.merge("XYZ", 53));
    try testing.expectEqualStrings("abcXYZ", buffer.bytes());
    try testing.expect(buffer.merge("12", 56));
    try testing.expectEqualStrings("abcXYZ12", buffer.bytes());
    try testing.expect(buffer.merge("", 58));
    try testing.expect(!buffer.merge("!", 58));
    try testing.expectEqual(@as(u64, 58), buffer.size());

    var other = try Buffer.init(testing.allocator, 50, 8);
    defer other.deinit(testing.allocator);
    try testing.expect(other.merge("abcdef", 50));
    _, const offset = other.take().?;
    try testing.expectEqual(@as(u64, 50), offset);
    try testing.expect(other.merge("12", 56));
    try testing.expectEqualStrings("12", other.bytes());
    _ = other.resize(56);
    try testing.expect(other.merge("!", 56));
    try testing.expectEqualStrings("!", other.bytes());
    try testing.expectEqual(@as(u64, 57), other.size());
}

test "tip merge zero fills a gap" {
    var buffer = try Buffer.init(testing.allocator, 10, 8);
    defer buffer.deinit(testing.allocator);
    try testing.expect(buffer.merge("ab", 10));
    try testing.expect(buffer.merge("z", 14));
    try testing.expectEqualSlices(u8, &.{ 'a', 'b', 0, 0, 'z' }, buffer.bytes());
    // Writes before the buffer's offset never merge.
    try testing.expect(!buffer.merge("x", 9));
}
