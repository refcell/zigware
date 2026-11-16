//! Cache-line prefetch hints and a lookahead cursor for software-pipelined scans (commonware
//! `utils/src/prefetch.rs`).
//!
//! A scan whose per-item work waits on a cache miss can issue that miss for an item some
//! distance ahead of consuming it, so several misses are in flight at once. `Lookahead` hands
//! the scan each item that distance ahead of consuming it, and `prefetch` and `prefetch_lines`
//! issue the hints through `@prefetch`, which never faults and has no architectural effect.

const std = @import("std");
const assert = std.debug.assert;

/// Bytes per cache line, the granularity of `prefetch_lines`.
const cache_line = 64;

const options: std.builtin.PrefetchOptions = .{ .rw = .read, .locality = 3, .cache = .data };

/// Hints the CPU to start loading the cache line holding `ptr`, without waiting for it.
pub inline fn prefetch(ptr: anytype) void {
    @prefetch(ptr, options);
}

/// Hints every cache line that the `len` values of `T` at `ptr` intersect, at most `lines_max`
/// of them from the first. Any address is allowed, including one whose span wraps.
pub fn prefetch_lines(
    comptime T: type,
    ptr: *allowzero const T,
    len: usize,
    lines_max: usize,
) void {
    var iterator = lines(@intFromPtr(ptr), len *| @sizeOf(T), lines_max);
    while (iterator.next()) |address| {
        const line: *allowzero const u8 = @ptrFromInt(address);
        @prefetch(line, options);
    }
}

/// The start addresses of the cache lines a byte span intersects.
const Lines = struct {
    first: usize,
    count: usize,
    index: usize = 0,

    fn next(iterator: *Lines) ?usize {
        assert(iterator.index <= iterator.count);
        if (iterator.index == iterator.count) return null;
        defer iterator.index += 1;
        return iterator.first +% iterator.index * cache_line;
    }
};

/// The start of each cache line that the `len` bytes at `address` intersect, at most
/// `lines_max` of them. A span that starts partway into a line can reach one line further than
/// its length alone would.
fn lines(address: usize, len: usize, lines_max: usize) Lines {
    const misalign = address % cache_line;
    const count = if (len == 0) 0 else std.math.divCeil(usize, misalign +| len, cache_line) catch
        unreachable; // The divisor is a non-zero constant.
    return .{ .first = address - misalign, .count = @min(count, lines_max) };
}

/// A cursor that runs a fixed distance ahead of a scan, handing out each item that many items
/// before the scan consumes it, so the caller can prefetch what the item's work reads.
///
/// Call `advance` with the scan's unconsumed tail before consuming its next item. It returns
/// every item exactly once, in scan order, and the first call returns the scan's first
/// `distance + 1` items so the pipeline starts full.
pub const Lookahead = struct {
    /// Items handed out ahead of the one the scan consumes next.
    distance: usize,
    /// Items at the end of the scan that no call has returned: all of them before the first.
    unreturned: usize = std.math.maxInt(usize),

    pub fn init(distance: usize) Lookahead {
        return .{ .distance = distance };
    }

    /// The items within `distance` of the scan's next item that no earlier call returned.
    /// `remaining` is the scan's unconsumed tail, in order.
    pub fn advance(self: *Lookahead, comptime T: type, remaining: []const T) []const T {
        const reach = @min(remaining.len, self.distance +| 1);
        const returned = remaining.len -| self.unreturned;
        if (returned > reach) @panic("Lookahead.advance: the scan skipped unreturned items");
        self.unreturned = remaining.len - reach;
        return remaining[returned..reach];
    }
};

const testing = std.testing;

fn expect_lines(start: usize, len: usize, lines_max: usize, expected: []const usize) !void {
    const base: usize = 0x10000;
    var iterator = lines(base + start, len, lines_max);
    for (expected) |offset| try testing.expectEqual(base + offset, iterator.next().?);
    try testing.expectEqual(null, iterator.next());
}

test "prefetch: lines cover every intersected line" {
    // Aligned spans take exactly the lines their length needs.
    try expect_lines(0, 64, 8, &.{0});
    try expect_lines(0, 65, 8, &.{ 0, 64 });
    // Unaligned spans also take the line their tail reaches into.
    try expect_lines(16, 64, 8, &.{ 0, 64 });
    try expect_lines(16, 128, 8, &.{ 0, 64, 128 });
    try expect_lines(63, 2, 8, &.{ 0, 64 });
    // An empty span takes no line, and the cap bounds a long one.
    try expect_lines(16, 0, 8, &.{});
    try expect_lines(16, 1024, 8, &.{ 0, 64, 128, 192, 256, 320, 384, 448 });
    // The longest span counts its lines without overflow.
    try expect_lines(1, std.math.maxInt(usize), 2, &.{ 0, 64 });
    try expect_lines(1, std.math.maxInt(usize), 0, &.{});
}

test "prefetch: lookahead returns each item once, distance ahead" {
    const max = std.math.maxInt(usize);
    const cases = [_]struct { usize, usize }{
        .{ 0, 2 }, .{ 1, 2 }, .{ 5, 0 }, .{ 5, 2 }, .{ 5, 8 }, .{ 5, max },
    };
    const items = [_]usize{ 0, 1, 2, 3, 4 };
    for (cases) |case| {
        const total, const distance = case;
        var ahead = Lookahead.init(distance);
        var hinted: [8]usize = undefined;
        var hinted_len: usize = 0;
        var consumed: usize = 0;
        while (true) {
            const batch = ahead.advance(usize, items[consumed..total]);
            @memcpy(hinted[hinted_len..][0..batch.len], batch);
            hinted_len += batch.len;
            try testing.expectEqual(@min(total, distance +| (consumed + 1)), hinted_len);
            if (consumed == total) break;
            consumed += 1;
        }
        try testing.expectEqualSlices(usize, items[0..total], hinted[0..hinted_len]);
    }
}

test "prefetch: lookahead never repeats an item" {
    const items = [_]u32{ 0, 1, 2, 3 };
    var ahead = Lookahead.init(1);
    try testing.expectEqualSlices(u32, &.{ 0, 1 }, ahead.advance(u32, &items));
    try testing.expectEqual(0, ahead.advance(u32, &items).len);
    // An item the scan consumed before any call reached it is never returned.
    try testing.expectEqualSlices(u32, &.{3}, ahead.advance(u32, items[3..]));
    try testing.expectEqual(0, ahead.advance(u32, items[4..]).len);
}

test "prefetch: any address is accepted" {
    const null_byte: *allowzero const u8 = @ptrFromInt(0);
    prefetch(null_byte);
    const near_end: *allowzero const u64 = @ptrFromInt(std.math.maxInt(usize) - 7);
    prefetch_lines(u64, near_end, 64, 8);
    const values = [_]u64{ 1, 2, 3 };
    prefetch_lines(u64, &values[0], values.len, 8);
}
