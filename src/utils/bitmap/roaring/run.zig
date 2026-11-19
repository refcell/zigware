//! Run container for consecutive sequences (commonware `bitmap/roaring/container/run.rs`):
//! sorted, disjoint, non-adjacent inclusive runs `[start, end]`. Adjacent and overlapping runs
//! merge on insert.
//!
//! Encoding: a `Vec<(u16, u16)>` (u32 varint length, then big-endian start and end); decoding
//! rejects more than 32768 runs, `start > end`, and unsorted, overlapping, or adjacent runs.

const std = @import("std");
const codec = @import("codec");
const Array = @import("array.zig").Array;
const bitmap_container = @import("bitmap.zig");
const Bitmap = bitmap_container.Bitmap;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub const MAX_RUNS: usize = 32768;
const BITS = bitmap_container.BITS;

/// An inclusive run `[start, end]`.
pub const Span = [2]u16;

pub const Run = struct {
    runs: std.ArrayList(Span) = .empty,

    pub const empty: Run = .{};
    pub const max_encode_size: usize = codec.varint.max_size(u32) + 4 * MAX_RUNS;

    pub fn full(gpa: Allocator) Allocator.Error!Run {
        var result: Run = .{};
        try result.runs.append(gpa, .{ 0, std.math.maxInt(u16) });
        return result;
    }

    pub fn from_array(gpa: Allocator, array: *const Array) Allocator.Error!Run {
        var result: Run = .{};
        errdefer result.deinit(gpa);
        try result.runs.ensureTotalCapacity(gpa, array.run_count());
        for (array.as_slice()) |value| result.append_value(value);
        assert(result.runs.items.len == array.run_count());
        return result;
    }

    pub fn from_bitmap(gpa: Allocator, bitmap: *const Bitmap) Allocator.Error!Run {
        var result: Run = .{};
        errdefer result.deinit(gpa);
        try result.runs.ensureTotalCapacity(gpa, bitmap.run_count());
        var start: ?u16 = null;
        for (bitmap.words, 0..) |word, word_index| {
            if (word == 0 and start == null) continue;
            if (word == std.math.maxInt(u64) and start != null) continue;
            for (0..64) |bit| {
                const value: u16 = @intCast(word_index << 6 | bit);
                const set = word & (@as(u64, 1) << @intCast(bit)) != 0;
                if (set and start == null) start = value;
                if (!set and start != null) {
                    result.runs.appendAssumeCapacity(.{ start.?, value - 1 });
                    start = null;
                }
            }
        }
        if (start) |run_start| result.runs.appendAssumeCapacity(.{ run_start, 65535 });
        assert(result.runs.items.len == bitmap.run_count());
        return result;
    }

    /// Appends `value`, which must be above every value so far (capacity reserved).
    fn append_value(self: *Run, value: u16) void {
        const items = self.runs.items;
        if (items.len > 0) {
            assert(value > items[items.len - 1][1]);
            if (@as(u32, items[items.len - 1][1]) + 1 == value) {
                items[items.len - 1][1] = value;
                return;
            }
        }
        self.runs.appendAssumeCapacity(.{ value, value });
    }

    /// Validates and takes ownership of `runs` (allocated by `gpa`).
    pub fn from_owned(runs: []Span) error{Invalid}!Run {
        _ = validate(runs) orelse return .{ .runs = .fromOwnedSlice(runs) };
        return error.Invalid;
    }

    pub fn clone(self: *const Run, gpa: Allocator) Allocator.Error!Run {
        return .{ .runs = try self.runs.clone(gpa) };
    }

    pub fn deinit(self: *Run, gpa: Allocator) void {
        self.runs.deinit(gpa);
        self.* = undefined;
    }

    pub fn run_count(self: *const Run) usize {
        return self.runs.items.len;
    }

    pub fn len(self: *const Run) u32 {
        var total: u32 = 0;
        for (self.runs.items) |run| total += @as(u32, run[1] - run[0]) + 1;
        assert(total <= BITS);
        return total;
    }

    pub fn is_empty(self: *const Run) bool {
        return self.runs.items.len == 0;
    }

    pub fn spans(self: *const Run) []const Span {
        return self.runs.items;
    }

    pub fn min(self: *const Run) ?u16 {
        if (self.runs.items.len == 0) return null;
        return self.runs.items[0][0];
    }

    pub fn max(self: *const Run) ?u16 {
        const last = self.runs.getLastOrNull() orelse return null;
        return last[1];
    }

    /// Runs whose start is at most `value`.
    fn starts_at_most(self: *const Run, value: u16) usize {
        const items = self.runs.items;
        var low: usize = 0;
        var high: usize = items.len;
        // Each pass halves `high - low`: at most 16 passes.
        while (low < high) {
            const middle = low + (high - low) / 2;
            if (items[middle][0] <= value) low = middle + 1 else high = middle;
        }
        return low;
    }

    pub fn contains(self: *const Run, value: u16) bool {
        const position = self.starts_at_most(value);
        return position > 0 and value <= self.runs.items[position - 1][1];
    }

    pub fn is_subset(self: *const Run, other: *const Run) bool {
        var j: usize = 0;
        const b = other.runs.items;
        for (self.runs.items) |run| {
            while (j < b.len and b[j][1] < run[0]) j += 1;
            if (j == b.len or b[j][0] > run[0] or b[j][1] < run[1]) return false;
        }
        return true;
    }

    pub fn intersects(self: *const Run, other: *const Run) bool {
        const a = self.runs.items;
        const b = other.runs.items;
        var i: usize = 0;
        var j: usize = 0;
        while (i < a.len and j < b.len) {
            if (a[i][1] < b[j][0]) {
                i += 1;
            } else if (b[j][1] < a[i][0]) {
                j += 1;
            } else return true;
        }
        return false;
    }

    /// Returns whether `value` was new.
    pub fn insert(self: *Run, gpa: Allocator, value: u16) Allocator.Error!bool {
        if (self.contains(value)) return false;
        const position = self.starts_at_most(value);
        const items = self.runs.items;
        const extends_previous = position > 0 and @as(u32, items[position - 1][1]) + 1 == value;
        const extends_next = position < items.len and @as(u32, value) + 1 == items[position][0];
        if (extends_previous and extends_next) {
            items[position - 1][1] = items[position][1];
            _ = self.runs.orderedRemove(position);
        } else if (extends_previous) {
            items[position - 1][1] = value;
        } else if (extends_next) {
            items[position][0] = value;
        } else {
            try self.runs.insert(gpa, position, .{ value, value });
        }
        assert(self.contains(value));
        return true;
    }

    /// Inserts `[start, end)`; returns how many values were new.
    pub fn insert_range(self: *Run, gpa: Allocator, start: u16, end: u16) Allocator.Error!u32 {
        if (start >= end) return 0;
        const last = end - 1;
        const items = self.runs.items;
        // Runs that overlap or touch `[start, last]`.
        var first: usize = 0;
        while (first < items.len and start > 0 and items[first][1] < start - 1) first += 1;
        var past: usize = first;
        while (past < items.len and (last == 65535 or items[past][0] <= last + 1)) past += 1;
        var merged: Span = .{ start, last };
        var covered: u32 = 0;
        for (items[first..past]) |run| {
            merged = .{ @min(merged[0], run[0]), @max(merged[1], run[1]) };
            const low = @max(run[0], start);
            const high = @min(run[1], last);
            if (low <= high) covered += @as(u32, high - low) + 1;
        }
        try self.runs.replaceRange(gpa, first, past - first, &.{merged});
        const range_size: u32 = end - start;
        assert(covered <= range_size);
        return range_size - covered;
    }

    // Iteration.

    pub const Iterator = struct {
        runs: []const Span,
        /// The next run to look at after the current one.
        next_index: usize,
        current: ?Span,
        value: ?u16,
        end: u32,

        pub fn next(it: *Iterator) ?u16 {
            // Each pass consumes a value or a run: bounded by the values and runs left.
            while (true) {
                const run = it.current orelse return null;
                const value = it.value orelse return null;
                if (value <= run[1] and value < it.end) {
                    it.value = if (value == 65535) null else value + 1;
                    return value;
                }
                it.advance(0);
            }
        }

        /// Moves to the next run ending at or after `start` and starting before `end`.
        fn advance(it: *Iterator, start: u16) void {
            it.current = null;
            it.value = null;
            while (it.next_index < it.runs.len) {
                const run = it.runs[it.next_index];
                it.next_index += 1;
                if (run[1] < start) continue;
                if (run[0] >= it.end) return;
                it.current = run;
                it.value = @max(run[0], start);
                return;
            }
        }

        /// Values left (Rust `size_hint`).
        pub fn remaining(it: *const Iterator) usize {
            var total: usize = 0;
            if (it.current) |run| {
                if (it.value) |value| {
                    if (value <= run[1]) total += (@min(it.end, @as(u32, run[1]) + 1) -| value);
                }
            }
            for (it.runs[it.next_index..]) |run| {
                if (run[0] >= it.end) break;
                total += @min(it.end, @as(u32, run[1]) + 1) -| run[0];
            }
            return total;
        }
    };

    pub fn iter(self: *const Run) Iterator {
        return self.iter_range(0, BITS);
    }

    /// Values in `[start, end)`, both clamped to 65536.
    pub fn iter_range(self: *const Run, start: u32, end: u32) Iterator {
        const low = @min(start, BITS);
        const high = @min(end, BITS);
        const items = self.runs.items;
        var it: Iterator = .{
            .runs = items,
            .next_index = if (low >= high) items.len else 0,
            .current = null,
            .value = null,
            .end = if (low >= high) 0 else high,
        };
        if (low < high) it.advance(@intCast(low));
        return it;
    }

    // Codec.

    pub fn write(self: Run, writer: *codec.Writer) void {
        codec.write([]const Span, self.runs.items, writer);
    }

    pub fn encode_size(self: Run) usize {
        return codec.encode_size([]const Span, self.runs.items);
    }

    pub fn read(gpa: Allocator, reader: *codec.Reader, _: void) codec.Error!Run {
        const count = try codec.read_usize(reader, .to_inclusive(MAX_RUNS));
        const runs = try codec.read_items(Span, gpa, reader, count, {});
        if (validate(runs)) |message| {
            gpa.free(runs);
            return reader.invalid("Run", message);
        }
        return .{ .runs = .fromOwnedSlice(runs) };
    }

    /// commonware's `Arbitrary`: up to 32768 runs, each starting at least two past the last.
    pub fn arbitrary(
        gpa: Allocator,
        u: *codec.arbitrary.Unstructured,
    ) codec.arbitrary.Error!Run {
        const count = u.int_in_range(usize, 0, MAX_RUNS);
        var result: Run = .{};
        errdefer result.deinit(gpa);
        var low: u32 = 0;
        for (0..count) |_| {
            if (low > 65535) break;
            const start: u16 = @intCast(u.int_in_range(u32, low, 65535));
            const end = u.int_in_range(u16, start, 65535);
            try result.runs.append(gpa, .{ start, end });
            low = @as(u32, end) + 2;
        }
        return result;
    }
};

/// Null when `runs` are well formed, else why not.
fn validate(runs: []const Span) ?[]const u8 {
    var previous_end: ?u16 = null;
    for (runs) |run| {
        if (run[0] > run[1]) return "start must be <= end";
        if (previous_end) |end| {
            if (run[0] <= end +| 1) {
                return "runs must be sorted, non-overlapping, and non-adjacent";
            }
        }
        previous_end = run[1];
    }
    return null;
}

const testing = std.testing;

fn collect(iterator: Run.Iterator, out: []u16) []u16 {
    var it = iterator;
    var count: usize = 0;
    while (it.next()) |value| : (count += 1) out[count] = value;
    return out[0..count];
}

fn expect_spans(run: *const Run, expected: []const Span) !void {
    try testing.expectEqualSlices(Span, expected, run.spans());
}

test "roaring run: insert merges neighbors" {
    const gpa = testing.allocator;
    var run: Run = .{};
    defer run.deinit(gpa);
    try testing.expect(run.is_empty() and run.min() == null);
    for ([_]u16{ 5, 7, 9 }) |value| try testing.expect(try run.insert(gpa, value));
    try testing.expect(!try run.insert(gpa, 7));
    try expect_spans(&run, &.{ .{ 5, 5 }, .{ 7, 7 }, .{ 9, 9 } });
    _ = try run.insert(gpa, 6);
    try expect_spans(&run, &.{ .{ 5, 7 }, .{ 9, 9 } });
    _ = try run.insert(gpa, 10);
    _ = try run.insert(gpa, 4);
    _ = try run.insert(gpa, 8);
    try expect_spans(&run, &.{.{ 4, 10 }});
    _ = try run.insert(gpa, 0);
    _ = try run.insert(gpa, 65535);
    try expect_spans(&run, &.{ .{ 0, 0 }, .{ 4, 10 }, .{ 65535, 65535 } });
    try testing.expectEqual(@as(u32, 9), run.len());
    try testing.expect(run.contains(4) and run.contains(10) and !run.contains(11));
    try testing.expectEqual(@as(?u16, 65535), run.max());
}

test "roaring run: insert_range" {
    const gpa = testing.allocator;
    var run: Run = .{};
    defer run.deinit(gpa);
    try testing.expectEqual(@as(u32, 10), try run.insert_range(gpa, 10, 20));
    try testing.expectEqual(@as(u32, 5), try run.insert_range(gpa, 30, 35));
    try testing.expectEqual(@as(u32, 10), try run.insert_range(gpa, 15, 30));
    try expect_spans(&run, &.{.{ 10, 34 }});
    try testing.expectEqual(@as(u32, 1), try run.insert_range(gpa, 35, 36));
    try testing.expectEqual(@as(u32, 0), try run.insert_range(gpa, 12, 20));
    try testing.expectEqual(@as(u32, 100), try run.insert_range(gpa, 65435, 65535));
    _ = try run.insert(gpa, 65535);
    try expect_spans(&run, &.{ .{ 10, 35 }, .{ 65435, 65535 } });
    var full = try Run.full(gpa);
    defer full.deinit(gpa);
    try testing.expectEqual(@as(u32, 65536), full.len());
    try testing.expectEqual(@as(u32, 0), try full.insert_range(gpa, 0, 65535));
}

test "roaring run: iterate, subset, intersects" {
    const gpa = testing.allocator;
    var run: Run = .{};
    defer run.deinit(gpa);
    _ = try run.insert_range(gpa, 2, 5);
    _ = try run.insert_range(gpa, 10, 12);
    var buffer: [16]u16 = undefined;
    try testing.expectEqualSlices(u16, &.{ 2, 3, 4, 10, 11 }, collect(run.iter(), &buffer));
    var range = run.iter_range(3, 11);
    try testing.expectEqual(@as(usize, 3), range.remaining());
    try testing.expectEqualSlices(u16, &.{ 3, 4, 10 }, collect(range, &buffer));
    _ = range.next();
    try testing.expectEqual(@as(usize, 2), range.remaining());
    var none = run.iter_range(5, 10);
    try testing.expectEqual(@as(?u16, null), none.next());
    var empty_range = run.iter_range(7, 3);
    try testing.expectEqual(@as(usize, 0), empty_range.remaining());

    var wide: Run = .{};
    defer wide.deinit(gpa);
    _ = try wide.insert_range(gpa, 0, 20);
    var apart: Run = .{};
    defer apart.deinit(gpa);
    _ = try apart.insert_range(gpa, 6, 9);
    try testing.expect(run.is_subset(&wide) and !wide.is_subset(&run));
    try testing.expect(!run.intersects(&apart) and wide.intersects(&apart));
}

test "roaring run: conversions" {
    const gpa = testing.allocator;
    var array = try Array.init(gpa, &.{ 1, 2, 3, 7, 9, 10 });
    defer array.deinit(gpa);
    var from_array = try Run.from_array(gpa, &array);
    defer from_array.deinit(gpa);
    try expect_spans(&from_array, &.{ .{ 1, 3 }, .{ 7, 7 }, .{ 9, 10 } });
    var dense: Bitmap = .{};
    _ = dense.insert_range(60, 200);
    _ = dense.insert(300);
    _ = dense.insert_range(65000, 65535);
    _ = dense.insert(65535);
    var from_bitmap = try Run.from_bitmap(gpa, &dense);
    defer from_bitmap.deinit(gpa);
    try expect_spans(&from_bitmap, &.{ .{ 60, 199 }, .{ 300, 300 }, .{ 65000, 65535 } });
    const back = Bitmap.from_runs(from_bitmap.spans());
    try testing.expectEqual(dense.words, back.words);
}

test "roaring run: codec" {
    const gpa = testing.allocator;
    var run: Run = .{};
    defer run.deinit(gpa);
    _ = try run.insert_range(gpa, 1, 3);
    const encoded = try codec.encode(Run, gpa, run);
    defer gpa.free(encoded);
    try testing.expectEqualSlices(u8, &.{ 1, 0, 1, 0, 2 }, encoded);
    var decoded = try codec.decode(Run, gpa, encoded);
    defer decoded.deinit(gpa);
    try expect_spans(&decoded, run.spans());
    const cases = [_]struct { []const Span, []const u8 }{
        .{ &.{.{ 5, 4 }}, "start must be <= end" },
        .{ &.{ .{ 1, 3 }, .{ 4, 5 } }, "runs must be sorted, non-overlapping, and non-adjacent" },
        .{ &.{ .{ 5, 6 }, .{ 1, 2 } }, "runs must be sorted, non-overlapping, and non-adjacent" },
    };
    for (cases) |case| {
        const bytes = try codec.encode([]const Span, gpa, case[0]);
        defer gpa.free(bytes);
        var reader = codec.Reader.init(bytes);
        try testing.expectError(error.Invalid, codec.decode_reader(Run, gpa, &reader, {}));
        try testing.expectEqualStrings(case[1], reader.diagnostic.message);
    }
}

test "roaring run: a full bitmap is one run (test_from_full_bitmap)" {
    const gpa = testing.allocator;
    const full = Bitmap.from_words(@splat(~@as(u64, 0)));
    var run = try Run.from_bitmap(gpa, &full);
    defer run.deinit(gpa);
    try testing.expectEqual(@as(usize, 1), run.run_count());
    try testing.expectEqual(@as(u32, 65536), run.len());
    try expect_spans(&run, &.{.{ 0, 65535 }});
}

test "roaring run: encode size is the count plus four bytes per run" {
    // commonware `test_encode_size_empty` and `test_encode_size_grows_per_run`.
    const gpa = testing.allocator;
    var run: Run = .{};
    defer run.deinit(gpa);
    try testing.expectEqual(codec.encode_size(usize, 0), codec.encode_size(Run, run));
    for (0..5) |i| {
        const start: u16 = @intCast(i * 100);
        try testing.expectEqual(@as(u32, 50), try run.insert_range(gpa, start, start + 50));
    }
    try testing.expectEqual(codec.encode_size(usize, 5) + 5 * 4, codec.encode_size(Run, run));
    const encoded = try codec.encode(Run, gpa, run);
    defer gpa.free(encoded);
    try testing.expectEqual(codec.encode_size(Run, run), encoded.len);
}

/// `Run.arbitrary` over fixed bytes, as `arbitrary::Unstructured::new(data)` gives: a keystream
/// whose cached block 0 is preset to `data`, so it never generates one.
fn arbitrary_from(gpa: Allocator, data: []const u8) !Run {
    assert(data.len <= 64);
    var stream: codec.arbitrary.Keystream = .{ .key = @splat(0), .len = data.len };
    stream.block_index = 0;
    @memset(&stream.block, 0);
    @memcpy(stream.block[0..data.len], data);
    var u: codec.arbitrary.Unstructured = .init(&stream);
    return Run.arbitrary(gpa, &u);
}

test "roaring run: arbitrary can generate a run starting at zero" {
    // commonware `test_arbitrary_can_generate_run_starting_at_zero`.
    const gpa = testing.allocator;
    var run = try arbitrary_from(gpa, &.{ 0, 1, 0, 0, 0, 5 });
    defer run.deinit(gpa);
    try expect_spans(&run, &.{.{ 0, 5 }});
}

test "roaring run: arbitrary can generate a trailing max singleton" {
    // commonware `test_arbitrary_can_generate_trailing_max_singleton`.
    const gpa = testing.allocator;
    var run = try arbitrary_from(gpa, &.{ 0, 2, 0, 0, 0xff, 0xfd });
    defer run.deinit(gpa);
    try expect_spans(&run, &.{ .{ 0, 65533 }, .{ 65535, 65535 } });
}
