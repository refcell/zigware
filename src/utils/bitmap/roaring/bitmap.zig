//! Bitmap container for dense data (commonware `bitmap/roaring/container/bitmap.rs`): all
//! 65,536 values as 1024 `u64` words (8 KB), with the cardinality and the number of maximal
//! runs of set bits kept up to date.
//!
//! Encoding: the 1024 words, each big-endian, with no length prefix (8192 bytes).

const std = @import("std");
const codec = @import("codec");
const Array = @import("array.zig").Array;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub const WORDS: usize = 1024;
pub const BITS: u32 = WORDS * 64;
pub const ENCODED_BYTES: usize = WORDS * @sizeOf(u64);

pub const Bitmap = struct {
    words: [WORDS]u64 = @splat(0),
    cardinality: u32 = 0,
    run_total: u16 = 0,

    pub const empty: Bitmap = .{};
    pub const fixed_size: usize = ENCODED_BYTES;

    pub fn from_words(words: [WORDS]u64) Bitmap {
        var cardinality: u32 = 0;
        for (words) |word| cardinality += @popCount(word);
        return .{ .words = words, .cardinality = cardinality, .run_total = count_runs(&words) };
    }

    pub fn from_array(array: *const Array) Bitmap {
        var result: Bitmap = .{};
        for (array.as_slice()) |value| result.words[value >> 6] |= bit_mask(value);
        result.cardinality = @intCast(array.len());
        result.run_total = count_runs(&result.words);
        assert(result.run_total == array.run_count());
        return result;
    }

    /// From inclusive `[start, end]` runs, sorted and separated by gaps.
    pub fn from_runs(runs: []const [2]u16) Bitmap {
        var result: Bitmap = .{};
        for (runs) |run| {
            assert(run[0] <= run[1]);
            const inserted = result.fill(run[0], run[1]);
            assert(inserted == @as(u32, run[1] - run[0]) + 1);
            result.cardinality += inserted;
        }
        result.run_total = @intCast(runs.len);
        assert(result.run_total == count_runs(&result.words));
        return result;
    }

    fn bit_mask(value: u16) u64 {
        return @as(u64, 1) << @intCast(value & 63);
    }

    /// Mask of bits `low..=high` within one word.
    fn word_mask(low: u6, high: u6) u64 {
        assert(low <= high);
        const upper = if (high == 63) std.math.maxInt(u64) else (@as(u64, 1) << (high + 1)) - 1;
        return upper & (@as(u64, std.math.maxInt(u64)) << low);
    }

    /// Sets `start..=end`; returns how many bits were new.
    fn fill(self: *Bitmap, start: u16, end: u16) u32 {
        const start_word = start >> 6;
        const end_word = end >> 6;
        var inserted: u32 = 0;
        var word = start_word;
        while (word <= end_word) : (word += 1) {
            const low: u6 = if (word == start_word) @intCast(start & 63) else 0;
            const high: u6 = if (word == end_word) @intCast(end & 63) else 63;
            const before = @popCount(self.words[word]);
            self.words[word] |= word_mask(low, high);
            inserted += @popCount(self.words[word]) - before;
        }
        return inserted;
    }

    pub fn run_count(self: *const Bitmap) u16 {
        return self.run_total;
    }

    pub fn len(self: *const Bitmap) u32 {
        assert(self.cardinality <= BITS);
        return self.cardinality;
    }

    pub fn is_empty(self: *const Bitmap) bool {
        return self.cardinality == 0;
    }

    pub fn is_full(self: *const Bitmap) bool {
        return self.cardinality == BITS;
    }

    pub fn contains(self: *const Bitmap, value: u16) bool {
        return self.words[value >> 6] & bit_mask(value) != 0;
    }

    pub fn is_subset(self: *const Bitmap, other: *const Bitmap) bool {
        for (self.words, other.words) |a, b| if (a & ~b != 0) return false;
        return true;
    }

    pub fn intersects(self: *const Bitmap, other: *const Bitmap) bool {
        for (self.words, other.words) |a, b| if (a & b != 0) return true;
        return false;
    }

    /// Returns whether `value` was new; keeps the run count by checking its neighbors.
    pub fn insert(self: *Bitmap, value: u16) bool {
        if (self.contains(value)) return false;
        const left = value > 0 and self.contains(value - 1);
        const right = value < std.math.maxInt(u16) and self.contains(value + 1);
        self.words[value >> 6] |= bit_mask(value);
        self.cardinality += 1;
        if (!left and !right) self.run_total += 1;
        if (left and right) self.run_total -= 1;
        assert(self.contains(value));
        return true;
    }

    /// Inserts `[start, end)`; returns how many values were new.
    pub fn insert_range(self: *Bitmap, start: u16, end: u16) u32 {
        if (start >= end) return 0;
        const inserted = self.fill(start, end - 1);
        self.cardinality += inserted;
        self.run_total = count_runs(&self.words);
        return inserted;
    }

    pub fn min(self: *const Bitmap) ?u16 {
        for (self.words, 0..) |word, index| {
            if (word != 0) return @intCast(index << 6 | @ctz(word));
        }
        return null;
    }

    pub fn max(self: *const Bitmap) ?u16 {
        var index: usize = WORDS;
        while (index > 0) {
            index -= 1;
            const word = self.words[index];
            if (word != 0) return @intCast(index << 6 | (63 - @clz(word)));
        }
        return null;
    }

    pub const Operation = enum { @"or", @"and", and_not };

    /// `a | b`, `a & b`, or `a & ~b` (Rust `or_new`, `and_new`, `and_not_new`).
    pub fn combine(a: *const Bitmap, b: *const Bitmap, comptime operation: Operation) Bitmap {
        var result: Bitmap = .{};
        for (&result.words, a.words, b.words) |*out, left, right| {
            out.* = switch (operation) {
                .@"or" => left | right,
                .@"and" => left & right,
                .and_not => left & ~right,
            };
            result.cardinality += @popCount(out.*);
        }
        result.run_total = count_runs(&result.words);
        return result;
    }

    // Iteration.

    pub const Iterator = struct {
        words: *const [WORDS]u64,
        word_index: usize,
        end_word: usize,
        end_mask: u64,
        current: u64,

        pub fn next(it: *Iterator) ?u16 {
            // Each pass moves to the next word: at most `WORDS` passes.
            while (it.current == 0) {
                if (it.word_index >= it.end_word) return null;
                it.word_index += 1;
                it.current = it.words[it.word_index];
                if (it.word_index == it.end_word) it.current &= it.end_mask;
            }
            const bit = @ctz(it.current);
            it.current &= it.current - 1;
            return @intCast(it.word_index << 6 | bit);
        }

        /// Values left (Rust `size_hint`).
        pub fn remaining(it: *const Iterator) usize {
            if (it.word_index >= WORDS or it.word_index > it.end_word) return 0;
            var total: usize = @popCount(it.current);
            if (it.word_index < it.end_word) {
                for (it.words[it.word_index + 1 .. it.end_word]) |word| total += @popCount(word);
                total += @popCount(it.words[it.end_word] & it.end_mask);
            }
            return total;
        }
    };

    pub fn iter(self: *const Bitmap) Iterator {
        return self.iter_range(0, BITS);
    }

    /// Values in `[start, end)`, both clamped to `BITS`.
    pub fn iter_range(self: *const Bitmap, start: u32, end: u32) Iterator {
        const low = @min(start, BITS);
        const high = @min(end, BITS);
        if (low >= high) {
            return .{
                .words = &self.words,
                .word_index = WORDS,
                .end_word = 0,
                .end_mask = 0,
                .current = 0,
            };
        }
        const start_word: usize = low >> 6;
        const end_word: usize = (high - 1) >> 6;
        const end_mask = word_mask(0, @intCast((high - 1) & 63));
        const start_mask = @as(u64, std.math.maxInt(u64)) << @intCast(low & 63);
        var current = self.words[start_word] & start_mask;
        if (start_word == end_word) current &= end_mask;
        return .{
            .words = &self.words,
            .word_index = start_word,
            .end_word = end_word,
            .end_mask = end_mask,
            .current = current,
        };
    }

    // Codec.

    pub fn write(self: Bitmap, writer: *codec.Writer) void {
        for (self.words) |word| writer.write_int(u64, word);
    }

    pub fn read(_: Allocator, reader: *codec.Reader, _: void) codec.Error!Bitmap {
        const bytes = try reader.take_array(ENCODED_BYTES);
        var words: [WORDS]u64 = undefined;
        for (&words, 0..) |*word, index| {
            word.* = std.mem.readInt(u64, bytes[index * 8 ..][0..8], .big);
        }
        return from_words(words);
    }

    /// commonware's `Arbitrary`: 1024 arbitrary words.
    pub fn arbitrary(
        _: Allocator,
        u: *codec.arbitrary.Unstructured,
    ) codec.arbitrary.Error!Bitmap {
        var words: [WORDS]u64 = undefined;
        for (&words) |*word| word.* = u.int(u64);
        return from_words(words);
    }
};

/// Maximal runs of set bits.
pub fn count_runs(words: *const [WORDS]u64) u16 {
    var runs: u32 = 0;
    var previous: u64 = 0;
    for (words) |word| {
        runs += @popCount(word & ~((word << 1) | previous));
        previous = word >> 63;
    }
    assert(runs <= BITS / 2);
    return @intCast(runs);
}

const testing = std.testing;

fn collect(iterator: Bitmap.Iterator, out: []u16) []u16 {
    var it = iterator;
    var count: usize = 0;
    while (it.next()) |value| : (count += 1) out[count] = value;
    return out[0..count];
}

test "roaring bitmap: insert, contains, iterate, min, max" {
    var bitmap: Bitmap = .{};
    try testing.expect(bitmap.is_empty() and !bitmap.is_full());
    try testing.expect(bitmap.min() == null and bitmap.max() == null);
    for ([_]u16{ 5, 3, 7 }) |value| try testing.expect(bitmap.insert(value));
    try testing.expect(!bitmap.insert(5));
    try testing.expectEqual(@as(u32, 3), bitmap.len());
    try testing.expect(bitmap.contains(3) and !bitmap.contains(4));
    for ([_]u16{ 1000, 100, 10 }) |value| _ = bitmap.insert(value);
    var buffer: [16]u16 = undefined;
    const all = collect(bitmap.iter(), &buffer);
    try testing.expectEqualSlices(u16, &.{ 3, 5, 7, 10, 100, 1000 }, all);
    try testing.expectEqual(@as(?u16, 3), bitmap.min());
    try testing.expectEqual(@as(?u16, 1000), bitmap.max());

    var it = bitmap.iter_range(4, 101);
    try testing.expectEqual(@as(usize, 4), it.remaining());
    try testing.expectEqualSlices(u16, &.{ 5, 7, 10, 100 }, collect(it, &buffer));
    _ = it.next();
    _ = it.next();
    try testing.expectEqual(@as(usize, 2), it.remaining());
    var none = bitmap.iter_range(9, 9);
    try testing.expectEqual(@as(usize, 0), none.remaining());
    try testing.expectEqual(@as(?u16, null), none.next());
}

test "roaring bitmap: insert_range across words" {
    var bitmap: Bitmap = .{};
    try testing.expectEqual(@as(u32, 5), bitmap.insert_range(5, 10));
    var wide: Bitmap = .{};
    try testing.expectEqual(@as(u32, 70), wide.insert_range(60, 130));
    for (60..130) |value| try testing.expect(wide.contains(@intCast(value)));
    var aligned: Bitmap = .{};
    try testing.expectEqual(@as(u32, 64), aligned.insert_range(64, 128));
    try testing.expectEqual(@as(u32, 32), aligned.insert_range(96, 160));
    try testing.expectEqual(@as(u16, 1), aligned.run_count());
    var full: Bitmap = .{};
    try testing.expectEqual(@as(u32, 65535), full.insert_range(0, 65535));
    try testing.expect(full.insert(65535));
    try testing.expect(full.is_full());
    try testing.expectEqual(@as(u16, 1), full.run_count());
}

test "roaring bitmap: run count" {
    var bitmap: Bitmap = .{};
    try testing.expectEqual(@as(u16, 0), bitmap.run_count());
    _ = bitmap.insert(10);
    _ = bitmap.insert(9);
    _ = bitmap.insert(11);
    try testing.expectEqual(@as(u16, 1), bitmap.run_count());
    _ = bitmap.insert(13);
    try testing.expectEqual(@as(u16, 2), bitmap.run_count());
    _ = bitmap.insert(12);
    try testing.expectEqual(@as(u16, 1), bitmap.run_count());
    _ = bitmap.insert(63);
    _ = bitmap.insert(64);
    try testing.expectEqual(@as(u16, 2), bitmap.run_count());
    try testing.expectEqual(bitmap.run_count(), count_runs(&bitmap.words));
}

test "roaring bitmap: combine, subset, intersects, conversions" {
    var a: Bitmap = .{};
    var b: Bitmap = .{};
    for ([_]u16{ 1, 2, 3 }) |value| _ = a.insert(value);
    for ([_]u16{ 2, 3, 4 }) |value| _ = b.insert(value);
    var buffer: [8]u16 = undefined;
    const both = Bitmap.combine(&a, &b, .@"and");
    try testing.expectEqualSlices(u16, &.{ 2, 3 }, collect(both.iter(), &buffer));
    const either = Bitmap.combine(&a, &b, .@"or");
    try testing.expectEqualSlices(u16, &.{ 1, 2, 3, 4 }, collect(either.iter(), &buffer));
    const only = Bitmap.combine(&a, &b, .and_not);
    try testing.expectEqualSlices(u16, &.{1}, collect(only.iter(), &buffer));
    try testing.expect(both.is_subset(&a) and !a.is_subset(&b));
    try testing.expect(a.intersects(&b) and !only.intersects(&b));

    var array = try Array.init(testing.allocator, &.{ 5, 10, 15 });
    defer array.deinit(testing.allocator);
    const from_array = Bitmap.from_array(&array);
    try testing.expectEqual(@as(u32, 3), from_array.len());
    try testing.expect(from_array.contains(10));
    const from_runs = Bitmap.from_runs(&.{ .{ 0, 3 }, .{ 100, 200 } });
    try testing.expectEqual(@as(u32, 105), from_runs.len());
    try testing.expectEqual(@as(u16, 2), from_runs.run_count());
}

test "roaring bitmap: codec" {
    var bitmap: Bitmap = .{};
    _ = bitmap.insert(0);
    _ = bitmap.insert(65535);
    try testing.expectEqual(@as(usize, ENCODED_BYTES), codec.encode_size(Bitmap, bitmap));
    const encoded = try codec.encode(Bitmap, testing.allocator, bitmap);
    defer testing.allocator.free(encoded);
    try testing.expectEqual(@as(u8, 1), encoded[7]);
    try testing.expectEqual(@as(u8, 0x80), encoded[ENCODED_BYTES - 8]);
    const decoded = try codec.decode(Bitmap, testing.allocator, encoded);
    try testing.expectEqual(bitmap.words, decoded.words);
    try testing.expectEqual(@as(u16, 2), decoded.run_count());
    const short = codec.decode(Bitmap, testing.allocator, encoded[1..]);
    try testing.expectError(error.EndOfBuffer, short);
}

test "roaring bitmap: iterator remaining stays 0 after exhaustion" {
    // commonware `test_iterator_size_hint_after_exhaustion_regression`.
    var bitmap: Bitmap = .{};
    _ = bitmap.insert(5);
    _ = bitmap.insert(100);
    var it = bitmap.iter();
    try testing.expectEqual(@as(usize, 2), it.remaining());
    try testing.expectEqual(@as(?u16, 5), it.next());
    try testing.expectEqual(@as(usize, 1), it.remaining());
    try testing.expectEqual(@as(?u16, 100), it.next());
    try testing.expectEqual(@as(usize, 0), it.remaining());
    try testing.expectEqual(@as(?u16, null), it.next());
    try testing.expectEqual(@as(usize, 0), it.remaining());
    const empty: Bitmap = .{};
    var none = empty.iter();
    try testing.expectEqual(@as(usize, 0), none.remaining());
    try testing.expectEqual(@as(?u16, null), none.next());
    try testing.expectEqual(@as(usize, 0), none.remaining());
}

test "roaring bitmap: encode size is independent of cardinality" {
    // commonware `test_encode_size_independent_of_cardinality`.
    var full: Bitmap = .{};
    try testing.expectEqual(@as(u32, 65535), full.insert_range(0, 65535));
    try testing.expect(full.insert(65535));
    try testing.expect(full.is_full());
    try testing.expectEqual(codec.encode_size(Bitmap, .{}), codec.encode_size(Bitmap, full));
}

test "roaring bitmap: run_count on duplicates, at the boundaries, and from words" {
    // commonware `test_run_count_idempotent_on_duplicate`, `test_run_count_at_boundaries`,
    // and `test_from_words_run_count_matches_scan`.
    var duplicate: Bitmap = .{};
    _ = duplicate.insert(42);
    try testing.expect(!duplicate.insert(42));
    try testing.expectEqual(@as(u16, 1), duplicate.run_count());

    var edges: Bitmap = .{};
    const steps = [_]struct { u16, u16 }{ .{ 0, 1 }, .{ 65535, 2 }, .{ 65534, 2 }, .{ 1, 2 } };
    for (steps) |step| {
        _ = edges.insert(step[0]);
        try testing.expectEqual(step[1], edges.run_count());
    }
    try testing.expectEqual(count_runs(&edges.words), edges.run_count());

    var words: [WORDS]u64 = @splat(0);
    words[0] = 0xAAAA_AAAA_AAAA_AAAA;
    const alternating = Bitmap.from_words(words);
    try testing.expectEqual(@as(u16, 32), alternating.run_count());
    try testing.expectEqual(count_runs(&alternating.words), alternating.run_count());
}
