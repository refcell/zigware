//! The activity bitmap and floor-walk candidates (qmdb/bitmap.rs).
//!
//! A keyed database tracks which log locations hold active operations in a prunable bitmap.
//! The floor walk reads candidates from it with `fill_from`: the active locations at or past
//! the scan position, followed by every location past the bitmap's end (operations the
//! bitmap does not cover yet are treated as active), up to the tip.
//!
//! commonware wraps the bitmap in a `RwLock` (`Shared`) because `current` shares it with
//! readers on other threads; zigware databases are single-owner, so the bitmap is a plain
//! `utils.bitmap.Prunable(N)`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const utils = @import("utils");

/// The activity bitmap of a database with `N`-byte chunks.
pub fn Shared(comptime N: usize) type {
    return utils.bitmap.Prunable(N);
}

/// Appends to `out` up to `limit - out.len` candidate locations in `[scan_from, tip)`: the set
/// bits of `bitmap` below `min(len, tip)`, then each location from the bitmap's end up to
/// `tip`. Returns the position the next fill resumes from. `bitmap` provides `len()` and
/// `ones_iter_range(start, end)`.
pub fn fill_from(
    gpa: Allocator,
    bitmap: anytype,
    scan_from: u64,
    tip: u64,
    limit: usize,
    out: *std.ArrayList(u64),
) Allocator.Error!u64 {
    const bitmap_len = bitmap.len();
    const committed_end = @min(bitmap_len, tip);
    const count_before = out.items.len;
    var scan = scan_from;
    if (scan < committed_end) {
        var ones = bitmap.ones_iter_range(scan, committed_end);
        while (out.items.len < limit) {
            const index = ones.next() orelse break;
            assert(index >= scan and index < committed_end);
            try out.append(gpa, index);
            scan = index + 1;
        }
    }
    while (out.items.len < limit) {
        const candidate = @max(scan, bitmap_len);
        if (candidate >= tip) {
            scan = @max(scan, committed_end);
            break;
        }
        try out.append(gpa, candidate);
        scan = candidate + 1;
    }
    assert(out.items.len >= count_before);
    return scan;
}

const testing = std.testing;
const chunk_bytes = 4;
const chunk_bits: u64 = chunk_bytes * 8;
const Bits = Shared(chunk_bytes);

/// The next floor candidate in `[floor, tip)`, one at a time (commonware's oracle).
fn next_candidate(bitmap: *const Bits, floor: u64, tip: u64) ?u64 {
    const bitmap_len = bitmap.len();
    const committed_end = @min(bitmap_len, tip);
    if (floor < committed_end) {
        var ones = bitmap.ones_iter_range(floor, committed_end);
        if (ones.next()) |index| return index;
    }
    const candidate = @max(floor, bitmap_len);
    return if (candidate < tip) candidate else null;
}

fn shape(gpa: Allocator, kind: u8) !Bits {
    var bits: Bits = .empty;
    errdefer bits.deinit(gpa);
    switch (kind) {
        0 => {},
        1 => {
            try bits.extend_to(gpa, 10);
            bits.set_bit(3, true);
            bits.set_bit(7, true);
        },
        2 => {
            try bits.extend_to(gpa, 5);
            bits.set_bit(2, true);
        },
        3 => {
            try bits.extend_to(gpa, chunk_bits * 3);
            bits.set_bit(chunk_bits * 2 + 5, true);
            bits.prune_to_bit(chunk_bits * 2);
        },
        4 => {
            try bits.extend_to(gpa, chunk_bits * 2);
            bits.set_bit(chunk_bits + 3, true);
            bits.truncate(chunk_bits);
        },
        else => unreachable, // Proof: the test passes kinds 0 through 4.
    }
    return bits;
}

test "fill candidates matches the oracle" {
    const gpa = testing.allocator;
    for (0..5) |kind| {
        var bits = try shape(gpa, @intCast(kind));
        defer bits.deinit(gpa);
        const bitmap_len = bits.len();
        const start = bits.pruned_bits();
        for ([_]u64{ start, bitmap_len -| 2, bitmap_len, bitmap_len + 6 }) |tip| {
            var expected: std.ArrayList(u64) = .empty;
            defer expected.deinit(gpa);
            var floor = start;
            while (next_candidate(&bits, floor, tip)) |candidate| {
                try expected.append(gpa, candidate);
                floor = candidate + 1;
            }
            for (1..@max(expected.items.len, 1) + 2) |limit| {
                var actual: std.ArrayList(u64) = .empty;
                defer actual.deinit(gpa);
                var scan = start;
                while (true) {
                    var batch: std.ArrayList(u64) = .empty;
                    defer batch.deinit(gpa);
                    scan = try fill_from(gpa, &bits, scan, tip, limit, &batch);
                    if (batch.items.len == 0) break;
                    try testing.expect(batch.items.len <= limit);
                    try actual.appendSlice(gpa, batch.items);
                }
                try testing.expectEqualSlices(u64, expected.items, actual.items);
            }
        }
    }
}

test "fill stops at an empty bitmap's tip" {
    const gpa = testing.allocator;
    var bits: Bits = .empty;
    defer bits.deinit(gpa);
    try bits.extend_to(gpa, chunk_bits);
    var out: std.ArrayList(u64) = .empty;
    defer out.deinit(gpa);
    // No set bits and the tip at the bitmap's end: nothing to walk, and the scan moves to it.
    try testing.expectEqual(chunk_bits, try fill_from(gpa, &bits, 0, chunk_bits, 4, &out));
    try testing.expectEqual(@as(usize, 0), out.items.len);
}
