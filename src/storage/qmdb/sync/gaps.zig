//! Gap detection for sync (commonware's `qmdb/sync/gaps.rs`).

const std = @import("std");
const assert = std.debug.assert;
const merkle = @import("../../merkle/mod.zig");

pub const Range = merkle.Range;

fn is_empty(range: Range) bool {
    return range.start >= range.end;
}

/// The next range of operations to fetch in `range`, or null if `fetched` and `outstanding`
/// cover it. Both lists are sorted by start. Empty ranges are ignored, and the result is
/// bounded by `range`. Outstanding ranges describe maximum responses: a source may return
/// fewer operations, and a later call fetches the rest.
pub fn find_next(range: Range, fetched: []const Range, outstanding: []const Range) ?Range {
    if (is_empty(range)) return null;
    var next_uncovered = range.start;
    var fetched_at: usize = 0;
    var outstanding_at: usize = 0;
    // Merge both sorted lists; each step consumes one range, so the loop is bounded.
    while (fetched_at < fetched.len or outstanding_at < outstanding.len) {
        const take_fetched = outstanding_at == outstanding.len or
            (fetched_at < fetched.len and
                fetched[fetched_at].start <= outstanding[outstanding_at].start);
        const covered = if (take_fetched) fetched[fetched_at] else outstanding[outstanding_at];
        if (take_fetched) fetched_at += 1 else outstanding_at += 1;
        // Empty ranges cover no operations, so they must not split a gap.
        if (is_empty(covered)) continue;
        if (next_uncovered < covered.start) {
            const gap: Range = .{
                .start = next_uncovered,
                .end = @min(covered.start, range.end),
            };
            assert(!is_empty(gap));
            return gap;
        }
        next_uncovered = @max(next_uncovered, covered.end);
        if (next_uncovered >= range.end) return null;
    }
    if (next_uncovered >= range.end) return null;
    const gap: Range = .{ .start = next_uncovered, .end = range.end };
    assert(gap.start >= range.start);
    return gap;
}

const Case = struct {
    lower: u64,
    upper: u64,
    /// (start, count) of each fetched batch.
    fetched: []const [2]u64,
    /// Start of each outstanding request, each of `fetch_batch_size` operations.
    requested: []const u64,
    fetch_batch_size: u64,
    expected: ?Range,
};

const cases = [_]Case{
    .{
        .lower = 0,
        .upper = 11,
        .fetched = &.{},
        .requested = &.{},
        .fetch_batch_size = 5,
        .expected = .{ .start = 0, .end = 11 },
    },
    .{
        .lower = 10,
        .upper = 6,
        .fetched = &.{},
        .requested = &.{},
        .fetch_batch_size = 5,
        .expected = null,
    },
    .{
        .lower = 5,
        .upper = 6,
        .fetched = &.{},
        .requested = &.{},
        .fetch_batch_size = 5,
        .expected = .{ .start = 5, .end = 6 },
    },
    .{
        .lower = 0,
        .upper = 11,
        .fetched = &.{},
        .requested = &.{ 0, 3, 8 },
        .fetch_batch_size = 5,
        .expected = null,
    },
    .{
        .lower = 0,
        .upper = 11,
        .fetched = &.{},
        .requested = &.{8},
        .fetch_batch_size = 5,
        .expected = .{ .start = 0, .end = 8 },
    },
    .{
        .lower = 0,
        .upper = 11,
        .fetched = &.{},
        .requested = &.{ 0, 7 },
        .fetch_batch_size = 4,
        .expected = .{ .start = 4, .end = 7 },
    },
    .{
        .lower = 0,
        .upper = 5,
        .fetched = &.{.{ 7, 2 }},
        .requested = &.{},
        .fetch_batch_size = 2,
        .expected = .{ .start = 0, .end = 5 },
    },
    .{
        .lower = 0,
        .upper = 5,
        .fetched = &.{},
        .requested = &.{7},
        .fetch_batch_size = 2,
        .expected = .{ .start = 0, .end = 5 },
    },
    .{
        .lower = 0,
        .upper = 5,
        .fetched = &.{ .{ 2, 0 }, .{ 4, 1 } },
        .requested = &.{},
        .fetch_batch_size = 2,
        .expected = .{ .start = 0, .end = 4 },
    },
    .{
        .lower = 0,
        .upper = 5,
        .fetched = &.{.{ 4, 1 }},
        .requested = &.{2},
        .fetch_batch_size = 0,
        .expected = .{ .start = 0, .end = 4 },
    },
    .{
        .lower = 0,
        .upper = 11,
        .fetched = &.{ .{ 0, 1 }, .{ 2, 1 }, .{ 4, 1 } },
        .requested = &.{},
        .fetch_batch_size = 5,
        .expected = .{ .start = 1, .end = 2 },
    },
    .{
        .lower = 0,
        .upper = 11,
        .fetched = &.{.{ 0, 3 }},
        .requested = &.{},
        .fetch_batch_size = 5,
        .expected = .{ .start = 3, .end = 11 },
    },
    .{
        .lower = 0,
        .upper = 11,
        .fetched = &.{ .{ 0, 1 }, .{ 1, 1 } },
        .requested = &.{},
        .fetch_batch_size = 5,
        .expected = .{ .start = 2, .end = 11 },
    },
    .{
        .lower = 0,
        .upper = 11,
        .fetched = &.{
            .{ 0, 1 }, .{ 1, 1 }, .{ 2, 1 }, .{ 3, 1 }, .{ 4, 1 },  .{ 5, 1 },
            .{ 6, 1 }, .{ 7, 1 }, .{ 8, 1 }, .{ 9, 1 }, .{ 10, 1 },
        },
        .requested = &.{},
        .fetch_batch_size = 5,
        .expected = null,
    },
    .{
        .lower = 0,
        .upper = 11,
        .fetched = &.{},
        .requested = &.{ 2, 5, 8 },
        .fetch_batch_size = 1,
        .expected = .{ .start = 0, .end = 2 },
    },
    .{
        .lower = 5,
        .upper = 11,
        .fetched = &.{.{ 0, 8 }},
        .requested = &.{},
        .fetch_batch_size = 5,
        .expected = .{ .start = 8, .end = 11 },
    },
    .{
        .lower = 0,
        .upper = 7,
        .fetched = &.{.{ 4, 5 }},
        .requested = &.{},
        .fetch_batch_size = 5,
        .expected = .{ .start = 0, .end = 4 },
    },
    .{
        .lower = 0,
        .upper = 6,
        .fetched = &.{},
        .requested = &.{2},
        .fetch_batch_size = 100,
        .expected = .{ .start = 0, .end = 2 },
    },
    .{
        .lower = 0,
        .upper = 11,
        .fetched = &.{ .{ 0, 5 }, .{ 8, 3 } },
        .requested = &.{},
        .fetch_batch_size = 5,
        .expected = .{ .start = 5, .end = 8 },
    },
    .{
        .lower = 0,
        .upper = 16,
        .fetched = &.{ .{ 2, 3 }, .{ 10, 2 } },
        .requested = &.{ 6, 13 },
        .fetch_batch_size = 3,
        .expected = .{ .start = 0, .end = 2 },
    },
    .{
        .lower = 0,
        .upper = 16,
        .fetched = &.{ .{ 0, 2 }, .{ 8, 2 } },
        .requested = &.{ 3, 12 },
        .fetch_batch_size = 4,
        .expected = .{ .start = 2, .end = 3 },
    },
    .{
        .lower = 0,
        .upper = 11,
        .fetched = &.{ .{ 1, 2 }, .{ 6, 2 } },
        .requested = &.{ 3, 8 },
        .fetch_batch_size = 2,
        .expected = .{ .start = 0, .end = 1 },
    },
};

test "find_next matches commonware's cases" {
    for (cases, 0..) |case, i| {
        var fetched: [16]Range = undefined;
        var outstanding: [16]Range = undefined;
        for (case.fetched, 0..) |batch, j| {
            fetched[j] = .{ .start = batch[0], .end = batch[0] + batch[1] };
        }
        for (case.requested, 0..) |start, j| {
            outstanding[j] = .{ .start = start, .end = start + case.fetch_batch_size };
        }
        const result = find_next(
            .{ .start = case.lower, .end = case.upper },
            fetched[0..case.fetched.len],
            outstanding[0..case.requested.len],
        );
        std.testing.expectEqual(case.expected, result) catch |err| {
            std.debug.print("case {d}\n", .{i});
            return err;
        };
    }
}
