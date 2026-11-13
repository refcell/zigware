//! Tests of `types.zig`, ported from commonware's `consensus/src/types.rs` tests, and the
//! `CodecConformance` hashes of `Epoch`, `Height`, `View`, and `Round` from commonware's
//! `consensus/conformance.toml` (copied unchanged).

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const conformance = @import("conformance");
const utils = @import("utils");
const types = @import("types.zig");

const Epoch = types.Epoch;
const Height = types.Height;
const View = types.View;
const Round = types.Round;
const EpochDelta = types.EpochDelta;
const HeightDelta = types.HeightDelta;
const ViewDelta = types.ViewDelta;
const TermLength = types.TermLength;
const FixedEpocher = types.FixedEpocher;

fn term(length: u32) TermLength {
    return .new(utils.NonZero(u32).init(length).?);
}

fn epocher(length: u64) FixedEpocher {
    return .new(utils.NonZero(u64).init(length).?);
}

fn expect_format(expected: []const u8, value: anytype) !void {
    var buffer: [64]u8 = undefined;
    try testing.expectEqualStrings(expected, try std.fmt.bufPrint(&buffer, "{f}", .{value}));
}

fn expect_roundtrip(comptime T: type, value: T) !void {
    const encoded = try codec.encode(T, testing.allocator, value);
    defer testing.allocator.free(encoded);
    try testing.expectEqual(codec.encode_size(T, value), encoded.len);
    try testing.expectEqual(value, try codec.decode(T, testing.allocator, encoded));
}

test "counter constructors, is_zero, next, previous" {
    inline for (.{ Epoch, Height, View }) |T| {
        try testing.expectEqual(0, T.zero().get());
        try testing.expectEqual(42, T.new(42).get());
        try testing.expect(T.zero().is_zero() and T.new(0).is_zero());
        try testing.expect(!T.new(1).is_zero() and !T.new(100).is_zero());
        try testing.expectEqual(T.new(1), T.zero().next());
        try testing.expectEqual(T.new(6), T.new(5).next());
        try testing.expectEqual(T.new(1000), T.new(999).next());
        try testing.expectEqual(null, T.zero().previous());
        try testing.expectEqual(T.zero(), T.new(1).previous().?);
        try testing.expectEqual(T.new(999), T.new(1000).previous().?);
    }
}

test "counter saturating and checked arithmetic" {
    const max = std.math.maxInt(u64);
    try testing.expectEqual(5, Epoch.zero().saturating_add(.new(5)).get());
    try testing.expectEqual(30, Epoch.new(10).saturating_add(.new(20)).get());
    try testing.expectEqual(max, Epoch.new(max).saturating_add(.new(1)).get());
    try testing.expectEqual(max, Epoch.new(max - 5).saturating_add(.new(10)).get());
    try testing.expectEqual(Epoch.new(5), Epoch.new(10).checked_sub(.new(5)).?);
    try testing.expectEqual(Epoch.zero(), Epoch.new(5).checked_sub(.new(5)).?);
    try testing.expectEqual(null, Epoch.new(5).checked_sub(.new(10)));
    try testing.expectEqual(null, Epoch.zero().checked_sub(.new(1)));
    try testing.expectEqual(5, Epoch.new(10).saturating_sub(.new(5)).get());
    try testing.expectEqual(0, Epoch.new(5).saturating_sub(.new(10)).get());
    try testing.expectEqual(0, Height.zero().saturating_sub(.new(100)).get());
    try testing.expectEqual(110, Height.new(10).saturating_add(.new(100)).get());
    try testing.expectEqual(max, View.new(max).saturating_add(.new(1)).get());
    try testing.expectEqual(HeightDelta.new(7), Height.new(10).delta_from(.new(3)).?);
    try testing.expectEqual(HeightDelta.zero(), Height.new(5).delta_from(.new(5)).?);
    try testing.expectEqual(null, Height.new(3).delta_from(.new(10)));
    try testing.expectEqual(null, Height.zero().delta_from(.new(1)));
}

test "counter display, ordering, and codec" {
    try expect_format("0", Epoch.zero());
    try expect_format("42", Height.new(42));
    try expect_format("1000", View.new(1000));
    try expect_format("42", ViewDelta.new(42));
    try expect_format("(5, 100)", Round.new(.new(5), .new(100)));
    try testing.expectEqual(.lt, Epoch.order(.zero(), .new(1)));
    try testing.expectEqual(.gt, View.order(.new(10), .new(5)));
    try testing.expectEqual(.eq, Height.order(.new(42), .new(42)));
    try testing.expectEqual(.lt, EpochDelta.order(.zero(), .new(1)));
    for ([_]u64{ 0, 1, 127, 128, 255, 256, std.math.maxInt(u64) }) |value| {
        try expect_roundtrip(Epoch, .new(value));
        try expect_roundtrip(Height, .new(value));
        try expect_roundtrip(View, .new(value));
    }
    // A u64 varint: 128 is two bytes.
    const encoded = [_]u8{ 0x80, 0x01 };
    try testing.expectEqual(View.new(128), try codec.decode(View, testing.allocator, &encoded));
}

test "delta constructors" {
    try testing.expectEqual(0, ViewDelta.zero().get());
    try testing.expectEqual(42, ViewDelta.new(42).get());
    try testing.expect(ViewDelta.zero().is_zero() and !ViewDelta.new(1).is_zero());
    // Deltas of different point types are different types.
    try testing.expect(EpochDelta != ViewDelta and HeightDelta != ViewDelta);
}

test "ranges iterate forward, backward, and report their length" {
    inline for (.{ Height, View }) |T| {
        var range = T.range(.new(3), .new(6));
        try testing.expectEqual(3, range.len());
        try testing.expectEqual(T.new(3), range.next().?);
        try testing.expectEqual(T.new(4), range.next().?);
        try testing.expectEqual(T.new(5), range.next().?);
        try testing.expectEqual(null, range.next());
        try testing.expectEqual(null, range.next());
        var empty = T.range(.new(5), .new(5));
        try testing.expectEqual(0, empty.len());
        try testing.expectEqual(null, empty.next());
        var reversed = T.range(.new(10), .new(5));
        try testing.expectEqual(null, reversed.next_back());
        var mixed = T.range(.new(5), .new(10));
        try testing.expectEqual(T.new(5), mixed.next().?);
        try testing.expectEqual(T.new(9), mixed.next_back().?);
        try testing.expectEqual(T.new(6), mixed.next().?);
        try testing.expectEqual(T.new(8), mixed.next_back().?);
        try testing.expectEqual(1, mixed.len());
        try testing.expectEqual(T.new(7), mixed.next().?);
        try testing.expectEqual(null, mixed.next());
        try testing.expectEqual(null, mixed.next_back());
    }
}

test "view term_start, term_end, next_term_start, term_index" {
    const starts = [_][3]u64{
        .{ 0, 5, 0 }, .{ 1, 1, 1 }, .{ 5, 1, 5 },  .{ 6, 1, 6 },   .{ 7, 1, 7 },   .{ 1, 5, 1 },
        .{ 5, 5, 1 }, .{ 6, 5, 6 }, .{ 10, 5, 6 }, .{ 11, 5, 11 }, .{ 12, 3, 10 },
    };
    for (starts) |c| {
        try testing.expectEqual(c[2], View.new(c[0]).term_start(term(@intCast(c[1]))).get());
    }
    const ends = [_][3]u64{
        .{ 0, 5, 0 },  .{ 1, 1, 1 },   .{ 5, 1, 5 },   .{ 1, 5, 5 },   .{ 5, 5, 5 },
        .{ 6, 5, 10 }, .{ 10, 5, 10 }, .{ 11, 5, 15 }, .{ 12, 3, 12 },
    };
    for (ends) |c| {
        try testing.expectEqual(c[2], View.new(c[0]).term_end(term(@intCast(c[1]))).get());
    }
    const nexts = [_][3]u64{
        .{ 0, 1, 1 },  .{ 5, 1, 6 },   .{ 1, 5, 6 },   .{ 5, 5, 6 },
        .{ 6, 5, 11 }, .{ 10, 5, 11 }, .{ 11, 5, 16 }, .{ 12, 3, 13 },
    };
    for (nexts) |c| {
        try testing.expectEqual(c[2], View.new(c[0]).next_term_start(term(@intCast(c[1]))).get());
    }
    const indices = [_][3]u64{
        .{ 0, 1, 0 }, .{ 1, 1, 1 }, .{ 5, 1, 5 },  .{ 0, 5, 0 },  .{ 1, 5, 1 },
        .{ 5, 5, 1 }, .{ 6, 5, 2 }, .{ 10, 5, 2 }, .{ 11, 5, 3 },
    };
    for (indices) |c| {
        try testing.expectEqual(c[2], View.new(c[0]).term_index(term(@intCast(c[1]))));
    }
}

const ViewCase = struct { a: u64, b: u64, length: u32, expected: bool };

test "view is_term_start and same_term" {
    const starts = [_]ViewCase{
        .{ .a = 0, .b = 0, .length = 1, .expected = true },
        .{ .a = 1, .b = 0, .length = 1, .expected = true },
        .{ .a = 5, .b = 0, .length = 1, .expected = true },
        .{ .a = 1, .b = 0, .length = 5, .expected = true },
        .{ .a = 5, .b = 0, .length = 5, .expected = false },
        .{ .a = 6, .b = 0, .length = 5, .expected = true },
        .{ .a = 10, .b = 0, .length = 5, .expected = false },
        .{ .a = 11, .b = 0, .length = 5, .expected = true },
    };
    for (starts) |c| {
        try testing.expectEqual(c.expected, View.new(c.a).is_term_start(term(c.length)));
    }
    const same = [_]ViewCase{
        .{ .a = 0, .b = 0, .length = 1, .expected = true },
        .{ .a = 0, .b = 0, .length = 5, .expected = true },
        .{ .a = 0, .b = 1, .length = 5, .expected = false },
        .{ .a = 0, .b = 5, .length = 5, .expected = false },
        .{ .a = 1, .b = 1, .length = 1, .expected = true },
        .{ .a = 1, .b = 2, .length = 5, .expected = true },
        .{ .a = 1, .b = 5, .length = 5, .expected = true },
        .{ .a = 5, .b = 6, .length = 5, .expected = false },
        .{ .a = 6, .b = 10, .length = 5, .expected = true },
        .{ .a = 10, .b = 11, .length = 5, .expected = false },
        .{ .a = 11, .b = 15, .length = 5, .expected = true },
    };
    for (same) |c| {
        try testing.expectEqual(c.expected, View.new(c.a).same_term(.new(c.b), term(c.length)));
    }
}

test "view covers and covering_range" {
    const cases = [_]ViewCase{
        .{ .a = 0, .b = 0, .length = 5, .expected = true },
        .{ .a = 0, .b = 3, .length = 5, .expected = false },
        .{ .a = 1, .b = 0, .length = 5, .expected = false },
        .{ .a = 1, .b = 1, .length = 1, .expected = true },
        .{ .a = 1, .b = 2, .length = 1, .expected = false },
        .{ .a = 2, .b = 1, .length = 1, .expected = false },
        .{ .a = 6, .b = 6, .length = 5, .expected = true },
        .{ .a = 6, .b = 8, .length = 5, .expected = true },
        .{ .a = 6, .b = 10, .length = 5, .expected = true },
        .{ .a = 6, .b = 11, .length = 5, .expected = false },
        .{ .a = 8, .b = 6, .length = 5, .expected = false },
        .{ .a = 6, .b = 5, .length = 5, .expected = false },
    };
    for (cases) |c| {
        try testing.expectEqual(c.expected, View.new(c.a).covers(.new(c.b), term(c.length)));
    }
    // Every view in the covering range covers the view, and the view before it does not.
    const start, const end = View.new(8).covering_range(term(5));
    try testing.expectEqual(View.new(6), start);
    try testing.expectEqual(View.new(8), end);
    for (6..9) |v| try testing.expect(View.new(v).covers(.new(8), term(5)));
    try testing.expect(!View.new(5).covers(.new(8), term(5)));
}

test "view admits" {
    const cases = [_]ViewCase{
        .{ .a = 0, .b = 0, .length = 5, .expected = true },
        .{ .a = 0, .b = 1, .length = 5, .expected = true },
        .{ .a = 0, .b = 2, .length = 5, .expected = false },
        .{ .a = 0, .b = 5, .length = 5, .expected = false },
        .{ .a = 5, .b = 4, .length = 1, .expected = true },
        .{ .a = 5, .b = 5, .length = 1, .expected = true },
        .{ .a = 5, .b = 6, .length = 1, .expected = true },
        .{ .a = 5, .b = 7, .length = 1, .expected = false },
        .{ .a = 6, .b = 7, .length = 5, .expected = true },
        .{ .a = 6, .b = 11, .length = 5, .expected = true },
        .{ .a = 6, .b = 8, .length = 5, .expected = false },
        .{ .a = 6, .b = 12, .length = 5, .expected = false },
        .{ .a = 10, .b = 11, .length = 5, .expected = true },
        .{ .a = 10, .b = 12, .length = 5, .expected = false },
    };
    for (cases) |c| {
        try testing.expectEqual(c.expected, View.new(c.a).admits(.new(c.b), term(c.length)));
    }
    // Near u64 max the next term start overflows: only lower views and the successor.
    const max = std.math.maxInt(u64);
    const current = View.new(max - 2);
    try testing.expect(current.admits(.zero(), term(5)));
    try testing.expect(current.admits(.new(max - 1), term(5)));
    try testing.expect(!current.admits(.new(max), term(5)));
}

test "term length bounds" {
    try testing.expectEqual(1, TermLength.one.get());
    try testing.expectEqual(std.math.maxInt(u32), TermLength.max.get());
    // The largest term still has a representable end for realistic views.
    try testing.expectEqual(std.math.maxInt(u32), View.new(1).term_end(.max).get());
}

test "round order, codec, and fields" {
    const a = Round.new(.new(1), .new(2));
    try testing.expectEqual(.lt, Round.order(a, .new(.new(1), .new(3))));
    try testing.expectEqual(.lt, Round.order(a, .new(.new(2), .new(1))));
    try testing.expectEqual(.gt, Round.order(.new(.new(2), .zero()), a));
    try testing.expect(a == Round.new(.new(1), .new(2)));
    try testing.expectEqual(Round.new(.zero(), .zero()), Round.zero());
    try expect_roundtrip(Round, .new(.new(42), .new(1_000_000)));
    try testing.expectEqual(Epoch.new(10), Round.new(.new(10), .new(20)).epoch);
    try testing.expectEqual(View.new(20), Round.new(.new(10), .new(20)).view);
}

test "fixed epocher bounds" {
    const fixed = epocher(100);
    const zero = fixed.containing(.zero()).?;
    try testing.expectEqual(Epoch.zero(), zero.epoch);
    try testing.expectEqual(Height.zero(), zero.first);
    try testing.expectEqual(Height.new(99), zero.last);
    try testing.expectEqual(HeightDelta.new(100), zero.length());
    try testing.expectEqual(Epoch.zero(), fixed.containing(.new(99)).?.epoch);
    const one = fixed.containing(.new(100)).?;
    try testing.expectEqual(Epoch.new(1), one.epoch);
    try testing.expectEqual(Height.new(100), one.first);
    try testing.expectEqual(Height.new(199), one.last);
    try testing.expectEqual(Height.new(500), fixed.first(.new(5)).?);
    try testing.expectEqual(Height.new(599), fixed.last(.new(5)).?);
    try testing.expectEqual(Height.new(550), fixed.midpoint(.new(5)).?);
    const relative = [_][2]u64{
        .{ 0, 0 },    .{ 50, 50 }, .{ 99, 99 },  .{ 100, 0 },  .{ 150, 50 },
        .{ 199, 99 }, .{ 500, 0 }, .{ 567, 67 }, .{ 599, 99 },
    };
    for (relative) |c| {
        try testing.expectEqual(c[1], fixed.containing(.new(c[0])).?.relative().get());
    }
}

test "fixed epocher phases" {
    const Case = struct { length: u64, height: u64, phase: types.EpochPhase };
    const cases = [_]Case{
        .{ .length = 30, .height = 0, .phase = .early },
        .{ .length = 30, .height = 14, .phase = .early },
        .{ .length = 30, .height = 15, .phase = .midpoint },
        .{ .length = 30, .height = 16, .phase = .late },
        .{ .length = 30, .height = 29, .phase = .late },
        .{ .length = 30, .height = 30, .phase = .early },
        .{ .length = 30, .height = 44, .phase = .early },
        .{ .length = 30, .height = 45, .phase = .midpoint },
        .{ .length = 30, .height = 46, .phase = .late },
        .{ .length = 10, .height = 4, .phase = .early },
        .{ .length = 10, .height = 5, .phase = .midpoint },
        .{ .length = 10, .height = 6, .phase = .late },
        .{ .length = 10, .height = 9, .phase = .late },
        .{ .length = 11, .height = 4, .phase = .early },
        .{ .length = 11, .height = 5, .phase = .midpoint },
        .{ .length = 11, .height = 6, .phase = .late },
        .{ .length = 11, .height = 10, .phase = .late },
    };
    for (cases) |c| {
        try testing.expectEqual(c.phase, epocher(c.length).containing(.new(c.height)).?.phase());
    }
}

test "fixed epocher overflow" {
    const max = std.math.maxInt(u64);
    const fixed = epocher(100);
    const last_valid_first = Height.new(18446744073709551500);
    const last_valid_last = Height.new(18446744073709551599);
    const info = fixed.containing(last_valid_first).?;
    try testing.expectEqual(last_valid_first, info.first);
    try testing.expectEqual(last_valid_last, info.last);
    try testing.expectEqual(last_valid_last, fixed.containing(last_valid_last).?.last);
    try testing.expectEqual(null, fixed.containing(last_valid_last.next()));
    try testing.expectEqual(null, fixed.containing(.new(max)));
    // Length 2: the final epoch ends exactly at u64 max.
    try testing.expectEqual(Height.new(max), epocher(2).containing(.new(max - 1)).?.last);
    try testing.expectEqual(Height.new(max), epocher(2).containing(.new(max)).?.last);
    try testing.expectEqual(null, epocher(max).containing(.new(max)));
    // first, last, and containing agree on the last valid epoch and the first invalid one.
    const last_valid_epoch = Epoch.new(184467440737095515);
    const first = fixed.first(last_valid_epoch).?;
    try testing.expectEqual(fixed.last(last_valid_epoch).?, fixed.containing(first).?.last);
    try testing.expectEqual(null, fixed.first(.new(184467440737095516)));
    try testing.expectEqual(null, fixed.last(.new(184467440737095516)));
}

// Conformance.

const conformance_file = @embedFile("conformance.toml");

fn CodecConformance(comptime T: type) type {
    return struct {
        pub fn commit(gpa: std.mem.Allocator, seed: u64) ![]u8 {
            var arena = std.heap.ArenaAllocator.init(gpa);
            defer arena.deinit();
            const gen = codec.arbitrary.default_generator(T);
            const value = try codec.arbitrary.generate(T, gen, arena.allocator(), seed);
            return codec.encode(T, gpa, value);
        }
    };
}

test "consensus types conformance hashes match commonware" {
    const prefix = "commonware_consensus::types::tests::conformance::CodecConformance<";
    const entries = .{
        .{ "Epoch", Epoch }, .{ "Height", Height }, .{ "View", View }, .{ "Round", Round },
    };
    inline for (entries) |entry| {
        try conformance.verify(
            CodecConformance(entry[1]),
            std.heap.smp_allocator,
            prefix ++ entry[0] ++ ">",
            conformance.default_cases,
            conformance_file,
        );
    }
}
