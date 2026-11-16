//! Bridge tests: the dealer's output and CLI against commonware's `dealer` binary
//! (`testdata/dealer_*.txt`, printed by it for the same arguments). commonware's README
//! shows an older polynomial encoding, without the 6-byte header the binary now writes.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const dealer = @import("dealer.zig");

fn expect_dealing(seed: u64, participants: []const u64, expected: []const u8) !void {
    var out: Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try dealer.deal(testing.allocator, &out.writer, seed, participants);
    try testing.expectEqualStrings(expected, out.written());
}

test "the dealer prints commonware's dealing for the same seed" {
    try expect_dealing(1, &.{ 1, 2, 3, 4 }, @embedFile("testdata/dealer_seed_1.txt"));
    try expect_dealing(2, &.{ 5, 6, 7, 8 }, @embedFile("testdata/dealer_seed_2.txt"));
    // A repeated participant gets two shares, in the stable order of equal keys.
    const repeated = @embedFile("testdata/dealer_seed_7_repeated.txt");
    try expect_dealing(7, &.{ 3, 3, 1 }, repeated);
}

test "the dealer's CLI prints clap's help and errors" {
    const cases = @embedFile("testdata/dealer_clap_cases.txt");
    const gpa = testing.allocator;
    var records = std.mem.splitSequence(u8, cases[4..], "\n### ");
    var count: usize = 0;
    while (records.next()) |record| : (count += 1) {
        const args_end = std.mem.indexOfScalar(u8, record, '\n').?;
        var args: std.ArrayList([]const u8) = .empty;
        defer args.deinit(gpa);
        var words = std.mem.tokenizeScalar(u8, record[0..args_end], ' ');
        while (words.next()) |word| try args.append(gpa, word);
        const rest = record[args_end + 1 ..];
        const exit_end = std.mem.indexOfScalar(u8, rest, '\n').?;
        const expected_exit = try std.fmt.parseInt(u8, rest["exit=".len..exit_end], 10);
        const expected = std.mem.trimEnd(u8, rest[exit_end + 1 ..], "\n");
        var out: Io.Writer.Allocating = .init(gpa);
        defer out.deinit();
        errdefer std.debug.print("case: {s}\n", .{record[0..args_end]});
        const exit = try dealer.run(gpa, args.items, "dealer", &out.writer, &out.writer);
        try testing.expectEqual(expected_exit, exit);
        try testing.expectEqualStrings(expected, std.mem.trimEnd(u8, out.written(), "\n"));
    }
    try testing.expectEqual(@as(usize, 13), count);
}
