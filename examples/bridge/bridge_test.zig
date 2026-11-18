//! Bridge tests: the dealer's output and CLI against commonware's `dealer` binary
//! (`testdata/dealer_*.txt`, printed by it for the same arguments). commonware's README
//! shows an older polynomial encoding, without the 6-byte header the binary now writes.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const ui = @import("ui");
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

fn run_dealer(gpa: std.mem.Allocator, args: []const []const u8, out: *Io.Writer) !u8 {
    return dealer.run(gpa, args, "dealer", out, out);
}

test "the dealer's CLI prints clap's help and errors" {
    try expect_clap_cases(@embedFile("testdata/dealer_clap_cases.txt"), 13, run_dealer);
}

/// The clap-case harness, shared with the other examples in `ui.clap`.
pub const expect_clap_cases = ui.clap.expect_cases;
