//! The flood binary's CLI against commonware's `flood` binary
//! (`testdata/flood_clap_cases.txt`, printed by it for the same arguments).

const std = @import("std");
const Io = std.Io;
const ui = @import("ui");
const main = @import("main.zig");

fn run_cli(gpa: std.mem.Allocator, args: []const []const u8, out: *Io.Writer) !u8 {
    _ = gpa;
    return switch (try main.parse(args, "flood", out, out)) {
        .exit => |status| status,
        .run => unreachable, // Proof: every recorded case exits in clap.
    };
}

test "flood: the CLI prints clap's help and errors" {
    const cases = @embedFile("testdata/flood_clap_cases.txt");
    try ui.clap.expect_cases(cases, 12, run_cli);
}
