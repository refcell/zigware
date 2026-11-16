//! The indexer's CLI against commonware's `indexer` binary (`testdata/indexer_clap_cases.txt`,
//! printed by it for the same arguments), and the checks its `main` makes afterwards.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const zigware = @import("zigware");
const ui = @import("ui");
const indexer = @import("indexer.zig");
const bridge_test = @import("bridge_test.zig");

fn run_cli(gpa: std.mem.Allocator, args: []const []const u8, out: *Io.Writer) !u8 {
    _ = gpa;
    return switch (try indexer.parse(args, "indexer", out, out)) {
        .exit => |status| status,
        .run => unreachable, // Proof: every recorded case exits in clap.
    };
}

test "bridge: the indexer's CLI prints clap's help and errors" {
    const cases = @embedFile("testdata/indexer_clap_cases.txt");
    try bridge_test.expect_clap_cases(cases, 8, run_cli);
}

fn setup(args: []const []const u8, panic: *ui.rust.Panic) !indexer.Setup {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var sink: Io.Writer.Discarding = .init(&.{});
    const values = switch (try indexer.parse(args, "indexer", &sink.writer, &sink.writer)) {
        .run => |values| values,
        .exit => return error.TestUnexpectedResult,
    };
    var configured = try indexer.setup(arena.allocator(), values, .none, panic);
    configured.validators = &.{}; // Freed with the arena.
    configured.networks = &.{};
    return configured;
}

test "bridge: the indexer checks its arguments as commonware's main does" {
    var panic: ui.rust.Panic = .{};
    const valid = [_][]const u8{ "--me", "0@3000", "--participants", "1,2", "--networks", "ab" };
    const configured = try setup(&valid, &panic);
    try testing.expectEqual(@as(u16, 3000), configured.port);
    const cases = [_]struct { []const u8, []const u8 }{
        .{ "0", "Identity not well-formed" },
        .{ "0@1@2", "Identity not well-formed" },
        .{ "x@3000", "Key not well-formed: ParseIntError { kind: InvalidDigit }" },
        .{ "0@70000", "Port not well-formed: ParseIntError { kind: PosOverflow }" },
    };
    for (cases) |case| {
        const args = [_][]const u8{ "--me", case[0], "--participants", "1", "--networks", "ab" };
        try testing.expectError(error.Panic, setup(&args, &panic));
        try testing.expectEqualStrings(case[1], panic.message());
    }
    const duplicate = [_][]const u8{ "--me", "0@1", "--participants", "1,1", "--networks", "ab" };
    try testing.expectError(error.Panic, setup(&duplicate, &panic));
    try testing.expectEqualStrings("public keys are unique: DuplicateKey", panic.message());
}

test "bridge: the indexer decodes networks as commonware does" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var panic: ui.rust.Panic = .{};
    const dealt = @embedFile("testdata/dealer_seed_1.txt");
    const start = std.mem.indexOf(u8, dealt, "public: ").? + "public: ".len;
    const public = dealt[start..][0..192];
    const publics = try indexer.decode_networks(arena.allocator(), &.{public}, &panic);
    var hex: [192]u8 = undefined;
    const bytes = zigware.codec.encode_fixed(@TypeOf(publics[0]), publics[0]);
    _ = try std.fmt.bufPrint(&hex, "{x}", .{&bytes});
    try testing.expectEqualStrings(public, &hex);
    // commonware's panics: not hex, then hex that is too short for a public key.
    const decode = indexer.decode_networks;
    try testing.expectError(error.Panic, decode(arena.allocator(), &.{"zz"}, &panic));
    try testing.expectEqualStrings("Network not well-formed", panic.message());
    try testing.expectError(error.Panic, decode(arena.allocator(), &.{"ab"}, &panic));
    try testing.expectEqualStrings("Network not well-formed: EndOfBuffer", panic.message());
}
