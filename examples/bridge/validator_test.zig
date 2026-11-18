//! The validator's CLI against commonware's `validator` binary
//! (`testdata/validator_clap_cases.txt`, printed by it for the same arguments), and the
//! panics its `main` raises for malformed arguments, as that binary prints them.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const ui = @import("ui");
const validator = @import("validator.zig");
const bridge_test = @import("bridge_test.zig");

fn run_cli(gpa: std.mem.Allocator, args: []const []const u8, out: *Io.Writer) !u8 {
    _ = gpa;
    return switch (try validator.parse(args, "validator", out, out)) {
        .exit => |status| status,
        .run => unreachable, // Proof: every recorded case exits in clap.
    };
}

test "bridge: the validator's CLI prints clap's help and errors" {
    const cases = @embedFile("testdata/validator_clap_cases.txt");
    try bridge_test.expect_clap_cases(cases, 5, run_cli);
}

fn field(comptime file: []const u8, comptime prefix: []const u8) []const u8 {
    const text = @embedFile("testdata/" ++ file);
    const start = std.mem.indexOf(u8, text, prefix).? + prefix.len;
    const end = std.mem.indexOfScalarPos(u8, text, start, '\n').?;
    return text[start..end];
}

const polynomial = field("dealer_seed_1.txt", "polynomial: ");
const share = field("dealer_seed_1.txt", "validator=1): ");
const other = field("dealer_seed_2.txt", "public: ");

/// Runs setup on a valid command line with one argument replaced; returns the panic.
fn expect_panic(name: []const u8, value: []const u8, expected: []const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var args = [_][]const u8{
        "--me",           "1@3001",      "--participants", "1,2,3,4",
        "--storage-dir",  "/tmp/unused", "--indexer",      "0@127.0.0.1:3000",
        "--identity",     polynomial,    "--share",        share,
        "--other-public", other,
    };
    var index: usize = 0;
    while (!std.mem.eql(u8, args[index], name)) index += 2;
    args[index + 1] = value;
    var sink: Io.Writer.Discarding = .init(&.{});
    const values = switch (try validator.parse(&args, "validator", &sink.writer, &sink.writer)) {
        .run => |values| values,
        .exit => return error.TestUnexpectedResult,
    };
    var panic: ui.rust.Panic = .{};
    const result = validator.setup(arena.allocator(), values, .none, &panic);
    if (expected.len == 0) {
        _ = try result;
        return;
    }
    try testing.expectError(error.Panic, result);
    try testing.expectEqualStrings(expected, panic.message());
}

test "bridge: the validator panics as commonware's main does" {
    try expect_panic("--me", "1@3001", "");
    try expect_panic("--identity", "zz", "Identity not well-formed");
    try expect_panic("--identity", "ab", "Identity not well-formed: InvalidEnum(171)");
    try expect_panic("--share", "ab", "Share not well-formed: EndOfBuffer");
    try expect_panic(
        "--indexer",
        "0x@1",
        "Indexer key not well-formed: ParseIntError { kind: InvalidDigit }",
    );
    try expect_panic("--indexer", "0", "index out of bounds: the len is 1 but the index is 1");
    try expect_panic(
        "--indexer",
        "0@nope",
        "Indexer address not well-formed: AddrParseError(Socket)",
    );
    try expect_panic("--other-public", "ab", "Other identity not well-formed: EndOfBuffer");
    try expect_panic(
        "--participants",
        "1,2,3",
        "Identity not well-formed: Invalid(\"Sharing\", \"total not in range\")",
    );
}
