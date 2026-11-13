//! Tests for the `.lazy` DSL: commonware lib.rs's parser and validation tests, the example
//! task files, and a seeded plus coverage-guided fuzz of the parser.

const std = @import("std");
const testing = std.testing;
const zigware = @import("zigware");
const build_options = @import("build_options");
const dsl = @import("dsl.zig");

const Duration = zigware.utils.Duration;

fn parse(content: []const u8) !dsl.Task {
    var diagnostic: dsl.Diagnostic = .{};
    return dsl.parse_task(testing.allocator, content, &diagnostic) catch |err| {
        std.debug.print("unexpected parse failure: {s}\n", .{diagnostic.message()});
        return err;
    };
}

/// Expects parsing to fail with a message containing `expected` (Rust `should_panic`).
fn expect_parse_failure(content: []const u8, expected: []const u8) !void {
    var diagnostic: dsl.Diagnostic = .{};
    var task = dsl.parse_task(testing.allocator, content, &diagnostic) catch |err| {
        try testing.expectEqual(error.InvalidTask, err);
        if (std.mem.indexOf(u8, diagnostic.message(), expected) == null) {
            std.debug.print("message {s} lacks {s}\n", .{ diagnostic.message(), expected });
            return error.TestUnexpectedMessage;
        }
        return;
    };
    task.deinit(testing.allocator);
    return error.TestExpectedFailure;
}

/// The postfix form of a command, one token per item: `wait1 wait2 && wait3 ||`.
fn render(command: dsl.Command, buffer: []u8) ![]const u8 {
    var writer: std.Io.Writer = .fixed(buffer);
    for (command.items, 0..) |item, index| {
        if (index > 0) try writer.writeByte(' ');
        switch (item) {
            .leaf => |leaf| try writer.print("{t}{d}", .{ leaf, dsl.leaf_id(leaf) }),
            .@"and" => try writer.writeAll("&&"),
            .@"or" => try writer.writeAll("||"),
        }
    }
    return writer.buffered();
}

fn expect_shape(content: []const u8, expected: []const u8) !void {
    var task = try parse(content);
    defer task.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), task.commands.len);
    var buffer: [256]u8 = undefined;
    try testing.expectEqualStrings(expected, try render(task.commands[0], &buffer));
}

fn gate_of(item: dsl.Item) dsl.Gate {
    return item.leaf.gate().?;
}

test "parse_task commands" {
    var task = try parse(
        \\
        \\# This is a comment with new syntax
        \\propose{1}
        \\broadcast{2}
        \\reply{3}
        \\
    );
    defer task.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 3), task.commands.len);
    try testing.expectEqual(@as(u32, 1), task.commands[0].single().?.propose.id);
    try testing.expectEqual(@as(u32, 2), task.commands[1].single().?.broadcast.id);
    try testing.expectEqual(@as(u32, 3), task.commands[2].single().?.reply.id);
}

test "parse_task collect command" {
    var task = try parse("collect{1, threshold=75%}");
    defer task.deinit(testing.allocator);
    const collect = task.commands[0].single().?.collect;
    try testing.expectEqual(@as(u32, 1), collect.id);
    try testing.expectEqual(@as(f64, 0.75), collect.threshold.percent);
    try testing.expectEqual(@as(?dsl.Delay, null), collect.delay);
}

test "parse_task wait with delay" {
    var task = try parse("wait{2, threshold=5, delay=(0.5,1.0)}");
    defer task.deinit(testing.allocator);
    const wait = task.commands[0].single().?.wait;
    try testing.expectEqual(@as(u32, 2), wait.id);
    try testing.expectEqual(@as(u64, 5), wait.threshold.count);
    try testing.expectEqual(Duration.from_micros(500), wait.delay.?.message);
    try testing.expectEqual(Duration.from_millis(1), wait.delay.?.completion);
}

test "parse_task empty lines and comments" {
    var task = try parse(
        \\
        \\# Comment line
        \\
        \\# Another comment
        \\propose{1}
        \\
        \\# Final comment
        \\
    );
    defer task.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), task.commands.len);
    try testing.expectEqual(@as(u32, 5), task.commands[0].line);
}

test "parse_task failures carry commonware's panic messages" {
    try expect_parse_failure("propose invalid_arg_format", "Missing opening brace");
    try expect_parse_failure("propose threshold=50%", "Missing opening brace");
    try expect_parse_failure("unknown_command{1}", "Unknown command");
    try expect_parse_failure("propose{}", "Missing arguments in curly braces");
    try expect_parse_failure("wait{1}", "Missing threshold for wait");
    try expect_parse_failure(
        "(wait{1, threshold=1} && wait{2, threshold=1}",
        "Expected ')' but reached end of input",
    );
    try expect_parse_failure(
        "wait{1, threshold=1} && wait{2, threshold=1})",
        "Unexpected character ')' at position",
    );
    // Beyond lib.rs: the remaining messages, checked against the commonware binary.
    try expect_parse_failure("propose{x}", "Invalid id: ParseIntError { kind: InvalidDigit }");
    try expect_parse_failure(
        "propose{1, size}",
        "Invalid argument format (expected key=value): size",
    );
    try expect_parse_failure("propose{1, size=-1}", "Invalid size: ParseIntError");
    try expect_parse_failure("wait{1, threshold=x%}", "Invalid percent: ParseFloatError");
    try expect_parse_failure("wait{1, threshold=}", "Invalid count: ParseIntError { kind: Empty }");
    try expect_parse_failure(
        "wait{1, threshold=1, delay=(1,2,3)}",
        "Invalid delay format (expected (value1,value2)): 1,2,3",
    );
    try expect_parse_failure("wait{1, threshold=1, delay=(1, 2)}", "Invalid completion delay");
    try expect_parse_failure("wait{1, threshold=1, delay=(-1,2)}", "value is negative");
    try expect_parse_failure("propose}{", "begin <= end");
    try expect_parse_failure("(wait{1, threshold=1}) &&", "Missing opening brace");
    // Without a spaced operator or parentheses the line is one instruction; the tail is ignored.
    var tail = try parse("wait{1, threshold=1} &&");
    tail.deinit(testing.allocator);
}

test "parse_task or command" {
    const content = "wait{1, threshold=67%, delay=(0.1,1)} || wait{2, threshold=1, delay=(0.1,1)}";
    var task = try parse(content);
    defer task.deinit(testing.allocator);
    const items = task.commands[0].items;
    try testing.expectEqual(@as(usize, 3), items.len);
    try testing.expect(items[2] == .@"or");
    try testing.expectEqual(@as(u32, 1), gate_of(items[0]).id);
    try testing.expectEqual(@as(f64, 0.67), gate_of(items[0]).threshold.percent);
    try testing.expect(gate_of(items[0]).delay != null);
    try testing.expectEqual(@as(u32, 2), gate_of(items[1]).id);
    try testing.expectEqual(@as(u64, 1), gate_of(items[1]).threshold.count);
    try testing.expect(gate_of(items[1]).delay != null);
}

test "parse_task and command" {
    var task = try parse("wait{3, threshold=67%} && wait{4, threshold=1}");
    defer task.deinit(testing.allocator);
    const items = task.commands[0].items;
    try testing.expectEqual(@as(usize, 3), items.len);
    try testing.expect(items[2] == .@"and");
    try testing.expectEqual(@as(u32, 3), gate_of(items[0]).id);
    try testing.expectEqual(@as(f64, 0.67), gate_of(items[0]).threshold.percent);
    try testing.expectEqual(@as(?dsl.Delay, null), gate_of(items[0]).delay);
    try testing.expectEqual(@as(u32, 4), gate_of(items[1]).id);
    try testing.expectEqual(@as(u64, 1), gate_of(items[1]).threshold.count);
}

test "parse_task expression shapes" {
    // Chained ORs are left-associative: Or(Or(1, 2), 3).
    try expect_shape(
        "wait{1, threshold=67%} || wait{2, threshold=1} || wait{3, threshold=50%}",
        "wait1 wait2 || wait3 ||",
    );
    try expect_shape(
        "(wait{1, threshold=67%} && wait{2, threshold=1}) || wait{3, threshold=50%}",
        "wait1 wait2 && wait3 ||",
    );
    try expect_shape(
        "((wait{1, threshold=1} || wait{2, threshold=1}) && wait{3, threshold=1}) || " ++
            "wait{4, threshold=1}",
        "wait1 wait2 || wait3 && wait4 ||",
    );
    try expect_shape(
        "(wait{1, threshold=1} && wait{2, threshold=1}) || " ++
            "(wait{3, threshold=1} && wait{4, threshold=1})",
        "wait1 wait2 && wait3 wait4 && ||",
    );
    // AND binds tighter than OR without parentheses.
    try expect_shape(
        "wait{1, threshold=1} || wait{2, threshold=1} && wait{3, threshold=1}",
        "wait1 wait2 wait3 && ||",
    );
    try expect_shape(
        "(wait{1, threshold=1} || wait{2, threshold=1}) && wait{3, threshold=1}",
        "wait1 wait2 || wait3 &&",
    );
    try expect_shape(
        "(propose{1} && broadcast{2}) || reply{3}",
        "propose1 broadcast2 && reply3 ||",
    );
}

test "parse_task commands with message sizes" {
    var task = try parse(
        \\
        \\propose{1, size=1024}
        \\broadcast{2, size=100}
        \\reply{3, size=64}
        \\reply{4}
        \\
    );
    defer task.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 4), task.commands.len);
    const expected = [_]dsl.Send{
        .{ .id = 1, .size = 1024 }, .{ .id = 2, .size = 100 },
        .{ .id = 3, .size = 64 },   .{ .id = 4, .size = null },
    };
    try testing.expectEqual(expected[0], task.commands[0].single().?.propose);
    try testing.expectEqual(expected[1], task.commands[1].single().?.broadcast);
    try testing.expectEqual(expected[2], task.commands[2].single().?.reply);
    try testing.expectEqual(expected[3], task.commands[3].single().?.reply);
}

fn expect_validate(content: []const u8, expected: bool) !void {
    var task = try parse(content);
    defer task.deinit(testing.allocator);
    try testing.expectEqual(expected, try dsl.validate(testing.allocator, &task, 3, 0));
}

test "validate or/and logic" {
    // Waits for id=0 (one message) AND id=99 (never sent), so the AND cannot be satisfied.
    try expect_validate(
        \\## Propose a block
        \\propose{0}
        \\wait{0, threshold=1} && wait{99, threshold=1}
        \\broadcast{1}
    , false);
    try expect_validate(
        \\propose{0}
        \\broadcast{6}
        \\wait{0, threshold=1} && (wait{99, threshold=1} || wait{6, threshold=2})
        \\broadcast{1}
    , true);
}

test "example files" {
    const files = [_]struct { []const u8, []const u8, bool }{
        .{ "stall.lazy", @embedFile("stall.lazy"), false },
        .{ "echo.lazy", @embedFile("echo.lazy"), true },
        .{ "simplex.lazy", @embedFile("simplex.lazy"), true },
        .{ "simplex_with_delay.lazy", @embedFile("simplex_with_delay.lazy"), true },
        .{ "simplex_with_certificates.lazy", @embedFile("simplex_with_certificates.lazy"), true },
        .{ "simplex_small_block.lazy", @embedFile("simplex_small_block.lazy"), true },
        .{ "simplex_large_block.lazy", @embedFile("simplex_large_block.lazy"), true },
        .{
            "simplex_large_block_coding_50.lazy",
            @embedFile("simplex_large_block_coding_50.lazy"),
            true,
        },
        .{ "minimmit.lazy", @embedFile("minimmit.lazy"), true },
        .{ "minimmit_small_block.lazy", @embedFile("minimmit_small_block.lazy"), true },
        .{ "minimmit_large_block.lazy", @embedFile("minimmit_large_block.lazy"), true },
        .{
            "minimmit_large_block_coding_50.lazy",
            @embedFile("minimmit_large_block_coding_50.lazy"),
            true,
        },
        .{ "kudzu_small_block.lazy", @embedFile("kudzu_small_block.lazy"), true },
        .{ "kudzu_large_block.lazy", @embedFile("kudzu_large_block.lazy"), true },
        .{
            "kudzu_large_block_coding_50.lazy",
            @embedFile("kudzu_large_block_coding_50.lazy"),
            true,
        },
        .{ "hotstuff.lazy", @embedFile("hotstuff.lazy"), true },
    };
    for (files) |file| {
        var task = try parse(file[1]);
        defer task.deinit(testing.allocator);
        const completed = try dsl.validate(testing.allocator, &task, 3, 0);
        if (completed != file[2]) std.debug.print("{s}\n", .{file[0]});
        try testing.expectEqual(file[2], completed);
    }
}

/// Characters the DSL gives meaning to, so random inputs reach deep into the parser.
const alphabet = "{}(),=%|&# \t\n.-+0123456789propsebadcltwihz";

/// Parses `input`, and when it parses, checks the postfix form is well formed and validates.
fn fuzz_one(input: []const u8) !void {
    var diagnostic: dsl.Diagnostic = .{};
    var task = dsl.parse_task(testing.allocator, input, &diagnostic) catch |err| {
        try testing.expectEqual(error.InvalidTask, err);
        try testing.expect(diagnostic.message().len > 0);
        return;
    };
    defer task.deinit(testing.allocator);
    for (task.commands) |command| {
        var depth: usize = 0;
        for (command.items) |item| switch (item) {
            .leaf => depth += 1,
            .@"and", .@"or" => {
                try testing.expect(depth >= 2);
                depth -= 1;
            },
        };
        try testing.expectEqual(@as(usize, 1), depth);
    }
    _ = try dsl.validate(testing.allocator, &task, 3, 1);
}

test "fuzz parse_task (seeded)" {
    var rng = zigware.utils.TestRng.init(0x1a2b ^ build_options.fuzz_seed);
    const iterations: u64 = 2000 * @as(u64, build_options.fuzz_soak);
    var input: [96]u8 = undefined;
    for (0..iterations) |_| {
        const len = zigware.utils.rng.range_at_most(&rng, usize, 0, input.len);
        for (input[0..len]) |*byte| {
            byte.* = alphabet[zigware.utils.rng.range_less_than(&rng, usize, 0, alphabet.len)];
        }
        try fuzz_one(input[0..len]);
    }
}

test "fuzz parse_task" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var bytes: [4096]u8 = undefined;
            const length = smith.slice(&bytes);
            try fuzz_one(bytes[0..length]);
        }
    }.run, .{});
}
