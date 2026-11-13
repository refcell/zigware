//! The `.lazy` task DSL (commonware `examples/estimator/src/lib.rs`): parsing a task file into
//! commands, deciding whether a command can advance, and `validate`, the message-free dry run.
//!
//! Each non-empty, non-comment line is one command: a single instruction
//! (`propose{0, size=1024}`, `wait{1, threshold=67%, delay=(0.1,1)}`) or an expression of them
//! joined with `&&` and `||` and grouped with parentheses (`&&` binds tighter). A command is
//! stored in postfix order: leaves left to right with each operator after its operands, so
//! `(a && b) || c` is `a b && c ||`. Evaluating the postfix form with a stack visits leaves in
//! the order commonware's recursive evaluation does, without recursion.
//!
//! Errors match commonware's panics: a parse failure returns `error.InvalidTask` and leaves
//! commonware's panic message in the `Diagnostic`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const zigware = @import("zigware");
const rust = @import("rust.zig");

const Duration = zigware.utils.Duration;

const milliseconds_per_second: f64 = 1000.0;

/// Longest task file the estimator reads.
pub const task_size_max: usize = 1 << 20;

pub const Threshold = union(enum) {
    count: u64,
    /// A fraction of the peers in `[0, 1]` for sensible inputs (`67%` is `0.67`).
    percent: f64,
};

/// `delay=(message,completion)` in milliseconds: `message` is slept before every check and
/// `completion` once after the threshold is met.
pub const Delay = struct { message: Duration, completion: Duration };

/// `propose`, `broadcast`, `reply`: a message id and an optional size in bytes.
pub const Send = struct { id: u32, size: ?u64 };

/// `collect`, `wait`: a message id, how many distinct senders to wait for, and a delay.
pub const Gate = struct { id: u32, threshold: Threshold, delay: ?Delay };

pub const Leaf = union(enum) {
    propose: Send,
    broadcast: Send,
    reply: Send,
    collect: Gate,
    wait: Gate,

    pub fn gate(leaf: Leaf) ?Gate {
        return switch (leaf) {
            .collect, .wait => |g| g,
            else => null,
        };
    }
};

pub const Item = union(enum) {
    leaf: Leaf,
    @"and",
    @"or",
};

/// One line of the task: its 1-based line number and its postfix items.
pub const Command = struct {
    line: u32,
    items: []const Item,

    /// The lone instruction of a command without operators.
    pub fn single(command: Command) ?Leaf {
        if (command.items.len != 1) return null;
        return command.items[0].leaf;
    }
};

pub const Task = struct {
    commands: []Command,
    items: []Item,
    /// Every message id named by a leaf, ascending and distinct.
    ids: []u32,
    /// The most leaves in one command, which bounds an evaluation stack.
    leaves_max: usize,

    pub fn deinit(task: *Task, gpa: Allocator) void {
        gpa.free(task.commands);
        gpa.free(task.items);
        gpa.free(task.ids);
        task.* = undefined;
    }
};

/// The message of a parse failure (commonware's panic message), truncated to its buffer.
pub const Diagnostic = struct {
    buffer: [512]u8 = undefined,
    len: usize = 0,

    pub fn message(diagnostic: *const Diagnostic) []const u8 {
        return diagnostic.buffer[0..diagnostic.len];
    }

    pub fn fail(
        diagnostic: *Diagnostic,
        comptime format: []const u8,
        args: anytype,
    ) error{InvalidTask} {
        var writer: std.Io.Writer = .fixed(&diagnostic.buffer);
        writer.print(format, args) catch {}; // Truncated: the buffer is full.
        diagnostic.len = writer.end;
        assert(diagnostic.len <= diagnostic.buffer.len);
        return error.InvalidTask;
    }
};

pub const ParseError = error{ InvalidTask, OutOfMemory };

/// Rust's `{:?}` of a `ParseIntError`.
pub fn int_error_name(err: rust.ParseIntError) []const u8 {
    return switch (err) {
        error.Empty => "ParseIntError { kind: Empty }",
        error.InvalidDigit => "ParseIntError { kind: InvalidDigit }",
        error.PosOverflow => "ParseIntError { kind: PosOverflow }",
    };
}

/// Rust's `{:?}` of a `ParseFloatError`.
pub fn float_error_name(err: rust.ParseFloatError) []const u8 {
    return switch (err) {
        error.Empty => "ParseFloatError { kind: Empty }",
        error.Invalid => "ParseFloatError { kind: Invalid }",
    };
}

const Range = struct { line: u32, start: usize, end: usize };

/// Parses a task file into commands (commonware `parse_task`).
pub fn parse_task(gpa: Allocator, content: []const u8, diagnostic: *Diagnostic) ParseError!Task {
    var items: std.ArrayList(Item) = .empty;
    defer items.deinit(gpa);
    var ranges: std.ArrayList(Range) = .empty;
    defer ranges.deinit(gpa);
    var lines: rust.Lines = .{ .text = content };
    var line_number: u32 = 0;
    while (lines.next()) |raw| {
        line_number += 1;
        const line = rust.trim(raw);
        if (line.len == 0 or line[0] == '#') continue;
        const start = items.items.len;
        const compound = std.mem.indexOf(u8, line, " || ") != null or
            std.mem.indexOf(u8, line, " && ") != null or
            std.mem.indexOfAny(u8, line, "()") != null;
        if (compound) {
            try parse_expression(gpa, line, &items, diagnostic);
        } else {
            try items.append(gpa, .{ .leaf = try parse_single_command(line, diagnostic) });
        }
        assert(items.items.len > start);
        try ranges.append(gpa, .{ .line = line_number, .start = start, .end = items.items.len });
    }
    return build_task(gpa, items.items, ranges.items);
}

fn build_task(gpa: Allocator, items: []const Item, ranges: []const Range) Allocator.Error!Task {
    const owned_items = try gpa.dupe(Item, items);
    errdefer gpa.free(owned_items);
    const commands = try gpa.alloc(Command, ranges.len);
    errdefer gpa.free(commands);
    var leaves_max: usize = 0;
    for (ranges, commands) |range, *command| {
        command.* = .{ .line = range.line, .items = owned_items[range.start..range.end] };
        var leaves: usize = 0;
        for (command.items) |item| leaves += @intFromBool(item == .leaf);
        leaves_max = @max(leaves_max, leaves);
    }
    var ids: std.ArrayList(u32) = .empty;
    errdefer ids.deinit(gpa);
    for (owned_items) |item| {
        const leaf = switch (item) {
            .leaf => |leaf| leaf,
            else => continue,
        };
        const id = leaf_id(leaf);
        const slot = std.sort.lowerBound(u32, ids.items, id, order_u32);
        if (slot < ids.items.len and ids.items[slot] == id) continue;
        try ids.insert(gpa, slot, id);
    }
    return .{
        .commands = commands,
        .items = owned_items,
        .ids = try ids.toOwnedSlice(gpa),
        .leaves_max = leaves_max,
    };
}

fn order_u32(key: u32, item: u32) std.math.Order {
    return std.math.order(key, item);
}

pub fn leaf_id(leaf: Leaf) u32 {
    return switch (leaf) {
        .propose, .broadcast, .reply => |send| send.id,
        .collect, .wait => |gate| gate.id,
    };
}

/// Splits the text between braces at commas outside parentheses and quotes, yielding each
/// non-empty trimmed argument.
const Arguments = struct {
    text: []const u8,
    index: usize = 0,

    fn next(arguments: *Arguments) ?[]const u8 {
        while (arguments.index < arguments.text.len) {
            const start = arguments.index;
            var depth: i64 = 0;
            var in_quotes = false;
            while (arguments.index < arguments.text.len) : (arguments.index += 1) {
                switch (arguments.text[arguments.index]) {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    '"' => in_quotes = !in_quotes,
                    ',' => if (depth == 0 and !in_quotes) break,
                    else => {},
                }
            }
            const argument = rust.trim(arguments.text[start..arguments.index]);
            if (arguments.index < arguments.text.len) arguments.index += 1; // The comma.
            if (argument.len > 0) return argument;
        }
        return null;
    }
};

const Values = struct {
    size: ?[]const u8 = null,
    threshold: ?[]const u8 = null,
    delay: ?[]const u8 = null,
};

/// Parses one instruction such as `wait{1, threshold=67%}` (commonware `parse_single_command`).
pub fn parse_single_command(line: []const u8, diagnostic: *Diagnostic) error{InvalidTask}!Leaf {
    const brace_start = std.mem.indexOfScalar(u8, line, '{') orelse
        return diagnostic.fail("Missing opening brace", .{});
    const brace_end = std.mem.lastIndexOfScalar(u8, line, '}') orelse
        return diagnostic.fail("Missing closing brace", .{});
    if (brace_end < brace_start + 1) {
        return diagnostic.fail("begin <= end ({d} <= {d}) when slicing `{s}`", .{
            brace_start + 1, brace_end, line,
        });
    }
    const name = rust.trim(line[0..brace_start]);
    var arguments: Arguments = .{ .text = line[brace_start + 1 .. brace_end] };
    const first = arguments.next() orelse
        return diagnostic.fail("Missing arguments in curly braces", .{});
    const id = rust.parse_unsigned(u32, first) catch |err|
        return diagnostic.fail("Invalid id: {s}", .{int_error_name(err)});
    var values: Values = .{};
    while (arguments.next()) |argument| {
        const equals = std.mem.indexOfScalar(u8, argument, '=') orelse {
            const format = "Invalid argument format (expected key=value): {s}";
            return diagnostic.fail(format, .{argument});
        };
        const key = rust.trim(argument[0..equals]);
        const value = rust.trim(argument[equals + 1 ..]);
        if (std.mem.eql(u8, key, "size")) values.size = value;
        if (std.mem.eql(u8, key, "threshold")) values.threshold = value;
        if (std.mem.eql(u8, key, "delay")) values.delay = value;
    }
    inline for (.{ "propose", "broadcast", "reply" }) |entry| {
        if (std.mem.eql(u8, name, entry)) {
            const send: Send = .{ .id = id, .size = try parse_size(values.size, diagnostic) };
            return @unionInit(Leaf, entry, send);
        }
    }
    const is_collect = std.mem.eql(u8, name, "collect");
    if (!is_collect and !std.mem.eql(u8, name, "wait")) {
        return diagnostic.fail("Unknown command: {s}", .{name});
    }
    const threshold_text = values.threshold orelse
        return diagnostic.fail("Missing threshold for {s}", .{name});
    const gate: Gate = .{
        .id = id,
        .threshold = try parse_threshold(threshold_text, diagnostic),
        .delay = if (values.delay) |text| try parse_delay(text, diagnostic) else null,
    };
    return if (is_collect) .{ .collect = gate } else .{ .wait = gate };
}

fn parse_size(text: ?[]const u8, diagnostic: *Diagnostic) error{InvalidTask}!?u64 {
    const value = text orelse return null;
    return rust.parse_unsigned(u64, value) catch |err|
        diagnostic.fail("Invalid size: {s}", .{int_error_name(err)});
}

fn parse_threshold(text: []const u8, diagnostic: *Diagnostic) error{InvalidTask}!Threshold {
    if (text.len > 0 and text[text.len - 1] == '%') {
        const number = std.mem.trimEnd(u8, text, "%");
        const percent = rust.parse_f64(number) catch |err|
            return diagnostic.fail("Invalid percent: {s}", .{float_error_name(err)});
        return .{ .percent = percent / 100.0 };
    }
    const count = rust.parse_unsigned(u64, text) catch |err|
        return diagnostic.fail("Invalid count: {s}", .{int_error_name(err)});
    return .{ .count = count };
}

fn parse_delay(text: []const u8, diagnostic: *Diagnostic) error{InvalidTask}!Delay {
    const inner = std.mem.trim(u8, std.mem.trim(u8, text, "("), ")");
    const comma = std.mem.indexOfScalar(u8, inner, ',');
    const valid = comma != null and std.mem.indexOfScalarPos(u8, inner, comma.? + 1, ',') == null;
    if (!valid) {
        return diagnostic.fail("Invalid delay format (expected (value1,value2)): {s}", .{inner});
    }
    const message = try parse_milliseconds(inner[0..comma.?], "message", diagnostic);
    const completion = try parse_milliseconds(inner[comma.? + 1 ..], "completion", diagnostic);
    return .{ .message = message, .completion = completion };
}

fn parse_milliseconds(
    text: []const u8,
    comptime what: []const u8,
    diagnostic: *Diagnostic,
) error{InvalidTask}!Duration {
    const milliseconds = rust.parse_f64(text) catch |err|
        return diagnostic.fail("Invalid " ++ what ++ " delay: {s}", .{float_error_name(err)});
    const prefix = "cannot convert float seconds to Duration: ";
    return rust.duration_from_secs_f64(milliseconds / milliseconds_per_second) catch |err|
        switch (err) {
            error.Negative => diagnostic.fail(prefix ++ "value is negative", .{}),
            error.OverflowOrNan => diagnostic.fail(prefix ++ "value is either too big or NaN", .{}),
        };
}

const Operator = enum { @"and", @"or", paren };

/// Parses a line with operators or parentheses into postfix items appended to `out`, with the
/// precedence, associativity, and error messages of commonware's recursive-descent
/// `ExpressionParser`, but iteratively (an explicit operator stack, shunting-yard style).
fn parse_expression(
    gpa: Allocator,
    line: []const u8,
    out: *std.ArrayList(Item),
    diagnostic: *Diagnostic,
) ParseError!void {
    var operators: std.ArrayList(Operator) = .empty;
    defer operators.deinit(gpa);
    var position: usize = 0;
    var depth: usize = 0;
    // Each pass handles one primary: open parentheses, an instruction, then what follows.
    for (0..line.len + 1) |_| {
        position = skip_whitespace(line, position);
        while (position < line.len and line[position] == '(') {
            try operators.append(gpa, .paren);
            depth += 1;
            position = skip_whitespace(line, position + 1);
        }
        const atomic = extract_atomic_command(line, &position);
        try out.append(gpa, .{ .leaf = try parse_single_command(atomic, diagnostic) });
        // Close groups until an operator follows.
        while (true) {
            if (peek_operator(line, position)) |operator| {
                try push_operator(gpa, &operators, out, operator);
                position = skip_whitespace(line, skip_whitespace(line, position) + 2);
                break;
            }
            position = skip_whitespace(line, position);
            if (depth == 0) {
                if (position < line.len) {
                    return diagnostic.fail("Unexpected character '{c}' at position {d}", .{
                        line[position], position,
                    });
                }
                while (operators.pop()) |operator| try out.append(gpa, operator_item(operator));
                return;
            }
            if (position == line.len) {
                return diagnostic.fail("Expected ')' but reached end of input", .{});
            }
            if (line[position] != ')') {
                return diagnostic.fail("Expected ')' but found '{c}' at position {d}", .{
                    line[position], position,
                });
            }
            position = skip_whitespace(line, position + 1);
            while (operators.pop()) |operator| {
                if (operator == .paren) break;
                try out.append(gpa, operator_item(operator));
            }
            depth -= 1;
        }
    }
    unreachable; // Every pass consumes an operator, and a line holds at most len/2 of them.
}

fn operator_item(operator: Operator) Item {
    return switch (operator) {
        .@"and" => .@"and",
        .@"or" => .@"or",
        .paren => unreachable, // Parentheses are popped by the `)` that closes them.
    };
}

/// Pushes a left-associative operator, first emitting stacked operators that bind at least as
/// tightly (`&&` over `&&`; anything over `||`).
fn push_operator(
    gpa: Allocator,
    operators: *std.ArrayList(Operator),
    out: *std.ArrayList(Item),
    operator: Operator,
) Allocator.Error!void {
    assert(operator != .paren);
    while (operators.items.len > 0) {
        const top = operators.items[operators.items.len - 1];
        if (top == .paren) break;
        if (operator == .@"and" and top == .@"or") break;
        _ = operators.pop();
        try out.append(gpa, operator_item(top));
    }
    try operators.append(gpa, operator);
}

fn skip_whitespace(line: []const u8, position: usize) usize {
    var index = position;
    while (index < line.len and rust.is_whitespace(line[index])) index += 1;
    assert(index >= position);
    return index;
}

fn peek_operator(line: []const u8, position: usize) ?Operator {
    const rest = line[skip_whitespace(line, position)..];
    if (std.mem.startsWith(u8, rest, "||")) return .@"or";
    if (std.mem.startsWith(u8, rest, "&&")) return .@"and";
    return null;
}

/// The text of one instruction: up to a top-level ` || `, ` && `, or an unmatched `)`.
fn extract_atomic_command(line: []const u8, position: *usize) []const u8 {
    const start = position.*;
    var depth: i64 = 0;
    while (position.* < line.len) : (position.* += 1) {
        const rest = line[position.*..];
        switch (rest[0]) {
            '(' => depth += 1,
            ')' => {
                if (depth == 0) break;
                depth -= 1;
            },
            else => if (depth == 0 and (std.mem.startsWith(u8, rest, " || ") or
                std.mem.startsWith(u8, rest, " && "))) break,
        }
    }
    assert(position.* >= start);
    return rust.trim(line[start..position.*]);
}

/// Distinct senders seen per message id, for each id named in the task.
pub const Received = struct {
    ids: []const u32,
    peers: usize,
    seen: std.DynamicBitSetUnmanaged,
    counts: []u64,

    pub fn init(gpa: Allocator, ids: []const u32, peers: usize) Allocator.Error!Received {
        assert(peers > 0);
        const seen = try std.DynamicBitSetUnmanaged.initEmpty(gpa, ids.len * peers);
        errdefer {
            var bits = seen;
            bits.deinit(gpa);
        }
        const counts = try gpa.alloc(u64, ids.len);
        @memset(counts, 0);
        return .{ .ids = ids, .peers = peers, .seen = seen, .counts = counts };
    }

    pub fn deinit(received: *Received, gpa: Allocator) void {
        received.seen.deinit(gpa);
        gpa.free(received.counts);
        received.* = undefined;
    }

    fn slot(received: *const Received, id: u32) ?usize {
        return std.sort.binarySearch(u32, received.ids, id, order_u32);
    }

    /// Records that `peer` sent `id`; a repeat from the same peer counts once.
    pub fn insert(received: *Received, id: u32, peer: usize) void {
        assert(peer < received.peers);
        const index = received.slot(id).?; // Only ids from the task are ever sent.
        const bit = index * received.peers + peer;
        if (received.seen.isSet(bit)) return;
        received.seen.set(bit);
        received.counts[index] += 1;
        assert(received.counts[index] <= received.peers);
    }

    pub fn count(received: *const Received, id: u32) u64 {
        const index = received.slot(id) orelse return 0;
        return received.counts[index];
    }
};

/// Required count for a threshold among `peers` (commonware `calculate_threshold`).
pub fn calculate_threshold(threshold: Threshold, peers: u64) u64 {
    return switch (threshold) {
        .count => |count| count,
        .percent => |percent| rust.f64_to_u64(@ceil(@as(f64, @floatFromInt(peers)) * percent)),
    };
}

/// Whether one instruction would advance (commonware `can_command_advance` on a leaf).
pub fn can_leaf_advance(leaf: Leaf, is_proposer: bool, peers: u64, received: *const Received) bool {
    return switch (leaf) {
        .propose, .broadcast, .reply => true,
        .collect => |gate| !is_proposer or
            received.count(gate.id) >= calculate_threshold(gate.threshold, peers),
        .wait => |gate| received.count(gate.id) >= calculate_threshold(gate.threshold, peers),
    };
}

/// Combines postfix results: `results` holds one value per leaf, in leaf order.
pub fn combine(items: []const Item, results: []const bool, stack: []bool) bool {
    var depth: usize = 0;
    var leaf_index: usize = 0;
    for (items) |item| {
        switch (item) {
            .leaf => {
                stack[depth] = results[leaf_index];
                depth += 1;
                leaf_index += 1;
            },
            .@"and", .@"or" => {
                assert(depth >= 2);
                const right = stack[depth - 1];
                const left = stack[depth - 2];
                depth -= 1;
                stack[depth - 1] = if (item == .@"and") left and right else left or right;
            },
        }
    }
    assert(depth == 1);
    assert(leaf_index == results.len);
    return stack[0];
}

/// Whether a command would advance (commonware `can_command_advance`). `scratch` holds at
/// least `2 * task.leaves_max` booleans.
pub fn can_command_advance(
    command: Command,
    is_proposer: bool,
    peers: u64,
    received: *const Received,
    scratch: []bool,
) bool {
    var leaves: usize = 0;
    for (command.items) |item| {
        if (item != .leaf) continue;
        scratch[leaves] = can_leaf_advance(item.leaf, is_proposer, peers, received);
        leaves += 1;
    }
    assert(scratch.len >= 2 * leaves);
    return combine(command.items, scratch[0..leaves], scratch[leaves .. 2 * leaves]);
}

const Pending = struct { from: usize, to: ?usize, id: u32 };

const PeerState = struct { received: Received, index: usize = 0 };

/// Runs the task without timing, delivering every message each round, and reports whether
/// every peer finishes (commonware `validate`).
pub fn validate(gpa: Allocator, task: *const Task, peers: usize, proposer: usize) !bool {
    assert(proposer < peers);
    const states = try gpa.alloc(PeerState, peers);
    defer gpa.free(states);
    var initialized: usize = 0;
    defer for (states[0..initialized]) |*state| state.received.deinit(gpa);
    for (states) |*state| {
        state.* = .{ .received = try .init(gpa, task.ids, peers) };
        initialized += 1;
    }
    const scratch = try gpa.alloc(bool, 2 * task.leaves_max);
    defer gpa.free(scratch);
    var messages: std.ArrayList(Pending) = .empty;
    defer messages.deinit(gpa);
    // Every round but the last advances a peer or delivers what an advance sent.
    const rounds_max = 2 * peers * task.commands.len + 2;
    for (0..rounds_max) |_| {
        var progressed = false;
        for (states, 0..) |*state, peer| {
            while (state.index < task.commands.len) {
                const command = task.commands[state.index];
                const is_proposer = peer == proposer;
                if (!can_command_advance(command, is_proposer, peers, &state.received, scratch)) {
                    break;
                }
                if (command.single()) |leaf| {
                    try validate_effects(gpa, leaf, peer, proposer, state, &messages);
                }
                state.index += 1;
                progressed = true;
            }
        }
        if (messages.items.len > 0) progressed = true;
        for (messages.items) |message| deliver(states, message);
        messages.clearRetainingCapacity();
        var done = true;
        for (states) |state| done = done and state.index >= task.commands.len;
        if (done) return true;
        if (!progressed) return false;
    }
    unreachable; // See `rounds_max`.
}

fn validate_effects(
    gpa: Allocator,
    leaf: Leaf,
    peer: usize,
    proposer: usize,
    state: *PeerState,
    messages: *std.ArrayList(Pending),
) Allocator.Error!void {
    const is_proposer = peer == proposer;
    switch (leaf) {
        .propose => |send| if (is_proposer) {
            try messages.append(gpa, .{ .from = peer, .to = null, .id = send.id });
            state.received.insert(send.id, peer);
        },
        .broadcast => |send| {
            try messages.append(gpa, .{ .from = peer, .to = null, .id = send.id });
            state.received.insert(send.id, peer);
        },
        .reply => |send| if (is_proposer) {
            state.received.insert(send.id, peer);
        } else {
            try messages.append(gpa, .{ .from = peer, .to = proposer, .id = send.id });
        },
        .collect, .wait => {},
    }
}

fn deliver(states: []PeerState, message: Pending) void {
    if (message.to) |to| {
        states[to].received.insert(message.id, message.from);
        return;
    }
    for (states, 0..) |*state, to| {
        if (to != message.from) state.received.insert(message.id, message.from);
    }
}
