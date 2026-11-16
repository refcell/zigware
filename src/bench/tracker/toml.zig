//! The TOML subset the benchmark tracker reads and writes (commonware uses the `toml` crate).
//!
//! Supported: comments, bare and quoted keys, dotted keys outside inline tables, `[table]` and
//! `[[array.of.tables]]` headers (a path through an array of tables descends into its last
//! table), basic and literal single-line strings, integers and floats (with `_` separators,
//! `inf`, and `nan`), booleans, arrays (multi-line, trailing comma), and inline tables.
//! Not supported: multi-line strings, dates and times, dotted keys inside inline tables.
//!
//! Values nest at most `depth_max` deep and are parsed iteratively. Everything is allocated
//! from the caller's allocator, which should be an arena: values are never freed one by one.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// The deepest nesting of arrays and inline tables in one value, and of keys in one path.
pub const depth_max = 16;

pub const Value = union(enum) {
    string: []const u8,
    integer: i64,
    float: f64,
    boolean: bool,
    array: *Array,
    table: *Table,
};

pub const Array = struct {
    items: std.ArrayList(Value) = .empty,
    /// Defined by `[[...]]` headers, so later headers may append to it.
    of_tables: bool = false,
};

pub const Table = struct {
    keys: std.ArrayList([]const u8) = .empty,
    values: std.ArrayList(Value) = .empty,

    pub fn get(table: *const Table, key: []const u8) ?Value {
        assert(table.keys.items.len == table.values.items.len);
        for (table.keys.items, table.values.items) |existing, value| {
            if (std.mem.eql(u8, existing, key)) return value;
        }
        return null;
    }
};

/// The message of the last `error.Invalid`.
pub const Diagnostic = struct {
    buffer: [256]u8 = undefined,
    len: usize = 0,

    pub fn message(diagnostic: *const Diagnostic) []const u8 {
        return diagnostic.buffer[0..diagnostic.len];
    }

    /// Records a message and returns `error.Invalid`.
    pub fn fail(
        diagnostic: *Diagnostic,
        comptime format: []const u8,
        args: anytype,
    ) error{Invalid} {
        const text = std.fmt.bufPrint(&diagnostic.buffer, format, args) catch blk: {
            const truncated = "(message too long)";
            @memcpy(diagnostic.buffer[0..truncated.len], truncated);
            break :blk diagnostic.buffer[0..truncated.len];
        };
        diagnostic.len = text.len;
        return error.Invalid;
    }
};

pub const Error = error{Invalid} || Allocator.Error;

/// Parses `input` into its root table.
pub fn parse(gpa: Allocator, input: []const u8, diagnostic: *Diagnostic) Error!*Table {
    var parser: Parser = .{ .gpa = gpa, .input = input, .diagnostic = diagnostic };
    const root = try parser.new_table();
    var current = root;
    while (true) {
        parser.skip_blank();
        const char = parser.peek() orelse break;
        if (char == '[') {
            current = try parser.header(root);
        } else {
            try parser.key_value(current);
        }
        parser.skip_space();
        parser.skip_comment();
        const next = parser.peek() orelse break;
        if (next != '\n' and next != '\r') return parser.fail("expected a new line", .{});
    }
    assert(parser.index == input.len);
    return root;
}

const Parser = struct {
    gpa: Allocator,
    input: []const u8,
    index: usize = 0,
    line: u32 = 1,
    diagnostic: *Diagnostic,

    fn fail(parser: *Parser, comptime format: []const u8, args: anytype) error{Invalid} {
        return parser.diagnostic.fail("line {d}: " ++ format, .{parser.line} ++ args);
    }

    fn peek(parser: *const Parser) ?u8 {
        if (parser.index >= parser.input.len) return null;
        return parser.input[parser.index];
    }

    fn expect(parser: *Parser, char: u8) error{Invalid}!void {
        if (parser.peek() != char) return parser.fail("expected `{c}`", .{char});
        parser.index += 1;
    }

    fn skip_space(parser: *Parser) void {
        while (parser.peek()) |char| {
            if (char != ' ' and char != '\t') return;
            parser.index += 1;
        }
    }

    fn skip_comment(parser: *Parser) void {
        if (parser.peek() != '#') return;
        while (parser.peek()) |char| {
            if (char == '\n') return;
            parser.index += 1;
        }
    }

    /// Skips spaces, new lines, and comments.
    fn skip_blank(parser: *Parser) void {
        while (parser.peek()) |char| {
            switch (char) {
                ' ', '\t', '\r' => parser.index += 1,
                '\n' => {
                    parser.index += 1;
                    parser.line += 1;
                },
                '#' => parser.skip_comment(),
                else => return,
            }
        }
    }

    fn new_table(parser: *Parser) Allocator.Error!*Table {
        const table = try parser.gpa.create(Table);
        table.* = .{};
        return table;
    }

    fn new_array(parser: *Parser, of_tables: bool) Allocator.Error!*Array {
        const array = try parser.gpa.create(Array);
        array.* = .{ .of_tables = of_tables };
        return array;
    }

    fn put(parser: *Parser, table: *Table, key: []const u8, value: Value) Error!void {
        if (table.get(key) != null) return parser.fail("duplicate key `{s}`", .{key});
        try table.keys.append(parser.gpa, key);
        try table.values.append(parser.gpa, value);
    }

    /// The table at `key` of `table`, created if absent; through an array of tables, its last.
    fn descend(parser: *Parser, table: *Table, key: []const u8) Error!*Table {
        const existing = table.get(key) orelse {
            const created = try parser.new_table();
            try parser.put(table, key, .{ .table = created });
            return created;
        };
        switch (existing) {
            .table => |found| return found,
            .array => |array| {
                const items = array.items.items;
                if (array.of_tables and items.len > 0) return items[items.len - 1].table;
            },
            else => {},
        }
        return parser.fail("`{s}` is not a table", .{key});
    }

    fn header(parser: *Parser, root: *Table) Error!*Table {
        assert(parser.peek() == '[');
        parser.index += 1;
        const array = parser.peek() == '[';
        if (array) parser.index += 1;
        var buffer: [depth_max][]const u8 = undefined;
        const path = try parser.key_path(&buffer);
        try parser.expect(']');
        if (array) try parser.expect(']');
        var table = root;
        for (path[0 .. path.len - 1]) |key| table = try parser.descend(table, key);
        const last = path[path.len - 1];
        if (!array) return parser.descend(table, last);
        const list = if (table.get(last)) |existing| switch (existing) {
            .array => |found| if (found.of_tables) found else null,
            else => null,
        } else blk: {
            const created = try parser.new_array(true);
            try parser.put(table, last, .{ .array = created });
            break :blk created;
        };
        const target = list orelse return parser.fail("`{s}` is not an array of tables", .{last});
        const element = try parser.new_table();
        try target.items.append(parser.gpa, .{ .table = element });
        return element;
    }

    fn key_value(parser: *Parser, current: *Table) Error!void {
        var buffer: [depth_max][]const u8 = undefined;
        const path = try parser.key_path(&buffer);
        try parser.expect('=');
        const value = try parser.parse_value();
        var table = current;
        for (path[0 .. path.len - 1]) |key| table = try parser.descend(table, key);
        try parser.put(table, path[path.len - 1], value);
    }

    /// Reads `key(.key)*` into `buffer`, skipping spaces around it.
    fn key_path(parser: *Parser, buffer: *[depth_max][]const u8) Error![]const []const u8 {
        var len: usize = 0;
        while (true) {
            if (len == depth_max) return parser.fail("key path deeper than {d}", .{depth_max});
            parser.skip_space();
            buffer[len] = try parser.read_key();
            len += 1;
            parser.skip_space();
            if (parser.peek() != '.') break;
            parser.index += 1;
        }
        assert(len >= 1);
        return buffer[0..len];
    }

    fn read_key(parser: *Parser) Error![]const u8 {
        const char = parser.peek() orelse return parser.fail("expected a key", .{});
        if (char == '"' or char == '\'') return parser.string();
        const start = parser.index;
        while (parser.peek()) |next| {
            if (!is_bare(next)) break;
            parser.index += 1;
        }
        if (parser.index == start) return parser.fail("expected a key", .{});
        return parser.input[start..parser.index];
    }

    /// Parses one value, nesting arrays and inline tables up to `depth_max` without recursion.
    fn parse_value(parser: *Parser) Error!Value {
        var stack: [depth_max]Value = undefined;
        var keys: [depth_max][]const u8 = undefined;
        var depth: usize = 0;
        while (true) {
            var done = (try parser.open(&stack, &keys, &depth)) orelse continue;
            // Add the finished value to its container, closing containers that end with it.
            while (depth > 0) {
                const top = stack[depth - 1];
                switch (top) {
                    .array => |array| try array.items.append(parser.gpa, done),
                    .table => |table| try parser.put(table, keys[depth - 1], done),
                    else => unreachable,
                }
                if (try parser.separator(top, &keys[depth - 1])) break;
                depth -= 1;
                done = top;
            } else return done;
        }
    }

    /// Starts a value: returns a scalar or an empty container, or opens a container and
    /// returns null.
    fn open(
        parser: *Parser,
        stack: *[depth_max]Value,
        keys: *[depth_max][]const u8,
        depth: *usize,
    ) Error!?Value {
        const in_array = depth.* > 0 and stack[depth.* - 1] == .array;
        if (in_array) parser.skip_blank() else parser.skip_space();
        const char = parser.peek() orelse return parser.fail("expected a value", .{});
        if (char != '[' and char != '{') return try parser.scalar();
        if (depth.* == depth_max) return parser.fail("value nested deeper than {d}", .{depth_max});
        parser.index += 1;
        if (char == '[') {
            const array: Value = .{ .array = try parser.new_array(false) };
            parser.skip_blank();
            if (parser.peek() == ']') {
                parser.index += 1;
                return array;
            }
            stack[depth.*] = array;
            depth.* += 1;
            return null;
        }
        const table: Value = .{ .table = try parser.new_table() };
        parser.skip_space();
        if (parser.peek() == '}') {
            parser.index += 1;
            return table;
        }
        stack[depth.*] = table;
        keys[depth.*] = try parser.inline_key();
        depth.* += 1;
        return null;
    }

    /// Reads what follows an element of `container`: true when another element follows (for
    /// a table, its key is in `key_slot`), false once the container closed.
    fn separator(parser: *Parser, container: Value, key_slot: *[]const u8) Error!bool {
        if (container == .array) {
            parser.skip_blank();
            if (parser.peek() == ']') {
                parser.index += 1;
                return false;
            }
            try parser.expect(',');
            parser.skip_blank();
            if (parser.peek() != ']') return true;
            parser.index += 1;
            return false;
        }
        parser.skip_space();
        if (parser.peek() == '}') {
            parser.index += 1;
            return false;
        }
        try parser.expect(',');
        key_slot.* = try parser.inline_key();
        return true;
    }

    fn inline_key(parser: *Parser) Error![]const u8 {
        parser.skip_space();
        const name = try parser.read_key();
        parser.skip_space();
        if (parser.peek() == '.') return parser.fail("dotted keys in inline tables", .{});
        try parser.expect('=');
        return name;
    }

    fn scalar(parser: *Parser) Error!Value {
        const char = parser.peek().?;
        if (char == '"' or char == '\'') return .{ .string = try parser.string() };
        const start = parser.index;
        while (parser.peek()) |next| {
            if (!is_bare(next) and next != '+' and next != '.') break;
            parser.index += 1;
        }
        const token = parser.input[start..parser.index];
        if (token.len == 0) return parser.fail("expected a value", .{});
        if (std.mem.eql(u8, token, "true")) return .{ .boolean = true };
        if (std.mem.eql(u8, token, "false")) return .{ .boolean = false };
        return parser.number(token);
    }

    fn number(parser: *Parser, token: []const u8) Error!Value {
        var buffer: [64]u8 = undefined;
        if (token.len > buffer.len) return parser.fail("number too long", .{});
        var len: usize = 0;
        for (token) |char| {
            if (char == '_') continue;
            buffer[len] = char;
            len += 1;
        }
        const digits = buffer[0..len];
        const float = std.mem.indexOfAny(u8, digits, ".eEn") != null or
            std.mem.endsWith(u8, digits, "inf");
        if (float) {
            const value = std.fmt.parseFloat(f64, digits) catch
                return parser.fail("invalid number `{s}`", .{token});
            return .{ .float = value };
        }
        const value = std.fmt.parseInt(i64, digits, 10) catch
            return parser.fail("invalid number `{s}`", .{token});
        return .{ .integer = value };
    }

    /// A basic (`"..."`, with escapes) or literal (`'...'`) single-line string.
    fn string(parser: *Parser) Error![]const u8 {
        const quote = parser.peek().?;
        assert(quote == '"' or quote == '\'');
        parser.index += 1;
        const start = parser.index;
        var escaped = false;
        while (true) {
            const char = parser.peek() orelse return parser.fail("unterminated string", .{});
            if (char == '\n') return parser.fail("unterminated string", .{});
            if (char == quote) break;
            if (char == '\\' and quote == '"') {
                escaped = true;
                parser.index += 1;
                if (parser.peek() == null) return parser.fail("unterminated string", .{});
            }
            parser.index += 1;
        }
        const raw = parser.input[start..parser.index];
        parser.index += 1;
        if (!escaped) return raw;
        return parser.unescape(raw);
    }

    fn unescape(parser: *Parser, raw: []const u8) Error![]const u8 {
        var out: std.ArrayList(u8) = try .initCapacity(parser.gpa, raw.len);
        var index: usize = 0;
        while (index < raw.len) : (index += 1) {
            if (raw[index] != '\\') {
                out.appendAssumeCapacity(raw[index]);
                continue;
            }
            index += 1;
            assert(index < raw.len);
            const replacement: u8 = switch (raw[index]) {
                '"' => '"',
                '\\' => '\\',
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                'b' => 0x08,
                'f' => 0x0c,
                'u' => {
                    if (index + 5 > raw.len) return parser.fail("short unicode escape", .{});
                    const hex = raw[index + 1 .. index + 5];
                    const code = std.fmt.parseInt(u21, hex, 16) catch
                        return parser.fail("invalid unicode escape", .{});
                    var bytes: [4]u8 = undefined;
                    const width = std.unicode.utf8Encode(code, &bytes) catch
                        return parser.fail("invalid unicode escape", .{});
                    try out.appendSlice(parser.gpa, bytes[0..width]);
                    index += 4;
                    continue;
                },
                else => return parser.fail("invalid escape", .{}),
            };
            out.appendAssumeCapacity(replacement);
        }
        return out.items;
    }
};

fn is_bare(char: u8) bool {
    return std.ascii.isAlphanumeric(char) or char == '_' or char == '-';
}

/// Writes `key` bare when it can be, else quoted.
pub fn write_key(writer: *std.Io.Writer, key: []const u8) std.Io.Writer.Error!void {
    for (key) |char| {
        if (!is_bare(char)) return write_string(writer, key);
    }
    if (key.len == 0) return write_string(writer, key);
    try writer.writeAll(key);
}

/// Writes `value` as a basic string.
pub fn write_string(writer: *std.Io.Writer, value: []const u8) std.Io.Writer.Error!void {
    try writer.writeByte('"');
    for (value) |char| switch (char) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        '\n' => try writer.writeAll("\\n"),
        '\t' => try writer.writeAll("\\t"),
        '\r' => try writer.writeAll("\\r"),
        0...0x08, 0x0b, 0x0c, 0x0e...0x1f, 0x7f => try writer.print("\\u{x:0>4}", .{char}),
        else => try writer.writeByte(char),
    };
    try writer.writeByte('"');
}

/// Writes `value` as a TOML float (`10.0`, `-1.5`, `inf`, `nan`).
pub fn write_float(writer: *std.Io.Writer, value: f64) std.Io.Writer.Error!void {
    if (std.math.isNan(value)) return writer.writeAll("nan");
    if (std.math.isInf(value)) return writer.writeAll(if (value > 0) "inf" else "-inf");
    if (@trunc(value) == value and @abs(value) < 1e15) return writer.print("{d}.0", .{value});
    try writer.print("{d}", .{value});
}

/// Writes `values` as an array of strings.
pub fn write_strings(writer: *std.Io.Writer, values: []const []const u8) std.Io.Writer.Error!void {
    try writer.writeByte('[');
    for (values, 0..) |value, index| {
        if (index > 0) try writer.writeAll(", ");
        try write_string(writer, value);
    }
    try writer.writeByte(']');
}
