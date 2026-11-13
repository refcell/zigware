//! The YAML that serde_yaml 0.9 writes for flood's config and the deployer's hosts file: block
//! mappings and sequences of scalars and mappings, `[]`/`{}` for empty collections, and plain,
//! single-quoted, or double-quoted scalars. Not a general YAML parser: anchors, tags, flow
//! collections with items, multi-line scalars, and multiple documents are rejected.
//!
//! Parsing is iterative over lines with an explicit stack of open collections (no recursion);
//! nodes borrow plain scalars from the input and live in an arena.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const Error = error{
    /// The text is outside the supported subset or is not valid YAML.
    InvalidYaml,
    /// A required key is absent.
    MissingKey,
    /// A value has the wrong shape or does not parse as the expected type.
    InvalidValue,
    OutOfMemory,
};

/// Deepest nesting accepted; flood's files nest three levels.
pub const depth_max = 16;

pub const Entry = struct { key: []const u8, value: Node };

pub const Node = union(enum) {
    /// A scalar's value with quotes removed; `quoted` scalars are always strings.
    scalar: struct { text: []const u8, quoted: bool },
    map: []const Entry,
    list: []const Node,

    pub fn as_map(node: Node) Error!Map {
        return switch (node) {
            .map => |entries| .{ .entries = entries },
            else => error.InvalidValue,
        };
    }

    pub fn as_list(node: Node) Error![]const Node {
        return switch (node) {
            .list => |items| items,
            else => error.InvalidValue,
        };
    }

    pub fn string(node: Node) Error![]const u8 {
        return switch (node) {
            .scalar => |value| value.text,
            else => error.InvalidValue,
        };
    }

    pub fn strings(node: Node, arena: Allocator) Error![]const []const u8 {
        const items = try node.as_list();
        const result = try arena.alloc([]const u8, items.len);
        for (items, result) |item, *text| text.* = try item.string();
        return result;
    }

    pub fn integer(node: Node, comptime T: type) Error!T {
        const text = try node.string();
        if (node.scalar.quoted) return error.InvalidValue;
        return std.fmt.parseInt(T, text, 10) catch error.InvalidValue;
    }

    pub fn boolean(node: Node) Error!bool {
        const text = try node.string();
        if (!node.scalar.quoted) {
            if (is_any(text, &.{ "true", "True", "TRUE" })) return true;
            if (is_any(text, &.{ "false", "False", "FALSE" })) return false;
        }
        return error.InvalidValue;
    }

    pub fn ip(node: Node) Error!Io.net.IpAddress {
        return Io.net.IpAddress.parse(try node.string(), 0) catch error.InvalidValue;
    }
};

pub const Map = struct {
    entries: []const Entry,

    /// The value of `key`; the last one wins when a key repeats.
    pub fn get(map: Map, key: []const u8) Error!Node {
        var index = map.entries.len;
        while (index > 0) {
            index -= 1;
            if (std.mem.eql(u8, map.entries[index].key, key)) return map.entries[index].value;
        }
        return error.MissingKey;
    }
};

fn is_any(text: []const u8, words: []const []const u8) bool {
    for (words) |word| if (std.mem.eql(u8, text, word)) return true;
    return false;
}

const Frame = struct {
    /// Column of this collection's keys or `-` markers.
    indent: usize,
    kind: enum { map, list },
    entries: std.ArrayList(Entry) = .empty,
    items: std.ArrayList(Node) = .empty,
    /// A key whose value is the next, more indented block.
    pending_key: ?[]const u8 = null,
};

pub const Document = struct {
    root: Node,

    pub fn parse(arena: Allocator, text: []const u8) Error!Document {
        var parser: Parser = .{ .arena = arena };
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw| try parser.line(std.mem.trimEnd(u8, raw, " \t\r"));
        return .{ .root = try parser.finish() };
    }
};

const Parser = struct {
    arena: Allocator,
    stack: [depth_max]Frame = undefined,
    depth: usize = 0,
    root: ?Node = null,

    fn top(parser: *Parser) ?*Frame {
        return if (parser.depth == 0) null else &parser.stack[parser.depth - 1];
    }

    fn push(parser: *Parser, frame: Frame) Error!void {
        if (parser.root != null) return error.InvalidYaml; // A second document.
        if (parser.depth == depth_max) return error.InvalidYaml;
        parser.stack[parser.depth] = frame;
        parser.depth += 1;
    }

    /// Closes the innermost collection and hands it to its parent.
    fn pop(parser: *Parser) Error!void {
        assert(parser.depth > 0);
        parser.depth -= 1;
        const frame = &parser.stack[parser.depth];
        if (frame.pending_key != null) try parser.attach_to(frame, null_node);
        const node: Node = switch (frame.kind) {
            .map => .{ .map = try frame.entries.toOwnedSlice(parser.arena) },
            .list => .{ .list = try frame.items.toOwnedSlice(parser.arena) },
        };
        const parent = parser.top() orelse {
            parser.root = node;
            return;
        };
        try parser.attach_to(parent, node);
    }

    fn attach_to(parser: *Parser, frame: *Frame, node: Node) Error!void {
        switch (frame.kind) {
            .map => {
                const key = frame.pending_key orelse return error.InvalidYaml;
                frame.pending_key = null;
                try frame.entries.append(parser.arena, .{ .key = key, .value = node });
            },
            .list => try frame.items.append(parser.arena, node),
        }
    }

    fn line(parser: *Parser, text: []const u8) Error!void {
        const indent = std.mem.indexOfNone(u8, text, " ") orelse return; // Blank.
        const content = text[indent..];
        if (content[0] == '#') return;
        if (std.mem.eql(u8, content, "---")) {
            // Only a leading document marker: a second document is unsupported.
            if (parser.depth > 0 or parser.root != null) return error.InvalidYaml;
            return;
        }
        if (content[0] == '\t') return error.InvalidYaml;
        const is_item = std.mem.eql(u8, content, "-") or std.mem.startsWith(u8, content, "- ");
        // Close collections this line is not inside. A sequence written at its key's column
        // ends at the next key of that mapping.
        while (parser.top()) |frame| {
            const deeper = frame.indent > indent;
            const list_ends = frame.kind == .list and frame.indent == indent and !is_item;
            if (!deeper and !list_ends) break;
            try parser.pop();
        }
        if (parser.top()) |frame| {
            if (frame.kind == .map and frame.pending_key != null) {
                if (is_item and indent >= frame.indent) {
                    try parser.push(.{ .indent = indent, .kind = .list });
                } else if (!is_item and indent > frame.indent) {
                    try parser.push(.{ .indent = indent, .kind = .map });
                } else try parser.attach_to(frame, null_node);
            }
        } else try parser.push(.{ .indent = indent, .kind = if (is_item) .list else .map });
        const frame = parser.top().?;
        if (frame.indent != indent) return error.InvalidYaml;
        if (!is_item) {
            if (frame.kind != .map) return error.InvalidYaml;
            return parser.key_value(frame, content);
        }
        if (frame.kind != .list) return error.InvalidYaml;
        const rest = std.mem.trimStart(u8, content[1..], " ");
        if (rest.len == 0) return error.InvalidYaml; // Nested blocks under `-` are unsupported.
        if (split_key(rest) != null) {
            try parser.push(.{ .indent = indent + (content.len - rest.len), .kind = .map });
            return parser.key_value(parser.top().?, rest);
        }
        try frame.items.append(parser.arena, try scalar(rest));
    }

    fn key_value(parser: *Parser, frame: *Frame, content: []const u8) Error!void {
        assert(frame.kind == .map);
        const split = split_key(content) orelse return error.InvalidYaml;
        const key = (try scalar(split.key)).scalar.text;
        if (split.value.len == 0) {
            frame.pending_key = key;
            return;
        }
        const value: Node = if (std.mem.eql(u8, split.value, "[]"))
            .{ .list = &.{} }
        else if (std.mem.eql(u8, split.value, "{}"))
            .{ .map = &.{} }
        else
            try scalar(split.value);
        try frame.entries.append(parser.arena, .{ .key = key, .value = value });
    }

    fn finish(parser: *Parser) Error!Node {
        while (parser.depth > 0) try parser.pop();
        return parser.root orelse null_node;
    }
};

const null_node: Node = .{ .scalar = .{ .text = "~", .quoted = false } };

/// Splits `key: value` (or `key:`) at the first colon followed by a space or the end, outside
/// quotes.
fn split_key(content: []const u8) ?struct { key: []const u8, value: []const u8 } {
    var quote: ?u8 = null;
    for (content, 0..) |byte, index| {
        if (quote) |open| {
            if (byte == open) quote = null;
            continue;
        }
        if (byte == '\'' or byte == '"') {
            if (index == 0) quote = byte;
            continue;
        }
        if (byte != ':') continue;
        if (index + 1 != content.len and content[index + 1] != ' ') continue;
        const value = std.mem.trimStart(u8, content[index + 1 ..], " ");
        return .{ .key = std.mem.trimEnd(u8, content[0..index], " "), .value = value };
    }
    return null;
}

/// A plain or quoted scalar. Quoted text with escapes must be unescaped into new memory, so
/// only escape-free double-quoted scalars and `''` in single-quoted ones are supported.
fn scalar(text: []const u8) Error!Node {
    if (text.len == 0) return error.InvalidYaml;
    if (std.mem.indexOfAny(u8, text[0..1], "&*!|>%@`[{")) |_| return error.InvalidYaml;
    const plain = text.len < 2 or (text[0] != '\'' and text[0] != '"');
    if (plain) {
        if (std.mem.indexOf(u8, text, " #") != null) return error.InvalidYaml; // Comments.
        return .{ .scalar = .{ .text = text, .quoted = false } };
    }
    const quote = text[0];
    if (text[text.len - 1] != quote) return error.InvalidYaml;
    const inner = text[1 .. text.len - 1];
    const escape: []const u8 = if (quote == '\'') "''" else "\\";
    if (std.mem.indexOf(u8, inner, escape) != null) return error.InvalidYaml;
    if (std.mem.indexOfScalar(u8, inner, quote) != null) return error.InvalidYaml;
    return .{ .scalar = .{ .text = inner, .quoted = true } };
}

/// Whether serde_yaml writes `text` single-quoted: when plain it would read back as null, a
/// bool, an integer, a finite float, or a zero-padded number, or plain style cannot hold it.
pub fn needs_quotes(text: []const u8) bool {
    if (text.len == 0) return true;
    if (is_any(text, &.{ "~", "null", "Null", "NULL", "true", "True", "TRUE" })) return true;
    if (is_any(text, &.{ "false", "False", "FALSE" })) return true;
    if (is_any(text, &.{ ".inf", ".Inf", ".INF", "-.inf", "-.Inf", "-.INF", "+.inf" })) {
        return true;
    }
    if (is_any(text, &.{ ".nan", ".NaN", ".NAN" })) return true;
    if (is_radix_integer(text) or is_decimal_number(text)) return true;
    if (std.mem.indexOfScalar(u8, "-?:,[]{}#&*!|>'\"%@` \t", text[0]) != null) return true;
    if (text[text.len - 1] == ' ' or text[text.len - 1] == ':') return true;
    return std.mem.indexOf(u8, text, ": ") != null or std.mem.indexOf(u8, text, " #") != null;
}

/// `[+-]0x...`, `0o...`, or `0b...` that fits 128 bits.
fn is_radix_integer(text: []const u8) bool {
    const unsigned = if (text[0] == '+' or text[0] == '-') text[1..] else text;
    if (unsigned.len < 3 or unsigned[0] != '0') return false;
    const base: u8 = switch (unsigned[1]) {
        'x' => 16,
        'o' => 8,
        'b' => 2,
        else => return false,
    };
    const digits = unsigned[2..];
    if (digits[0] == '+' or digits[0] == '-') return false;
    _ = std.fmt.parseInt(u128, digits, base) catch return false;
    return true;
}

/// Rust's finite `f64` grammar (which includes every decimal integer and zero-padded digits).
fn is_decimal_number(text: []const u8) bool {
    const body = if (text[0] == '+' or text[0] == '-') text[1..] else text;
    var index: usize = 0;
    var digits: usize = 0;
    while (index < body.len and std.ascii.isDigit(body[index])) : (index += 1) digits += 1;
    if (index < body.len and body[index] == '.') {
        index += 1;
        while (index < body.len and std.ascii.isDigit(body[index])) : (index += 1) digits += 1;
    }
    if (digits == 0) return false;
    if (index < body.len and (body[index] == 'e' or body[index] == 'E')) {
        index += 1;
        if (index < body.len and (body[index] == '+' or body[index] == '-')) index += 1;
        const start = index;
        while (index < body.len and std.ascii.isDigit(body[index])) index += 1;
        if (index == start) return false;
    }
    return index == body.len;
}

/// Writes a string as serde_yaml does: plain, or single-quoted with `'` doubled.
pub fn write_string(writer: *Io.Writer, text: []const u8) Io.Writer.Error!void {
    assert(std.mem.indexOfScalar(u8, text, '\n') == null); // serde_yaml uses block literals.
    if (!needs_quotes(text)) return writer.writeAll(text);
    try writer.writeByte('\'');
    for (text) |byte| {
        if (byte == '\'') try writer.writeByte('\'');
        try writer.writeByte(byte);
    }
    try writer.writeByte('\'');
}

pub fn write_string_field(
    writer: *Io.Writer,
    key: []const u8,
    text: []const u8,
) Io.Writer.Error!void {
    try writer.print("{s}: ", .{key});
    try write_string(writer, text);
    try writer.writeByte('\n');
}

/// `key: []` when empty, else `key:` and one `- item` line per item at the key's column.
pub fn write_string_list(
    writer: *Io.Writer,
    key: []const u8,
    items: []const []const u8,
) Io.Writer.Error!void {
    if (items.len == 0) return writer.print("{s}: []\n", .{key});
    try writer.print("{s}:\n", .{key});
    for (items) |item| {
        try writer.writeAll("- ");
        try write_string(writer, item);
        try writer.writeByte('\n');
    }
}
