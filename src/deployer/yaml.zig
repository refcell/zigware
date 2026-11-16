//! The YAML the deployer reads and writes: the subset serde_yaml 0.9 produces for its types.
//!
//! Reading accepts block mappings and sequences of scalars and mappings, `[]`/`{}` for empty
//! collections, comments, and plain, single-quoted, or double-quoted single-line scalars.
//! Anchors, tags, flow collections with items, multi-line scalars, and multiple documents are
//! rejected. Parsing is iterative over lines with an explicit stack of open collections (no
//! recursion); nodes live in an arena.
//!
//! Writing matches serde_yaml byte for byte. A string's style follows serde_yaml's inference
//! (strings that would read back as null, a bool, an integer, or a finite float are
//! single-quoted) and libyaml's `analyze_scalar` and `select_scalar_style` with serde_yaml's
//! emitter settings (unicode output, unlimited width). Strings with line breaks, which
//! serde_yaml writes as literal blocks, are rejected.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const Error = error{
    /// The text is outside the supported subset or is not valid YAML.
    InvalidYaml,
    /// A required key is absent.
    MissingKey,
    /// A key appears twice in one mapping.
    DuplicateKey,
    /// A value has the wrong shape or does not parse as the expected type.
    InvalidValue,
    OutOfMemory,
};

/// Deepest nesting accepted (the deployer's files nest three levels).
pub const depth_max = 16;

pub const Style = enum { plain, single_quoted, double_quoted };

pub const Entry = struct { key: []const u8, value: Node };

pub const Node = union(enum) {
    scalar: struct { text: []const u8, style: Style },
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

    /// Any scalar as a string (serde_yaml `deserialize_str`).
    pub fn string(node: Node) Error![]const u8 {
        return switch (node) {
            .scalar => |value| value.text,
            else => error.InvalidValue,
        };
    }

    /// The text of a plain scalar: typed values must be unquoted.
    fn plain(node: Node) Error![]const u8 {
        const value = switch (node) {
            .scalar => |value| value,
            else => return error.InvalidValue,
        };
        if (value.style != .plain) return error.InvalidValue;
        return value.text;
    }

    /// An integer (serde_yaml `deserialize_i64`/`deserialize_u64`, then a range check).
    pub fn integer(node: Node, comptime T: type) Error!T {
        const text = try node.plain();
        const info = @typeInfo(T).int;
        if (info.signedness == .unsigned) {
            const value = parse_unsigned(text, u64) orelse return error.InvalidValue;
            return std.math.cast(T, value) orelse error.InvalidValue;
        }
        const value = parse_signed(text, i64) orelse return error.InvalidValue;
        return std.math.cast(T, value) orelse error.InvalidValue;
    }

    pub fn boolean(node: Node) Error!bool {
        return parse_bool(try node.plain()) orelse error.InvalidValue;
    }

    /// Whether the node reads as `None` for an `Option` (an empty or null plain scalar).
    pub fn is_null(node: Node) bool {
        const value = switch (node) {
            .scalar => |value| value,
            else => return false,
        };
        return value.style == .plain and (value.text.len == 0 or is_null_word(value.text));
    }
};

pub const Map = struct {
    entries: []const Entry,

    /// The value of `key`, or null when absent.
    pub fn find(map: Map, key: []const u8) Error!?Node {
        var found: ?Node = null;
        for (map.entries) |entry| {
            if (!std.mem.eql(u8, entry.key, key)) continue;
            if (found != null) return error.DuplicateKey;
            found = entry.value;
        }
        return found;
    }

    pub fn get(map: Map, key: []const u8) Error!Node {
        return try map.find(key) orelse error.MissingKey;
    }

    /// An optional integer: absent or null is `null` (serde `default` on an `Option`).
    pub fn optional_integer(map: Map, key: []const u8, comptime T: type) Error!?T {
        const node = try map.find(key) orelse return null;
        if (node.is_null()) return null;
        return try node.integer(T);
    }
};

fn is_any(text: []const u8, words: []const []const u8) bool {
    for (words) |word| if (std.mem.eql(u8, text, word)) return true;
    return false;
}

fn is_null_word(text: []const u8) bool {
    return is_any(text, &.{ "~", "null", "Null", "NULL" });
}

fn parse_bool(text: []const u8) ?bool {
    if (is_any(text, &.{ "true", "True", "TRUE" })) return true;
    if (is_any(text, &.{ "false", "False", "FALSE" })) return false;
    return null;
}

// --- Numbers, as serde_yaml's `de.rs` reads them ---------------------------------------------

/// Rust `from_str_radix` for `T`: an optional sign (`-` only for signed types), then at
/// least one digit of `radix`, with no underscores.
fn from_str_radix(comptime T: type, text: []const u8, radix: u8) ?T {
    const signed = @typeInfo(T).int.signedness == .signed;
    var digits = text;
    var negative = false;
    if (digits.len > 0 and (digits[0] == '+' or (signed and digits[0] == '-'))) {
        negative = digits[0] == '-';
        digits = digits[1..];
    }
    if (digits.len == 0) return null;
    var value: T = 0;
    for (digits) |byte| {
        const digit = std.fmt.charToDigit(byte, radix) catch return null;
        value = std.math.mul(T, value, radix) catch return null;
        value = if (negative)
            std.math.sub(T, value, digit) catch return null
        else
            std.math.add(T, value, digit) catch return null;
    }
    return value;
}

/// Leading zeros followed by digits are a string in YAML 1.2.
pub fn digits_but_not_number(text: []const u8) bool {
    const body = if (text.len > 0 and (text[0] == '-' or text[0] == '+')) text[1..] else text;
    if (body.len < 2 or body[0] != '0') return false;
    for (body[1..]) |byte| if (!std.ascii.isDigit(byte)) return false;
    return true;
}

const radixes = [_]struct { prefix: []const u8, radix: u8 }{
    .{ .prefix = "0x", .radix = 16 },
    .{ .prefix = "0o", .radix = 8 },
    .{ .prefix = "0b", .radix = 2 },
};

/// serde_yaml `parse_unsigned_int`.
fn parse_unsigned(text: []const u8, comptime T: type) ?T {
    const unpositive = if (std.mem.startsWith(u8, text, "+")) text[1..] else text;
    for (radixes) |entry| {
        if (!std.mem.startsWith(u8, unpositive, entry.prefix)) continue;
        const rest = unpositive[entry.prefix.len..];
        if (rest.len > 0 and (rest[0] == '+' or rest[0] == '-')) return null;
        if (from_str_radix(T, rest, entry.radix)) |value| return value;
    }
    if (unpositive.len > 0 and (unpositive[0] == '+' or unpositive[0] == '-')) return null;
    if (digits_but_not_number(text)) return null;
    return from_str_radix(T, unpositive, 10);
}

/// serde_yaml `parse_negative_int` (also accepts a decimal with either sign).
fn parse_negative(text: []const u8, comptime T: type) ?T {
    var buffer: [64]u8 = undefined;
    for (radixes) |entry| {
        if (text.len < 3 or text[0] != '-') continue;
        if (!std.mem.startsWith(u8, text[1..], entry.prefix)) continue;
        const rest = text[1 + entry.prefix.len ..];
        if (rest.len + 1 > buffer.len) continue;
        buffer[0] = '-';
        @memcpy(buffer[1 .. rest.len + 1], rest);
        if (from_str_radix(T, buffer[0 .. rest.len + 1], entry.radix)) |value| return value;
    }
    if (digits_but_not_number(text)) return null;
    return from_str_radix(T, text, 10);
}

/// serde_yaml `parse_signed_int`.
fn parse_signed(text: []const u8, comptime T: type) ?T {
    var unpositive = text;
    if (std.mem.startsWith(u8, text, "+")) {
        unpositive = text[1..];
        if (unpositive.len > 0 and (unpositive[0] == '+' or unpositive[0] == '-')) return null;
    }
    for (radixes) |entry| {
        if (!std.mem.startsWith(u8, unpositive, entry.prefix)) continue;
        const rest = unpositive[entry.prefix.len..];
        if (rest.len > 0 and (rest[0] == '+' or rest[0] == '-')) return null;
        if (from_str_radix(T, rest, entry.radix)) |value| return value;
    }
    return parse_negative(text, T);
}

/// Whether serde_yaml reads `text` as an integer (`visit_int`: u64, i64, u128, i128).
fn reads_as_integer(text: []const u8) bool {
    if (parse_unsigned(text, u128) != null) return true;
    return parse_negative(text, i128) != null;
}

/// Whether serde_yaml reads `text` as a float (`parse_f64`): `.inf`/`.nan` spellings, or
/// Rust's `f64` grammar with a finite value.
fn reads_as_float(text: []const u8) bool {
    var unpositive = text;
    if (std.mem.startsWith(u8, text, "+")) {
        unpositive = text[1..];
        if (unpositive.len > 0 and (unpositive[0] == '+' or unpositive[0] == '-')) return false;
    }
    if (is_any(unpositive, &.{ ".inf", ".Inf", ".INF" })) return true;
    if (is_any(text, &.{ "-.inf", "-.Inf", "-.INF", ".nan", ".NaN", ".NAN" })) return true;
    if (!is_rust_decimal(unpositive)) return false;
    const value = std.fmt.parseFloat(f64, unpositive) catch return false;
    return std.math.isFinite(value);
}

/// Rust's decimal `f64` grammar: `[+-]? (digits [. digits?] | . digits) ([eE] [+-]? digits)?`.
/// (Rust also accepts `inf`/`nan` words, which are never finite.)
fn is_rust_decimal(text: []const u8) bool {
    const body = if (text.len > 0 and (text[0] == '+' or text[0] == '-')) text[1..] else text;
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

// --- Reading -----------------------------------------------------------------------------------

const Frame = struct {
    /// Column of this collection's keys or `-` markers.
    indent: usize,
    kind: enum { map, list },
    entries: std.ArrayList(Entry) = .empty,
    items: std.ArrayList(Node) = .empty,
    /// A key whose value is the next, more indented block.
    pending_key: ?[]const u8 = null,
};

/// A missing value (`key:` with nothing after it) reads as an empty plain scalar.
const empty_node: Node = .{ .scalar = .{ .text = "", .style = .plain } };

pub const Document = struct {
    root: Node,

    /// Parses `text`; nodes and decoded scalars are allocated in `arena`, and plain scalars
    /// borrow `text`.
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
        if (frame.pending_key != null) try parser.attach_to(frame, empty_node);
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
        if (parser.depth == 0 and parser.root == null and !is_item and split_key(content) == null) {
            parser.root = try parser.value(content); // A document that is one scalar.
            return;
        }
        try parser.open(indent, is_item);
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
        try frame.items.append(parser.arena, try parser.value(rest));
    }

    /// Closes the collections a line at `indent` is not inside, then opens the block a
    /// pending key's value starts with.
    fn open(parser: *Parser, indent: usize, is_item: bool) Error!void {
        // A sequence written at its key's column ends at the next key of that mapping.
        while (parser.top()) |frame| {
            const deeper = frame.indent > indent;
            const list_ends = frame.kind == .list and frame.indent == indent and !is_item;
            if (!deeper and !list_ends) break;
            try parser.pop();
        }
        const frame = parser.top() orelse {
            return parser.push(.{ .indent = indent, .kind = if (is_item) .list else .map });
        };
        if (frame.kind != .map or frame.pending_key == null) return;
        if (is_item and indent >= frame.indent) {
            try parser.push(.{ .indent = indent, .kind = .list });
        } else if (!is_item and indent > frame.indent) {
            try parser.push(.{ .indent = indent, .kind = .map });
        } else {
            try parser.attach_to(frame, empty_node);
        }
    }

    fn key_value(parser: *Parser, frame: *Frame, content: []const u8) Error!void {
        assert(frame.kind == .map);
        const split = split_key(content) orelse return error.InvalidYaml;
        const key = try (try parser.value(split.key)).string();
        if (split.value.len == 0) {
            frame.pending_key = key;
            return;
        }
        const node = try parser.value(split.value);
        try frame.entries.append(parser.arena, .{ .key = key, .value = node });
    }

    fn value(parser: *Parser, text: []const u8) Error!Node {
        if (std.mem.eql(u8, text, "[]")) return .{ .list = &.{} };
        if (std.mem.eql(u8, text, "{}")) return .{ .map = &.{} };
        return scalar(parser.arena, text);
    }

    fn finish(parser: *Parser) Error!Node {
        while (parser.depth > 0) try parser.pop();
        return parser.root orelse empty_node;
    }
};

/// Splits `key: value` (or `key:`) at the first colon followed by a space or the end, outside
/// a quoted key.
fn split_key(content: []const u8) ?struct { key: []const u8, value: []const u8 } {
    var quote: ?u8 = null;
    var escaped = false;
    for (content, 0..) |byte, index| {
        if (quote) |open_quote| {
            // `\x` escapes in a double-quoted key; `''` in a single-quoted key reopens it.
            if (escaped) {
                escaped = false;
            } else if (open_quote == '"' and byte == '\\') {
                escaped = true;
            } else if (byte == open_quote) {
                const doubled = open_quote == '\'' and index + 1 < content.len and
                    content[index + 1] == '\'';
                if (doubled) escaped = true else quote = null;
            }
            continue;
        }
        if (index == 0 and (byte == '\'' or byte == '"')) {
            quote = byte;
            continue;
        }
        if (byte != ':') continue;
        if (index + 1 != content.len and content[index + 1] != ' ') continue;
        const rest = std.mem.trimStart(u8, content[index + 1 ..], " ");
        return .{ .key = std.mem.trimEnd(u8, content[0..index], " "), .value = rest };
    }
    return null;
}

/// A plain, single-quoted, or double-quoted scalar.
fn scalar(arena: Allocator, text: []const u8) Error!Node {
    if (text.len == 0) return error.InvalidYaml;
    if (text[0] == '\'') {
        return .{ .scalar = .{ .text = try unquote_single(arena, text), .style = .single_quoted } };
    }
    if (text[0] == '"') {
        return .{ .scalar = .{ .text = try unquote_double(arena, text), .style = .double_quoted } };
    }
    if (std.mem.indexOfScalar(u8, "&*!|>%@`[{", text[0]) != null) return error.InvalidYaml;
    if (std.mem.indexOf(u8, text, " #")) |end| {
        return .{ .scalar = .{ .text = std.mem.trimEnd(u8, text[0..end], " "), .style = .plain } };
    }
    return .{ .scalar = .{ .text = text, .style = .plain } };
}

/// `'...'` with `''` for a quote; text after the closing quote may only be a comment.
fn unquote_single(arena: Allocator, text: []const u8) Error![]const u8 {
    assert(text[0] == '\'');
    var out: std.ArrayList(u8) = .empty;
    var index: usize = 1;
    while (index < text.len) : (index += 1) {
        if (text[index] != '\'') {
            try out.append(arena, text[index]);
            continue;
        }
        if (index + 1 < text.len and text[index + 1] == '\'') {
            try out.append(arena, '\'');
            index += 1;
            continue;
        }
        try expect_trailer(text[index + 1 ..]);
        return out.toOwnedSlice(arena);
    }
    return error.InvalidYaml; // Unterminated.
}

fn expect_trailer(rest: []const u8) Error!void {
    const trailer = std.mem.trimStart(u8, rest, " ");
    if (trailer.len != 0 and trailer[0] != '#') return error.InvalidYaml;
}

/// `"..."` with YAML's escapes.
fn unquote_double(arena: Allocator, text: []const u8) Error![]const u8 {
    assert(text[0] == '"');
    var out: std.ArrayList(u8) = .empty;
    var index: usize = 1;
    while (index < text.len) : (index += 1) {
        const byte = text[index];
        if (byte == '"') {
            try expect_trailer(text[index + 1 ..]);
            return out.toOwnedSlice(arena);
        }
        if (byte != '\\') {
            try out.append(arena, byte);
            continue;
        }
        index += 1;
        if (index == text.len) return error.InvalidYaml;
        index += try unescape(arena, &out, text[index..]);
    }
    return error.InvalidYaml; // Unterminated.
}

/// Decodes the escape at the start of `rest` (after its backslash) into `out`; returns how
/// many bytes after the escape letter it consumed.
fn unescape(arena: Allocator, out: *std.ArrayList(u8), rest: []const u8) Error!usize {
    assert(rest.len > 0);
    const simple: ?u8 = switch (rest[0]) {
        '0' => 0x00,
        'a' => 0x07,
        'b' => 0x08,
        't', '\t' => 0x09,
        'n' => 0x0A,
        'v' => 0x0B,
        'f' => 0x0C,
        'r' => 0x0D,
        'e' => 0x1B,
        ' ' => ' ',
        '"' => '"',
        '/' => '/',
        '\\' => '\\',
        else => null,
    };
    if (simple) |byte| {
        try out.append(arena, byte);
        return 0;
    }
    const named: ?u21 = switch (rest[0]) {
        'N' => 0x85,
        '_' => 0xA0,
        'L' => 0x2028,
        'P' => 0x2029,
        else => null,
    };
    const digits: usize = switch (rest[0]) {
        'x' => 2,
        'u' => 4,
        'U' => 8,
        else => if (named != null) 0 else return error.InvalidYaml,
    };
    if (rest.len < 1 + digits) return error.InvalidYaml;
    const code: u21 = named orelse
        std.fmt.parseInt(u21, rest[1 .. 1 + digits], 16) catch return error.InvalidYaml;
    var encoded: [4]u8 = undefined;
    const length = std.unicode.utf8Encode(code, &encoded) catch return error.InvalidYaml;
    try out.appendSlice(arena, encoded[0..length]);
    return digits;
}

// --- Writing -----------------------------------------------------------------------------------

/// libyaml's analysis of a scalar (only what block context needs).
const Analysis = struct {
    block_plain_allowed: bool,
    single_quoted_allowed: bool,
};

/// A decoded character of a UTF-8 scalar.
const Char = struct { code: u21, width: u3 };

fn decode(text: []const u8, index: usize) Error!Char {
    const width = std.unicode.utf8ByteSequenceLength(text[index]) catch return error.InvalidValue;
    if (index + width > text.len) return error.InvalidValue;
    const code = std.unicode.utf8Decode(text[index .. index + width]) catch
        return error.InvalidValue;
    return .{ .code = code, .width = width };
}

/// libyaml `IS_PRINTABLE`.
fn is_printable(code: u21) bool {
    return switch (code) {
        0x0A, 0x20...0x7E, 0xA0...0xD7FF => true,
        0xE000...0xFFFD => code != 0xFEFF,
        0x10000...0x10FFFF => true,
        else => false,
    };
}

fn is_break(code: u21) bool {
    return code == '\n' or code == '\r' or code == 0x85 or code == 0x2028 or code == 0x2029;
}

/// Whether the character at `index` is a blank, a break, or the end.
fn blankz_at(text: []const u8, index: usize) bool {
    if (index >= text.len) return true;
    const byte = text[index];
    return byte == ' ' or byte == '\t' or byte == '\n' or byte == '\r' or
        std.mem.startsWith(u8, text[index..], "\u{85}") or
        std.mem.startsWith(u8, text[index..], "\u{2028}") or
        std.mem.startsWith(u8, text[index..], "\u{2029}");
}

/// libyaml `yaml_emitter_analyze_scalar` for a single-line, non-empty scalar.
fn analyze(text: []const u8) Error!Analysis {
    assert(text.len > 0);
    var block_indicators = std.mem.startsWith(u8, text, "---") or
        std.mem.startsWith(u8, text, "...");
    var special = false;
    var preceded_by_whitespace = true;
    var index: usize = 0;
    while (index < text.len) {
        const char = try decode(text, index);
        assert(!is_break(char.code));
        const followed_by_whitespace = blankz_at(text, index + char.width);
        if (index == 0) {
            if (std.mem.indexOfScalar(u8, "#,[]{}&*!|>'\"%@`", text[0]) != null) {
                block_indicators = true;
            }
            const indicator = text[0] == '?' or text[0] == ':' or text[0] == '-';
            if (indicator and followed_by_whitespace) block_indicators = true;
        } else {
            if (char.code == ':' and followed_by_whitespace) block_indicators = true;
            if (char.code == '#' and preceded_by_whitespace) block_indicators = true;
        }
        if (!is_printable(char.code)) special = true;
        preceded_by_whitespace = blankz_at(text, index);
        index += char.width;
    }
    const leading_space = text[0] == ' ';
    const trailing_space = text[text.len - 1] == ' ';
    return .{
        .block_plain_allowed = !(leading_space or trailing_space or special or block_indicators),
        .single_quoted_allowed = !special,
    };
}

/// The style serde_yaml writes `text` in (as a block mapping value or sequence item).
pub fn style_of(text: []const u8) Error!Style {
    for (text) |byte| if (byte == '\n' or byte == '\r') return error.InvalidValue;
    if (std.mem.indexOf(u8, text, "\u{85}") != null) return error.InvalidValue;
    if (std.mem.indexOf(u8, text, "\u{2028}") != null) return error.InvalidValue;
    if (std.mem.indexOf(u8, text, "\u{2029}") != null) return error.InvalidValue;
    if (text.len == 0) return .single_quoted; // libyaml: empty is plain-safe; serde: unit.
    // serde_yaml: anything that would read back as another type is single-quoted.
    const reads_typed = is_null_word(text) or parse_bool(text) != null or
        reads_as_integer(text) or digits_but_not_number(text) or
        (!digits_but_not_number(text) and reads_as_float(text));
    const analysis = try analyze(text);
    if (!reads_typed and analysis.block_plain_allowed) return .plain;
    return if (analysis.single_quoted_allowed) .single_quoted else .double_quoted;
}

/// Writes `text` as serde_yaml does.
pub fn write_string(writer: *Io.Writer, text: []const u8) (Error || Io.Writer.Error)!void {
    switch (try style_of(text)) {
        .plain => try writer.writeAll(text),
        .single_quoted => {
            try writer.writeByte('\'');
            for (text) |byte| {
                if (byte == '\'') try writer.writeByte('\'');
                try writer.writeByte(byte);
            }
            try writer.writeByte('\'');
        },
        .double_quoted => try write_double_quoted(writer, text),
    }
}

/// libyaml `yaml_emitter_write_double_quoted_scalar` without line breaks.
fn write_double_quoted(writer: *Io.Writer, text: []const u8) (Error || Io.Writer.Error)!void {
    try writer.writeByte('"');
    var index: usize = 0;
    while (index < text.len) {
        const char = try decode(text, index);
        const code = char.code;
        const escape = !is_printable(code) or code == 0xFEFF or is_break(code) or
            code == '"' or code == '\\';
        if (!escape) {
            try writer.writeAll(text[index .. index + char.width]);
        } else {
            try write_escape(writer, code);
        }
        index += char.width;
    }
    try writer.writeByte('"');
}

fn write_escape(writer: *Io.Writer, code: u21) Io.Writer.Error!void {
    try writer.writeByte('\\');
    const letter: ?u8 = switch (code) {
        0x00 => '0',
        0x07 => 'a',
        0x08 => 'b',
        0x09 => 't',
        0x0A => 'n',
        0x0B => 'v',
        0x0C => 'f',
        0x0D => 'r',
        0x1B => 'e',
        0x22 => '"',
        0x5C => '\\',
        0x85 => 'N',
        0xA0 => '_',
        0x2028 => 'L',
        0x2029 => 'P',
        else => null,
    };
    if (letter) |byte| return writer.writeByte(byte);
    if (code <= 0xFF) return writer.print("x{X:0>2}", .{code});
    if (code <= 0xFFFF) return writer.print("u{X:0>4}", .{code});
    return writer.print("U{X:0>8}", .{code});
}

/// Writes block YAML in serde_yaml's layout: mapping keys at their column, sequences at their
/// key's column (`key:` then `- item` lines), mappings in sequences as `- key: value` with the
/// following keys two columns in, and `[]`/`{}` for empty collections.
pub const Emitter = struct {
    writer: *Io.Writer,
    /// Column of the current mapping's keys or the current sequence's `-` markers.
    indent: u16 = 0,
    /// The next key opens a sequence item: it is written after `- ` at `indent - 2`.
    dash: bool = false,
    saved: [depth_max]u16 = undefined,
    depth: u8 = 0,

    pub const WriteError = Error || Io.Writer.Error;

    fn save(e: *Emitter) void {
        assert(e.depth < depth_max);
        e.saved[e.depth] = e.indent;
        e.depth += 1;
    }

    fn restore(e: *Emitter) void {
        assert(e.depth > 0);
        assert(!e.dash);
        e.depth -= 1;
        e.indent = e.saved[e.depth];
    }

    fn spaces(e: *Emitter, count: u16) Io.Writer.Error!void {
        for (0..count) |_| try e.writer.writeByte(' ');
    }

    /// `key:` at the current column (or after a pending item's `- `).
    pub fn key(e: *Emitter, name: []const u8) WriteError!void {
        assert(name.len > 0);
        if (e.dash) {
            try e.spaces(e.indent - 2);
            try e.writer.writeAll("- ");
            e.dash = false;
        } else {
            try e.spaces(e.indent);
        }
        try write_string(e.writer, name);
        try e.writer.writeByte(':');
    }

    pub fn string_field(e: *Emitter, name: []const u8, text: []const u8) WriteError!void {
        try e.key(name);
        try e.writer.writeByte(' ');
        try write_string(e.writer, text);
        try e.writer.writeByte('\n');
    }

    pub fn int_field(e: *Emitter, name: []const u8, value: anytype) WriteError!void {
        try e.key(name);
        try e.writer.print(" {d}\n", .{value});
    }

    pub fn bool_field(e: *Emitter, name: []const u8, value: bool) WriteError!void {
        try e.key(name);
        try e.writer.writeAll(if (value) " true\n" else " false\n");
    }

    /// `name:` then a mapping of at least one field, two columns in; close with `end`.
    pub fn begin_map(e: *Emitter, name: []const u8) WriteError!void {
        try e.key(name);
        try e.writer.writeByte('\n');
        e.save();
        e.indent += 2;
    }

    /// `name: []`, or `name:` then items at the key's column; close with `end`.
    pub fn begin_list(e: *Emitter, name: []const u8, len: usize) WriteError!void {
        try e.key(name);
        try e.writer.writeAll(if (len == 0) " []\n" else "\n");
        e.save();
    }

    /// Starts a sequence item that is a mapping; close with `end`.
    pub fn begin_item(e: *Emitter) void {
        assert(!e.dash);
        e.save();
        e.indent += 2;
        e.dash = true;
    }

    pub fn string_item(e: *Emitter, text: []const u8) WriteError!void {
        assert(!e.dash);
        try e.spaces(e.indent);
        try e.writer.writeAll("- ");
        try write_string(e.writer, text);
        try e.writer.writeByte('\n');
    }

    pub fn end(e: *Emitter) void {
        e.restore();
    }
};
