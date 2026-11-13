//! formatting: Format and parse encoded data.
//!
//! Zig port of commonware's `commonware-formatting` crate
//! (https://github.com/commonwarexyz/monorepo/tree/main/formatting).
//!
//! - `hex` / `hex_encode`: bytes to lowercase hexadecimal.
//! - `from_hex`: hexadecimal to bytes, ignoring ASCII whitespace and one `0x`/`0X` prefix.
//! - `Hex` / `fmt_hex`: a `{f}` formatter that renders bytes as lowercase hex without
//!   allocating.
//! - `hex_literal`: comptime hex literal parsing (commonware's `hex!` macro).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const hex_digits_lower = "0123456789abcdef";

/// Writes the lowercase hexadecimal encoding of `bytes` into `out` and returns the written
/// prefix. `out` must hold at least `2 * bytes.len` bytes.
pub fn hex_encode(out: []u8, bytes: []const u8) []u8 {
    assert(out.len >= bytes.len * 2);
    for (bytes, 0..) |byte, index| {
        out[index * 2] = hex_digits_lower[byte >> 4];
        out[index * 2 + 1] = hex_digits_lower[byte & 0x0f];
    }
    const written = out[0 .. bytes.len * 2];
    assert(written.len % 2 == 0);
    return written;
}

/// Converts bytes to a newly allocated lowercase hexadecimal string. Caller owns the result.
pub fn hex(gpa: Allocator, bytes: []const u8) Allocator.Error![]u8 {
    const out = try gpa.alloc(u8, bytes.len * 2);
    const written = hex_encode(out, bytes);
    assert(written.len == out.len);
    return out;
}

fn hex_value(char: u8) ?u8 {
    return switch (char) {
        '0'...'9' => char - '0',
        'a'...'f' => char - 'a' + 10,
        'A'...'F' => char - 'A' + 10,
        else => null,
    };
}

fn is_hex_whitespace(char: u8) bool {
    return char == ' ' or char == '\t' or char == '\n' or char == '\r';
}

/// Converts a hexadecimal string to newly allocated bytes, stripping ASCII whitespace
/// (space, tab, newline, carriage return) and an optional `0x` / `0X` prefix. Returns null if
/// the input is not valid hex. Caller owns the result.
///
/// Matches commonware exactly: whitespace is removed first, then a leading `0X` is stripped,
/// then `const-hex` strips one more leading `0x` or `0X`.
pub fn from_hex(gpa: Allocator, string: []const u8) Allocator.Error!?[]u8 {
    const compact = try gpa.alloc(u8, string.len);
    defer gpa.free(compact);
    var compact_len: usize = 0;
    for (string) |char| {
        if (is_hex_whitespace(char)) continue;
        compact[compact_len] = char;
        compact_len += 1;
    }
    var digits = compact[0..compact_len];
    if (std.mem.startsWith(u8, digits, "0X")) digits = digits[2..];
    if (digits.len >= 2 and digits[0] == '0' and (digits[1] == 'x' or digits[1] == 'X')) {
        digits = digits[2..];
    }
    if (digits.len % 2 != 0) return null;

    const out = try gpa.alloc(u8, digits.len / 2);
    for (out, 0..) |*byte, index| {
        const high = hex_value(digits[index * 2]) orelse {
            gpa.free(out);
            return null;
        };
        const low = hex_value(digits[index * 2 + 1]) orelse {
            gpa.free(out);
            return null;
        };
        byte.* = (high << 4) | low;
    }
    assert(out.len * 2 == digits.len);
    return out;
}

/// Formatter that renders bytes as lowercase hex without allocating. Use with `{f}`:
/// `try writer.print("{f}", .{formatting.fmt_hex(digest)})`.
pub const Hex = struct {
    bytes: []const u8,

    pub fn format(self: Hex, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        // Encode in fixed chunks so arbitrary input lengths need no heap allocation.
        const chunk_size = 64;
        var buffer: [chunk_size * 2]u8 = undefined;
        var offset: usize = 0;
        while (offset < self.bytes.len) {
            const end = @min(offset + chunk_size, self.bytes.len);
            try writer.writeAll(hex_encode(&buffer, self.bytes[offset..end]));
            offset = end;
        }
        assert(offset == self.bytes.len);
    }
};

/// Returns a `Hex` formatter for `bytes`.
pub fn fmt_hex(bytes: []const u8) Hex {
    return .{ .bytes = bytes };
}

/// Removes at most one leading `0x` or `0X` prefix from `string`.
pub fn strip_hex_prefix(string: []const u8) []const u8 {
    if (string.len >= 2 and string[0] == '0' and (string[1] == 'x' or string[1] == 'X')) {
        return string[2..];
    }
    return string;
}

fn literal_digit(comptime char: u8) ?u8 {
    if (is_hex_whitespace(char)) return null;
    if (hex_value(char)) |digit| return digit;
    if (char < 128) @compileError("hex_literal: encountered invalid ASCII character");
    @compileError("hex_literal: encountered non-ASCII character");
}

/// Number of bytes a hex literal decodes to, after its optional prefix and whitespace.
pub fn hex_literal_len(comptime literal: []const u8) usize {
    @setEvalBranchQuota(literal.len * 16 + 1000);
    comptime var digits: usize = 0;
    inline for (comptime strip_hex_prefix(literal)) |char| {
        if (comptime literal_digit(char) != null) digits += 1;
    }
    if (digits % 2 != 0) @compileError("hex_literal: odd number of hex characters");
    return digits / 2;
}

fn hex_literal_decode(comptime literal: []const u8) [hex_literal_len(literal)]u8 {
    @setEvalBranchQuota(literal.len * 16 + 1000);
    var out: [hex_literal_len(literal)]u8 = undefined;
    var digit_count: usize = 0;
    for (strip_hex_prefix(literal)) |char| {
        const digit = literal_digit(char) orelse continue;
        if (digit_count % 2 == 0) {
            out[digit_count / 2] = digit << 4;
        } else {
            out[digit_count / 2] |= digit;
        }
        digit_count += 1;
    }
    assert(digit_count == out.len * 2);
    return out;
}

/// Decodes a hex literal at compile time (commonware's `hex!`). The literal may begin with
/// `0x` or `0X`; spaces, tabs, carriage returns, and newlines are ignored. Concatenate the
/// results with `++` to join several literals, each with its own optional prefix.
pub fn hex_literal(comptime literal: []const u8) [hex_literal_len(literal)]u8 {
    return comptime hex_literal_decode(literal);
}

const testing = std.testing;

fn expect_from_hex(expected: ?[]const u8, input: []const u8) !void {
    const decoded = try from_hex(testing.allocator, input);
    defer if (decoded) |d| testing.allocator.free(d);
    if (expected) |e| {
        try testing.expect(decoded != null);
        try testing.expectEqualSlices(u8, e, decoded.?);
    } else {
        try testing.expect(decoded == null);
    }
}

test "hex roundtrip" {
    const cases = [_]struct { bytes: []const u8, encoded: []const u8 }{
        .{ .bytes = &.{}, .encoded = "" },
        .{ .bytes = &.{0x01}, .encoded = "01" },
        .{ .bytes = &.{ 0x01, 0x02, 0x03 }, .encoded = "010203" },
    };
    for (cases) |case| {
        const encoded = try hex(testing.allocator, case.bytes);
        defer testing.allocator.free(encoded);
        try testing.expectEqualStrings(case.encoded, encoded);
        try expect_from_hex(case.bytes, case.encoded);
    }
}

test "from_hex" {
    const expected = &[_]u8{ 0x01, 0x02, 0x03 };
    try expect_from_hex(expected, "010203");
    try expect_from_hex(expected, "01 02 03");
    try expect_from_hex(expected, "0x010203");
    try expect_from_hex(expected, "0X010203");
    try expect_from_hex(expected, "    \n\n0x\r\n01\n                            02\t03\n");
    try expect_from_hex(&.{}, "");
    try expect_from_hex(null, "0102030");
    try expect_from_hex(null, "01g3");
    try expect_from_hex(null, "+123");
}

test "from_hex utf8 char boundaries" {
    try expect_from_hex(null, "쀘\n");
}

test "from_hex prefix order matches commonware" {
    try expect_from_hex(&.{0x12}, "0X0x12");
    try expect_from_hex(null, "0x0X12");
}

test "hex formatter display" {
    const bytes = [_]u8{ 0x01, 0x02, 0xab, 0xcd };
    var buffer: [512]u8 = undefined;
    try testing.expectEqualStrings("0102abcd", try std.fmt.bufPrint(&buffer, "{f}", .{
        fmt_hex(&bytes),
    }));
    try testing.expectEqualStrings("", try std.fmt.bufPrint(&buffer, "{f}", .{fmt_hex(&.{})}));
    try testing.expectEqualStrings("ff00", try std.fmt.bufPrint(&buffer, "{f}", .{
        Hex{ .bytes = &.{ 0xff, 0x00 } },
    }));

    // Larger than the internal chunk to exercise the loop.
    var big: [200]u8 = undefined;
    for (&big, 0..) |*byte, index| byte.* = @truncate(index);
    const formatted = try std.fmt.bufPrint(&buffer, "{f}", .{fmt_hex(&big)});
    const owned = try hex(testing.allocator, &big);
    defer testing.allocator.free(owned);
    try testing.expectEqualStrings(owned, formatted);
}

test "hex_literal single" {
    try testing.expectEqual([_]u8{ 0xff, 0xe4 }, hex_literal("ff e4"));
}

test "hex_literal empty" {
    try testing.expectEqual([0]u8{}, hex_literal(""));
    try testing.expectEqual([0]u8{}, hex_literal("") ++ hex_literal("") ++ hex_literal(""));
}

test "hex_literal case" {
    try testing.expectEqual([_]u8{ 0xae, 0xdf, 0x04, 0xb2 }, hex_literal("AE DF 04 B2"));
    try testing.expectEqual([_]u8{ 0xff, 0xba, 0x8c, 0x00, 0x01 }, hex_literal("FF BA 8C 00 01"));
    try testing.expectEqual([_]u8{ 0xbf, 0xdd, 0xe4, 0xcd }, hex_literal("bF dd E4 Cd"));
}

test "hex_literal optional prefix" {
    const expected = [_]u8{ 0x1a, 0x2b, 0x3c };
    try testing.expectEqual(expected, hex_literal("1a2b3c"));
    try testing.expectEqual(expected, hex_literal("0x1a2b3c"));
    try testing.expectEqual(expected, hex_literal("0X1a2b3c"));
    try testing.expectEqual(
        [_]u8{ 0xa1, 0xb2, 0xc3 },
        hex_literal("0xa1") ++ hex_literal("b2") ++ hex_literal("0Xc3"),
    );
}

test "strip_hex_prefix strips exactly one prefix" {
    try testing.expectEqualStrings("12", strip_hex_prefix("0x12"));
    try testing.expectEqualStrings("12", strip_hex_prefix("0X12"));
    try testing.expectEqualStrings("0X12", strip_hex_prefix("0x0X12"));
    try testing.expectEqualStrings("x012", strip_hex_prefix("x012"));
}

test "hex_literal multiple and spacing" {
    try testing.expectEqual(
        [_]u8{ 0x01, 0xdd, 0xf7, 0x7f, 0xee, 0xf0, 0xd8 },
        hex_literal("01 dd f7 7f") ++ hex_literal("ee f0 d8"),
    );
    try testing.expectEqual(
        [_]u8{ 0xab, 0xf0, 0xd8, 0xbb, 0x0f, 0x14 },
        hex_literal("abf0d8bb0f14"),
    );
    try testing.expectEqual(
        [_]u8{ 0x09, 0xff, 0xd8, 0x90, 0xcb, 0xcc, 0xd1, 0xd0, 0x8f },
        hex_literal("09FFd890cbcCd1d08F"),
    );
    try testing.expectEqual([_]u8{ 0xff, 0xd0, 0xe8 }, hex_literal("f\n f\n d\n 0\n e\n\n 8\n "));
    try testing.expectEqual(
        [_]u8{ 0x9f, 0xd1, 0xf0, 0x73, 0x01 },
        hex_literal("9f\td\t\t1\t\tf07\t3\t\t01\t"),
    );
    const spaced = hex_literal(" e    e d0  9 1   f  f  ");
    try testing.expectEqual([_]u8{ 0xee, 0xd0, 0x91, 0xff }, spaced);
}

test "hex_literal usable in const" {
    const bytes = comptime hex_literal("ff d3 01 7f");
    comptime assert(bytes.len == 4);
}

fn fuzz_hex_roundtrip(_: void, smith: *testing.Smith) anyerror!void {
    var input: [256]u8 = undefined;
    const len = smith.slice(&input);
    const encoded = try hex(testing.allocator, input[0..len]);
    defer testing.allocator.free(encoded);
    const decoded = (try from_hex(testing.allocator, encoded)).?;
    defer testing.allocator.free(decoded);
    try testing.expectEqualSlices(u8, input[0..len], decoded);
}

fn fuzz_from_hex(_: void, smith: *testing.Smith) anyerror!void {
    var input: [256]u8 = undefined;
    const len = smith.slice(&input);
    const decoded = try from_hex(testing.allocator, input[0..len]);
    if (decoded) |bytes| {
        defer testing.allocator.free(bytes);
        try testing.expect(bytes.len * 2 <= len);
    }
}

test "fuzz hex roundtrip" {
    try testing.fuzz({}, fuzz_hex_roundtrip, .{});
}

test "fuzz from_hex" {
    try testing.fuzz({}, fuzz_from_hex, .{ .corpus = &.{ "0x0102", "zz", "0X0x12" } });
}
