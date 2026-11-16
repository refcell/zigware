//! Terminal key decoding: crossterm 0.29's Unix parser (`event/sys/unix/parse.rs`) for the keys
//! chat reacts to. Bytes are fed one at a time as crossterm's `Parser::advance` does: a complete
//! sequence yields a key, an incomplete one waits for more bytes, and an invalid one clears the
//! buffer. Sequences chat ignores (Home, function keys, mouse, focus, cursor reports) are
//! consumed with crossterm's boundaries and yield `.other`.

const std = @import("std");
const assert = std.debug.assert;

pub const Key = union(enum) {
    /// A character, including Ctrl and Alt combinations (crossterm `KeyCode::Char`).
    char: u21,
    backspace,
    tab,
    enter,
    esc,
    up,
    down,
    left,
    right,
    /// A key or event chat ignores.
    other,
};

/// Longest pending sequence kept. crossterm's buffer is unbounded; a longer sequence is
/// dropped as invalid.
pub const sequence_size_max = 64;

const Outcome = union(enum) { wait, invalid, key: Key };

pub const Parser = struct {
    buffer: [sequence_size_max]u8 = undefined,
    len: u8 = 0,

    /// crossterm `Parser::advance`: feeds `bytes`, where `more` says more input is already
    /// pending after them, and writes each completed key to `keys`. Returns the key count.
    /// Each byte completes at most one key, so `keys` needs `bytes.len` slots.
    pub fn advance(parser: *Parser, bytes: []const u8, more: bool, keys: []Key) usize {
        assert(keys.len >= bytes.len);
        assert(parser.len < sequence_size_max);
        var count: usize = 0;
        for (bytes, 0..) |byte, index| {
            parser.buffer[parser.len] = byte;
            parser.len += 1;
            const pending = more or index + 1 < bytes.len;
            switch (parse(parser.buffer[0..parser.len], pending)) {
                .key => |key| {
                    keys[count] = key;
                    count += 1;
                    parser.len = 0;
                },
                .wait => if (parser.len == sequence_size_max) {
                    parser.len = 0;
                },
                .invalid => parser.len = 0,
            }
        }
        assert(count <= bytes.len);
        return count;
    }
};

/// crossterm `parse_event`.
fn parse(buffer: []const u8, more: bool) Outcome {
    assert(buffer.len > 0);
    assert(buffer.len <= sequence_size_max);
    if (buffer[0] != 0x1b) return parse_plain(buffer);
    if (buffer.len == 1) return if (more) .wait else .{ .key = .esc };
    return switch (buffer[1]) {
        'O' => parse_ss3(buffer),
        '[' => parse_csi(buffer),
        0x1b => .{ .key = .esc },
        // Alt+key: crossterm parses the rest, which starts with a byte other than ESC.
        else => parse_plain(buffer[1..]),
    };
}

/// A sequence that does not start with ESC (raw mode, so `\n` is Ctrl+J).
fn parse_plain(buffer: []const u8) Outcome {
    assert(buffer.len > 0);
    assert(buffer[0] != 0x1b);
    const byte = buffer[0];
    return switch (byte) {
        '\r' => .{ .key = .enter },
        '\t' => .{ .key = .tab },
        0x7f => .{ .key = .backspace },
        0x01...0x08, 0x0a...0x0c, 0x0e...0x1a => .{ .key = .{ .char = byte - 0x01 + 'a' } },
        0x1c...0x1f => .{ .key = .{ .char = byte - 0x1c + '4' } },
        0x00 => .{ .key = .{ .char = ' ' } },
        else => parse_utf8_char(buffer),
    };
}

/// ESC O: SS3 cursor keys and F1 to F4.
fn parse_ss3(buffer: []const u8) Outcome {
    assert(buffer.len >= 2);
    assert(buffer[1] == 'O');
    if (buffer.len == 2) return .wait;
    return switch (buffer[2]) {
        'A' => .{ .key = .up },
        'B' => .{ .key = .down },
        'C' => .{ .key = .right },
        'D' => .{ .key = .left },
        'H', 'F', 'P'...'S' => .{ .key = .other },
        else => .invalid,
    };
}

/// ESC [: crossterm `parse_csi`.
fn parse_csi(buffer: []const u8) Outcome {
    assert(buffer.len >= 2);
    assert(buffer[1] == '[');
    if (buffer.len == 2) return .wait;
    const last = buffer[buffer.len - 1];
    return switch (buffer[2]) {
        '[' => if (buffer.len == 3)
            .wait
        else switch (buffer[3]) {
            'A'...'E' => .{ .key = .other },
            else => .invalid,
        },
        'A' => .{ .key = .up },
        'B' => .{ .key = .down },
        'C' => .{ .key = .right },
        'D' => .{ .key = .left },
        'H', 'F', 'Z', 'P', 'Q', 'S', 'I', 'O' => .{ .key = .other },
        // Normal mouse: ESC [ M and three bytes.
        'M' => if (buffer.len < 6) .wait else .{ .key = .other },
        // SGR mouse ends in `m` or `M`.
        '<' => if (last == 'm' or last == 'M') .{ .key = .other } else .wait,
        ';' => parse_csi_modifier_key_code(buffer),
        '?' => if (last == 'u' or last == 'c') .{ .key = .other } else .wait,
        '0'...'9' => if (buffer.len == 3 or last < 64 or last > 126)
            .wait
        else switch (last) {
            // rxvt mouse, special keys (Delete, PageUp, ...), CSI u keys, cursor position.
            'M', '~', 'u', 'R' => .{ .key = .other },
            else => parse_csi_modifier_key_code(buffer),
        },
        else => .invalid,
    };
}

/// crossterm `parse_csi_modifier_key_code`: `ESC [ 1 ; <modifiers> <key>`. The modifiers must
/// parse, but chat ignores them.
fn parse_csi_modifier_key_code(buffer: []const u8) Outcome {
    assert(buffer.len >= 3);
    assert(std.mem.startsWith(u8, buffer, "\x1b["));
    const parameters = buffer[2 .. buffer.len - 1];
    if (!std.unicode.utf8ValidateSlice(parameters)) return .invalid;
    var fields = std.mem.splitScalar(u8, parameters, ';');
    _ = fields.next();
    const modifiers_parse = if (fields.next()) |field|
        parse_u8(std.mem.sliceTo(field, ':'))
    else
        false;
    if (!modifiers_parse and buffer.len > 3 and !std.ascii.isDigit(buffer[buffer.len - 2])) {
        return .invalid;
    }
    return switch (buffer[buffer.len - 1]) {
        'A' => .{ .key = .up },
        'B' => .{ .key = .down },
        'C' => .{ .key = .right },
        'D' => .{ .key = .left },
        'F', 'H', 'P', 'Q', 'R', 'S' => .{ .key = .other },
        else => .invalid,
    };
}

/// Whether `text` parses as Rust's `u8::from_str`: an optional `+`, then one or more decimal
/// digits whose value fits.
fn parse_u8(text: []const u8) bool {
    const digits = if (std.mem.startsWith(u8, text, "+")) text[1..] else text;
    if (digits.len == 0) return false;
    var value: u16 = 0;
    for (digits) |digit| {
        if (!std.ascii.isDigit(digit)) return false;
        value = value * 10 + (digit - '0');
        if (value > std.math.maxInt(u8)) return false;
    }
    assert(value <= std.math.maxInt(u8));
    return true;
}

/// crossterm `parse_utf8_char`: one character, or wait while the bytes so far start a valid
/// encoding.
fn parse_utf8_char(buffer: []const u8) Outcome {
    assert(buffer.len > 0);
    if (std.unicode.utf8ValidateSlice(buffer)) {
        const length = std.unicode.utf8ByteSequenceLength(buffer[0]) catch unreachable;
        const char = std.unicode.utf8Decode(buffer[0..length]) catch unreachable;
        return .{ .key = .{ .char = char } };
    }
    const required: usize = switch (buffer[0]) {
        0x00...0x7f => 1,
        0xc0...0xdf => 2,
        0xe0...0xef => 3,
        0xf0...0xf7 => 4,
        0x80...0xbf, 0xf8...0xff => return .invalid,
    };
    if (required > 1) {
        for (buffer[1..]) |byte| if (byte & 0b1100_0000 != 0b1000_0000) return .invalid;
    }
    assert(required >= 1);
    return if (buffer.len < required) .wait else .invalid;
}
