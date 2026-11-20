//! The pieces of Rust's standard library whose exact behavior the estimator's output depends
//! on: `str::lines`, integer and float parsing (with their error kinds), `f64 as u64`,
//! `Duration::from_secs_f64`, fixed-precision float formatting (`{:.2}`), and `{:?}` of a
//! string. Each matches Rust's results bit for bit, so the port prints what commonware prints.
//!
//! Text is handled as bytes: whitespace is ASCII whitespace, and positions are byte offsets.

const std = @import("std");
const assert = std.debug.assert;
const zigware = @import("zigware");
const ui = @import("ui");

const Duration = zigware.utils.Duration;

/// ASCII whitespace, as Rust's `char::is_whitespace` sees it in the ASCII range.
pub const whitespace = " \t\n\r\x0B\x0C";

pub fn trim(text: []const u8) []const u8 {
    return std.mem.trim(u8, text, whitespace);
}

pub fn is_whitespace(byte: u8) bool {
    return std.mem.indexOfScalar(u8, whitespace, byte) != null;
}

/// Rust `str::lines`: split at `\n`, drop one `\r` before each `\n`, and no empty final line
/// after a trailing `\n`. A bare `\r` at the very end is kept.
pub const Lines = struct {
    text: []const u8,
    index: usize = 0,

    pub fn next(lines: *Lines) ?[]const u8 {
        assert(lines.index <= lines.text.len);
        if (lines.index == lines.text.len) return null;
        const rest = lines.text[lines.index..];
        const newline = std.mem.indexOfScalar(u8, rest, '\n') orelse {
            lines.index = lines.text.len;
            return rest;
        };
        lines.index += newline + 1;
        const line = rest[0..newline];
        if (line.len > 0 and line[line.len - 1] == '\r') return line[0 .. line.len - 1];
        return line;
    }
};

/// Rust `IntErrorKind`, printed as `ParseIntError { kind: ... }`.
pub const ParseIntError = ui.rust.ParseIntError;

/// Rust `FloatErrorKind`, printed as `ParseFloatError { kind: ... }`.
pub const ParseFloatError = error{ Empty, Invalid };

/// Rust `str::parse::<T>()` for an unsigned integer: an optional `+`, then decimal digits.
pub const parse_unsigned = ui.rust.parse_unsigned;

/// Rust `str::parse::<f64>()`: `[+-]` then `inf`, `infinity`, or `nan` (any case), or decimal
/// digits with an optional fraction and exponent (`1.`, `.5`, `1e5`). Correctly rounded.
pub fn parse_f64(text: []const u8) ParseFloatError!f64 {
    if (text.len == 0) return error.Empty;
    const negative = text[0] == '-';
    const body = if (text[0] == '+' or text[0] == '-') text[1..] else text;
    const magnitude: f64 = if (is_special(body, "inf") or is_special(body, "infinity"))
        std.math.inf(f64)
    else if (is_special(body, "nan"))
        std.math.nan(f64)
    else blk: {
        if (!is_decimal(body)) return error.Invalid;
        break :blk std.fmt.parseFloat(f64, body) catch return error.Invalid;
    };
    return if (negative) -magnitude else magnitude;
}

fn is_special(body: []const u8, word: []const u8) bool {
    return std.ascii.eqlIgnoreCase(body, word);
}

/// `Digit* ('.' Digit*)? ([eE] [+-]? Digit+)?` with at least one mantissa digit.
fn is_decimal(body: []const u8) bool {
    var index: usize = 0;
    var mantissa_digits: usize = 0;
    while (index < body.len and std.ascii.isDigit(body[index])) index += 1;
    mantissa_digits += index;
    if (index < body.len and body[index] == '.') {
        index += 1;
        const start = index;
        while (index < body.len and std.ascii.isDigit(body[index])) index += 1;
        mantissa_digits += index - start;
    }
    if (mantissa_digits == 0) return false;
    if (index == body.len) return true;
    if (body[index] != 'e' and body[index] != 'E') return false;
    index += 1;
    if (index < body.len and (body[index] == '+' or body[index] == '-')) index += 1;
    const exponent_start = index;
    while (index < body.len and std.ascii.isDigit(body[index])) index += 1;
    return index > exponent_start and index == body.len;
}

/// Rust `f64 as u64`: truncates toward zero, saturates, and maps NaN to zero.
pub fn f64_to_u64(value: f64) u64 {
    if (!(value > 0)) return 0;
    if (value >= 18446744073709551616.0) return std.math.maxInt(u64);
    return @intFromFloat(value);
}

/// The binary decomposition `mantissa * 2^exponent` of a finite, non-negative `value`.
const Decomposed = struct { mantissa: u64, exponent: i32 };

fn decompose(value: f64) Decomposed {
    assert(std.math.isFinite(value));
    assert(!std.math.signbit(value));
    const bits: u64 = @bitCast(value);
    const biased: i32 = @intCast(bits >> 52);
    const fraction = bits & ((@as(u64, 1) << 52) - 1);
    if (biased == 0) return .{ .mantissa = fraction, .exponent = -1074 };
    return .{ .mantissa = fraction | (@as(u64, 1) << 52), .exponent = biased - 1075 };
}

/// `numerator / 2^shift`, rounded to the nearest integer with ties to even.
fn shift_round_even(numerator: u128, shift: u32) u128 {
    if (shift == 0) return numerator;
    // A numerator below 2^127 is below half of 2^shift for any shift of 128 or more.
    assert(numerator < (@as(u128, 1) << 127));
    if (shift >= 128) return 0;
    const shift_amount: u7 = @intCast(shift);
    const quotient = numerator >> shift_amount;
    const remainder = numerator & ((@as(u128, 1) << shift_amount) - 1);
    const half = @as(u128, 1) << @intCast(shift - 1);
    const round_up = remainder > half or (remainder == half and quotient & 1 == 1);
    return quotient + @intFromBool(round_up);
}

pub const DurationError = error{ Negative, OverflowOrNan };

/// Rust `Duration::try_from_secs_f64`: the exact value rounded to the nearest nanosecond, ties
/// to even. `-0.0` is zero; any other negative value is `Negative`.
pub fn duration_from_secs_f64(secs: f64) DurationError!Duration {
    if (std.math.isNan(secs)) return error.OverflowOrNan;
    if (secs < 0) return error.Negative;
    if (secs >= 18446744073709551616.0) return error.OverflowOrNan;
    const parts = decompose(@abs(secs));
    if (parts.exponent >= 0) {
        const whole = @as(u128, parts.mantissa) << @intCast(parts.exponent);
        assert(whole <= std.math.maxInt(u64));
        return Duration.init(@intCast(whole), 0);
    }
    const shift: u32 = @intCast(-parts.exponent);
    const whole: u64 = if (shift >= 64) 0 else parts.mantissa >> @intCast(shift);
    const fraction: u64 = if (shift >= 64) parts.mantissa else blk: {
        break :blk parts.mantissa & ((@as(u64, 1) << @intCast(shift)) - 1);
    };
    const nanos = shift_round_even(@as(u128, fraction) * std.time.ns_per_s, shift);
    assert(nanos <= std.time.ns_per_s);
    if (nanos == std.time.ns_per_s) {
        const carried = std.math.add(u64, whole, 1) catch return error.OverflowOrNan;
        return Duration.init(carried, 0);
    }
    return Duration.init(whole, @intCast(nanos));
}

/// Rust `format!("{value:.precision$}")`: the exact decimal value of `value` rounded to
/// `precision` fractional digits with ties to even (Zig's `{d:.2}` rounds ties away and
/// rounds the shortest representation instead, so `1.005` and `0.125` differ).
pub fn write_fixed(writer: *std.Io.Writer, value: f64, precision: u8) std.Io.Writer.Error!void {
    assert(precision <= 9);
    if (std.math.isNan(value)) return writer.writeAll("NaN");
    if (std.math.signbit(value)) try writer.writeByte('-');
    if (std.math.isInf(value)) return writer.writeAll("inf");
    const parts = decompose(@abs(value));
    if (parts.exponent >= 0) {
        try write_integer_shifted(writer, parts.mantissa, @intCast(parts.exponent));
        if (precision > 0) {
            try writer.writeByte('.');
            try writer.splatByteAll('0', precision);
        }
        return;
    }
    const scale = std.math.pow(u64, 10, precision);
    const scaled = @as(u128, parts.mantissa) * scale;
    const rounded = shift_round_even(scaled, @intCast(-parts.exponent));
    var digits: [48]u8 = undefined;
    const text = std.fmt.bufPrint(&digits, "{d}", .{rounded}) catch unreachable; // 40 digits.
    if (precision == 0) return writer.writeAll(text);
    if (text.len <= precision) {
        try writer.writeAll("0.");
        try writer.splatByteAll('0', precision - text.len);
        return writer.writeAll(text);
    }
    try writer.writeAll(text[0 .. text.len - precision]);
    try writer.writeByte('.');
    try writer.writeAll(text[text.len - precision ..]);
}

/// Writes `mantissa * 2^exponent` in decimal using base-10^9 limbs (at most 2^1077).
fn write_integer_shifted(
    writer: *std.Io.Writer,
    mantissa: u64,
    exponent: u32,
) std.Io.Writer.Error!void {
    assert(exponent <= 1024);
    const base: u64 = 1_000_000_000;
    var limbs: [40]u64 = undefined; // little-endian; 2^1077 < 10^325 needs 37 limbs.
    var count: usize = 0;
    var rest = mantissa;
    while (true) {
        limbs[count] = rest % base;
        count += 1;
        rest /= base;
        if (rest == 0) break;
    }
    for (0..exponent) |_| {
        var carry: u64 = 0;
        for (limbs[0..count]) |*limb| {
            const doubled = limb.* * 2 + carry;
            limb.* = doubled % base;
            carry = doubled / base;
        }
        if (carry > 0) {
            assert(count < limbs.len);
            limbs[count] = carry;
            count += 1;
        }
    }
    try writer.print("{d}", .{limbs[count - 1]});
    var index = count - 1;
    while (index > 0) {
        index -= 1;
        try writer.print("{d:0>9}", .{limbs[index]});
    }
}

/// Rust `{:?}` of a string: quoted, with `"`, `\`, and control characters escaped.
pub fn write_debug_string(writer: *std.Io.Writer, text: []const u8) std.Io.Writer.Error!void {
    try writer.writeByte('"');
    for (text) |byte| switch (byte) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        '\t' => try writer.writeAll("\\t"),
        '\r' => try writer.writeAll("\\r"),
        '\n' => try writer.writeAll("\\n"),
        0 => try writer.writeAll("\\0"),
        1...8, 0x0B, 0x0C, 0x0E...0x1F, 0x7F => try writer.print("\\u{{{x}}}", .{byte}),
        else => try writer.writeByte(byte),
    };
    try writer.writeByte('"');
}

const testing = std.testing;

fn expect_fixed(expected: []const u8, value: f64, precision: u8) !void {
    var buffer: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&buffer);
    try write_fixed(&writer, value, precision);
    try testing.expectEqualStrings(expected, writer.buffered());
}

test "write_fixed matches Rust {:.2} and {:.0}" {
    // Generated with rustc: `format!("{v:.2} {v:.0}")`.
    const cases = [_]struct { f64, []const u8, []const u8 }{
        .{ 0.125, "0.12", "0" },
        .{ 0.375, "0.38", "0" },
        .{ 0.625, "0.62", "1" },
        .{ 2.5, "2.50", "2" },
        .{ 1.005, "1.00", "1" },
        .{ 17.125, "17.12", "17" },
        .{ 0.0, "0.00", "0" },
        .{ -0.0, "-0.00", "-0" },
        .{ 1e21, "1000000000000000000000.00", "1000000000000000000000" },
        .{ 123456789.125, "123456789.12", "123456789" },
        .{ 0.5, "0.50", "0" },
        .{ 1.5, "1.50", "2" },
        .{ 3.5, "3.50", "4" },
        .{ 0.875, "0.88", "1" },
        .{ 1.125, "1.12", "1" },
        .{ 0.005, "0.01", "0" },
        .{ 0.015, "0.01", "0" },
        .{ 0.025, "0.03", "0" },
        .{ 1e-300, "0.00", "0" },
        .{ 69.8, "69.80", "70" },
    };
    for (cases) |case| {
        try expect_fixed(case[1], case[0], 2);
        try expect_fixed(case[2], case[0], 0);
    }
    try expect_fixed("NaN", std.math.nan(f64), 2);
    try expect_fixed("inf", std.math.inf(f64), 2);
    try expect_fixed("-inf", -std.math.inf(f64), 2);
    try expect_fixed("1267650600228229401496703205376.00", std.math.pow(f64, 2, 100), 2);
    try expect_fixed("0.00", 5e-324, 2);
    try expect_fixed("2251799813685248.50", 2251799813685248.5, 2);
}

test "duration_from_secs_f64 matches Rust Duration::from_secs_f64" {
    // Generated with rustc: `Duration::from_secs_f64(v).as_nanos()`.
    const cases = [_]struct { f64, u128 }{
        .{ 0.1 / 1000.0, 100_000 },
        .{ 1.5e-9, 1 },
        .{ 2.5e-9, 3 },
        .{ std.math.pow(f64, 2, -10), 976_562 },
        .{ 3.0 * std.math.pow(f64, 2, -10), 2_929_688 },
        .{ std.math.pow(f64, 2, -31), 0 },
        .{ 3.0 * std.math.pow(f64, 2, -31), 1 },
        .{ 5.0 * std.math.pow(f64, 2, -31), 2 },
        .{ 0.9999999999999999, 1_000_000_000 },
        .{ 1.0000000005, 1_000_000_001 },
        .{ -0.0, 0 },
        .{ 0.5 / 1000.0, 500_000 },
    };
    for (cases) |case| {
        const duration = try duration_from_secs_f64(case[0]);
        try testing.expectEqual(case[1], duration.as_nanos());
    }
    try testing.expectError(error.Negative, duration_from_secs_f64(-1e-40));
    try testing.expectError(error.OverflowOrNan, duration_from_secs_f64(std.math.nan(f64)));
    try testing.expectError(error.OverflowOrNan, duration_from_secs_f64(1e20));
    try testing.expectError(error.OverflowOrNan, duration_from_secs_f64(std.math.inf(f64)));
}

test "parse_f64 and parse_unsigned follow Rust's grammar" {
    const floats = [_]struct { []const u8, ?f64 }{
        .{ "1.e5", 100000.0 }, .{ ".5", 0.5 },      .{ "5.", 5.0 },     .{ "+1", 1.0 },
        .{ "-1", -1.0 },       .{ "1e+3", 1000.0 }, .{ "1E-3", 0.001 }, .{ "1e", null },
        .{ "e5", null },       .{ ".", null },      .{ "1_0", null },   .{ "0x10", null },
        .{ " 1", null },       .{ "+", null },      .{ "0.67", 0.67 },
    };
    for (floats) |case| {
        if (case[1]) |expected| {
            try testing.expectEqual(expected, try parse_f64(case[0]));
        } else {
            try testing.expectError(error.Invalid, parse_f64(case[0]));
        }
    }
    try testing.expectError(error.Empty, parse_f64(""));
    try testing.expect(std.math.isInf(try parse_f64("+Infinity")));
    try testing.expect(std.math.isNan(try parse_f64("NaN")));
    try testing.expectEqual(@as(u32, 5), try parse_unsigned(u32, "+5"));
    try testing.expectEqual(@as(u32, 7), try parse_unsigned(u32, "007"));
    try testing.expectError(error.InvalidDigit, parse_unsigned(u32, "-0"));
    try testing.expectError(error.InvalidDigit, parse_unsigned(u32, "+"));
    try testing.expectError(error.InvalidDigit, parse_unsigned(u32, "1_0"));
    try testing.expectError(error.Empty, parse_unsigned(u32, ""));
    try testing.expectError(error.PosOverflow, parse_unsigned(u32, "4294967296"));
    try testing.expectEqual(@as(u32, 4294967295), try parse_unsigned(u32, "4294967295"));
}

test "lines matches Rust str::lines" {
    const cases = [_]struct { []const u8, []const []const u8 }{
        .{ "", &.{} },
        .{ "a", &.{"a"} },
        .{ "a\n", &.{"a"} },
        .{ "a\r\nb\r\n", &.{ "a", "b" } },
        .{ "a\n\nb", &.{ "a", "", "b" } },
        .{ "a\r", &.{"a\r"} },
        .{ "\n", &.{""} },
    };
    for (cases) |case| {
        var lines: Lines = .{ .text = case[0] };
        for (case[1]) |expected| try testing.expectEqualStrings(expected, lines.next().?);
        try testing.expectEqual(@as(?[]const u8, null), lines.next());
    }
}

test "f64_to_u64 saturates like Rust" {
    try testing.expectEqual(@as(u64, 0), f64_to_u64(-1.5));
    try testing.expectEqual(@as(u64, 0), f64_to_u64(std.math.nan(f64)));
    try testing.expectEqual(@as(u64, 2), f64_to_u64(2.99));
    try testing.expectEqual(std.math.maxInt(u64), f64_to_u64(1e30));
}
