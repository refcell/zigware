//! Log lines for chat's Logs pane (commonware `examples/chat/src/logger.rs`).
//!
//! Commonware prints tracing's JSON events as `[MM/DD HH:MM:SS|LEVEL] target => message (k=v
//! ...)`: the event's fields sorted by name (serde_json's map order), then the innermost
//! span's name and fields, then `spans=` with every span as compact JSON, outermost first. A
//! line without fields drops its `()`. zigware records events through a `traces.Collector`,
//! which keeps field values as text, so a value prints bare when it reads as a JSON number,
//! `true`, or `false` (as tracing's numeric and boolean fields do) and quoted otherwise.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const zigware = @import("zigware");
const clock = @import("clock.zig");

const traces = zigware.runtime.telemetry.traces;
const Field = traces.collector.Field;
pub const RecordedEvent = traces.collector.RecordedEvent;

/// Most fields printed from one event or span.
const field_count_max = 64;

/// Formats `event`, recorded at `utc_seconds`, as one log line owned by the caller.
pub fn format(gpa: Allocator, utc_seconds: i64, event: RecordedEvent) Allocator.Error![]u8 {
    var out: Writer.Allocating = .init(gpa);
    defer out.deinit();
    write_raw(&out.writer, utc_seconds, event) catch return error.OutOfMemory;
    // `format!("{})", log_message.trim_end())`, then `.replace("()", "")`, then `trim_end`.
    const raw = trim_end(out.written());
    const closed = try std.mem.concat(gpa, u8, &.{ raw, ")" });
    defer gpa.free(closed);
    const replaced = try std.mem.replaceOwned(u8, gpa, closed, "()", "");
    defer gpa.free(replaced);
    const line = trim_end(replaced);
    assert(line.len <= replaced.len);
    return gpa.dupe(u8, line);
}

fn write_raw(writer: *Writer, utc_seconds: i64, event: RecordedEvent) Writer.Error!void {
    const stamp = clock.stamp(utc_seconds);
    try writer.print("[{s}|{s}] {s} => {s} (", .{
        &stamp,
        level_name(event.level),
        event.target,
        event.metadata.content,
    });
    // Top-level keys in serde_json order: fields, level, span, spans, target, timestamp.
    try write_pairs(writer, null, event.metadata.fields);
    if (event.spans.len == 0) return;
    const innermost = event.spans[0];
    try write_pairs(writer, innermost.content, innermost.fields);
    try writer.writeAll("spans=[");
    var index = event.spans.len;
    while (index > 0) {
        index -= 1;
        const span = event.spans[index];
        try write_object(writer, span.content, span.fields);
        if (index > 0) try writer.writeByte(',');
    }
    try writer.writeAll("] ");
}

fn level_name(level: traces.Level) []const u8 {
    return switch (level) {
        .trace => "TRACE",
        .debug => "DEBUG",
        .info => "INFO",
        .warn => "WARN",
        .@"error" => "ERROR",
    };
}

/// `key=value ` for each field in name order, with a span's `name` among them, skipping the
/// keys logger.rs skips.
fn write_pairs(writer: *Writer, span_name: ?[]const u8, fields: []const Field) Writer.Error!void {
    var sorted: [field_count_max + 1]Field = undefined;
    const pairs = sort_fields(&sorted, span_name, fields);
    for (pairs) |pair| {
        if (is_skipped(pair.name)) continue;
        try writer.print("{s}=", .{pair.name});
        try write_value(writer, pair.value);
        try writer.writeByte(' ');
    }
}

/// A span as compact JSON with its keys sorted.
fn write_object(writer: *Writer, span_name: []const u8, fields: []const Field) Writer.Error!void {
    var sorted: [field_count_max + 1]Field = undefined;
    const pairs = sort_fields(&sorted, span_name, fields);
    try writer.writeByte('{');
    for (pairs, 0..) |pair, index| {
        if (index > 0) try writer.writeByte(',');
        try write_string(writer, pair.name);
        try writer.writeByte(':');
        try write_value(writer, pair.value);
    }
    try writer.writeByte('}');
}

fn sort_fields(
    buffer: *[field_count_max + 1]Field,
    span_name: ?[]const u8,
    fields: []const Field,
) []Field {
    assert(fields.len <= field_count_max);
    var count: usize = 0;
    if (span_name) |name| {
        buffer[0] = .{ .name = "name", .value = name };
        count = 1;
    }
    for (fields) |field| {
        buffer[count] = field;
        count += 1;
    }
    const pairs = buffer[0..count];
    std.sort.insertion(Field, pairs, {}, struct {
        fn less(_: void, a: Field, b: Field) bool {
            return std.mem.lessThan(u8, a.name, b.name);
        }
    }.less);
    assert(pairs.len == fields.len + @intFromBool(span_name != null));
    return pairs;
}

fn is_skipped(name: []const u8) bool {
    const skipped = [_][]const u8{ "", "level", "timestamp", "target", "message" };
    for (skipped) |key| if (std.mem.eql(u8, name, key)) return true;
    return false;
}

fn write_value(writer: *Writer, value: []const u8) Writer.Error!void {
    if (is_json_literal(value)) return writer.writeAll(value);
    try write_string(writer, value);
}

/// Whether `value` is `true`, `false`, or a JSON number.
pub fn is_json_literal(value: []const u8) bool {
    if (std.mem.eql(u8, value, "true") or std.mem.eql(u8, value, "false")) return true;
    var index: usize = @intFromBool(std.mem.startsWith(u8, value, "-"));
    const integer_start = index;
    while (index < value.len and std.ascii.isDigit(value[index])) index += 1;
    const integer = value[integer_start..index];
    if (integer.len == 0 or (integer.len > 1 and integer[0] == '0')) return false;
    if (index < value.len and value[index] == '.') {
        index += 1;
        const fraction_start = index;
        while (index < value.len and std.ascii.isDigit(value[index])) index += 1;
        if (index == fraction_start) return false;
    }
    if (index < value.len and (value[index] == 'e' or value[index] == 'E')) {
        index += 1;
        if (index < value.len and (value[index] == '+' or value[index] == '-')) index += 1;
        const exponent_start = index;
        while (index < value.len and std.ascii.isDigit(value[index])) index += 1;
        if (index == exponent_start) return false;
    }
    assert(index <= value.len);
    return index == value.len;
}

/// A JSON string as serde_json writes it.
fn write_string(writer: *Writer, value: []const u8) Writer.Error!void {
    try writer.writeByte('"');
    for (value) |byte| switch (byte) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        0x08 => try writer.writeAll("\\b"),
        0x0c => try writer.writeAll("\\f"),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        0x00...0x07, 0x0b, 0x0e...0x1f => try writer.print("\\u{x:0>4}", .{byte}),
        else => try writer.writeByte(byte),
    };
    try writer.writeByte('"');
}

/// Rust's `str::trim_end`: drops trailing Unicode whitespace.
pub fn trim_end(text: []u8) []u8 {
    var end = text.len;
    while (end > 0) {
        var start = end - 1;
        while (start > 0 and end - start < 4 and text[start] & 0xc0 == 0x80) start -= 1;
        const char = std.unicode.utf8Decode(text[start..end]) catch break;
        if (!is_whitespace(char)) break;
        end = start;
    }
    assert(end <= text.len);
    return text[0..end];
}

/// Rust's `char::is_whitespace` (the Unicode White_Space property).
fn is_whitespace(char: u21) bool {
    return switch (char) {
        0x09...0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000...0x200a => true,
        0x2028, 0x2029, 0x202f, 0x205f, 0x3000 => true,
        else => false,
    };
}
