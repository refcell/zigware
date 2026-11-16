//! A trace subscriber that prints events the way `tracing_subscriber::fmt()` does by default
//! (its `Full` format), as commonware's command-line examples log:
//!
//! ```text
//! 2026-11-16T08:01:50.123456Z  INFO span{a=1}: target: message key=value
//! ```
//!
//! The timestamp is UTC with microseconds; the level is padded to five columns; active spans
//! follow from the root, each with its fields in braces; then the target, the message, and
//! the event's fields. With ANSI (tracing's default, off when `NO_COLOR` is set and not
//! empty) the timestamp, colons, `=`, and target are dimmed, field names are italic, span
//! names bold, and the level colored.
//!
//! zigware records field values as text, so a string field prints without the quotes Rust's
//! `Debug` adds; every other value prints as tracing prints it.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const Writer = Io.Writer;
const zigware = @import("zigware");

const traces = zigware.runtime.telemetry.traces;
const Level = traces.Level;

const dim = "\x1b[2m";
const italic = "\x1b[3m";
const bold = "\x1b[1m";
const reset = "\x1b[0m";

/// Longest line printed; longer events are cut.
pub const line_size_max = 8 * 1024;

pub const Fmt = struct {
    io: Io,
    /// Where lines go; flushed after each.
    out: *Writer,
    ansi: bool,
    /// The most verbose level printed (`with_max_level`).
    level: Level,
    mutex: Io.Mutex = .init,

    pub fn subscriber(self: *Fmt) traces.Subscriber {
        return .{ .ptr = self, .on_event = on_event, .level = self.level };
    }

    fn on_event(ptr: *anyopaque, event: *const traces.Event) void {
        const self: *Fmt = @ptrCast(@alignCast(ptr));
        const now = Io.Clock.real.now(self.io);
        const now_us: u64 = @intCast(@divFloor(now.nanoseconds, std.time.ns_per_us));
        var buffer: [line_size_max]u8 = undefined;
        var line: Writer = .fixed(&buffer);
        write_event(&line, self.ansi, now_us, event) catch {}; // Cuts an overlong line.
        if (line.end == buffer.len) buffer[buffer.len - 1] = '\n';
        assert(line.buffered().len > 0);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.out.writeAll(line.buffered()) catch return;
        self.out.flush() catch return;
    }
};

/// Writes `event` as one line, at wall-clock time `now_us` (microseconds since the epoch).
pub fn write_event(writer: *Writer, ansi: bool, now_us: u64, event: *const traces.Event) !void {
    if (ansi) try writer.writeAll(dim);
    try write_timestamp(writer, now_us);
    if (ansi) try writer.writeAll(reset);
    try writer.writeByte(' ');
    try write_level(writer, ansi, event.level);
    try writer.writeByte(' ');
    try write_spans(writer, ansi, event.span);
    if (ansi) {
        try writer.print(dim ++ "{s}" ++ reset ++ dim ++ ":" ++ reset ++ " ", .{event.target});
    } else {
        try writer.print("{s}: ", .{event.target});
    }
    try write_message(writer, event.message);
    for (event.fields) |field| {
        try writer.writeByte(' ');
        try write_field(writer, ansi, field.name, field.value);
    }
    try writer.writeByte('\n');
}

/// RFC 3339 in UTC with microseconds, as `SystemTime` formats.
pub fn write_timestamp(writer: *Writer, now_us: u64) !void {
    const seconds = now_us / std.time.us_per_s;
    const epoch: std.time.epoch.EpochSeconds = .{ .secs = seconds };
    const year_day = epoch.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day = epoch.getDaySeconds();
    assert(month_day.day_index < 31);
    try writer.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>6}Z", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day.getHoursIntoDay(),
        day.getMinutesIntoHour(),
        day.getSecondsIntoMinute(),
        now_us % std.time.us_per_s,
    });
}

fn write_level(writer: *Writer, ansi: bool, level: Level) !void {
    const text, const color: u8 = switch (level) {
        .trace => .{ "TRACE", 35 },
        .debug => .{ "DEBUG", 34 },
        .info => .{ " INFO", 32 },
        .warn => .{ " WARN", 33 },
        .@"error" => .{ "ERROR", 31 },
    };
    assert(text.len == 5);
    if (ansi) return writer.print("\x1b[{d}m{s}" ++ reset, .{ color, text });
    try writer.writeAll(text);
}

/// The active spans from the root, as `name{fields}:`, then a space when there are any.
fn write_spans(writer: *Writer, ansi: bool, innermost: ?*const traces.Span) !void {
    var spans: [traces.span_depth_max]*const traces.Span = undefined;
    var depth: usize = 0;
    var cursor = innermost;
    while (cursor) |span| : (cursor = span.parent) {
        if (depth == spans.len) break;
        spans[depth] = span;
        depth += 1;
    }
    assert(depth <= spans.len);
    if (depth == 0) return;
    var index = depth;
    while (index > 0) {
        index -= 1;
        const span = spans[index];
        if (ansi) try writer.print(bold ++ "{s}" ++ reset, .{span.name}) else {
            try writer.writeAll(span.name);
        }
        if (span.field_count > 0) {
            try writer.writeAll(if (ansi) bold ++ "{" ++ reset else "{");
            for (0..span.field_count) |field| {
                if (field > 0) try writer.writeByte(' ');
                const name = span.field_names[field];
                try write_field(writer, ansi, name, span.field_value(field));
            }
            try writer.writeAll(if (ansi) bold ++ "}" ++ reset else "}");
        }
        try writer.writeAll(if (ansi) dim ++ ":" ++ reset else ":");
    }
    try writer.writeByte(' ');
}

/// The message with terminal control characters shown as escapes, so a message cannot drive
/// the terminal (tracing's `Escape`): ESC, BEL, BS, FF, DEL, and the C1 controls.
fn write_message(writer: *Writer, message: []const u8) !void {
    var index: usize = 0;
    while (index < message.len) : (index += 1) {
        const byte = message[index];
        switch (byte) {
            0x1b, 0x07, 0x08, 0x0c, 0x7f => try writer.print("\\x{x:0>2}", .{byte}),
            0xc2 => if (index + 1 < message.len and message[index + 1] >= 0x80 and
                message[index + 1] <= 0x9f)
            {
                try writer.print("\\u{{{x}}}", .{message[index + 1]});
                index += 1;
            } else try writer.writeByte(byte),
            else => try writer.writeByte(byte),
        }
    }
    assert(index == message.len);
}

fn write_field(writer: *Writer, ansi: bool, name: []const u8, value: []const u8) !void {
    assert(name.len > 0);
    const shown = if (std.mem.startsWith(u8, name, "r#")) name[2..] else name;
    if (ansi) {
        try writer.print(italic ++ "{s}" ++ reset ++ dim ++ "=" ++ reset ++ "{s}", .{
            shown,
            value,
        });
    } else {
        try writer.print("{s}={s}", .{ shown, value });
    }
}

/// Whether tracing writes ANSI sequences: unless `NO_COLOR` is set and not empty.
pub fn ansi_enabled(no_color: ?[]const u8) bool {
    const value = no_color orelse return true;
    return value.len == 0;
}
