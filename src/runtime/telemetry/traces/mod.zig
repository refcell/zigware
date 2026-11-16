//! Traces (commonware `runtime::telemetry::traces`).
//!
//! Commonware logs with the `tracing` crate: `info!`, `debug!`, and `warn!` events with a
//! target, a message, and fields, inside spans, delivered to whatever subscriber is installed
//! (tests read them back through `collector::CollectingLayer`). zigware has no global
//! subscriber: a component holds a `Tracer` (a `Subscriber` and a target, or `Tracer.none`)
//! and emits events and opens spans through it. A runner carries the subscriber
//! (`Config.subscriber`), and `Context.tracer(target)` hands it out. With no subscriber, or
//! one that takes only less verbose levels, an event returns before formatting a field.
//!
//! ```zig
//! var collector: traces.Collector = .init(gpa, .{});
//! defer collector.deinit();
//! const tracer = collector.tracer("storage::journal");
//! tracer.event(.warn, "rewinding journal items", .{ .journal_size = 2, .rewound_items = 1 });
//! try collector.get_by_level(.warn).expect_message_exact("rewinding journal items");
//! ```

const std = @import("std");
const encoding = @import("../metrics/encoding.zig");
const dtoa = @import("../metrics/dtoa.zig");
const assert = std.debug.assert;
const Writer = std.Io.Writer;

pub const collector = @import("collector.zig");
pub const status = @import("status.zig");
pub const Collector = collector.Collector;

/// Event levels, most verbose first (tracing's `Level`).
pub const Level = enum {
    trace,
    debug,
    info,
    warn,
    @"error",
};

/// Most fields one span keeps.
pub const span_field_count_max = 8;
/// Most fields one event carries.
pub const event_field_count_max = 32;
/// Longest formatted field value kept by a span or an event.
pub const field_value_size_max = 128;
/// Deepest span nesting an event records.
pub const span_depth_max = 32;

/// A field's name and its value as text (`write_field_value`).
pub const Field = struct {
    name: []const u8,
    value: []const u8,
};

/// One event as a subscriber receives it (tracing's `Event`), borrowed for the call only.
pub const Event = struct {
    level: Level,
    /// The emitting component's module path, such as `commonware_p2p::authenticated`.
    target: []const u8,
    message: []const u8,
    /// In the order the emitter gave them.
    fields: []const Field,
    /// The innermost active span, if any; `parent` leads outward.
    span: ?*const Span,
};

/// Receives events (tracing's `Subscriber`). It may be called from any thread at once, so it
/// synchronizes itself. `level` is the most verbose level it takes (tracing's `LevelFilter`),
/// checked before an event's fields are formatted.
pub const Subscriber = struct {
    ptr: *anyopaque,
    on_event: *const fn (ptr: *anyopaque, event: *const Event) void,
    level: Level = .trace,

    pub fn enabled(subscriber: Subscriber, level: Level) bool {
        return @backingInt(level) >= @backingInt(subscriber.level);
    }
};

/// Emits events and opens spans for one target (a component's module path).
pub const Tracer = struct {
    subscriber: ?Subscriber,
    target: []const u8,

    /// A tracer that records nothing.
    pub const none: Tracer = .{ .subscriber = null, .target = "" };

    pub fn init(subscriber: ?Subscriber, target: []const u8) Tracer {
        return .{ .subscriber = subscriber, .target = target };
    }

    /// The same subscriber under another target.
    pub fn with_target(tracer: Tracer, target: []const u8) Tracer {
        return .{ .subscriber = tracer.subscriber, .target = target };
    }

    /// Whether an event at `level` reaches a subscriber (tracing's `enabled!`).
    pub fn enabled(tracer: Tracer, level: Level) bool {
        const subscriber = tracer.subscriber orelse return false;
        return subscriber.enabled(level);
    }

    /// Emits an event with `message` and `fields` (a struct literal of name/value pairs)
    /// outside any span.
    pub fn event(tracer: Tracer, level: Level, message: []const u8, fields: anytype) void {
        if (!tracer.enabled(level)) return;
        emit(tracer, level, null, message, fields);
    }

    /// Opens a span named `name` with `fields`; events emitted through it carry it (and its
    /// parents). Spans are values: no close is needed.
    pub fn span(tracer: Tracer, name: []const u8, fields: anytype) Span {
        return Span.init(tracer, null, name, fields);
    }
};

/// Formats `fields` on the stack and hands the event to the tracer's subscriber.
fn emit(
    tracer: Tracer,
    level: Level,
    span: ?*const Span,
    message: []const u8,
    fields: anytype,
) void {
    const subscriber = tracer.subscriber.?;
    assert(subscriber.enabled(level));
    const names = @typeInfo(@TypeOf(fields)).@"struct".field_names;
    comptime assert(names.len <= event_field_count_max);
    var values: [names.len][field_value_size_max]u8 = undefined;
    var event_fields: [names.len]Field = undefined;
    inline for (names, 0..) |name, index| {
        var writer: Writer = .fixed(&values[index]);
        write_field_value(&writer, @field(fields, name)) catch {}; // Truncates.
        event_fields[index] = .{ .name = name, .value = writer.buffered() };
    }
    const recorded: Event = .{
        .level = level,
        .target = tracer.target,
        .message = message,
        .fields = &event_fields,
        .span = span,
    };
    subscriber.on_event(subscriber.ptr, &recorded);
}

/// A span: a name and fields that events inside it carry (tracing's `Span`). Its fields are
/// formatted when it opens; `record` adds or replaces one later. It points at its parent, so
/// a child must not outlive it.
pub const Span = struct {
    tracer: Tracer,
    parent: ?*const Span,
    name: []const u8,
    field_names: [span_field_count_max][]const u8 = undefined,
    field_values: [span_field_count_max][field_value_size_max]u8 = undefined,
    field_lens: [span_field_count_max]u8 = undefined,
    field_count: u8 = 0,
    /// The OTLP status set through `status.ok` / `status.error`.
    otel_status: status.Status = .unset,

    fn init(tracer: Tracer, parent: ?*const Span, name: []const u8, fields: anytype) Span {
        assert(name.len > 0);
        var result: Span = .{ .tracer = tracer, .parent = parent, .name = name };
        if (tracer.subscriber == null) return result; // Nobody reads its fields.
        const field_names = @typeInfo(@TypeOf(fields)).@"struct".field_names;
        comptime assert(field_names.len <= span_field_count_max);
        inline for (field_names) |field_name| result.record(field_name, @field(fields, field_name));
        return result;
    }

    /// Opens a child span.
    pub fn child(parent: *const Span, name: []const u8, fields: anytype) Span {
        return Span.init(parent.tracer, parent, name, fields);
    }

    /// Emits an event inside this span.
    pub fn event(span: *const Span, level: Level, message: []const u8, fields: anytype) void {
        if (!span.tracer.enabled(level)) return;
        emit(span.tracer, level, span, message, fields);
    }

    /// Sets field `name` to `value`, replacing an earlier value (tracing's `Span::record`).
    pub fn record(span: *Span, name: []const u8, value: anytype) void {
        if (span.tracer.subscriber == null) return;
        var index: usize = 0;
        while (index < span.field_count) : (index += 1) {
            if (std.mem.eql(u8, span.field_names[index], name)) break;
        }
        assert(index < span_field_count_max);
        var writer: Writer = .fixed(&span.field_values[index]);
        write_field_value(&writer, value) catch {}; // Truncates an overlong value.
        span.field_names[index] = name;
        span.field_lens[index] = @intCast(writer.buffered().len);
        if (index == span.field_count) span.field_count += 1;
        assert(span.field_count <= span_field_count_max);
    }

    pub fn field_value(span: *const Span, index: usize) []const u8 {
        assert(index < span.field_count);
        return span.field_values[index][0..span.field_lens[index]];
    }
};

/// Formats a field value as tracing records it: strings verbatim, errors by name, and other
/// values like a metric label value (integers in decimal, floats through `dtoa`, enums by
/// name, `{f}` for formattable types).
pub fn write_field_value(writer: *Writer, value: anytype) Writer.Error!void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .error_set => try writer.writeAll(@errorName(value)),
        .float => {
            var buffer: [dtoa.buffer_size]u8 = undefined;
            try writer.writeAll(dtoa.format(&buffer, @floatCast(value)));
        },
        else => try encoding.write_label_value(writer, value),
    }
}

/// Converts an integer to `i64` for a numeric trace field, saturating (commonware `TracedExt`).
pub fn traced(value: anytype) i64 {
    const T = @TypeOf(value);
    comptime assert(@typeInfo(T) == .int or @typeInfo(T) == .comptime_int);
    if (std.math.cast(i64, value)) |converted| return converted;
    return if (value < 0) std.math.minInt(i64) else std.math.maxInt(i64);
}

test {
    std.testing.refAllDecls(@This());
}

test "traced saturates" {
    const max = std.math.maxInt(i64);
    const min = std.math.minInt(i64);
    try std.testing.expectEqual(@as(i64, 7), traced(@as(u8, 7)));
    try std.testing.expectEqual(@as(i64, max), traced(@as(u64, std.math.maxInt(u64))));
    try std.testing.expectEqual(@as(i64, min), traced(@as(i128, std.math.minInt(i128))));
    try std.testing.expectEqual(@as(i64, -5), traced(@as(i32, -5)));
    try std.testing.expectEqual(@as(i64, max), traced(@as(usize, std.math.maxInt(usize))));
}
