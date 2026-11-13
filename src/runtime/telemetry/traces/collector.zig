//! In-memory trace collection for tests (commonware `traces::collector`): `Collector` keeps
//! every event with its level, target, message, fields, and active spans (innermost first),
//! and the `expect_*` methods are commonware's assertions, returning `error.TraceAssertion`.

const std = @import("std");
const traces = @import("mod.zig");
const raw = @import("../metrics/raw.zig");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const Level = traces.Level;

pub const Error = error{TraceAssertion};

pub const Field = struct {
    name: []const u8,
    value: []const u8,
};

/// An event's or span's content and fields (commonware `EventMetadata`). For a span the
/// content is its name.
pub const EventMetadata = struct {
    content: []const u8,
    fields: []const Field,

    pub fn expect_content_exact(metadata: EventMetadata, content: []const u8) Error!void {
        if (!std.mem.eql(u8, metadata.content, content)) return error.TraceAssertion;
    }

    pub fn expect_content_contains(metadata: EventMetadata, substring: []const u8) Error!void {
        if (std.mem.indexOf(u8, metadata.content, substring) == null) return error.TraceAssertion;
    }

    pub fn expect_field_count(metadata: EventMetadata, count: usize) Error!void {
        if (metadata.fields.len != count) return error.TraceAssertion;
    }

    pub fn expect_field_at_index(
        metadata: EventMetadata,
        index: usize,
        context: anytype,
        comptime predicate: fn (@TypeOf(context), Field) Error!void,
    ) Error!void {
        if (index >= metadata.fields.len) return error.TraceAssertion;
        try predicate(context, metadata.fields[index]);
    }

    pub fn expect_field_exact(
        metadata: EventMetadata,
        name: []const u8,
        value: []const u8,
    ) Error!void {
        for (metadata.fields) |field| {
            if (std.mem.eql(u8, field.name, name) and std.mem.eql(u8, field.value, value)) return;
        }
        return error.TraceAssertion;
    }

    pub fn expect_field_contains(
        metadata: EventMetadata,
        name: []const u8,
        substring: []const u8,
    ) Error!void {
        for (metadata.fields) |field| {
            if (!std.mem.eql(u8, field.name, name)) continue;
            if (std.mem.indexOf(u8, field.value, substring) != null) return;
        }
        return error.TraceAssertion;
    }
};

/// One recorded event (commonware `RecordedEvent`).
pub const RecordedEvent = struct {
    level: Level,
    target: []const u8,
    /// Active spans, innermost first.
    spans: []const EventMetadata,
    metadata: EventMetadata,

    pub fn expect_span_count(event: RecordedEvent, count: usize) Error!void {
        if (event.spans.len != count) return error.TraceAssertion;
    }

    pub fn expect_span_at_index(
        event: RecordedEvent,
        index: usize,
        context: anytype,
        comptime predicate: fn (@TypeOf(context), EventMetadata) Error!void,
    ) Error!void {
        if (index >= event.spans.len) return error.TraceAssertion;
        try predicate(context, event.spans[index]);
    }

    pub fn expect_span(
        event: RecordedEvent,
        context: anytype,
        comptime predicate: fn (@TypeOf(context), EventMetadata) bool,
    ) Error!void {
        for (event.spans) |span| if (predicate(context, span)) return;
        return error.TraceAssertion;
    }
};

/// A view of recorded events, optionally filtered by level (commonware `RecordedEvents`).
pub const RecordedEvents = struct {
    all: []const RecordedEvent,
    level: ?Level = null,

    pub fn len(events: RecordedEvents) usize {
        var count: usize = 0;
        for (events.all) |event| count += @intFromBool(events.includes(event));
        return count;
    }

    pub fn is_empty(events: RecordedEvents) bool {
        return events.len() == 0;
    }

    /// The `index`th event in the view.
    pub fn get(events: RecordedEvents, index: usize) ?RecordedEvent {
        var seen: usize = 0;
        for (events.all) |event| {
            if (!events.includes(event)) continue;
            if (seen == index) return event;
            seen += 1;
        }
        return null;
    }

    pub fn expect_event_at_index(
        events: RecordedEvents,
        index: usize,
        context: anytype,
        comptime predicate: fn (@TypeOf(context), RecordedEvent) Error!void,
    ) Error!void {
        const event = events.get(index) orelse return error.TraceAssertion;
        try predicate(context, event);
    }

    pub fn expect_event(
        events: RecordedEvents,
        context: anytype,
        comptime predicate: fn (@TypeOf(context), RecordedEvent) bool,
    ) Error!void {
        for (events.all) |event| {
            if (events.includes(event) and predicate(context, event)) return;
        }
        return error.TraceAssertion;
    }

    pub fn expect_message_exact(events: RecordedEvents, message: []const u8) Error!void {
        for (events.all) |event| {
            if (!events.includes(event)) continue;
            if (std.mem.eql(u8, event.metadata.content, message)) return;
        }
        return error.TraceAssertion;
    }

    pub fn expect_message_contains(events: RecordedEvents, substring: []const u8) Error!void {
        for (events.all) |event| {
            if (!events.includes(event)) continue;
            if (std.mem.indexOf(u8, event.metadata.content, substring) != null) return;
        }
        return error.TraceAssertion;
    }

    fn includes(events: RecordedEvents, event: RecordedEvent) bool {
        const level = events.level orelse return true;
        return event.level == level;
    }
};

pub const Config = struct {
    /// Most events kept; later events are counted in `dropped` (commonware keeps all).
    event_count_max: u32 = 1 << 16,
};

/// Collects events (commonware `TraceStorage` plus `CollectingLayer`). Recording allocates in
/// an arena freed by `deinit`; an allocation failure drops the event and counts it.
pub const Collector = struct {
    arena: std.heap.ArenaAllocator,
    config: Config,
    lock: raw.SpinLock = .{},
    events: std.ArrayList(RecordedEvent) = .empty,
    /// Events not kept, because the collector was full or out of memory.
    dropped: u64 = 0,

    pub fn init(gpa: Allocator, config: Config) Collector {
        assert(config.event_count_max > 0);
        return .{ .arena = .init(gpa), .config = config };
    }

    pub fn deinit(collector: *Collector) void {
        collector.arena.deinit();
        collector.* = undefined;
    }

    /// A tracer that records into this collector under `target`.
    pub fn tracer(collector: *Collector, target: []const u8) traces.Tracer {
        return .{ .collector = collector, .target = target };
    }

    /// Every recorded event (commonware `get_all`). Valid until the next event is recorded.
    pub fn get_all(collector: *Collector) RecordedEvents {
        return .{ .all = collector.events.items };
    }

    /// The events at `level` (commonware `get_by_level`).
    pub fn get_by_level(collector: *Collector, level: Level) RecordedEvents {
        return .{ .all = collector.events.items, .level = level };
    }

    pub fn is_empty(collector: *Collector) bool {
        return collector.events.items.len == 0;
    }

    pub fn record(
        collector: *Collector,
        level: Level,
        target: []const u8,
        span: ?*const traces.Span,
        message: []const u8,
        fields: anytype,
    ) void {
        collector.lock.lock();
        defer collector.lock.unlock();
        if (collector.events.items.len >= collector.config.event_count_max) {
            collector.dropped += 1;
            return;
        }
        const event = collector.build(level, target, span, message, fields) catch {
            collector.dropped += 1;
            return;
        };
        const gpa = collector.arena.allocator();
        collector.events.append(gpa, event) catch {
            collector.dropped += 1;
        };
    }

    fn build(
        collector: *Collector,
        level: Level,
        target: []const u8,
        span: ?*const traces.Span,
        message: []const u8,
        fields: anytype,
    ) Allocator.Error!RecordedEvent {
        const arena = collector.arena.allocator();
        const names = @typeInfo(@TypeOf(fields)).@"struct".field_names;
        const event_fields = try arena.alloc(Field, names.len);
        inline for (names, 0..) |name, index| {
            var buffer: [traces.field_value_size_max]u8 = undefined;
            var writer: Writer = .fixed(&buffer);
            traces.write_field_value(&writer, @field(fields, name)) catch {}; // Truncates.
            event_fields[index] = .{ .name = name, .value = try arena.dupe(u8, writer.buffered()) };
        }
        var depth: usize = 0;
        var cursor = span;
        while (cursor) |active| : (cursor = active.parent) {
            depth += 1;
            assert(depth <= traces.span_depth_max);
        }
        const spans = try arena.alloc(EventMetadata, depth);
        cursor = span;
        for (spans) |*slot| {
            const active = cursor.?;
            const span_fields = try arena.alloc(Field, active.field_count);
            for (span_fields, 0..) |*field, index| {
                field.* = .{
                    .name = try arena.dupe(u8, active.field_names[index]),
                    .value = try arena.dupe(u8, active.field_value(index)),
                };
            }
            slot.* = .{ .content = try arena.dupe(u8, active.name), .fields = span_fields };
            cursor = active.parent;
        }
        assert(cursor == null);
        return .{
            .level = level,
            .target = try arena.dupe(u8, target),
            .spans = spans,
            .metadata = .{ .content = try arena.dupe(u8, message), .fields = event_fields },
        };
    }
};

const testing = std.testing;

test "collects events with fields and spans" {
    var collector: Collector = .init(testing.allocator, .{});
    defer collector.deinit();
    const tracer = collector.tracer("storage::journal");
    try testing.expect(collector.is_empty());
    tracer.event(.warn, "rewinding journal items", .{ .journal_size = 2, .rewound_items = 1 });
    var outer = tracer.span("recover", .{ .partition = "log" });
    outer.record("attempt", 3);
    const inner = outer.child("replay", .{ .section = @as(u64, 7), .ok = true });
    inner.event(.info, "replayed", .{ .err = error.Corrupt, .ratio = 0.5 });
    tracer.event(.debug, "done", .{});

    const all = collector.get_all();
    try testing.expectEqual(@as(usize, 3), all.len());
    const warns = collector.get_by_level(.warn);
    try warns.expect_message_exact("rewinding journal items");
    try testing.expectError(error.TraceAssertion, warns.expect_message_exact("replayed"));
    try warns.expect_event({}, struct {
        fn matches(_: void, event: RecordedEvent) bool {
            const metadata = event.metadata;
            metadata.expect_field_exact("journal_size", "2") catch return false;
            metadata.expect_field_exact("rewound_items", "1") catch return false;
            return std.mem.eql(u8, metadata.content, "rewinding journal items");
        }
    }.matches);

    const replayed = collector.get_by_level(.info).get(0).?;
    try testing.expectEqualStrings("storage::journal", replayed.target);
    try replayed.metadata.expect_field_count(2);
    try replayed.metadata.expect_field_exact("err", "Corrupt");
    try replayed.metadata.expect_field_exact("ratio", "0.5");
    try replayed.expect_span_count(2);
    try replayed.spans[0].expect_content_exact("replay");
    try replayed.spans[0].expect_field_exact("section", "7");
    try replayed.spans[0].expect_field_exact("ok", "true");
    try replayed.spans[1].expect_content_exact("recover");
    try replayed.spans[1].expect_field_exact("partition", "log");
    try replayed.spans[1].expect_field_exact("attempt", "3");
    try replayed.expect_span({}, struct {
        fn matches(_: void, span: EventMetadata) bool {
            return std.mem.eql(u8, span.content, "recover");
        }
    }.matches);
    try all.expect_message_contains("replay");
    try testing.expectError(error.TraceAssertion, all.expect_message_contains("missing"));
    try testing.expect(collector.get_by_level(.@"error").is_empty());
}

test "collector bounds its events" {
    var collector: Collector = .init(testing.allocator, .{ .event_count_max = 2 });
    defer collector.deinit();
    const tracer = collector.tracer("bounded");
    for (0..5) |_| tracer.event(.trace, "tick", .{});
    try testing.expectEqual(@as(usize, 2), collector.get_all().len());
    try testing.expectEqual(@as(u64, 3), collector.dropped);
    traces.Tracer.none.event(.info, "ignored", .{});
}
