//! Log's terminal UI (commonware `examples/log/src/gui.rs`): Activity above (60%), Logs below
//! (40%). TAB toggles the focused pane (its border turns red), arrows scroll it, and ESC
//! quits. Activity lines that mention `proposed`, `prepared`, or `finalized` are blue,
//! yellow, or green.
//!
//! Like commonware's `Writer`, events of the `commonware_log::application` target become
//! Activity lines (`[%Y-%m-%dT%H:%M:%S] => message (k=v ...)`) and every other event a Logs
//! line (`[%Y-%m-%dT%H:%M:%S|LEVEL] target => message (k=v ...)`), stamped in local time.
//! Commonware follows the newest line of Activity unless Logs has focus (so Activity
//! scrolling is undone on the next frame) and of Logs unless Logs has focus; so does this.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const zigware = @import("zigware");
const ui = @import("ui");
const application = @import("application.zig");

const tui = ui.tui;
const keys = ui.keys;
const clock = ui.clock;
const logger = ui.logger;
const terminal = ui.terminal;
const traces = zigware.runtime.telemetry.traces;

/// Rows a pane's borders take.
const height_offset: u16 = 2;

pub const Focus = enum { progress, logs };

/// A scroll position: rows down, then columns right.
pub const Scroll = struct { y: u16 = 0, x: u16 = 0 };

/// What the UI shows; owns its lines.
pub const State = struct {
    gpa: Allocator,
    progress: std.ArrayList(tui.Line) = .empty,
    logs: std.ArrayList(tui.Line) = .empty,
    focus: Focus = .progress,
    progress_scroll: Scroll = .{},
    logs_scroll: Scroll = .{},
    /// Events of the collector already formatted into lines.
    events_seen: usize = 0,

    pub fn init(gpa: Allocator) State {
        return .{ .gpa = gpa };
    }

    pub fn deinit(state: *State) void {
        for (state.progress.items) |line| state.gpa.free(line.text);
        for (state.logs.items) |line| state.gpa.free(line.text);
        state.progress.deinit(state.gpa);
        state.logs.deinit(state.gpa);
        state.* = undefined;
    }

    /// Formats the collector's new events, stamped `utc_seconds` in `zone`.
    pub fn collect(
        state: *State,
        collector: *traces.Collector,
        zone: *const clock.Zone,
        utc_seconds: i64,
    ) Allocator.Error!void {
        collector.lock.lock();
        defer collector.lock.unlock();
        const events = collector.events.items;
        assert(state.events_seen <= events.len);
        const stamp = zone.local_iso_stamp(utc_seconds);
        while (state.events_seen < events.len) : (state.events_seen += 1) {
            const event = events[state.events_seen];
            const is_progress = std.mem.indexOf(u8, event.target, application.target) != null;
            const text = try format_line(state.gpa, &stamp, event);
            errdefer state.gpa.free(text);
            if (is_progress) {
                try state.progress.append(state.gpa, .{ .text = text, .fg = progress_color(text) });
            } else {
                try state.logs.append(state.gpa, .{ .text = text });
            }
        }
        assert(state.events_seen == events.len);
    }

    /// Draws both panes into `buffer` (commonware's `terminal.draw` closure).
    pub fn draw(state: *State, buffer: *tui.Buffer) void {
        const chunks = tui.split(buffer.area, .vertical, 60);

        const progress_height = chunks[0].height -% height_offset;
        const progress_len: u16 = @truncate(state.progress.items.len);
        if (state.focus != .logs) state.progress_scroll.y = progress_len -| progress_height;
        state.pane("Activity", .progress).render(buffer, chunks[0], state.progress.items);

        const logs_height = chunks[1].height -% height_offset;
        const logs_len: u16 = @truncate(state.logs.items.len);
        if (state.focus != .logs) state.logs_scroll.y = logs_len -| logs_height;
        state.pane("Logs", .logs).render(buffer, chunks[1], state.logs.items);
        assert(chunks[0].height + chunks[1].height == buffer.area.height);
    }

    fn pane(state: *const State, title: []const u8, focus: Focus) tui.Pane {
        const position = if (focus == .progress) state.progress_scroll else state.logs_scroll;
        return .{
            .title = title,
            .border_fg = if (state.focus == focus) .red else null,
            .scroll_y = position.y,
            .scroll_x = position.x,
        };
    }

    /// Applies a key; false once the UI should quit (ESC).
    pub fn handle_key(state: *State, key: keys.Key) bool {
        const scroll = if (state.focus == .progress) &state.progress_scroll else &state.logs_scroll;
        switch (key) {
            .tab => state.focus = if (state.focus == .progress) .logs else .progress,
            .up => scroll.y -|= 1,
            .down => scroll.y +|= 1,
            .left => scroll.x -|= 1,
            .right => scroll.x +|= 1,
            .esc => return false,
            else => {},
        }
        return true;
    }
};

/// One line as gui.rs's `Writer` formats `event`, stamped `stamp` (local time).
pub fn format_line(
    gpa: Allocator,
    stamp: *const clock.IsoStamp,
    event: logger.RecordedEvent,
) Allocator.Error![]u8 {
    if (std.mem.indexOf(u8, event.target, application.target) != null) {
        // The application's fields are all strings (`%view`, `?payload`, `String`).
        const header = try std.fmt.allocPrint(gpa, "[{s}] => ", .{stamp});
        defer gpa.free(header);
        return logger.format(gpa, header, event, .strings);
    }
    const level = logger.level_name(event.level);
    const header = try std.fmt.allocPrint(gpa, "[{s}|{s}] {s} => ", .{
        stamp,
        level,
        event.target,
    });
    defer gpa.free(header);
    assert(header.len > stamp.len + level.len);
    return logger.format(gpa, header, event, .inferred);
}

/// The color gui.rs gives an Activity line.
pub fn progress_color(text: []const u8) ?tui.Color {
    if (std.mem.indexOf(u8, text, "proposed") != null) return .blue;
    if (std.mem.indexOf(u8, text, "prepared") != null) return .yellow;
    if (std.mem.indexOf(u8, text, "finalized") != null) return .green;
    return null;
}

pub const Context = struct {
    gpa: Allocator,
    io: Io,
    state: *State,
    collector: *traces.Collector,
    zone: *const clock.Zone,
    device: terminal.Device,
};

/// Runs the UI until ESC or until input closes (commonware `Gui::run`): draws, then waits up
/// to `tick_ms` for keys. The caller owns the terminal's mode.
pub fn run(context: Context) !void {
    const device = context.device;
    var screen: tui.Screen = try .init(context.gpa, device.size(device.context));
    defer screen.deinit(context.gpa);
    var parser: keys.Parser = .{};
    var bytes: [1024]u8 = undefined;
    var parsed: [bytes.len]keys.Key = undefined;
    while (true) {
        try draw_frame(context, &screen);
        const keyboard = device.keyboard;
        const count = keyboard.read(keyboard.context, context.io, &bytes) catch |err| {
            if (err == error.Canceled) return error.Canceled;
            return; // Input is gone: commonware's keyboard task ends and the UI stops.
        } orelse continue; // A tick: refresh the screen.
        assert(count <= bytes.len);
        const key_count = parser.advance(bytes[0..count], count == bytes.len, &parsed);
        for (parsed[0..key_count]) |key| {
            if (!context.state.handle_key(key)) return;
            try draw_frame(context, &screen);
        }
    }
}

fn draw_frame(context: Context, screen: *tui.Screen) !void {
    const now_ns = Io.Clock.real.now(context.io).nanoseconds;
    const now_seconds: i64 = @intCast(@divFloor(now_ns, std.time.ns_per_s));
    try context.state.collect(context.collector, context.zone, now_seconds);
    const out = context.device.out;
    try screen.resize(context.gpa, context.device.size(context.device.context), out);
    context.state.draw(&screen.current);
    try screen.flush(out);
    try out.flush();
    assert(screen.current.cells.len == screen.previous.cells.len);
}
