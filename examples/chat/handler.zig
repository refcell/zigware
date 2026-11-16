//! Chat's terminal UI (commonware `examples/chat/src/handler.rs`): Messages and Input on the
//! left, Metrics on the right, Logs below. TAB cycles the focused pane, arrows scroll it,
//! ENTER sends the input to every connected friend, and ESC quits. Panes without focus
//! follow their newest line.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const zigware = @import("zigware");
const tui = @import("tui.zig");
const keys = @import("keys.zig");
const clock = @import("clock.zig");
const logger = @import("logger.zig");

const traces = zigware.runtime.telemetry.traces;
const metrics = zigware.runtime.telemetry.metrics;

/// The chat channel.
pub const channel: u64 = 0;
/// Rows a pane's borders take.
const height_offset: u16 = 2;
/// How often the keyboard task ticks (the cursor blink) without input.
pub const tick_ms = 500;
/// Capacity of the event queue between the input tasks and the UI.
const event_queue_size = 100;
/// The log target of the handler's events.
pub const target = "commonware_chat::handler";

pub const Focus = enum { input, logs, metrics, messages };

/// A scroll position: rows down, then columns right.
pub const Scroll = struct { y: u16 = 0, x: u16 = 0 };

/// What the UI shows and edits; owns its messages, logs, and input.
pub const State = struct {
    gpa: Allocator,
    messages: std.ArrayList(tui.Line) = .empty,
    logs: std.ArrayList(tui.Line) = .empty,
    input: std.ArrayList(u8) = .empty,
    cursor_visible: bool = true,
    focus: Focus = .input,
    logs_scroll: Scroll = .{},
    metrics_scroll: Scroll = .{},
    messages_scroll: Scroll = .{},
    /// Events of the log collector already formatted into `logs`.
    logs_seen: usize = 0,

    pub fn init(gpa: Allocator) State {
        return .{ .gpa = gpa };
    }

    pub fn deinit(state: *State) void {
        for (state.messages.items) |line| state.gpa.free(line.text);
        for (state.logs.items) |line| state.gpa.free(line.text);
        state.messages.deinit(state.gpa);
        state.logs.deinit(state.gpa);
        state.input.deinit(state.gpa);
        state.* = undefined;
    }

    /// Appends a message line, joining its lines as ratatui's `Line` from a string does.
    pub fn push_message(state: *State, text: []const u8, fg: ?tui.Color) Allocator.Error!void {
        const joined = try join_lines(state.gpa, text);
        errdefer state.gpa.free(joined);
        try state.messages.append(state.gpa, .{ .text = joined, .fg = fg });
    }

    pub fn push_log(state: *State, text: []const u8) Allocator.Error!void {
        const joined = try join_lines(state.gpa, text);
        errdefer state.gpa.free(joined);
        try state.logs.append(state.gpa, .{ .text = joined });
    }

    /// Formats the collector's new events into log lines stamped `utc_seconds`.
    pub fn collect_logs(
        state: *State,
        collector: *traces.Collector,
        utc_seconds: i64,
    ) Allocator.Error!void {
        collector.lock.lock();
        defer collector.lock.unlock();
        const events = collector.events.items;
        assert(state.logs_seen <= events.len);
        while (state.logs_seen < events.len) : (state.logs_seen += 1) {
            const line = try logger.format(state.gpa, utc_seconds, events[state.logs_seen]);
            defer state.gpa.free(line);
            try state.push_log(line);
        }
    }

    /// Draws every pane into `buffer` (commonware's `terminal.draw` closure). `arena` holds
    /// this frame's temporary text.
    pub fn draw(
        state: *State,
        arena: Allocator,
        buffer: *tui.Buffer,
        metrics_text: []const u8,
    ) Allocator.Error!void {
        const chunks = tui.split(buffer.area, .vertical, 70);
        const horizontal = tui.split(chunks[0], .horizontal, 50);
        const messages_chunks = tui.split(horizontal[0], .vertical, 80);

        const messages_height = messages_chunks[0].height -% height_offset;
        const messages_len: u16 = @truncate(state.messages.items.len);
        if (state.focus != .messages) state.messages_scroll.y = messages_len -| messages_height;
        state.pane("Messages", .cyan, .messages).render(
            buffer,
            messages_chunks[0],
            state.messages.items,
        );

        const metrics_lines = try text_lines(arena, metrics_text);
        state.pane("Metrics", null, .metrics).render(buffer, horizontal[1], metrics_lines);

        const cursor = if (state.cursor_visible) "_" else "";
        const input = try std.mem.concat(arena, u8, &.{ "> ", state.input.items, cursor });
        const input_title = "Input (TAB to switch panes | ESC to quit | ENTER to send)";
        const input_lines = try text_lines(arena, input);
        state.pane(input_title, .yellow, .input).render(buffer, messages_chunks[1], input_lines);

        const logs_height = chunks[1].height -% height_offset;
        const logs_len: u16 = @truncate(state.logs.items.len);
        if (state.focus != .logs) state.logs_scroll.y = logs_len -| logs_height;
        state.pane("Logs", null, .logs).render(buffer, chunks[1], state.logs.items);
        assert(state.messages_scroll.y <= messages_len or state.focus == .messages);
    }

    fn pane(state: *const State, title: []const u8, fg: ?tui.Color, focus: Focus) tui.Pane {
        const position: Scroll = switch (focus) {
            .input => .{},
            .logs => state.logs_scroll,
            .metrics => state.metrics_scroll,
            .messages => state.messages_scroll,
        };
        return .{
            .title = title,
            .fg = fg,
            .border_fg = if (state.focus == focus) .red else null,
            .scroll_y = position.y,
            .scroll_x = position.x,
        };
    }

    /// Applies a key that only edits the UI. Returns the keys the caller acts on: ENTER with
    /// a non-empty input (`.enter`) and ESC (`.esc`); `null` when the key was handled here.
    pub fn handle_key(state: *State, key: keys.Key) Allocator.Error!?keys.Key {
        switch (key) {
            .char => |char| {
                var bytes: [4]u8 = undefined;
                const length = std.unicode.utf8Encode(char, &bytes) catch {
                    try state.input.appendSlice(state.gpa, "\u{fffd}");
                    return null;
                };
                try state.input.appendSlice(state.gpa, bytes[0..length]);
            },
            .backspace => pop_char(&state.input),
            .tab => state.focus = switch (state.focus) {
                .input => .logs,
                .logs => .metrics,
                .metrics => .messages,
                .messages => .input,
            },
            .up => if (state.scroll()) |position| {
                position.y -|= 1;
            },
            .down => if (state.scroll()) |position| {
                position.y +|= 1;
            },
            .left => if (state.scroll()) |position| {
                position.x -|= 1;
            },
            .right => if (state.scroll()) |position| {
                position.x +|= 1;
            },
            .enter => return if (state.input.items.len == 0) null else .enter,
            .esc => return .esc,
            .other => {},
        }
        return null;
    }

    fn scroll(state: *State) ?*Scroll {
        return switch (state.focus) {
            .input => null,
            .logs => &state.logs_scroll,
            .metrics => &state.metrics_scroll,
            .messages => &state.messages_scroll,
        };
    }
};

/// Rust's `String::pop`: removes the last character.
fn pop_char(input: *std.ArrayList(u8)) void {
    var length = input.items.len;
    if (length == 0) return;
    length -= 1;
    while (length > 0 and input.items[length] & 0xc0 == 0x80) length -= 1;
    assert(length < input.items.len);
    input.shrinkRetainingCapacity(length);
}

/// One ratatui `Line` from a string: its `str::lines()` pieces joined, so `\n` and `\r\n`
/// vanish.
pub fn join_lines(gpa: Allocator, text: []const u8) Allocator.Error![]u8 {
    var joined: std.ArrayList(u8) = .empty;
    errdefer joined.deinit(gpa);
    var pieces = std.mem.splitScalar(u8, text, '\n');
    while (pieces.next()) |piece| {
        const has_newline = pieces.index != null;
        const trimmed = if (has_newline and std.mem.endsWith(u8, piece, "\r"))
            piece[0 .. piece.len - 1]
        else
            piece;
        try joined.appendSlice(gpa, trimmed);
    }
    assert(joined.items.len <= text.len);
    return joined.toOwnedSlice(gpa);
}

/// ratatui `Text::raw`: one line per `str::lines()` piece, or one empty line for "".
pub fn text_lines(arena: Allocator, text: []const u8) Allocator.Error![]tui.Line {
    var lines: std.ArrayList(tui.Line) = .empty;
    var pieces = std.mem.splitScalar(u8, text, '\n');
    while (pieces.next()) |piece| {
        const has_newline = pieces.index != null;
        if (!has_newline and piece.len == 0 and lines.items.len > 0) break;
        const trimmed = if (has_newline and std.mem.endsWith(u8, piece, "\r"))
            piece[0 .. piece.len - 1]
        else
            piece;
        try lines.append(arena, .{ .text = trimmed });
    }
    assert(lines.items.len > 0);
    return lines.items;
}

/// `XXXX**YYYY` from a hex public key.
pub fn short_name(hex: []const u8) [10]u8 {
    assert(hex.len >= 4);
    var name: [10]u8 = undefined;
    @memcpy(name[0..4], hex[0..4]);
    @memcpy(name[4..6], "**");
    @memcpy(name[6..10], hex[hex.len - 4 ..]);
    return name;
}

/// Where keys come from: `read` fills `buffer` with input bytes, returning null when none
/// arrived within `tick_ms` and an error once input is gone.
pub const Keyboard = struct {
    context: *anyopaque,
    read: *const fn (context: *anyopaque, io: Io, buffer: []u8) anyerror!?usize,
};

/// The terminal: its size and where frames go.
pub const Terminal = struct {
    out: *Io.Writer,
    context: *anyopaque,
    size: *const fn (context: *anyopaque) tui.Rect,
    keyboard: Keyboard,
};

pub const Context = struct {
    gpa: Allocator,
    io: Io,
    /// This peer's public key in hex.
    me: []const u8,
    state: *State,
    collector: *traces.Collector,
    scope: *const metrics.Scope,
    zone: *const clock.Zone,
    terminal: Terminal,
};

const Event = union(enum) {
    key: keys.Key,
    tick,
    /// Input is gone (commonware's keyboard task ends and drops its sender).
    input_closed,
    message: struct { name: [10]u8, payload: []u8 },
};

/// Runs the UI until ESC or until input closes (commonware `handler::run`). The caller owns
/// the terminal's mode; `sender` is a `LimitedSender` and `receiver` a p2p receiver.
pub fn run(context: Context, sender: anytype, receiver: anytype) !void {
    const io = context.io;
    var buffer: [event_queue_size]Event = undefined;
    var queue: Io.Queue(Event) = .init(&buffer);
    const keyboard = context.terminal.keyboard;
    var keyboard_task = try io.concurrent(read_keyboard, .{ io, &queue, keyboard });
    defer keyboard_task.cancel(io) catch {};
    const receive = Receiving(@TypeOf(receiver.*)).receive;
    var receive_task = try io.concurrent(receive, .{ context.gpa, io, &queue, receiver });
    defer receive_task.cancel(io) catch {};
    defer {
        queue.close(io);
        while (queue.getOne(io)) |event| free_event(context.gpa, event) else |_| {}
    }
    const area = context.terminal.size(context.terminal.context);
    var screen: tui.Screen = try .init(context.gpa, area);
    defer screen.deinit(context.gpa);
    while (true) {
        try draw_frame(context, &screen);
        const event = queue.getOne(io) catch break;
        defer free_event(context.gpa, event);
        if (!try handle_event(context, sender, event)) break;
    }
}

fn draw_frame(context: Context, screen: *tui.Screen) !void {
    const now_seconds = @divFloor(Io.Clock.real.now(context.io).nanoseconds, std.time.ns_per_s);
    try context.state.collect_logs(context.collector, @intCast(now_seconds));
    var arena_state: std.heap.ArenaAllocator = .init(context.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const metrics_text = try context.scope.encode(arena);
    const out = context.terminal.out;
    try screen.resize(context.gpa, context.terminal.size(context.terminal.context), out);
    try context.state.draw(arena, &screen.current, metrics_text);
    try screen.flush(out);
    try out.flush();
    assert(screen.current.cells.len == screen.previous.cells.len);
}

/// Handles one event; false once the UI should quit.
fn handle_event(context: Context, sender: anytype, event: Event) !bool {
    const state = context.state;
    switch (event) {
        .key => |key| {
            const action = try state.handle_key(key) orelse return true;
            if (action == .esc) return false;
            assert(action == .enter);
            try send_input(context, sender);
        },
        .tick => state.cursor_visible = !state.cursor_visible,
        .input_closed => return false,
        .message => |message| {
            const stamp = local_stamp(context);
            const lossy = try std.fmt.allocPrint(context.gpa, "[{s}] {s}: {f}", .{
                &stamp,
                &message.name,
                std.unicode.fmtUtf8(message.payload),
            });
            defer context.gpa.free(lossy);
            try state.push_message(lossy, null);
        },
    }
    return true;
}

fn local_stamp(context: Context) clock.Stamp {
    const now_ns = Io.Clock.real.now(context.io).nanoseconds;
    const seconds: i64 = @intCast(@divFloor(now_ns, std.time.ns_per_s));
    return context.zone.local_stamp(seconds);
}

/// Sends the input to every friend, logs who got it, and shows it as this peer's message.
fn send_input(context: Context, sender: anytype) !void {
    const state = context.state;
    const gpa = context.gpa;
    const input = state.input.items;
    assert(input.len > 0);
    const tracer = context.collector.tracer(target);
    const PublicKey = @TypeOf(sender.*).PublicKey;
    const successful = sender.send(.all, &.{input}, false) catch try gpa.alloc(PublicKey, 0);
    defer gpa.free(successful);
    if (successful.len > 0) {
        std.sort.pdq(PublicKey, successful, {}, struct {
            fn less(_: void, a: PublicKey, b: PublicKey) bool {
                return PublicKey.order(a, b) == .lt;
            }
        }.less);
        var friends: Io.Writer.Allocating = .init(gpa);
        defer friends.deinit();
        try friends.writer.writeByte('[');
        for (successful, 0..) |friend, index| {
            if (index > 0) try friends.writer.writeByte(',');
            try friends.writer.print("{f}", .{friend});
        }
        try friends.writer.writeByte(']');
        tracer.event(.debug, "sent message", .{ .friends = friends.written(), .input = input });
    } else {
        tracer.event(.warn, "dropped message", .{ .input = input });
    }
    const stamp = local_stamp(context);
    const name = short_name(context.me);
    const line = try std.fmt.allocPrint(gpa, "[{s}] {s}: {s}", .{ &stamp, &name, input });
    defer gpa.free(line);
    try state.push_message(line, .yellow);
    state.input.clearRetainingCapacity();
}

fn free_event(gpa: Allocator, event: Event) void {
    if (event == .message) gpa.free(event.message.payload);
}

/// commonware's keyboard task: keys as they arrive, a tick after `tick_ms` without input.
fn read_keyboard(io: Io, queue: *Io.Queue(Event), keyboard: Keyboard) Io.Cancelable!void {
    var parser: keys.Parser = .{};
    var bytes: [1024]u8 = undefined;
    var parsed: [bytes.len]keys.Key = undefined;
    while (true) {
        const count = keyboard.read(keyboard.context, io, &bytes) catch |err| {
            if (err == error.Canceled) return error.Canceled;
            queue.putOne(io, .input_closed) catch {};
            return;
        } orelse {
            queue.putOne(io, .tick) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                error.Closed => return,
            };
            continue;
        };
        assert(count <= bytes.len);
        const key_count = parser.advance(bytes[0..count], count == bytes.len, &parsed);
        for (parsed[0..key_count]) |key| queue.putOne(io, .{ .key = key }) catch |err| {
            switch (err) {
                error.Canceled => return error.Canceled,
                error.Closed => return,
            }
        };
    }
}

/// Forwards every received message to the UI until the network closes.
fn Receiving(comptime Receiver: type) type {
    return struct {
        fn receive(
            gpa: Allocator,
            io: Io,
            queue: *Io.Queue(Event),
            receiver: *Receiver,
        ) Io.Cancelable!void {
            while (true) {
                var message = receiver.recv() catch |err| switch (err) {
                    error.Canceled => return error.Canceled,
                    else => return,
                };
                defer message.deinit();
                try forward(gpa, io, queue, message.peer, message.payload);
            }
        }
    };
}

fn forward(
    gpa: Allocator,
    io: Io,
    queue: *Io.Queue(Event),
    peer: anytype,
    payload: []const u8,
) Io.Cancelable!void {
    var hex: [256]u8 = undefined;
    const peer_hex = std.fmt.bufPrint(&hex, "{f}", .{peer}) catch return;
    assert(peer_hex.len >= 4);
    const copy = gpa.dupe(u8, payload) catch return;
    const event: Event = .{ .message = .{ .name = short_name(peer_hex), .payload = copy } };
    queue.putOne(io, event) catch |err| {
        gpa.free(copy);
        switch (err) {
            error.Canceled => return error.Canceled,
            error.Closed => return,
        }
    };
}
