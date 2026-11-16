//! The slice of ratatui 0.30 (with its crossterm backend) the examples' UIs draw with:
//! percentage layouts, bordered blocks with a title, and scrolled, truncated paragraphs,
//! rendered into a cell buffer and written to the terminal as ratatui's buffer diff.
//!
//! Text is split into graphemes and measured with tables generated from the unicode-width and
//! unicode-segmentation versions ratatui uses (`unicode_tables.zig`). Graphemes are a base
//! character plus the characters that extend it; rarer clusters (Hangul jamo sequences,
//! Prepend characters) split where unicode-segmentation would not.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const tables = @import("unicode_tables.zig");

/// The foreground colors the examples use; ratatui's `Color::Red` and friends map to
/// crossterm's dark variants, written as 256-color indexes.
pub const Color = enum(u8) {
    reset,
    red,
    green,
    yellow,
    blue,
    cyan,

    fn sgr(color: Color) []const u8 {
        return switch (color) {
            .reset => "39",
            .red => "38;5;1",
            .green => "38;5;2",
            .yellow => "38;5;3",
            .blue => "38;5;4",
            .cyan => "38;5;6",
        };
    }
};

/// Longest grapheme a cell keeps; longer ones show as U+FFFD.
pub const symbol_size_max = 32;

pub const Cell = struct {
    symbol_bytes: [symbol_size_max]u8 = .{' '} ++ @as([symbol_size_max - 1]u8, @splat(0)),
    symbol_len: u8 = 1,
    fg: Color = .reset,

    pub const empty: Cell = .{};

    pub fn symbol(cell: *const Cell) []const u8 {
        assert(cell.symbol_len <= symbol_size_max);
        return cell.symbol_bytes[0..cell.symbol_len];
    }

    pub fn set_symbol(cell: *Cell, grapheme: []const u8) void {
        const text = if (grapheme.len <= symbol_size_max) grapheme else "\u{fffd}";
        @memcpy(cell.symbol_bytes[0..text.len], text);
        cell.symbol_len = @intCast(text.len);
        assert(cell.symbol_len > 0);
    }

    fn eql(a: *const Cell, b: *const Cell) bool {
        return a.fg == b.fg and std.mem.eql(u8, a.symbol(), b.symbol());
    }
};

pub const Rect = struct {
    x: u16 = 0,
    y: u16 = 0,
    width: u16 = 0,
    height: u16 = 0,

    pub fn is_empty(rect: Rect) bool {
        return rect.width == 0 or rect.height == 0;
    }

    fn right(rect: Rect) u16 {
        return rect.x +| rect.width;
    }

    fn bottom(rect: Rect) u16 {
        return rect.y +| rect.height;
    }

    /// ratatui `Block::inner` for `Borders::ALL`.
    pub fn inner(rect: Rect) Rect {
        var result = rect;
        result.x = @min(rect.x +| 1, rect.right());
        result.y = @min(rect.y +| 1, rect.bottom());
        result.width = rect.width -| 2;
        result.height = rect.height -| 2;
        assert(result.x >= rect.x and result.y >= rect.y);
        assert(result.width <= rect.width and result.height <= rect.height);
        return result;
    }
};

pub const Direction = enum { vertical, horizontal };

/// ratatui `Layout` with `[Percentage(first), Percentage(100 - first)]`: the first part takes
/// `round(length * first / 100)` cells (ties away from zero) and the second the rest.
pub fn split(area: Rect, direction: Direction, first_percent: u8) [2]Rect {
    assert(first_percent <= 100);
    const length: u32 = if (direction == .vertical) area.height else area.width;
    const first: u16 = @intCast((length * first_percent + 50) / 100);
    assert(first <= length);
    var parts: [2]Rect = .{ area, area };
    if (direction == .vertical) {
        parts[0].height = first;
        parts[1].y = area.y + first;
        parts[1].height = area.height - first;
    } else {
        parts[0].width = first;
        parts[1].x = area.x + first;
        parts[1].width = area.width - first;
    }
    return parts;
}

pub const Buffer = struct {
    area: Rect,
    cells: []Cell,

    pub fn init(gpa: Allocator, area: Rect) Allocator.Error!Buffer {
        assert(area.x == 0 and area.y == 0);
        const cells = try gpa.alloc(Cell, @as(usize, area.width) * area.height);
        @memset(cells, .empty);
        return .{ .area = area, .cells = cells };
    }

    pub fn deinit(buffer: *Buffer, gpa: Allocator) void {
        gpa.free(buffer.cells);
        buffer.* = undefined;
    }

    pub fn reset(buffer: *Buffer) void {
        @memset(buffer.cells, .empty);
    }

    /// Resizes to `area`, keeping the leading cells as ratatui's `Buffer::resize` does.
    pub fn resize(buffer: *Buffer, gpa: Allocator, area: Rect) Allocator.Error!void {
        const length = @as(usize, area.width) * area.height;
        const previous = buffer.cells.len;
        buffer.cells = try gpa.realloc(buffer.cells, length);
        if (length > previous) @memset(buffer.cells[previous..], .empty);
        buffer.area = area;
        assert(buffer.cells.len == length);
    }

    pub fn at(buffer: *Buffer, x: u16, y: u16) *Cell {
        assert(x < buffer.area.width);
        assert(y < buffer.area.height);
        return &buffer.cells[@as(usize, y) * buffer.area.width + x];
    }

    /// Sets the foreground of every cell in `area` (ratatui `set_style` with an `fg`).
    fn set_fg(buffer: *Buffer, area: Rect, fg: ?Color) void {
        const color = fg orelse return;
        const clipped = intersection(area, buffer.area);
        var y = clipped.y;
        while (y < clipped.bottom()) : (y += 1) {
            var x = clipped.x;
            while (x < clipped.right()) : (x += 1) buffer.at(x, y).fg = color;
        }
    }
};

fn intersection(a: Rect, b: Rect) Rect {
    const x = @max(a.x, b.x);
    const y = @max(a.y, b.y);
    const right_edge = @min(a.right(), b.right());
    const bottom_edge = @min(a.bottom(), b.bottom());
    if (right_edge <= x or bottom_edge <= y) return .{ .x = x, .y = y };
    return .{ .x = x, .y = y, .width = right_edge - x, .height = bottom_edge - y };
}

/// One line of a paragraph and its own color (ratatui `Line::styled`), if any.
pub const Line = struct {
    text: []const u8,
    fg: ?Color = null,
};

/// A bordered block with a title holding a paragraph scrolled by (`scroll_y`, `scroll_x`)
/// (ratatui `Paragraph::new(text).style(..).block(Block::default().borders(ALL)...)`).
pub const Pane = struct {
    title: []const u8,
    /// The paragraph's style.
    fg: ?Color = null,
    /// The border's style: red when the pane has focus.
    border_fg: ?Color = null,
    scroll_y: u16 = 0,
    scroll_x: u16 = 0,

    pub fn render(pane: Pane, buffer: *Buffer, area_unclipped: Rect, lines: []const Line) void {
        const area = intersection(area_unclipped, buffer.area);
        buffer.set_fg(area, pane.fg);
        if (!area.is_empty()) {
            render_borders(buffer, area, pane.border_fg);
            render_title(buffer, area, pane.title);
        }
        const inner = area.inner();
        if (inner.is_empty()) return;
        buffer.set_fg(inner, pane.fg);
        var row: u16 = 0;
        var index: usize = pane.scroll_y;
        while (index < lines.len and row < inner.height) : ({
            index += 1;
            row += 1;
        }) {
            render_line(buffer, inner, row, lines[index], pane.scroll_x);
        }
        assert(row <= inner.height);
    }
};

fn render_borders(buffer: *Buffer, area: Rect, fg: ?Color) void {
    assert(!area.is_empty());
    const right_x = area.right() - 1;
    const bottom_y = area.bottom() - 1;
    var y = area.y;
    while (y <= bottom_y) : (y += 1) {
        set_border(buffer, area.x, y, "│", fg);
        set_border(buffer, right_x, y, "│", fg);
    }
    var x = area.x;
    while (x <= right_x) : (x += 1) {
        set_border(buffer, x, area.y, "─", fg);
        set_border(buffer, x, bottom_y, "─", fg);
    }
    set_border(buffer, right_x, bottom_y, "┘", fg);
    set_border(buffer, right_x, area.y, "┐", fg);
    set_border(buffer, area.x, bottom_y, "└", fg);
    set_border(buffer, area.x, area.y, "┌", fg);
}

fn set_border(buffer: *Buffer, x: u16, y: u16, symbol: []const u8, fg: ?Color) void {
    const cell = buffer.at(x, y);
    cell.set_symbol(symbol);
    if (fg) |color| cell.fg = color;
}

/// A left-aligned title on the top border, between the corners.
fn render_title(buffer: *Buffer, area: Rect, title: []const u8) void {
    assert(!area.is_empty());
    const width = area.width -| 2;
    var x: u16 = 0;
    var iterator: Graphemes = .{ .text = title };
    while (iterator.next()) |grapheme| {
        if (has_control(grapheme)) continue;
        const cell_width = grapheme_width(grapheme);
        if (x + cell_width > width) break;
        if (cell_width > 0) buffer.at(area.x + 1 + x, area.y).set_symbol(grapheme);
        x += cell_width;
    }
    assert(x <= width);
}

/// ratatui's `LineTruncator` and `render_line`: skips `offset` cells of the line, then draws
/// the graphemes that fit in `area.width`.
fn render_line(buffer: *Buffer, area: Rect, row: u16, line: Line, offset_cells: u16) void {
    assert(row < area.height);
    assert(!area.is_empty());
    var offset = offset_cells;
    var used: u16 = 0;
    var x: u16 = 0;
    var iterator: Graphemes = .{ .text = line.text };
    while (iterator.next()) |grapheme| {
        if (has_control(grapheme)) continue;
        const cell_width = grapheme_width(grapheme);
        if (cell_width > area.width) continue;
        if (used + cell_width > area.width) break;
        if (offset > 0) {
            if (cell_width > offset) {
                offset = 0;
            } else {
                offset -= cell_width;
                continue;
            }
        }
        used += cell_width;
        if (cell_width == 0) continue;
        const cell = buffer.at(area.x + x, area.y + row);
        cell.set_symbol(grapheme);
        if (line.fg) |color| cell.fg = color;
        x += cell_width;
    }
    assert(x == used);
}

/// Splits text into graphemes. Invalid UTF-8 bytes are graphemes of their own.
pub const Graphemes = struct {
    text: []const u8,
    index: usize = 0,

    pub fn next(iterator: *Graphemes) ?[]const u8 {
        const start = iterator.index;
        if (start == iterator.text.len) return null;
        const first = decode(iterator.text, start);
        var end = start + first.len;
        if (first.char == '\r' and end < iterator.text.len and iterator.text[end] == '\n') {
            end += 1;
        } else if (!is_control(first.char)) {
            var previous = first.char;
            var regional_pair = is_regional_indicator(first.char);
            while (end < iterator.text.len) {
                const following = decode(iterator.text, end);
                const joins = in_ranges(&tables.extend, following.char) or
                    (previous == 0x200d and in_ranges(&tables.wide, following.char)) or
                    (regional_pair and is_regional_indicator(following.char));
                if (!joins) break;
                regional_pair = false;
                previous = following.char;
                end += following.len;
            }
        }
        iterator.index = end;
        assert(end > start);
        return iterator.text[start..end];
    }
};

const Decoded = struct { char: u21, len: u8 };

fn decode(text: []const u8, index: usize) Decoded {
    assert(index < text.len);
    const length = std.unicode.utf8ByteSequenceLength(text[index]) catch
        return .{ .char = 0xfffd, .len = 1 };
    if (index + length > text.len) return .{ .char = 0xfffd, .len = 1 };
    const char = std.unicode.utf8Decode(text[index..][0..length]) catch
        return .{ .char = 0xfffd, .len = 1 };
    return .{ .char = char, .len = length };
}

fn is_regional_indicator(char: u21) bool {
    return char >= 0x1f1e6 and char <= 0x1f1ff;
}

/// Rust's `char::is_control` (general category Cc).
fn is_control(char: u21) bool {
    return char < 0x20 or (char >= 0x7f and char < 0xa0);
}

/// Whether a grapheme holds a control character; ratatui drops such graphemes.
pub fn has_control(grapheme: []const u8) bool {
    var index: usize = 0;
    while (index < grapheme.len) {
        const decoded = decode(grapheme, index);
        if (is_control(decoded.char)) return true;
        index += decoded.len;
    }
    assert(index == grapheme.len);
    return false;
}

fn in_ranges(ranges: []const tables.Range, char: u21) bool {
    var low: usize = 0;
    var high: usize = ranges.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        if (char < ranges[middle][0]) {
            high = middle;
        } else if (char > ranges[middle][1]) {
            low = middle + 1;
        } else return true;
    }
    assert(low == high);
    return false;
}

/// ratatui's `cell_width`: one byte is one cell; otherwise the base character's width, two
/// for an emoji presentation (U+FE0F), plus one per halfwidth sound mark.
pub fn grapheme_width(grapheme: []const u8) u16 {
    assert(grapheme.len > 0);
    if (grapheme.len == 1) return 1;
    const base = decode(grapheme, 0);
    var width: u16 = if (in_ranges(&tables.wide, base.char))
        2
    else if (in_ranges(&tables.zero, base.char))
        0
    else
        1;
    var index: usize = base.len;
    while (index < grapheme.len) {
        const decoded = decode(grapheme, index);
        if (decoded.char == 0xfe0f and width == 1) width = 2;
        if (decoded.char == 0xff9e or decoded.char == 0xff9f) width += 1;
        index += decoded.len;
    }
    return width;
}

/// The terminal side of ratatui's `Terminal`: the previous frame, so each draw writes only
/// the cells that changed, the way ratatui's crossterm backend writes them.
pub const Screen = struct {
    previous: Buffer,
    current: Buffer,

    pub fn init(gpa: Allocator, area: Rect) Allocator.Error!Screen {
        var previous: Buffer = try .init(gpa, area);
        errdefer previous.deinit(gpa);
        return .{ .previous = previous, .current = try .init(gpa, area) };
    }

    pub fn deinit(screen: *Screen, gpa: Allocator) void {
        screen.previous.deinit(gpa);
        screen.current.deinit(gpa);
        screen.* = undefined;
    }

    /// ratatui `autoresize`: on a new size, clears the screen (twice when it narrowed) and
    /// forgets the previous frame so the next one redraws everything.
    pub fn resize(screen: *Screen, gpa: Allocator, area: Rect, out: *Writer) !void {
        if (area.width == screen.current.area.width and
            area.height == screen.current.area.height) return;
        if (area.width < screen.current.area.width) try out.writeAll("\x1b[2J");
        try screen.previous.resize(gpa, area);
        try screen.current.resize(gpa, area);
        try out.writeAll("\x1b[2J");
        screen.previous.reset();
        assert(screen.current.cells.len == screen.previous.cells.len);
    }

    /// Writes the cells of `current` that differ from `previous`, hides the cursor, and
    /// swaps the frames, leaving `current` blank for the next draw.
    pub fn flush(screen: *Screen, out: *Writer) Writer.Error!void {
        try write_diff(&screen.previous, &screen.current, out);
        try out.writeAll("\x1b[?25l");
        std.mem.swap(Buffer, &screen.previous, &screen.current);
        screen.current.reset();
        assert(screen.current.cells.len == screen.previous.cells.len);
    }
};

/// ratatui's `BufferDiff` fed to `CrosstermBackend::draw`.
fn write_diff(previous: *const Buffer, next: *const Buffer, out: *Writer) Writer.Error!void {
    assert(previous.area.width == next.area.width);
    const width = next.area.width;
    const length = @min(previous.cells.len, next.cells.len);
    var state: DrawState = .{};
    var position: usize = 0;
    while (position < length) {
        const index = position;
        position += 1;
        const current = &next.cells[index];
        const cell_width = grapheme_width(current.symbol());
        if (current.eql(&previous.cells[index])) {
            position += cell_width -| 1;
            continue;
        }
        try state.draw(out, index, width, current);
        if (cell_width > 1 and std.mem.indexOf(u8, current.symbol(), "\u{fe0f}") != null) {
            var trailing = index + 1;
            var end = @min(index + cell_width, length);
            while (trailing < end) {
                const cell = &next.cells[trailing];
                const symbol_changed =
                    !std.mem.eql(u8, cell.symbol(), previous.cells[trailing].symbol());
                if (symbol_changed) try state.draw(out, trailing, width, cell);
                trailing += @max(grapheme_width(cell.symbol()), 1);
                end = @min(@max(end, trailing), length);
            }
            position = end;
        } else if (cell_width > 1) {
            position += cell_width - 1;
        }
    }
    try out.writeAll("\x1b[39m\x1b[49m\x1b[59m\x1b[0m");
}

const DrawState = struct {
    fg: Color = .reset,
    last: ?usize = null,

    fn draw(state: *DrawState, out: *Writer, index: usize, width: u16, cell: *const Cell) !void {
        assert(width > 0);
        const x = index % width;
        const y = index / width;
        const follows = if (state.last) |last|
            last % width + 1 == x and last / width == y
        else
            false;
        if (!follows) try out.print("\x1b[{d};{d}H", .{ y + 1, x + 1 });
        state.last = index;
        if (cell.fg != state.fg) {
            try out.print("\x1b[{s};49m", .{cell.fg.sgr()});
            state.fg = cell.fg;
        }
        try out.writeAll(cell.symbol());
    }
};
