//! The real terminal for chat: crossterm's raw mode (`cfmakeraw`), the alternate screen, the
//! window size, and keyboard input read from stdin with a `tick_ms` poll.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const posix = std.posix;
const Io = std.Io;
const tui = @import("tui.zig");
const handler = @import("handler.zig");

pub const Terminal = struct {
    io: Io,
    original: posix.termios,

    /// Enters raw mode and the alternate screen (crossterm `enable_raw_mode` and
    /// `EnterAlternateScreen`).
    pub fn enter(io: Io, out: *Io.Writer) !Terminal {
        const stdin = Io.File.stdin();
        const original = try posix.tcgetattr(stdin.handle);
        var raw = original;
        raw.iflag.IGNBRK = false;
        raw.iflag.BRKINT = false;
        raw.iflag.PARMRK = false;
        raw.iflag.ISTRIP = false;
        raw.iflag.INLCR = false;
        raw.iflag.IGNCR = false;
        raw.iflag.ICRNL = false;
        raw.iflag.IXON = false;
        raw.oflag.OPOST = false;
        raw.lflag.ECHO = false;
        raw.lflag.ECHONL = false;
        raw.lflag.ICANON = false;
        raw.lflag.ISIG = false;
        raw.lflag.IEXTEN = false;
        raw.cflag.CSIZE = .CS8;
        raw.cflag.PARENB = false;
        raw.cc[@backingInt(posix.V.MIN)] = 1;
        raw.cc[@backingInt(posix.V.TIME)] = 0;
        try posix.tcsetattr(stdin.handle, .NOW, raw);
        errdefer posix.tcsetattr(stdin.handle, .NOW, original) catch {};
        try out.writeAll("\x1b[?1049h");
        try out.flush();
        assert(!raw.lflag.ICANON);
        return .{ .io = io, .original = original };
    }

    /// Restores the terminal (crossterm `disable_raw_mode`, `LeaveAlternateScreen`, and
    /// `show_cursor`).
    pub fn leave(terminal: *Terminal, out: *Io.Writer) void {
        posix.tcsetattr(Io.File.stdin().handle, .NOW, terminal.original) catch {};
        out.writeAll("\x1b[?1049l\x1b[?25h") catch {};
        out.flush() catch {};
    }

    /// The window size, or 80x24 when it cannot be read.
    pub fn size(context: *anyopaque) tui.Rect {
        const terminal: *Terminal = @ptrCast(@alignCast(context));
        var winsize: posix.winsize = .{ .row = 0, .col = 0, .xpixel = 0, .ypixel = 0 };
        const result = terminal.io.operate(.{ .device_io_control = .{
            .file = Io.File.stdout(),
            .code = posix.T.IOCGWINSZ,
            .arg = &winsize,
        } }) catch return .{ .width = 80, .height = 24 };
        if (result.device_io_control < 0 or winsize.col == 0 or winsize.row == 0) {
            return .{ .width = 80, .height = 24 };
        }
        assert(winsize.col > 0 and winsize.row > 0);
        return .{ .width = winsize.col, .height = winsize.row };
    }

    pub fn keyboard(terminal: *Terminal) handler.Keyboard {
        return .{ .context = terminal, .read = read };
    }

    /// Waits up to `tick_ms` for stdin, then reads what is there; EOF ends input.
    fn read(context: *anyopaque, io: Io, buffer: []u8) anyerror!?usize {
        _ = context;
        assert(buffer.len > 0);
        const stdin = Io.File.stdin().handle;
        var fds = [1]posix.pollfd{.{ .fd = stdin, .events = posix.POLL.IN, .revents = 0 }};
        const ready = try posix.poll(&fds, handler.tick_ms);
        try io.checkCancel();
        if (ready == 0) return null;
        const count = try Io.File.stdin().readStreaming(io, &.{buffer});
        if (count == 0) return error.EndOfStream;
        assert(count <= buffer.len);
        return count;
    }
};

comptime {
    assert(builtin.os.tag != .windows);
}
