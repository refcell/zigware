//! How one completion advances one ring request (commonware `runtime::iouring::request`,
//! reduced to the I/O production storage and network submit).
//!
//! A logical request (a positioned read or write, a send of several buffers, a receive) may
//! need several SQEs: the kernel can complete part of it, ask for a retry (`EAGAIN`,
//! `EINTR`), and take at most `u32::MAX` bytes per SQE. Each request here builds its next
//! operation from its progress and folds a raw CQE result into it, returning null while it
//! needs another SQE. Cancellation and timeouts stay in `ring.zig`: a request whose SQE was
//! canceled never sees that CQE, and a completion that beat its cancellation is folded in
//! here like any other.

const std = @import("std");
const assert = std.debug.assert;
const linux = std.os.linux;
const posix = std.posix;
const ring = @import("ring.zig");

/// A raw CQE result (commonware `CqeResult`).
pub const CqeResult = union(enum) {
    /// The operation should be submitted again unchanged (`EAGAIN`, `EWOULDBLOCK`, `EINTR`).
    retry,
    /// Bytes transferred (zero for an fsync, or at the end of a file or stream).
    count: u32,
    /// The operation failed with this errno.
    failure: linux.E,

    pub fn from_raw(result: i32) CqeResult {
        if (result >= 0) return .{ .count = @intCast(result) };
        const code = ring.errno(result);
        assert(code != .SUCCESS);
        return switch (code) {
            .INTR, .AGAIN => .retry,
            else => .{ .failure = code },
        };
    }
};

/// The length one SQE carries of `remaining` bytes: at most `u32::MAX` (commonware
/// `scalar_len`); the rest goes in later SQEs.
pub fn scalar_len(remaining: usize) u32 {
    return @intCast(@min(remaining, std.math.maxInt(u32)));
}

/// A positioned read of all of `buffer` at `offset`.
pub const ReadAt = struct {
    fd: posix.fd_t,
    buffer: []u8,
    offset: u64,
    /// Bytes read so far.
    read: usize = 0,

    pub const Error = error{ ReadFailed, BlobInsufficientLength };

    /// The next SQE: the unread suffix, at most `u32::MAX` bytes of it.
    pub fn operation(self: *const ReadAt) ring.Operation {
        assert(self.read < self.buffer.len);
        const rest = self.buffer[self.read..];
        return .{ .read = .{
            .fd = self.fd,
            .buffer = rest[0..scalar_len(rest.len)],
            .offset = self.offset + self.read,
        } };
    }

    /// Folds `result` in: null to submit again, otherwise the read's end. The end of the
    /// file before the buffer fills is `BlobInsufficientLength`.
    pub fn on_cqe(self: *ReadAt, result: i32) ?Error!void {
        assert(self.read < self.buffer.len);
        switch (CqeResult.from_raw(result)) {
            .retry => return null,
            .failure => return error.ReadFailed,
            .count => |count| {
                if (count == 0) return error.BlobInsufficientLength;
                assert(count <= scalar_len(self.buffer.len - self.read));
                self.read += count;
                if (self.read == self.buffer.len) return {};
                return null;
            },
        }
    }
};

/// A positioned write of all of `bytes` at `offset`.
pub const WriteAt = struct {
    fd: posix.fd_t,
    bytes: []const u8,
    offset: u64,
    /// Bytes written so far.
    written: usize = 0,

    pub const Error = error{WriteFailed};

    /// The next SQE: the unwritten suffix, at most `u32::MAX` bytes of it.
    pub fn operation(self: *const WriteAt) ring.Operation {
        assert(self.written < self.bytes.len);
        const rest = self.bytes[self.written..];
        return .{ .write = .{
            .fd = self.fd,
            .bytes = rest[0..scalar_len(rest.len)],
            .offset = self.offset + self.written,
        } };
    }

    /// Folds `result` in: null to submit again, otherwise the write's end. A write that
    /// makes no progress fails.
    pub fn on_cqe(self: *WriteAt, result: i32) ?Error!void {
        assert(self.written < self.bytes.len);
        switch (CqeResult.from_raw(result)) {
            .retry => return null,
            .failure => return error.WriteFailed,
            .count => |count| {
                if (count == 0) return error.WriteFailed;
                assert(count <= scalar_len(self.bytes.len - self.written));
                self.written += count;
                if (self.written == self.bytes.len) return {};
                return null;
            },
        }
    }
};

/// Most buffers one send carries (as `std.Io.Threaded` does per write).
pub const send_iovecs_max = 8;

/// A send of every buffer of `bufs`, in order, as one logical write.
pub const Send = struct {
    fd: posix.fd_t,
    bufs: []const []const u8,
    /// The buffer being sent and the bytes of it already sent.
    index: usize = 0,
    offset: usize = 0,
    /// The current SQE's message; the SQE points into it until it completes.
    iovecs: [send_iovecs_max]posix.iovec_const = undefined,
    msg: posix.msghdr_const = undefined,

    pub const Error = error{SendFailed};

    pub fn init(fd: posix.fd_t, bufs: []const []const u8) Send {
        var send: Send = .{ .fd = fd, .bufs = bufs };
        send.skip_empty();
        return send;
    }

    pub fn is_complete(self: *const Send) bool {
        assert(self.index <= self.bufs.len);
        return self.index == self.bufs.len;
    }

    /// The unsent part of the current buffer.
    pub fn first(self: *const Send) []const u8 {
        assert(!self.is_complete());
        return self.bufs[self.index][self.offset..];
    }

    /// The buffers after the current one.
    pub fn rest(self: *const Send) []const []const u8 {
        assert(!self.is_complete());
        return self.bufs[self.index + 1 ..];
    }

    /// The next SQE: a `sendmsg` of the unsent suffix, up to `send_iovecs_max` buffers.
    pub fn operation(self: *Send) ring.Operation {
        assert(!self.is_complete());
        self.iovecs[0] = .{ .base = self.first().ptr, .len = self.first().len };
        const count = 1 + @min(self.rest().len, send_iovecs_max - 1);
        for (self.iovecs[1..count], self.rest()[0 .. count - 1]) |*iovec, buf| {
            iovec.* = .{ .base = buf.ptr, .len = buf.len };
        }
        self.msg = .{
            .name = null,
            .namelen = 0,
            .iov = &self.iovecs,
            .iovlen = @intCast(count),
            .control = null,
            .controllen = 0,
            .flags = 0,
        };
        return .{ .sendmsg = .{ .fd = self.fd, .msg = &self.msg } };
    }

    /// Folds `result` in: null to submit again, otherwise the send's end. A send that
    /// makes no progress fails.
    pub fn on_cqe(self: *Send, result: i32) ?Error!void {
        assert(!self.is_complete());
        switch (CqeResult.from_raw(result)) {
            .retry => return null,
            .failure => return error.SendFailed,
            .count => |count| {
                if (count == 0) return error.SendFailed;
                self.advance(count);
                if (self.is_complete()) return {};
                return null;
            },
        }
    }

    /// Moves past `sent` bytes, across buffers.
    pub fn advance(self: *Send, sent: usize) void {
        assert(sent > 0);
        var left = sent;
        // Bounded by the buffers.
        while (left > 0) {
            assert(!self.is_complete());
            const step = @min(left, self.bufs[self.index].len - self.offset);
            self.offset += step;
            left -= step;
            self.skip_empty();
        }
    }

    /// Moves past a finished current buffer and any empty ones after it.
    fn skip_empty(self: *Send) void {
        // Bounded by the buffers.
        while (self.index < self.bufs.len and self.offset == self.bufs[self.index].len) {
            self.index += 1;
            self.offset = 0;
        }
        assert(self.index == self.bufs.len or self.offset < self.bufs[self.index].len);
    }
};

/// A receive into `buffer`: until it is full when `exact`, otherwise of whatever arrives
/// first.
pub const Recv = struct {
    fd: posix.fd_t,
    buffer: []u8,
    exact: bool,
    /// Bytes received so far.
    received: usize = 0,

    pub const Error = error{RecvFailed};

    /// The next SQE: the unfilled suffix, at most `u32::MAX` bytes of it.
    pub fn operation(self: *const Recv) ring.Operation {
        assert(self.received < self.buffer.len);
        const rest = self.buffer[self.received..];
        return .{ .recv = .{ .fd = self.fd, .buffer = rest[0..scalar_len(rest.len)] } };
    }

    /// Folds `result` in: null to submit again, otherwise the bytes received. The end of
    /// the stream fails.
    pub fn on_cqe(self: *Recv, result: i32) ?Error!usize {
        assert(self.received < self.buffer.len);
        switch (CqeResult.from_raw(result)) {
            .retry => return null,
            .failure => return error.RecvFailed,
            .count => |count| {
                if (count == 0) return error.RecvFailed;
                // A CQE never reports more than its SQE asked for.
                assert(count <= scalar_len(self.buffer.len - self.received));
                self.received += count;
                if (self.exact and self.received < self.buffer.len) return null;
                return self.received;
            },
        }
    }
};
