//! In-memory sink/stream pair (commonware `runtime/src/mocks.rs` `Channel`), the transport of
//! the deterministic network.
//!
//! Transport contract (commonware `runtime::{Sink, Stream}`), which `stream` builds on:
//!
//! ```zig
//! sink.send(bufs: []const []const u8) !void  // all buffers, in order, as one write
//! stream.recv(out: []u8) !void                // exactly out.len bytes
//! stream.peek(max_len: usize) []const u8      // buffered bytes, no I/O, never blocks
//! sink.deinit(); stream.deinit();             // close each half
//! ```
//!
//! After any error the sink or stream is unusable: the next call returns `error.Closed`.
//! `error.Canceled` passes through and also poisons the half it interrupted, like dropping a
//! Rust future mid-await. A canceled send closes the sink, so the peer's pending recv fails.
//!
//! The channel buffers what the sink sent. A receiving stream pulls up to `buffer_size` bytes
//! (at least what it asked for) into its local buffer, which `peek` exposes. A send that
//! leaves more than `buffer_size` bytes in the channel blocks until the stream drains it.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

/// Default buffer size (64 KiB): how much the stream pulls per recv and the backpressure
/// threshold for send.
pub const default_buffer_size = 64 * 1024;

pub const Error = error{ SendFailed, RecvFailed, Closed, OutOfMemory } || Io.Cancelable;

const Shared = struct {
    gpa: Allocator,
    io: Io,
    mutex: Io.Mutex = .init,
    condition: Io.Condition = .init,
    /// Bytes sent by the sink, not yet pulled by the stream.
    channel: std.ArrayList(u8) = .empty,
    /// Bytes pulled by the stream, not yet consumed (what `peek` sees). The sink appends here
    /// only while a `recv` waits, so `peek` never races it.
    local: std.ArrayList(u8) = .empty,
    buffer_size: usize,
    /// Bytes a blocked `recv` still needs; the sink hands them over directly.
    waiter: ?usize = null,
    drain_waiting: bool = false,
    sink_alive: bool = true,
    stream_alive: bool = true,
    handles: u8 = 2,

    fn lock(shared: *Shared) void {
        shared.mutex.lockUncancelable(shared.io);
    }

    fn unlock(shared: *Shared) void {
        shared.mutex.unlock(shared.io);
    }

    /// Move `count` bytes from the front of the channel to the local buffer (lock held).
    fn pull(shared: *Shared, count: usize) Allocator.Error!void {
        assert(count <= shared.channel.items.len);
        try shared.local.appendSlice(shared.gpa, shared.channel.items[0..count]);
        shared.channel.replaceRangeAssumeCapacity(0, count, &.{});
    }

    /// Mark the sink closed and wake a waiting receiver (lock held).
    fn close_sink(shared: *Shared) void {
        shared.sink_alive = false;
        shared.condition.broadcast(shared.io);
    }

    fn release(shared: *Shared) void {
        shared.lock();
        assert(shared.handles > 0);
        shared.handles -= 1;
        const last = shared.handles == 0;
        shared.unlock();
        if (!last) return;
        shared.channel.deinit(shared.gpa);
        shared.local.deinit(shared.gpa);
        shared.gpa.destroy(shared);
    }
};

pub const Pair = struct { sink: Sink, stream: Stream };

/// Returns a sink/stream pair with the default buffer size.
pub fn channel(gpa: Allocator, io: Io) Allocator.Error!Pair {
    return channel_with_buffer_size(gpa, io, default_buffer_size);
}

/// Returns a sink/stream pair with the given buffer size. Zero is valid, as in commonware:
/// every send then blocks until the stream reads it, and `peek` sees nothing a recv did not
/// pull (commonware's stream tests use sizes 0 through 5).
pub fn channel_with_buffer_size(gpa: Allocator, io: Io, buffer_size: usize) Allocator.Error!Pair {
    const shared = try gpa.create(Shared);
    shared.* = .{ .gpa = gpa, .io = io, .buffer_size = buffer_size };
    return .{ .sink = .{ .shared = shared }, .stream = .{ .shared = shared } };
}

pub const Sink = struct {
    shared: *Shared,
    closed: bool = false,

    pub fn send(sink: *Sink, bufs: []const []const u8) Error!void {
        if (sink.closed) return error.Closed;
        const shared = sink.shared;
        shared.lock();
        defer shared.unlock();
        if (!shared.stream_alive) return sink.fail();
        for (bufs) |buf| shared.channel.appendSlice(shared.gpa, buf) catch return sink.fail();

        // Hand a blocked receiver what it needs (up to `buffer_size`) directly.
        const requested = shared.waiter orelse std.math.maxInt(usize);
        if (requested <= shared.channel.items.len) {
            const amount = @min(shared.channel.items.len, @max(requested, shared.buffer_size));
            shared.pull(amount) catch return sink.fail();
            shared.waiter = null;
            shared.condition.broadcast(shared.io);
        }

        // Block until the receiver drains the channel below the limit.
        if (shared.channel.items.len <= shared.buffer_size) return;
        assert(!shared.drain_waiting);
        shared.drain_waiting = true;
        while (shared.drain_waiting and shared.stream_alive) {
            shared.condition.wait(shared.io, &shared.mutex) catch |err| {
                shared.drain_waiting = false;
                sink.closed = true;
                shared.close_sink();
                return err;
            };
        }
        if (shared.drain_waiting) {
            shared.drain_waiting = false;
            return sink.fail();
        }
    }

    /// Close the sink after an error (lock held).
    fn fail(sink: *Sink) Error {
        sink.closed = true;
        sink.shared.close_sink();
        return error.SendFailed;
    }

    /// Close the sink: a receiver waiting for more bytes fails.
    pub fn deinit(sink: *Sink) void {
        const shared = sink.shared;
        sink.* = undefined;
        shared.lock();
        shared.close_sink();
        shared.unlock();
        shared.release();
    }
};

pub const Stream = struct {
    shared: *Shared,
    poisoned: bool = false,

    pub fn recv(stream: *Stream, out: []u8) Error!void {
        if (stream.poisoned) return error.Closed;
        const shared = stream.shared;
        shared.lock();
        defer shared.unlock();
        assert(shared.waiter == null);

        // Pull from the channel into the local buffer, then wake a blocked sender.
        const target = @max(out.len, shared.buffer_size);
        const room = target -| shared.local.items.len;
        const amount = @min(shared.channel.items.len, room);
        if (amount > 0) {
            shared.pull(amount) catch return stream.fail();
            if (shared.channel.items.len <= shared.buffer_size and shared.drain_waiting) {
                shared.drain_waiting = false;
                shared.condition.broadcast(shared.io);
            }
        }

        if (shared.local.items.len < out.len) {
            if (!shared.sink_alive) return stream.fail();
            shared.waiter = out.len - shared.local.items.len;
            while (shared.waiter != null and shared.sink_alive) {
                shared.condition.wait(shared.io, &shared.mutex) catch |err| {
                    shared.waiter = null;
                    stream.poisoned = true;
                    return err;
                };
            }
            if (shared.waiter != null) {
                shared.waiter = null;
                return stream.fail();
            }
        }
        assert(shared.local.items.len >= out.len);
        @memcpy(out, shared.local.items[0..out.len]);
        shared.local.replaceRangeAssumeCapacity(0, out.len, &.{});
    }

    fn fail(stream: *Stream) Error {
        stream.poisoned = true;
        return error.RecvFailed;
    }

    /// Up to `max_len` received bytes not yet consumed by `recv`.
    pub fn peek(stream: *const Stream, max_len: usize) []const u8 {
        const local = stream.shared.local.items;
        return local[0..@min(max_len, local.len)];
    }

    /// Close the stream: a blocked or later send fails.
    pub fn deinit(stream: *Stream) void {
        const shared = stream.shared;
        stream.* = undefined;
        shared.lock();
        shared.stream_alive = false;
        shared.condition.broadcast(shared.io);
        shared.unlock();
        shared.release();
    }
};

test {
    _ = @import("mocks_test.zig");
}
