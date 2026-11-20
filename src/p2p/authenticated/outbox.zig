//! Outbound queues of one connection (commonware `p2p/src/authenticated/relay.rs` and the
//! `Outbox` in `connection.rs`): a kill signal and bounded control (gossip), high-, and
//! low-priority queues behind one lock, read in priority order (kill, control, high, low) with a
//! deadline for pings.
//!
//! commonware selects over three mailboxes; one locked queue gives the same priority order
//! and the same `Rejected` on a full queue, and a timed wait replaces the ping timer branch.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const metrics = @import("runtime").telemetry.metrics;
const p2p = @import("../root.zig");
const data = @import("data.zig");

const Channel = p2p.Channel;
const Feedback = p2p.Feedback;
const Unreliable = p2p.Unreliable;

/// An encoded data frame (`data_prefix || channel || len || message`) shared by every
/// recipient of one send; the last `release` frees it.
pub const Frame = struct {
    gpa: Allocator,
    refs: std.atomic.Value(u32),
    /// The data channel, or null for a control frame.
    channel: ?Channel,
    bytes: []u8,

    /// Encodes `parts` (concatenated) as a data frame on `channel`, with one reference.
    pub fn create(
        gpa: Allocator,
        channel: Channel,
        parts: []const []const u8,
    ) Allocator.Error!*Frame {
        var len: usize = 0;
        for (parts) |part| len += part.len;
        const header: data.Header = .init(channel, len);
        const bytes = try gpa.alloc(u8, header.len + len);
        errdefer gpa.free(bytes);
        @memcpy(bytes[0..header.len], header.slice());
        var offset: usize = header.len;
        for (parts) |part| {
            @memcpy(bytes[offset..][0..part.len], part);
            offset += part.len;
        }
        assert(offset == bytes.len);
        const frame = try gpa.create(Frame);
        frame.* = .{ .gpa = gpa, .refs = .init(1), .channel = channel, .bytes = bytes };
        return frame;
    }

    /// Wraps `bytes` (owned, already encoded) as a control frame with one reference.
    pub fn adopt(gpa: Allocator, bytes: []u8) Allocator.Error!*Frame {
        errdefer gpa.free(bytes);
        const frame = try gpa.create(Frame);
        frame.* = .{ .gpa = gpa, .refs = .init(1), .channel = null, .bytes = bytes };
        return frame;
    }

    pub fn retain(frame: *Frame) *Frame {
        const previous = frame.refs.fetchAdd(1, .monotonic);
        assert(previous > 0);
        return frame;
    }

    pub fn release(frame: *Frame) void {
        const previous = frame.refs.fetchSub(1, .acq_rel);
        assert(previous > 0);
        if (previous > 1) return;
        frame.gpa.free(frame.bytes);
        frame.gpa.destroy(frame);
    }
};

pub const Next = union(enum) {
    /// The connection was killed (commonware `Message::Kill`) or closed.
    killed,
    /// The ping deadline passed.
    deadline,
    frame: *Frame,
};

pub const Outbox = struct {
    io: Io,
    gpa: Allocator,
    mutex: Io.Mutex = .init,
    condition: Io.Condition = .init,
    /// Frames each queue holds before sends are rejected.
    capacity: u32,
    killed: bool = false,
    /// Counts a kill that finds the control queue full: commonware's peer mailbox takes
    /// `Kill` into its overflow then, which its `backoff` counter records.
    kill_backoff: ?*metrics.raw.Counter = null,
    control: std.Deque(*Frame) = .empty,
    high: std.Deque(*Frame) = .empty,
    low: std.Deque(*Frame) = .empty,

    pub fn init(gpa: Allocator, io: Io, capacity: u32) Outbox {
        assert(capacity > 0);
        return .{ .io = io, .gpa = gpa, .capacity = capacity };
    }

    /// Releases queued frames; `kill` must have run, or no one else may hold the outbox.
    pub fn deinit(outbox: *Outbox) void {
        outbox.drain();
        outbox.control.deinit(outbox.gpa);
        outbox.high.deinit(outbox.gpa);
        outbox.low.deinit(outbox.gpa);
        outbox.* = undefined;
    }

    fn drain(outbox: *Outbox) void {
        while (outbox.control.popFront()) |frame| frame.release();
        while (outbox.high.popFront()) |frame| frame.release();
        while (outbox.low.popFront()) |frame| frame.release();
    }

    /// Queues `frame` (taking a reference) on the queue `priority` selects. `rejected` when
    /// that queue is full; `closed` once the connection is killed.
    pub fn send(outbox: *Outbox, frame: *Frame, priority: bool) Unreliable(Feedback) {
        outbox.mutex.lockUncancelable(outbox.io);
        defer outbox.mutex.unlock(outbox.io);
        if (outbox.killed) return .new(.closed);
        const queue = if (priority) &outbox.high else &outbox.low;
        if (queue.len >= outbox.capacity) return .rejected;
        queue.pushBack(outbox.gpa, frame.retain()) catch {
            frame.release();
            return .rejected;
        };
        outbox.condition.signal(outbox.io);
        return .new(.ok);
    }

    /// Queues a control `frame` (taking a reference) ahead of data. Returns false, dropping
    /// it, when the control queue is full or the connection is killed (commonware's
    /// unreliable control mailbox; a kill is never dropped).
    pub fn send_control(outbox: *Outbox, frame: *Frame) bool {
        outbox.mutex.lockUncancelable(outbox.io);
        defer outbox.mutex.unlock(outbox.io);
        if (outbox.killed or outbox.control.len >= outbox.capacity) return false;
        outbox.control.pushBack(outbox.gpa, frame.retain()) catch {
            frame.release();
            return false;
        };
        outbox.condition.signal(outbox.io);
        return true;
    }

    /// Ends the connection: the sender sees `killed` and later sends report `closed`.
    pub fn kill(outbox: *Outbox) void {
        outbox.mutex.lockUncancelable(outbox.io);
        defer outbox.mutex.unlock(outbox.io);
        const full = !outbox.killed and outbox.control.len >= outbox.capacity;
        if (full) if (outbox.kill_backoff) |counter| counter.inc();
        outbox.killed = true;
        outbox.drain();
        outbox.condition.broadcast(outbox.io);
    }

    /// The next frame, a kill, or the deadline, whichever comes first (kill before high
    /// before low). The caller owns a returned frame's reference.
    pub fn next(outbox: *Outbox, deadline: Io.Clock.Timestamp) Io.Cancelable!Next {
        try outbox.mutex.lock(outbox.io);
        defer outbox.mutex.unlock(outbox.io);
        while (true) {
            if (outbox.take()) |item| return item;
            const timeout: Io.Timeout = .{ .deadline = deadline };
            outbox.condition.waitTimeout(outbox.io, &outbox.mutex, timeout) catch |err| {
                switch (err) {
                    error.Timeout => return outbox.take() orelse .deadline,
                    error.Canceled => return error.Canceled,
                }
            };
        }
    }

    /// The next queued item without waiting.
    pub fn try_next(outbox: *Outbox) ?Next {
        outbox.mutex.lockUncancelable(outbox.io);
        defer outbox.mutex.unlock(outbox.io);
        return outbox.take();
    }

    fn take(outbox: *Outbox) ?Next {
        if (outbox.killed) return .killed;
        if (outbox.control.popFront()) |frame| return .{ .frame = frame };
        if (outbox.high.popFront()) |frame| return .{ .frame = frame };
        if (outbox.low.popFront()) |frame| return .{ .frame = frame };
        return null;
    }
};

const testing = std.testing;

test "relay content priority and overflow" {
    var outbox = Outbox.init(testing.allocator, Io.failing, 1);
    defer outbox.deinit();
    const high = try Frame.create(testing.allocator, 1, &.{"high"});
    defer high.release();
    const low = try Frame.create(testing.allocator, 2, &.{"low"});
    defer low.release();
    try testing.expectEqual(Unreliable(Feedback).new(.ok), outbox.send(low, false));
    try testing.expectEqual(Unreliable(Feedback).rejected, outbox.send(low, false));
    try testing.expectEqual(Unreliable(Feedback).new(.ok), outbox.send(high, true));
    const first = outbox.try_next().?.frame;
    defer first.release();
    try testing.expectEqual(@as(?Channel, 1), first.channel);
    const second = outbox.try_next().?.frame;
    defer second.release();
    try testing.expectEqual(@as(?Channel, 2), second.channel);
    try testing.expect(outbox.try_next() == null);
}

test "kill comes first and closes later sends" {
    var outbox = Outbox.init(testing.allocator, Io.failing, 4);
    defer outbox.deinit();
    const frame = try Frame.create(testing.allocator, 3, &.{ "a", "bc" });
    defer frame.release();
    try testing.expectEqual(Unreliable(Feedback).new(.ok), outbox.send(frame, true));
    outbox.kill();
    try testing.expect(outbox.try_next().? == .killed);
    try testing.expectEqual(Unreliable(Feedback).new(.closed), outbox.send(frame, false));
}

test "control frames go ahead of data and drop when full" {
    var outbox = Outbox.init(testing.allocator, Io.failing, 1);
    defer outbox.deinit();
    const high = try Frame.create(testing.allocator, 1, &.{"high"});
    defer high.release();
    const control = try Frame.adopt(testing.allocator, try testing.allocator.dupe(u8, "ping"));
    defer control.release();
    try testing.expectEqual(Unreliable(Feedback).new(.ok), outbox.send(high, true));
    try testing.expect(outbox.send_control(control));
    try testing.expect(!outbox.send_control(control));
    const first = outbox.try_next().?.frame;
    defer first.release();
    try testing.expect(first == control and first.channel == null);
    const second = outbox.try_next().?.frame;
    defer second.release();
    try testing.expect(second == high);
    outbox.kill();
    try testing.expect(!outbox.send_control(control));
}

test "a kill lands when the control queue is full, and counts as backoff" {
    var backoff: metrics.raw.Counter = .{};
    // A kill with room in the control queue is not backoff.
    var roomy = Outbox.init(testing.allocator, Io.failing, 1);
    defer roomy.deinit();
    roomy.kill_backoff = &backoff;
    roomy.kill();
    try testing.expectEqual(@as(u64, 0), backoff.get());
    var outbox = Outbox.init(testing.allocator, Io.failing, 1);
    defer outbox.deinit();
    outbox.kill_backoff = &backoff;
    const control = try Frame.adopt(testing.allocator, try testing.allocator.dupe(u8, "peers"));
    defer control.release();
    try testing.expect(outbox.send_control(control));
    try testing.expect(!outbox.send_control(control));
    outbox.kill();
    try testing.expect(outbox.try_next().? == .killed);
    try testing.expectEqual(@as(u64, 1), backoff.get());
    // A second kill finds the connection already killed.
    outbox.kill();
    try testing.expectEqual(@as(u64, 1), backoff.get());
}

test "frame bytes encode a data message" {
    const codec = @import("codec");
    const frame = try Frame.create(testing.allocator, 12345, &.{ "hello ", "world", "!" });
    defer frame.release();
    try testing.expectEqual(data.data_prefix, frame.bytes[0]);
    const decoded = try codec.decode_cfg(data.Data, testing.allocator, frame.bytes[1..], .full());
    try testing.expectEqual(@as(Channel, 12345), decoded.channel);
    try testing.expectEqualStrings("hello world!", decoded.message);
}
