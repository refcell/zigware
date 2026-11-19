//! A bounded mpsc channel that drops the oldest item when full instead of applying
//! backpressure (commonware `utils/src/channel/ring.rs`).
//!
//! `channel(T, gpa, io, capacity)` allocates the whole buffer up front, so sends never
//! allocate or wait. The receiver ends (`recv` returns null) once every sender is gone and the
//! buffer is drained. State is guarded by a `std.Io.Mutex`; the receiver parks on a
//! `std.Io.Condition`. Dropped items (evicted, or unread when the receiver goes) are passed to
//! `T.discard`, if declared, outside the lock, so a discarded item may own a sender.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

/// The receiver was dropped.
pub const ChannelClosed = error{ChannelClosed};
pub const TryRecvError = error{ Empty, Disconnected };

pub fn Pair(comptime T: type) type {
    return struct { sender: Sender(T), receiver: Receiver(T) };
}

pub fn channel(comptime T: type, gpa: Allocator, io: Io, capacity: usize) Allocator.Error!Pair(T) {
    assert(capacity > 0);
    const state = try gpa.create(State(T));
    errdefer gpa.destroy(state);
    state.* = .{ .gpa = gpa, .io = io, .capacity = capacity };
    state.buffer = try .initCapacity(gpa, capacity);
    return .{ .sender = .{ .state = state }, .receiver = .{ .state = state } };
}

pub fn Sender(comptime T: type) type {
    return struct {
        const Self = @This();

        state: *State(T),

        pub fn clone(sender: Self) Self {
            const state = sender.state;
            state.lock();
            defer state.unlock();
            assert(state.senders > 0);
            state.senders += 1;
            state.handles += 1;
            return .{ .state = state };
        }

        /// Whether the receiver was dropped: later sends fail.
        pub fn is_closed(sender: Self) bool {
            const state = sender.state;
            state.lock();
            defer state.unlock();
            return state.receiver_dropped;
        }

        /// Sends `item`, evicting the oldest buffered item when full. Returns false once the
        /// receiver is dropped (the item is then discarded).
        pub fn send_lossy(sender: Self, item: T) bool {
            const state = sender.state;
            state.lock();
            if (state.receiver_dropped) {
                state.unlock();
                discard(T, item);
                return false;
            }
            const full = state.buffer.len >= state.capacity;
            const evicted = if (full) state.buffer.popFront() else null;
            state.buffer.pushBackAssumeCapacity(item);
            assert(state.buffer.len <= state.capacity);
            state.condition.signal(state.io);
            state.unlock();
            if (evicted) |old| discard(T, old);
            return true;
        }

        /// `send_lossy` as an error (Rust `Sink::send`); the item is discarded on error.
        pub fn send(sender: Self, item: T) ChannelClosed!void {
            if (!sender.send_lossy(item)) return error.ChannelClosed;
        }

        pub fn deinit(sender: *Self) void {
            const state = sender.state;
            sender.* = undefined;
            state.lock();
            assert(state.senders > 0);
            state.senders -= 1;
            if (state.senders == 0) state.condition.signal(state.io);
            state.release_locked();
        }
    };
}

pub fn Receiver(comptime T: type) type {
    return struct {
        const Self = @This();

        state: *State(T),

        /// The oldest buffered item, or null once every sender is gone and nothing is left.
        pub fn recv(receiver: *Self) Io.Cancelable!?T {
            const state = receiver.state;
            state.lock();
            defer state.unlock();
            while (true) {
                if (state.buffer.popFront()) |item| return item;
                if (state.senders == 0) return null;
                try state.condition.wait(state.io, &state.mutex);
            }
        }

        pub fn try_recv(receiver: *Self) TryRecvError!T {
            const state = receiver.state;
            state.lock();
            defer state.unlock();
            if (state.buffer.popFront()) |item| return item;
            if (state.senders == 0) return error.Disconnected;
            return error.Empty;
        }

        /// No sender remains and nothing is buffered (Rust `FusedStream::is_terminated`).
        pub fn is_terminated(receiver: *const Self) bool {
            const state = receiver.state;
            state.lock();
            defer state.unlock();
            return state.senders == 0 and state.buffer.len == 0;
        }

        /// Drops the receiver and every unread item.
        pub fn deinit(receiver: *Self) void {
            const state = receiver.state;
            receiver.* = undefined;
            state.lock();
            state.receiver_dropped = true;
            var buffer = state.buffer;
            state.buffer = .empty;
            const gpa = state.gpa;
            // Unread items are discarded after unlocking: one may own the last sender.
            state.release_locked();
            while (buffer.popFront()) |item| discard(T, item);
            buffer.deinit(gpa);
        }
    };
}

fn State(comptime T: type) type {
    return struct {
        const Self = @This();

        gpa: Allocator,
        io: Io,
        mutex: Io.Mutex = .init,
        condition: Io.Condition = .init,
        buffer: std.Deque(T) = .empty,
        capacity: usize,
        senders: usize = 1,
        receiver_dropped: bool = false,
        /// Live senders plus the receiver; zero frees the state.
        handles: usize = 2,

        fn lock(state: *Self) void {
            state.mutex.lockUncancelable(state.io);
        }

        fn unlock(state: *Self) void {
            state.mutex.unlock(state.io);
        }

        /// Drops one handle and unlocks, freeing the state with the last.
        fn release_locked(state: *Self) void {
            assert(state.handles > 0);
            state.handles -= 1;
            const last = state.handles == 0;
            state.unlock();
            if (!last) return;
            assert(state.senders == 0 and state.receiver_dropped);
            assert(state.buffer.len == 0);
            state.buffer.deinit(state.gpa);
            state.gpa.destroy(state);
        }
    };
}

fn discard(comptime T: type, value: T) void {
    switch (@typeInfo(T)) {
        .@"struct", .@"union", .@"enum", .@"opaque" => {
            if (@hasDecl(T, "discard")) T.discard(value);
        },
        else => {},
    }
}

const testing = std.testing;
const gpa_test = testing.allocator;

fn expect_recv(receiver: anytype, expected: ?i32) !void {
    try testing.expectEqual(expected, try receiver.recv());
}

test "ring: basic send and recv" {
    var pair = try channel(i32, gpa_test, testing.io, 10);
    defer pair.receiver.deinit();
    defer pair.sender.deinit();
    for ([_]i32{ 1, 2, 3 }) |item| try pair.sender.send(item);
    for ([_]i32{ 1, 2, 3 }) |item| try expect_recv(&pair.receiver, item);
}

test "ring: overflow drops the oldest" {
    var pair = try channel(i32, gpa_test, testing.io, 2);
    defer pair.receiver.deinit();
    defer pair.sender.deinit();
    for ([_]i32{ 1, 2, 3, 4 }) |item| try pair.sender.send(item);
    try expect_recv(&pair.receiver, 3);
    try expect_recv(&pair.receiver, 4);

    // Capacity one keeps only the newest.
    var single = try channel(i32, gpa_test, testing.io, 1);
    defer single.receiver.deinit();
    defer single.sender.deinit();
    try single.sender.send(1);
    try single.sender.send(2);
    try expect_recv(&single.receiver, 2);
    for ([_]i32{ 1, 2, 3 }) |item| try single.sender.send(item);
    try expect_recv(&single.receiver, 3);
}

test "ring: send after the receiver is dropped fails" {
    var pair = try channel(i32, gpa_test, testing.io, 10);
    defer pair.sender.deinit();
    try testing.expect(!pair.sender.is_closed());
    pair.receiver.deinit();
    try testing.expect(pair.sender.is_closed());
    try testing.expectError(error.ChannelClosed, pair.sender.send(1));
}

test "ring: recv drains, then ends after the senders go" {
    var pair = try channel(i32, gpa_test, testing.io, 10);
    defer pair.receiver.deinit();
    var second = pair.sender.clone();
    try pair.sender.send(1);
    pair.sender.deinit();
    // Still open: a clone remains.
    try testing.expect(!pair.receiver.is_terminated());
    try second.send(2);
    second.deinit();
    try testing.expect(!pair.receiver.is_terminated());
    try expect_recv(&pair.receiver, 1);
    try expect_recv(&pair.receiver, 2);
    try testing.expect(pair.receiver.is_terminated());
    try expect_recv(&pair.receiver, null);
    try testing.expectError(error.Disconnected, pair.receiver.try_recv());
}

/// An item that owns a sender of its own channel (commonware's `Probe`): it must be discarded
/// outside the channel lock, or releasing its sender deadlocks.
const Probe = struct {
    sender: Sender(Probe),
    released: *u32,

    pub fn discard(probe: Probe) void {
        var sender = probe.sender;
        sender.deinit();
        probe.released.* += 1;
    }
};

fn new_probe(sender: Sender(Probe), released: *u32) Probe {
    return .{ .sender = sender.clone(), .released = released };
}

test "ring: dropping the receiver releases unread items outside the lock" {
    var released: u32 = 0;
    var pair = try channel(Probe, gpa_test, testing.io, 1);
    try testing.expect(pair.sender.send_lossy(new_probe(pair.sender, &released)));
    // Evicting an item releases its sender too.
    try testing.expect(pair.sender.send_lossy(new_probe(pair.sender, &released)));
    try testing.expectEqual(1, released);
    pair.receiver.deinit();
    try testing.expectEqual(2, released);
    // A send after the receiver is gone discards the item.
    try testing.expect(!pair.sender.send_lossy(new_probe(pair.sender, &released)));
    try testing.expectEqual(3, released);
    pair.sender.deinit(); // The last handle frees the channel (the allocator checks).
}

fn send_later(sender: Sender(i32), io: Io) Io.Cancelable!void {
    var owned = sender;
    defer owned.deinit();
    try io.sleep(.fromMilliseconds(1), .awake);
    // Proof: the test awaits this task before it drops the receiver, so the channel is open
    // whether or not the receiver has parked in `recv` yet.
    owned.send(9) catch unreachable;
}

test "ring: recv waits for a concurrent sender" {
    const io = testing.io;
    var pair = try channel(i32, gpa_test, io, 2);
    defer pair.receiver.deinit();
    var future = try io.concurrent(send_later, .{ pair.sender, io });
    try expect_recv(&pair.receiver, 9);
    try future.await(io);
    try expect_recv(&pair.receiver, null);
}
