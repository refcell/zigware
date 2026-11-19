//! Multi-producer, single-consumer channels (commonware re-exports `tokio::sync::mpsc` as
//! `commonware_utils::channel::mpsc`).
//!
//! `channel(T, gpa, io, capacity)` is bounded: its buffer is allocated up front and `send`
//! waits for room. `unbounded(T, gpa, io)` never waits but allocates as it grows. State is
//! guarded by a `std.Io.Mutex`, and waiters park on a `std.Io.Condition`, so the channel runs
//! on any `std.Io`, deterministically on the simulated one.
//!
//! Semantics follow tokio:
//! - A send fails with `error.Closed` once the receiver is closed or dropped; the caller still
//!   owns the value.
//! - `recv` returns null once every sender is gone and the buffer is drained; `try_recv` fails
//!   with `error.Empty` (senders remain) or `error.Disconnected`.
//! - `reserve` waits for a slot and returns a `Permit` that sends without waiting; a dropped
//!   permit returns its slot. Buffered values plus outstanding permits never exceed capacity.
//! - `Receiver.close` refuses later sends and reservations but keeps buffered values
//!   readable. `Receiver.deinit` drops buffered values (passed to `T.discard`, if declared).
//!
//! Handles are values: `Sender.clone` adds a sender, and each handle is released exactly once
//! with `deinit` (or `Permit.send`). The state is freed with the last handle.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const SendError = error{Closed};
pub const TrySendError = error{ Full, Closed };
pub const TryRecvError = error{ Empty, Disconnected };

pub fn Pair(comptime T: type) type {
    return struct { sender: Sender(T), receiver: Receiver(T) };
}

/// A bounded channel holding at most `capacity` values (tokio `mpsc::channel`).
pub fn channel(comptime T: type, gpa: Allocator, io: Io, capacity: usize) Allocator.Error!Pair(T) {
    assert(capacity > 0); // tokio panics on a zero capacity.
    const state = try gpa.create(State(T));
    errdefer gpa.destroy(state);
    state.* = .{ .gpa = gpa, .io = io, .capacity = capacity };
    state.buffer = try .initCapacity(gpa, capacity);
    return .{ .sender = .{ .state = state }, .receiver = .{ .state = state } };
}

/// An unbounded channel (tokio `mpsc::unbounded_channel`): sends never wait.
pub fn unbounded(comptime T: type, gpa: Allocator, io: Io) Allocator.Error!Pair(T) {
    const state = try gpa.create(State(T));
    state.* = .{ .gpa = gpa, .io = io, .capacity = null };
    return .{ .sender = .{ .state = state }, .receiver = .{ .state = state } };
}

pub fn Sender(comptime T: type) type {
    return struct {
        const Self = @This();

        state: *State(T),

        /// Another sender for the same channel.
        pub fn clone(sender: Self) Self {
            const state = sender.state;
            state.lock();
            defer state.unlock();
            assert(state.senders > 0);
            state.senders += 1;
            state.handles += 1;
            return .{ .state = state };
        }

        /// Sends `value`, waiting for room in a bounded channel. On `error.Closed` the caller
        /// still owns `value`. An unbounded channel can fail with `error.OutOfMemory`.
        pub fn send(sender: Self, value: T) (SendError || Io.Cancelable || Allocator.Error)!void {
            const state = sender.state;
            state.lock();
            defer state.unlock();
            while (true) {
                if (!state.receiver_open) return error.Closed;
                if (state.has_room()) break;
                try state.condition.wait(state.io, &state.mutex);
            }
            try state.push(value);
        }

        /// Sends `value` without waiting. On an error the caller still owns `value`.
        pub fn try_send(sender: Self, value: T) (TrySendError || Allocator.Error)!void {
            const state = sender.state;
            state.lock();
            defer state.unlock();
            if (!state.receiver_open) return error.Closed;
            if (!state.has_room()) return error.Full;
            try state.push(value);
        }

        /// Waits for a slot and holds it. Bounded channels only.
        pub fn reserve(sender: Self) (SendError || Io.Cancelable)!Permit(T) {
            const state = sender.state;
            assert(state.capacity != null);
            state.lock();
            defer state.unlock();
            while (true) {
                if (!state.receiver_open) return error.Closed;
                if (state.has_room()) break;
                try state.condition.wait(state.io, &state.mutex);
            }
            return state.acquire_permit();
        }

        /// Holds a slot if one is free. Bounded channels only.
        pub fn try_reserve(sender: Self) TrySendError!Permit(T) {
            const state = sender.state;
            assert(state.capacity != null);
            state.lock();
            defer state.unlock();
            if (!state.receiver_open) return error.Closed;
            if (!state.has_room()) return error.Full;
            return state.acquire_permit();
        }

        /// Whether the receiver was closed or dropped.
        pub fn is_closed(sender: Self) bool {
            const state = sender.state;
            state.lock();
            defer state.unlock();
            return !state.receiver_open;
        }

        /// Waits until the receiver is closed or dropped (tokio `Sender::closed`).
        pub fn closed(sender: Self) Io.Cancelable!void {
            const state = sender.state;
            state.lock();
            defer state.unlock();
            while (state.receiver_open) try state.condition.wait(state.io, &state.mutex);
        }

        /// Free slots now (tokio `Sender::capacity`). Bounded channels only.
        pub fn capacity(sender: Self) usize {
            const state = sender.state;
            state.lock();
            defer state.unlock();
            return state.capacity.? - state.buffer.len - state.permits;
        }

        /// Whether both senders belong to the same channel.
        pub fn same_channel(a: Self, b: Self) bool {
            return a.state == b.state;
        }

        pub fn deinit(sender: *Self) void {
            const state = sender.state;
            sender.* = undefined;
            state.lock();
            state.release_sender();
            state.release_locked();
        }
    };
}

/// A held slot in a bounded channel (tokio `Permit`/`OwnedPermit`).
pub fn Permit(comptime T: type) type {
    return struct {
        const Self = @This();

        state: *State(T),

        /// Sends `value` through the held slot, never waiting. If the receiver is gone, the
        /// value is discarded (tokio drops it).
        pub fn send(permit: *Self, value: T) void {
            const state = permit.state;
            permit.* = undefined;
            state.lock();
            assert(state.permits > 0);
            state.permits -= 1;
            var dropped: ?T = value;
            if (state.receiver_open) {
                state.buffer.pushBackAssumeCapacity(value);
                dropped = null;
            }
            state.condition.broadcast(state.io);
            state.release_sender();
            const last = state.release_locked_keep();
            if (dropped) |unsent| discard(T, unsent);
            if (last) state.destroy();
        }

        /// Returns the slot unused.
        pub fn deinit(permit: *Self) void {
            const state = permit.state;
            permit.* = undefined;
            state.lock();
            assert(state.permits > 0);
            state.permits -= 1;
            state.condition.broadcast(state.io);
            state.release_sender();
            state.release_locked();
        }
    };
}

pub fn Receiver(comptime T: type) type {
    return struct {
        const Self = @This();

        state: *State(T),

        /// The next value, or null once every sender is gone and the buffer is empty.
        pub fn recv(receiver: *Self) Io.Cancelable!?T {
            const state = receiver.state;
            state.lock();
            defer state.unlock();
            while (true) {
                if (state.pop()) |value| return value;
                if (state.senders == 0) return null;
                // A closed receiver with no permits outstanding gets nothing more.
                if (!state.receiver_open and state.permits == 0) return null;
                try state.condition.wait(state.io, &state.mutex);
            }
        }

        pub fn try_recv(receiver: *Self) TryRecvError!T {
            const state = receiver.state;
            state.lock();
            defer state.unlock();
            if (state.pop()) |value| return value;
            if (state.senders == 0) return error.Disconnected;
            if (!state.receiver_open and state.permits == 0) return error.Disconnected;
            return error.Empty;
        }

        /// Refuses later sends and reservations; buffered values stay readable.
        pub fn close(receiver: *Self) void {
            const state = receiver.state;
            state.lock();
            defer state.unlock();
            state.receiver_open = false;
            state.condition.broadcast(state.io);
        }

        /// Buffered values.
        pub fn len(receiver: *const Self) usize {
            const state = receiver.state;
            state.lock();
            defer state.unlock();
            return state.buffer.len;
        }

        pub fn is_empty(receiver: *const Self) bool {
            return receiver.len() == 0;
        }

        /// Drops the receiver and every buffered value.
        pub fn deinit(receiver: *Self) void {
            const state = receiver.state;
            receiver.* = undefined;
            state.lock();
            state.receiver_open = false;
            var buffer = state.buffer;
            state.buffer = .empty;
            state.condition.broadcast(state.io);
            // Read before releasing: once released, the last sender may free `state`.
            const gpa = state.gpa;
            const last = state.release_locked_keep();
            // Outside the lock: a discarded value may own a sender of this channel.
            while (buffer.popFront()) |value| discard(T, value);
            buffer.deinit(gpa);
            if (last) state.destroy();
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
        /// Null for an unbounded channel.
        capacity: ?usize,
        /// Outstanding permits; each also counts as a sender.
        permits: usize = 0,
        /// Live senders, including permits.
        senders: usize = 1,
        receiver_open: bool = true,
        /// Live handles (senders, permits, receiver); zero frees the state.
        handles: usize = 2,

        fn lock(state: *Self) void {
            state.mutex.lockUncancelable(state.io);
        }

        fn unlock(state: *Self) void {
            state.mutex.unlock(state.io);
        }

        fn has_room(state: *const Self) bool {
            const limit = state.capacity orelse return true;
            assert(state.buffer.len + state.permits <= limit);
            return state.buffer.len + state.permits < limit;
        }

        fn push(state: *Self, value: T) Allocator.Error!void {
            if (state.capacity == null) {
                try state.buffer.pushBack(state.gpa, value);
            } else {
                state.buffer.pushBackAssumeCapacity(value);
            }
            state.condition.broadcast(state.io);
        }

        fn pop(state: *Self) ?T {
            const value = state.buffer.popFront() orelse return null;
            // A slot freed: wake senders waiting for room.
            if (state.capacity != null) state.condition.broadcast(state.io);
            return value;
        }

        fn acquire_permit(state: *Self) Permit(T) {
            state.permits += 1;
            state.senders += 1;
            state.handles += 1;
            return .{ .state = state };
        }

        /// Drops one sender (lock held); the last wakes the receiver.
        fn release_sender(state: *Self) void {
            assert(state.senders > 0);
            state.senders -= 1;
            if (state.senders == 0) state.condition.broadcast(state.io);
        }

        /// Drops one handle and unlocks; frees the state with the last.
        fn release_locked(state: *Self) void {
            if (state.release_locked_keep()) state.destroy();
        }

        /// Drops one handle and unlocks; returns whether it was the last.
        fn release_locked_keep(state: *Self) bool {
            assert(state.handles > 0);
            state.handles -= 1;
            const last = state.handles == 0;
            state.unlock();
            return last;
        }

        fn destroy(state: *Self) void {
            assert(state.handles == 0 and state.senders == 0 and state.permits == 0);
            while (state.buffer.popFront()) |value| discard(T, value);
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

test {
    _ = @import("mpsc_test.zig");
}
