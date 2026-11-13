//! A channel for sending a single value between tasks (commonware re-exports
//! `tokio::sync::oneshot` as `commonware_utils::channel::oneshot`).
//!
//! `channel(T, gpa, io)` returns a `Sender(T)` and a `Receiver(T)` sharing one heap state. The
//! state is guarded by a `std.Io.Mutex` and waiters park on a `std.Io.Condition`, so the
//! channel runs on any `std.Io`, including the deterministic runtime, where it is
//! deterministic.
//!
//! Semantics follow tokio:
//! - `Sender.send(value)` consumes the sender. It fails with `error.Closed` (the caller keeps
//!   `value`) when the receiver was closed or dropped.
//! - `Sender.deinit` drops the sender without a value; a waiting `recv` then fails with
//!   `error.Closed`.
//! - `Sender.is_closed` / `Sender.closed` detect that the receiver no longer wants the value
//!   (closed or dropped), so a producer can stop work early (tokio `closed().await`).
//! - `Receiver.recv` waits for the value (cancelable). `try_recv` never waits:
//!   `error.Empty` while the sender may still send, `error.Closed` once it cannot.
//! - `Receiver.close` refuses later sends but keeps a value already sent readable with
//!   `try_recv` / `recv` (tokio `close` then `try_recv`).
//! - `Receiver.deinit` drops the receiver and any unreceived value.
//!
//! Handles are values: each side is released exactly once, by `send`/`deinit` (sender) or
//! `deinit` (receiver); the state is freed with the last one. A value dropped by the channel
//! (sent but never received) is passed to `T.discard(value)` when `T` declares it (Rust
//! `Drop`), so values that own resources are not leaked.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

/// `send` failed: the receiver was closed or dropped. The caller still owns the value.
pub const SendError = error{Closed};

/// `recv` failed: the sender was dropped without sending, or the value was already taken.
pub const RecvError = error{Closed} || Io.Cancelable;

/// `try_recv` failed (tokio `TryRecvError`).
pub const TryRecvError = error{
    /// No value yet, and the sender may still send one.
    Empty,
    /// No value, and none will arrive.
    Closed,
};

/// The two halves returned by `channel`.
pub fn Pair(comptime T: type) type {
    return struct { sender: Sender(T), receiver: Receiver(T) };
}

/// Create a oneshot channel.
pub fn channel(comptime T: type, gpa: Allocator, io: Io) Allocator.Error!Pair(T) {
    const state = try gpa.create(State(T));
    state.* = .{ .gpa = gpa, .io = io };
    assert(state.handles == 2);
    assert(state.value == null);
    return .{ .sender = .{ .state = state }, .receiver = .{ .state = state } };
}

/// Sending half. Released by `send` or `deinit`.
pub fn Sender(comptime T: type) type {
    return struct {
        const Self = @This();

        state: *State(T),

        /// Send the value and release the sender. Fails with `error.Closed` when the receiver
        /// is closed or dropped; the caller then still owns `value`.
        pub fn send(sender: *Self, value: T) SendError!void {
            const state = sender.state;
            sender.* = undefined;
            state.lock();
            assert(state.sender_alive);
            assert(state.value == null);
            const open = state.receiver_open;
            if (open) {
                state.value = value;
                state.sent = true;
            }
            state.sender_alive = false;
            state.condition.broadcast(state.io);
            const last = state.release_locked();
            state.unlock();
            if (last) state.destroy();
            if (!open) return error.Closed;
        }

        /// Whether the receiver was closed or dropped: a sent value would be refused.
        pub fn is_closed(sender: Self) bool {
            const state = sender.state;
            state.lock();
            defer state.unlock();
            assert(state.sender_alive);
            return !state.receiver_open;
        }

        /// Wait until the receiver is closed or dropped (tokio `Sender::closed`).
        pub fn closed(sender: Self) Io.Cancelable!void {
            const state = sender.state;
            state.lock();
            defer state.unlock();
            assert(state.sender_alive);
            while (state.receiver_open) try state.condition.wait(state.io, &state.mutex);
            assert(!state.receiver_open);
        }

        /// Drop the sender without sending; a waiting receiver fails with `error.Closed`.
        pub fn deinit(sender: *Self) void {
            const state = sender.state;
            sender.* = undefined;
            state.lock();
            assert(state.sender_alive);
            assert(state.value == null);
            state.sender_alive = false;
            state.condition.broadcast(state.io);
            const last = state.release_locked();
            state.unlock();
            if (last) state.destroy();
        }
    };
}

/// Receiving half. Released by `deinit`.
pub fn Receiver(comptime T: type) type {
    return struct {
        const Self = @This();

        state: *State(T),

        /// Wait for the value. Fails with `error.Closed` when the sender was dropped without
        /// sending (or the value was already received), and `error.Canceled` on cancelation.
        pub fn recv(receiver: *Self) RecvError!T {
            const state = receiver.state;
            state.lock();
            defer state.unlock();
            while (true) {
                if (state.take()) |value| return value;
                if (!state.sender_alive) return error.Closed;
                try state.condition.wait(state.io, &state.mutex);
            }
        }

        /// Take the value without waiting.
        pub fn try_recv(receiver: *Self) TryRecvError!T {
            const state = receiver.state;
            state.lock();
            defer state.unlock();
            if (state.take()) |value| return value;
            if (!state.sender_alive) return error.Closed;
            // A closed receiver can never get a value it does not already hold.
            if (!state.receiver_open) return error.Closed;
            return error.Empty;
        }

        /// Refuse later sends and wake a sender waiting in `closed`. A value already sent
        /// stays readable.
        pub fn close(receiver: *Self) void {
            const state = receiver.state;
            state.lock();
            defer state.unlock();
            state.receiver_open = false;
            state.condition.broadcast(state.io);
            assert(!state.receiver_open);
        }

        /// Whether a value was sent and is waiting to be received.
        pub fn is_ready(receiver: Self) bool {
            const state = receiver.state;
            state.lock();
            defer state.unlock();
            return state.value != null;
        }

        /// Drop the receiver and any unreceived value (passed to `T.discard`, if declared).
        pub fn deinit(receiver: *Self) void {
            const state = receiver.state;
            receiver.* = undefined;
            state.lock();
            state.receiver_open = false;
            const dropped = state.value;
            state.value = null;
            state.condition.broadcast(state.io);
            const last = state.release_locked();
            state.unlock();
            // Outside the lock: a discarded value may own the other half of this channel.
            if (dropped) |value| discard(T, value);
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
        value: ?T = null,
        /// The value was sent (and possibly already received).
        sent: bool = false,
        sender_alive: bool = true,
        /// False once the receiver is closed or dropped.
        receiver_open: bool = true,
        /// Live halves; zero frees the state.
        handles: u8 = 2,

        fn lock(state: *Self) void {
            state.mutex.lockUncancelable(state.io);
        }

        fn unlock(state: *Self) void {
            state.mutex.unlock(state.io);
        }

        fn take(state: *Self) ?T {
            const value = state.value orelse return null;
            assert(state.sent);
            state.value = null;
            return value;
        }

        /// Drops one handle; returns true when it was the last (lock held).
        fn release_locked(state: *Self) bool {
            assert(state.handles > 0);
            assert(state.handles <= 2);
            state.handles -= 1;
            return state.handles == 0;
        }

        fn destroy(state: *Self) void {
            assert(state.handles == 0);
            assert(!state.sender_alive);
            assert(!state.receiver_open);
            // The receiver drops an unreceived value on `deinit`.
            assert(state.value == null);
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

test "send then recv" {
    var pair = try channel(u32, testing.allocator, testing.io);
    try pair.sender.send(7);
    try testing.expect(pair.receiver.is_ready());
    try testing.expectEqual(@as(u32, 7), try pair.receiver.recv());
    // The value is taken once.
    try testing.expectError(error.Closed, pair.receiver.recv());
    try testing.expectError(error.Closed, pair.receiver.try_recv());
    pair.receiver.deinit();
}

test "dropped sender closes the receiver" {
    var pair = try channel(u32, testing.allocator, testing.io);
    try testing.expectError(error.Empty, pair.receiver.try_recv());
    pair.sender.deinit();
    try testing.expectError(error.Closed, pair.receiver.try_recv());
    try testing.expectError(error.Closed, pair.receiver.recv());
    pair.receiver.deinit();
}

test "dropped receiver refuses the value" {
    var pair = try channel(u32, testing.allocator, testing.io);
    try testing.expect(!pair.sender.is_closed());
    pair.receiver.deinit();
    try testing.expect(pair.sender.is_closed());
    try pair.sender.closed(); // returns at once
    try testing.expectError(error.Closed, pair.sender.send(1));
}

test "close keeps a value already sent" {
    var pair = try channel(u32, testing.allocator, testing.io);
    try pair.sender.send(3);
    pair.receiver.close();
    try testing.expectEqual(@as(u32, 3), try pair.receiver.try_recv());
    try testing.expectError(error.Closed, pair.receiver.try_recv());
    pair.receiver.deinit();
}

test "close refuses later sends" {
    var pair = try channel(u32, testing.allocator, testing.io);
    pair.receiver.close();
    try testing.expectError(error.Closed, pair.receiver.try_recv());
    try testing.expect(pair.sender.is_closed());
    try testing.expectError(error.Closed, pair.sender.send(4));
    try testing.expectError(error.Closed, pair.receiver.recv());
    pair.receiver.deinit();
}

const Owned = struct {
    dropped: *u32,

    pub fn discard(value: Owned) void {
        value.dropped.* += 1;
    }
};

test "unreceived value is discarded" {
    var dropped: u32 = 0;
    var pair = try channel(Owned, testing.allocator, testing.io);
    try pair.sender.send(.{ .dropped = &dropped });
    try testing.expectEqual(@as(u32, 0), dropped);
    pair.receiver.deinit();
    try testing.expectEqual(@as(u32, 1), dropped);
}

fn send_later(sender: *Sender(u32), io: Io) Io.Cancelable!void {
    try io.sleep(.fromMilliseconds(1), .awake);
    sender.send(42) catch unreachable; // Proof: the receiver is waiting in `recv`.
}

test "recv waits for a concurrent sender" {
    const io = testing.io;
    var pair = try channel(u32, testing.allocator, io);
    var future = try io.concurrent(send_later, .{ &pair.sender, io });
    try testing.expectEqual(@as(u32, 42), try pair.receiver.recv());
    try future.await(io);
    pair.receiver.deinit();
}

fn wait_closed(sender: *Sender(u32)) Io.Cancelable!bool {
    try sender.closed();
    const refused = sender.is_closed();
    sender.deinit();
    return refused;
}

test "closed wakes when the receiver goes" {
    const io = testing.io;
    var pair = try channel(u32, testing.allocator, io);
    var future = try io.concurrent(wait_closed, .{&pair.sender});
    try io.sleep(.fromMilliseconds(1), .awake);
    pair.receiver.deinit();
    try testing.expect(try future.await(io));
}

fn recv_value(receiver: *Receiver(u32)) RecvError!u32 {
    return receiver.recv();
}

test "a waiting recv is cancelable" {
    const io = testing.io;
    var pair = try channel(u32, testing.allocator, io);
    var future = try io.concurrent(recv_value, .{&pair.receiver});
    try io.sleep(.fromMilliseconds(1), .awake);
    try testing.expectError(error.Canceled, future.cancel(io));
    // The channel is still usable after the canceled wait.
    try pair.sender.send(5);
    try testing.expectEqual(@as(u32, 5), try pair.receiver.try_recv());
    pair.receiver.deinit();
}

/// Model check of every single-task operation order against tokio's semantics.
fn oneshot_model(_: void, random: *@import("../rng.zig").FuzzRng) anyerror!void {
    const rng = @import("../rng.zig");
    var dropped: u32 = 0;
    var pair = try channel(Owned, testing.allocator, testing.io);
    var sender_live = true;
    var receiver_live = true;
    var receiver_closed = false;
    var held = false; // a sent value waits in the channel
    var step: u32 = 0;
    while (step < 8 and (sender_live or receiver_live)) : (step += 1) {
        switch (rng.range_less_than(random, u8, 0, 5)) {
            0 => if (sender_live) {
                try testing.expectEqual(!receiver_live or receiver_closed, pair.sender.is_closed());
                const result = pair.sender.send(.{ .dropped = &dropped });
                sender_live = false;
                if (!receiver_live or receiver_closed) {
                    try testing.expectError(error.Closed, result);
                } else {
                    try result;
                    held = true;
                }
            },
            1 => if (sender_live) {
                pair.sender.deinit();
                sender_live = false;
            },
            2 => if (receiver_live) {
                const result = pair.receiver.try_recv();
                if (held) {
                    _ = try result;
                    held = false;
                } else if (sender_live and !receiver_closed) {
                    try testing.expectError(error.Empty, result);
                } else {
                    try testing.expectError(error.Closed, result);
                }
            },
            3 => if (receiver_live) {
                pair.receiver.close();
                receiver_closed = true;
            },
            else => if (receiver_live) {
                const before = dropped;
                pair.receiver.deinit();
                receiver_live = false;
                try testing.expectEqual(before + @intFromBool(held), dropped);
                held = false;
            },
        }
    }
    if (sender_live) pair.sender.deinit();
    if (receiver_live) pair.receiver.deinit();
}

test "fuzz: oneshot matches tokio's semantics" {
    try @import("../fuzz.zig").run({}, oneshot_model, 0x6f6e6573686f74, 2000);
}
