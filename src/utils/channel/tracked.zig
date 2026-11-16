//! A bounded channel that tracks message delivery (commonware
//! `utils/src/channel/tracked.rs`).
//!
//! Each sent message carries a `Guard`. A message is delivered once every clone of its guard
//! is released. The sender reports the watermark (every sequence up to it is delivered) and
//! the undelivered count per batch.
//!
//! Instead of Rust's per-message `Arc`, a guard is the pair (tracker, sequence). The tracker
//! keeps, for every sequence above the watermark, the number of live guard clones and the
//! batch. The tracker state is freed with the last sender or guard. Batch IDs are plain
//! hashable values (`std.AutoHashMapUnmanaged` keys).

const std = @import("std");
const mpsc = @import("mpsc.zig");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub fn Guard(comptime B: type) type {
    return struct {
        const Self = @This();

        tracker: *Tracker(B),
        sequence: u64,

        /// Another reference to the same delivery.
        pub fn clone(guard: Self) Self {
            guard.tracker.retain(guard.sequence);
            return guard;
        }

        /// Releases this reference; the last marks the message delivered.
        pub fn deinit(guard: *Self) void {
            guard.tracker.release(guard.sequence);
            guard.* = undefined;
        }
    };
}

pub fn Message(comptime T: type, comptime B: type) type {
    return struct {
        const Self = @This();

        data: T,
        guard: Guard(B),

        /// Drops the message: the data (to `T.discard`, if declared) and its guard. A channel
        /// that drops an unread message calls this.
        pub fn discard(message: Self) void {
            var guard = message.guard;
            guard.deinit();
            if (comptime has_discard(T)) T.discard(message.data);
        }
    };
}

fn has_discard(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .@"struct", .@"union", .@"enum", .@"opaque" => @hasDecl(T, "discard"),
        else => false,
    };
}

fn Tracker(comptime B: type) type {
    return struct {
        const Self = @This();

        const Slot = struct {
            /// Live guard clones; zero once delivered.
            references: u32,
            batch: ?B,
        };

        gpa: Allocator,
        io: Io,
        mutex: Io.Mutex = .init,
        /// Every sequence up to and including the watermark is delivered.
        watermark: u64 = 0,
        /// `pending[i]` is sequence `watermark + 1 + i`.
        pending: std.Deque(Slot) = .empty,
        /// Undelivered messages per batch.
        batches: std.AutoHashMapUnmanaged(B, usize) = .empty,
        /// Live senders plus live guard references; zero frees the tracker.
        handles: usize = 1,

        fn lock(tracker: *Self) void {
            tracker.mutex.lockUncancelable(tracker.io);
        }

        fn unlock(tracker: *Self) void {
            tracker.mutex.unlock(tracker.io);
        }

        /// Issues the next sequence with one guard reference.
        fn guard(tracker: *Self, batch: ?B) Allocator.Error!Guard(B) {
            tracker.lock();
            defer tracker.unlock();
            if (batch) |id| {
                const entry = try tracker.batches.getOrPut(tracker.gpa, id);
                if (!entry.found_existing) entry.value_ptr.* = 0;
                entry.value_ptr.* += 1;
            }
            const fresh: Slot = .{ .references = 1, .batch = batch };
            tracker.pending.pushBack(tracker.gpa, fresh) catch |err| {
                if (batch) |id| tracker.uncount(id);
                return err;
            };
            tracker.handles += 1;
            const sequence = tracker.watermark + tracker.pending.len;
            return .{ .tracker = tracker, .sequence = sequence };
        }

        fn slot(tracker: *Self, sequence: u64) *Slot {
            assert(sequence > tracker.watermark);
            const index: usize = @intCast(sequence - tracker.watermark - 1);
            return tracker.pending.atPtr(index);
        }

        fn retain(tracker: *Self, sequence: u64) void {
            tracker.lock();
            defer tracker.unlock();
            const entry = tracker.slot(sequence);
            assert(entry.references > 0);
            entry.references += 1;
            tracker.handles += 1;
        }

        fn release(tracker: *Self, sequence: u64) void {
            tracker.lock();
            const entry = tracker.slot(sequence);
            assert(entry.references > 0);
            entry.references -= 1;
            if (entry.references == 0) {
                if (entry.batch) |id| tracker.uncount(id);
                // Advance the watermark past the delivered prefix.
                while (tracker.pending.front()) |front| {
                    if (front.references != 0) break;
                    _ = tracker.pending.popFront();
                    tracker.watermark += 1;
                }
            }
            tracker.release_locked();
        }

        fn uncount(tracker: *Self, id: B) void {
            const count = tracker.batches.getPtr(id).?;
            assert(count.* > 0);
            count.* -= 1;
            if (count.* == 0) assert(tracker.batches.remove(id));
        }

        /// Drops one handle and unlocks; frees the tracker with the last.
        fn release_locked(tracker: *Self) void {
            assert(tracker.handles > 0);
            tracker.handles -= 1;
            const last = tracker.handles == 0;
            tracker.unlock();
            if (!last) return;
            assert(tracker.pending.len == 0 and tracker.batches.count() == 0);
            tracker.pending.deinit(tracker.gpa);
            tracker.batches.deinit(tracker.gpa);
            tracker.gpa.destroy(tracker);
        }
    };
}

pub fn Sender(comptime T: type, comptime B: type) type {
    return struct {
        const Self = @This();

        inner: mpsc.Sender(Message(T, B)),
        tracker: *Tracker(B),

        pub fn clone(sender: Self) Self {
            const tracker = sender.tracker;
            tracker.lock();
            tracker.handles += 1;
            tracker.unlock();
            return .{ .inner = sender.inner.clone(), .tracker = tracker };
        }

        /// Sends `data` in `batch`, waiting for room; returns its sequence. On an error the
        /// caller still owns `data` (its guard is released, as Rust drops the message).
        pub fn send(
            sender: Self,
            batch: ?B,
            data: T,
        ) (mpsc.SendError || Io.Cancelable || Allocator.Error)!u64 {
            var guard = try sender.tracker.guard(batch);
            const sequence = guard.sequence;
            sender.inner.send(.{ .data = data, .guard = guard }) catch |err| {
                guard.deinit();
                return err;
            };
            return sequence;
        }

        /// Sends without waiting; on an error the caller still owns `data`.
        pub fn try_send(
            sender: Self,
            batch: ?B,
            data: T,
        ) (mpsc.TrySendError || Allocator.Error)!u64 {
            var guard = try sender.tracker.guard(batch);
            const sequence = guard.sequence;
            sender.inner.try_send(.{ .data = data, .guard = guard }) catch |err| {
                guard.deinit();
                return err;
            };
            return sequence;
        }

        /// The highest sequence such that it and every sequence below it are delivered.
        pub fn watermark(sender: Self) u64 {
            const tracker = sender.tracker;
            tracker.lock();
            defer tracker.unlock();
            return tracker.watermark;
        }

        /// Undelivered messages in `batch`.
        pub fn pending(sender: Self, batch: B) usize {
            const tracker = sender.tracker;
            tracker.lock();
            defer tracker.unlock();
            return tracker.batches.get(batch) orelse 0;
        }

        pub fn deinit(sender: *Self) void {
            sender.inner.deinit();
            const tracker = sender.tracker;
            sender.* = undefined;
            tracker.lock();
            tracker.release_locked();
        }
    };
}

pub fn Receiver(comptime T: type, comptime B: type) type {
    return struct {
        const Self = @This();

        inner: mpsc.Receiver(Message(T, B)),

        pub fn recv(receiver: *Self) Io.Cancelable!?Message(T, B) {
            return receiver.inner.recv();
        }

        pub fn try_recv(receiver: *Self) mpsc.TryRecvError!Message(T, B) {
            return receiver.inner.try_recv();
        }

        /// Drops the receiver; unread messages are delivered (their guards released).
        pub fn deinit(receiver: *Self) void {
            receiver.inner.deinit();
            receiver.* = undefined;
        }
    };
}

pub fn Pair(comptime T: type, comptime B: type) type {
    return struct { sender: Sender(T, B), receiver: Receiver(T, B) };
}

/// A bounded channel holding at most `capacity` messages, with delivery tracking.
pub fn bounded(
    comptime T: type,
    comptime B: type,
    gpa: Allocator,
    io: Io,
    capacity: usize,
) Allocator.Error!Pair(T, B) {
    const tracker = try gpa.create(Tracker(B));
    errdefer gpa.destroy(tracker);
    tracker.* = .{ .gpa = gpa, .io = io };
    const pair = try mpsc.channel(Message(T, B), gpa, io, capacity);
    return .{
        .sender = .{ .inner = pair.sender, .tracker = tracker },
        .receiver = .{ .inner = pair.receiver },
    };
}

const testing = std.testing;
const gpa_test = testing.allocator;

fn take(receiver: anytype) !Message(i32, u64) {
    return (try receiver.recv()) orelse error.TestUnexpectedResult;
}

fn take_bytes(receiver: anytype) !Message([]const u8, u64) {
    return (try receiver.recv()) orelse error.TestUnexpectedResult;
}

test "tracked: basic delivery" {
    var pair = try bounded(i32, u64, gpa_test, testing.io, 10);
    defer pair.receiver.deinit();
    defer pair.sender.deinit();
    try testing.expectEqual(1, try pair.sender.send(null, 42));
    try testing.expectEqual(0, pair.sender.watermark());
    var message = try take(&pair.receiver);
    try testing.expectEqual(42, message.data);
    try testing.expectEqual(0, pair.sender.watermark());
    message.guard.deinit();
    try testing.expectEqual(1, pair.sender.watermark());
}

test "tracked: out-of-order delivery" {
    var pair = try bounded(i32, u64, gpa_test, testing.io, 4);
    defer pair.receiver.deinit();
    defer pair.sender.deinit();
    for (1..5) |value| _ = try pair.sender.send(1, @intCast(value));
    var messages: [4]Message(i32, u64) = undefined;
    for (&messages) |*message| message.* = try take(&pair.receiver);
    messages[1].guard.deinit();
    messages[3].guard.deinit();
    try testing.expectEqual(0, pair.sender.watermark());
    try testing.expectEqual(2, pair.sender.pending(1));
    // A new message takes the sequence after every issued one.
    try testing.expectEqual(5, try pair.sender.send(2, 5));
    try testing.expectEqual(1, pair.sender.pending(2));
    messages[0].guard.deinit();
    try testing.expectEqual(2, pair.sender.watermark());
    try testing.expectEqual(1, pair.sender.pending(1));
    messages[2].guard.deinit();
    try testing.expectEqual(4, pair.sender.watermark());
    try testing.expectEqual(0, pair.sender.pending(1));
    try testing.expectEqual(6, try pair.sender.send(2, 6));
    try testing.expectEqual(2, pair.sender.pending(2));
    for (0..2) |_| {
        var message = try take(&pair.receiver);
        message.guard.deinit();
    }
    try testing.expectEqual(6, pair.sender.watermark());
    try testing.expectEqual(0, pair.sender.pending(2));
}

test "tracked: batch tracking" {
    var pair = try bounded([]const u8, u64, gpa_test, testing.io, 10);
    defer pair.receiver.deinit();
    defer pair.sender.deinit();
    try testing.expectEqual(1, try pair.sender.send(100, "msg1"));
    try testing.expectEqual(2, try pair.sender.send(100, "msg2"));
    try testing.expectEqual(3, try pair.sender.send(200, "msg3"));
    try testing.expectEqual(2, pair.sender.pending(100));
    try testing.expectEqual(1, pair.sender.pending(200));
    try testing.expectEqual(0, pair.sender.pending(300));
    var first = try take_bytes(&pair.receiver);
    try testing.expectEqualStrings("msg1", first.data);
    first.guard.deinit();
    try testing.expectEqual(1, pair.sender.pending(100));
    try testing.expectEqual(1, pair.sender.pending(200));
    var second = try take_bytes(&pair.receiver);
    var third = try take_bytes(&pair.receiver);
    second.guard.deinit();
    third.guard.deinit();
    try testing.expectEqual(0, pair.sender.pending(100));
    try testing.expectEqual(0, pair.sender.pending(200));
}

test "tracked: cloned guards share one delivery" {
    var pair = try bounded([]const u8, u64, gpa_test, testing.io, 10);
    defer pair.receiver.deinit();
    defer pair.sender.deinit();
    try testing.expectEqual(1, try pair.sender.send(1, "test"));
    var message = try take_bytes(&pair.receiver);
    var first = message.guard.clone();
    var second = message.guard.clone();
    try testing.expectEqual(1, pair.sender.pending(1));
    message.guard.deinit();
    first.deinit();
    try testing.expectEqual(1, pair.sender.pending(1));
    try testing.expectEqual(0, pair.sender.watermark());
    second.deinit();
    try testing.expectEqual(0, pair.sender.pending(1));
    try testing.expectEqual(1, pair.sender.watermark());
}

test "tracked: try_send" {
    var pair = try bounded(i32, u64, gpa_test, testing.io, 2);
    defer pair.receiver.deinit();
    defer pair.sender.deinit();
    try testing.expectEqual(1, try pair.sender.try_send(10, 1));
    try testing.expectEqual(2, try pair.sender.try_send(10, 2));
    // A full channel refuses; the refused message's guard is released at once.
    try testing.expectError(error.Full, pair.sender.try_send(10, 3));
    try testing.expectEqual(2, pair.sender.pending(10));
    var first = try take(&pair.receiver);
    try testing.expectEqual(1, first.data);
    first.guard.deinit();
    try testing.expectEqual(1, pair.sender.pending(10));
    var second = try take(&pair.receiver);
    second.guard.deinit();
    try testing.expectEqual(0, pair.sender.pending(10));
    try testing.expectEqual(3, pair.sender.watermark());
}

test "tracked: channel closure, and guards outlive the channel" {
    var pair = try bounded(i32, u64, gpa_test, testing.io, 10);
    _ = try pair.sender.send(null, 1);
    var held = try take(&pair.receiver);
    _ = try pair.sender.send(7, 2);
    // Dropping the receiver delivers its unread message.
    pair.receiver.deinit();
    try testing.expectEqual(0, pair.sender.pending(7));
    try testing.expectError(error.Closed, pair.sender.send(null, 3));
    pair.sender.deinit();
    // The tracker lives until the last guard goes (the allocator checks for leaks).
    held.guard.deinit();
}
