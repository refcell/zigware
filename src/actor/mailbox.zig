//! Bounded message queue with caller-managed overflow (commonware `actor/src/mailbox.rs`).
//!
//! # Architecture
//!
//! The mailbox is split into two queues: a bounded `ready` queue that producers push to and
//! the receiver pops from, and an `overflow` queue that holds messages displaced when ready is
//! full. The message type's policy (`handle`) decides how overflow is updated.
//!
//! ```text
//!                          senders
//!                             |
//!         +-------------------+--------------------+
//!         | overflow empty                         | overflow non-empty
//!         | and ready has room                     | or ready full
//!         v                                        v
//!     +----------+    refill front-to-back     +----------+
//!     |  ready   |<----------------------------| overflow |
//!     +----------+    after each ready pop     +----------+
//!         |
//!         | pop first
//!         v
//!      receiver
//! ```
//!
//! The receiver always pops from ready first. After each ready pop it eagerly refills ready
//! from overflow so senders return to the ready fast path as soon as possible. Overflow is
//! refilled from front to back, but policies decide which overflow messages are retained and
//! in what order. Enqueue calls from the same sender are delivered in order; concurrent
//! enqueue calls may interleave.
//!
//! # Policies
//!
//! A message type `T` declares its overflow policy:
//!
//! ```zig
//! pub const Overflow = std.Deque(T); // or a custom type, see below
//! // Reliable (commonware `Policy`): every overflow message is handled.
//! pub fn handle(gpa: Allocator, overflow: *Overflow, message: T) Allocator.Error!void
//! // Unreliable (commonware `UnreliablePolicy`): `false` rejects the message.
//! pub fn handle(gpa: Allocator, overflow: *Overflow, message: T) Allocator.Error!bool
//! // Optional: release a message the mailbox drops (Rust `Drop`), e.g. cancel a responder.
//! pub fn discard(message: T) void
//! ```
//!
//! `handle` may also be infallible (`void` / `bool`); then `enqueue` cannot fail either. The
//! mode follows from `handle`'s return type: reliable senders return `Feedback`, unreliable
//! senders return `Unreliable(Feedback)`. `handle` takes ownership of `message`: whatever it
//! does not retain it must `discard` itself. It runs under the mailbox lock, so it must not
//! enqueue into (or drop a sender of) the same mailbox.
//!
//! A custom `Overflow` type provides `pub const empty`, `deinit(*Overflow, gpa)`,
//! `is_empty(*const Overflow) bool`, and `drain(*Overflow, pusher: anytype) void`, which
//! hands retained messages in delivery order to `pusher.push(message) ?T` until it returns
//! the message back (ready is full); that message and later ones stay retained.
//! `std.Deque(T)` is supported directly, like `VecDeque` in commonware.
//!
//! # Differences from commonware
//!
//! - Ready is a lock-free bounded queue (crossbeam `ArrayQueue`), and an activity word keeps
//!   senders off it while overflow is retained or changing, as in commonware. A futex word
//!   replaces `AtomicWaker`, and an `std.Io.Mutex` guards overflow. Everything goes through
//!   `std.Io` futexes, so the mailbox runs on any `std.Io`, including the deterministic
//!   runtime.
//! - `Receiver.poll_recv` stands in for polling the `recv()` future once: a pending poll
//!   parks the receiver until the next `recv` or `try_recv`.
//! - Handles are values, so `Sender.clone`/`Sender.deinit` and `Receiver.deinit` replace Rust's
//!   `Clone`/`Drop`. Copying a handle without `clone` breaks sender counting.
//! - `new` takes no metrics context: its backoff counter is detached (commonware's test
//!   `mocks::Metrics`). `new_with_metrics` registers it as `<scope>_backoff_total`.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const metrics = @import("runtime").telemetry.metrics;

const actor = @import("root.zig");
const Feedback = actor.Feedback;
const Unreliable = actor.Unreliable;

/// Error returned by `try_recv` (Rust `std::sync::mpsc::TryRecvError`).
pub const TryRecvError = error{
    /// No message is buffered right now.
    Empty,
    /// Every sender is gone and every buffered message has been received.
    Disconnected,
};

/// Create a new bounded mailbox holding up to `capacity` ready messages, with a detached
/// backoff counter (read it with `backoff_total`).
pub fn new(comptime T: type, gpa: Allocator, io: Io, capacity: u32) Allocator.Error!Pair(T) {
    assert(capacity > 0);
    var backoff: metrics.Counter = try .detached(gpa, .{});
    errdefer backoff.deinit();
    const pair = try new_state(T, gpa, io, capacity, backoff);
    assert(pair.sender.state == pair.receiver.state);
    return pair;
}

/// Create a new bounded mailbox holding up to `capacity` ready messages, registering its
/// backoff counter in `scope` as `backoff` (commonware `new(metrics, capacity)`).
pub fn new_with_metrics(
    comptime T: type,
    gpa: Allocator,
    io: Io,
    scope: *const metrics.Scope,
    capacity: u32,
) Allocator.Error!Pair(T) {
    assert(capacity > 0);
    var backoff = try scope.counter("backoff", "number of enqueue calls that requested backoff");
    errdefer backoff.deinit();
    const pair = try new_state(T, gpa, io, capacity, backoff);
    assert(pair.sender.state == pair.receiver.state);
    return pair;
}

fn new_state(
    comptime T: type,
    gpa: Allocator,
    io: Io,
    capacity: u32,
    backoff: metrics.Counter,
) Allocator.Error!Pair(T) {
    assert(capacity > 0);
    const state = try gpa.create(State(T));
    errdefer gpa.destroy(state);
    state.* = .{
        .gpa = gpa,
        .io = io,
        .ready = try .init(gpa, capacity),
        .backoff = backoff,
    };
    assert(state.ready.capacity == capacity);
    assert(state.handles.load(.monotonic) == 2);
    return .{ .sender = .{ .state = state }, .receiver = .{ .state = state } };
}

/// The two halves returned by `new`.
pub fn Pair(comptime T: type) type {
    return struct { sender: Sender(T), receiver: Receiver(T) };
}

/// Whether `T`'s policy may reject messages (commonware `UnreliablePolicy`).
pub fn is_unreliable(comptime T: type) bool {
    const Return = @typeInfo(@TypeOf(T.handle)).@"fn".return_type.?;
    const Payload = switch (@typeInfo(Return)) {
        .error_union => |info| info.payload,
        else => Return,
    };
    comptime assert(Payload == void or Payload == bool);
    return Payload == bool;
}

fn handle_can_fail(comptime T: type) bool {
    const Return = @typeInfo(@TypeOf(T.handle)).@"fn".return_type.?;
    return @typeInfo(Return) == .error_union;
}

/// Feedback type returned by `Sender(T).enqueue`.
pub fn FeedbackOf(comptime T: type) type {
    return if (is_unreliable(T)) Unreliable(Feedback) else Feedback;
}

/// Sender half of a mailbox. Clone with `clone`, release with `deinit`.
pub fn Sender(comptime T: type) type {
    return struct {
        const Self = @This();
        pub const Result = if (handle_can_fail(T))
            Allocator.Error!FeedbackOf(T)
        else
            FeedbackOf(T);

        state: *State(T),

        /// Submit a message without waiting for inbox capacity.
        pub fn enqueue(sender: Self, message: T) Result {
            if (comptime handle_can_fail(T)) return sender.state.enqueue(message);
            // `handle` cannot fail, so neither can `enqueue`.
            return sender.state.enqueue(message) catch unreachable;
        }

        /// Another sender for the same mailbox.
        pub fn clone(sender: Self) Self {
            const state = sender.state;
            // Live sender count drives receiver disconnect detection.
            const senders = state.senders.fetchAdd(1, .monotonic);
            assert(senders > 0);
            _ = state.handles.fetchAdd(1, .monotonic);
            return .{ .state = state };
        }

        /// Release this sender. When the last sender goes, the receiver drains what is
        /// buffered and then reports disconnection.
        pub fn deinit(sender: *Self) void {
            const state = sender.state;
            sender.* = undefined;
            const senders = state.senders.fetchSub(1, .acq_rel);
            assert(senders > 0);
            // Wake a receiver parked waiting for data or disconnect.
            if (senders == 1) state.waker.wake(state.io);
            state.release();
        }

        /// Ready capacity (soft limit) of the mailbox.
        pub fn capacity(sender: Self) u32 {
            return sender.state.ready.capacity;
        }

        /// Whether the receiver closed the mailbox.
        pub fn is_closed(sender: Self) bool {
            return sender.state.closed.load(.acquire);
        }

        /// Number of enqueue calls that requested backoff (commonware `backoff` counter).
        pub fn backoff_total(sender: Self) u64 {
            return sender.state.backoff_count();
        }
    };
}

/// Receiver half of a mailbox. `deinit` closes the mailbox and discards buffered messages.
/// After the last sender is gone the receiver keeps returning buffered messages until ready
/// and overflow are empty.
pub fn Receiver(comptime T: type) type {
    return struct {
        const Self = @This();

        state: *State(T),
        /// `poll_recv` returned `.pending` and left the receiver parked.
        polled: bool = false,

        /// One poll of a receive (commonware's `recv()` future polled once).
        pub const Poll = union(enum) {
            /// The next message, or null once disconnected and drained, as `recv` returns.
            ready: ?T,
            /// Nothing ready: the receiver is parked, so the next enqueue wakes it, and a
            /// later `recv` or `try_recv` takes the message.
            pending,
        };

        /// Receive without waiting, or park the receiver (commonware registers the waker on a
        /// pending poll), so a sender that enqueues next takes the waiting-receiver wake path.
        pub fn poll_recv(receiver: *Self) Poll {
            const state = receiver.state;
            assert(!state.closed.load(.monotonic));
            if (state.pop()) |message| return .{ .ready = message };
            if (state.is_disconnected()) return .{ .ready = state.pop() };
            _ = state.waker.park();
            receiver.polled = true;
            assert(state.waker.word.load(.monotonic) & Waker.parked_bit != 0);
            return .pending;
        }

        /// End a pending poll: the receiver stops being parked.
        fn end_poll(receiver: *Self) void {
            if (!receiver.polled) return;
            receiver.polled = false;
            receiver.state.waker.unpark();
        }

        /// Receive the next message. Returns null after all senders are gone and every
        /// buffered message has been received.
        pub fn recv(receiver: *Self) Io.Cancelable!?T {
            const state = receiver.state;
            assert(!state.closed.load(.monotonic));
            receiver.end_poll();
            // Fast path avoids waker churn when a message is already ready.
            if (state.pop()) |message| return message;
            if (state.is_disconnected()) return state.pop();
            defer state.waker.unpark();
            while (true) {
                const parked = state.waker.park();
                // A sender can enqueue and wake after the pop above but before the receiver
                // parked. Re-check before sleeping so the wake is not lost.
                if (state.pop()) |message| return message;
                if (state.is_disconnected()) return state.pop();
                try state.io.futexWait(u32, &state.waker.word.raw, parked);
            }
        }

        /// Try to receive the next message without waiting.
        pub fn try_recv(receiver: *Self) TryRecvError!T {
            const state = receiver.state;
            assert(!state.closed.load(.monotonic));
            receiver.end_poll();
            if (state.pop()) |message| return message;
            if (state.is_disconnected()) return state.pop() orelse error.Disconnected;
            return error.Empty;
        }

        /// Number of enqueue calls that requested backoff (commonware `backoff` counter).
        pub fn backoff_total(receiver: Self) u64 {
            return receiver.state.backoff_count();
        }

        /// Close the mailbox: later sends return `closed` and every buffered message is
        /// discarded (outside the overflow lock, so a discarded message may own a sender of
        /// this mailbox).
        pub fn deinit(receiver: *Self) void {
            const state = receiver.state;
            receiver.* = undefined;
            assert(!state.closed.load(.monotonic));
            // Sequentially consistent with the ready fast path's closed re-check, so a racing
            // sender either sees closure or leaves its message where `drain` finds it.
            state.closed.store(true, .seq_cst);
            state.drain();
            state.release();
        }
    };
}

/// Low bit of `activity`: overflow has published messages, so the receiver must refill.
const overflow_has_messages: usize = 1;
/// Unit of `activity` held while a mutation may change or publish overflow, which keeps
/// senders off the ready fast path (commonware `OVERFLOW_MUTATION`).
const overflow_mutation: usize = 2;

fn State(comptime T: type) type {
    comptime assert(@hasDecl(T, "Overflow"));
    comptime assert(@hasDecl(T, "handle"));
    return struct {
        const Self = @This();
        const FeedbackType = FeedbackOf(T);

        gpa: Allocator,
        io: Io,
        ready: Ready(T),
        /// Guards `overflow`.
        mutex: Io.Mutex = .init,
        overflow: T.Overflow = .empty,
        /// `overflow_has_messages` plus `overflow_mutation` per active mutation.
        activity: std.atomic.Value(usize) = .init(0),
        closed: std.atomic.Value(bool) = .init(false),
        /// Live senders; zero means disconnected.
        senders: std.atomic.Value(u32) = .init(1),
        /// Live handles (senders plus the receiver); zero frees the state.
        handles: std.atomic.Value(u32) = .init(2),
        waker: Waker = .{},
        /// Enqueue calls that requested backoff (commonware `backoff` counter).
        backoff: metrics.Counter,

        fn backoff_count(state: *Self) u64 {
            assert(state.handles.load(.monotonic) > 0);
            return state.backoff.metric().get();
        }

        fn enqueue(state: *Self, message: T) Allocator.Error!FeedbackType {
            // Receiver closure makes new sends fail immediately.
            if (state.closed.load(.acquire)) {
                discard(T, message);
                return wrap(.closed);
            }
            // Common case: publish directly to ready without taking the overflow lock, unless
            // overflow is retained or changing.
            var pending = message;
            if (state.activity.load(.monotonic) == 0) {
                pending = state.ready.push(message) orelse {
                    if (state.closed.load(.seq_cst)) {
                        state.drain();
                        return wrap(.closed);
                    }
                    state.waker.wake(state.io);
                    return wrap(.ok);
                };
            }

            // Slow path: serialize through overflow and apply the policy.
            const feedback = try state.enqueue_overflow(pending);
            if (feedback == null) {
                discard(T, pending);
                return wrap(.closed);
            }
            const handled = feedback.?;
            if (handled == .handled) state.backoff.metric().inc();
            // Wake after any non-closed slow-path enqueue: a receiver may have skipped refill
            // while this mutation was active, and it is published by now.
            state.waker.wake(state.io);
            return switch (handled) {
                .ready => wrap(.ok),
                .handled => if (comptime is_unreliable(T)) .new(.backoff) else .backoff,
                .rejected => if (comptime is_unreliable(T)) .rejected else unreachable,
            };
        }

        const Outcome = enum { ready, handled, rejected };

        /// The overflow slow path; null when the mailbox closed (the message is not taken).
        fn enqueue_overflow(state: *Self, message: T) Allocator.Error!?Outcome {
            // Mark overflow active so racing senders stay off the ready fast path.
            state.begin_mutation();
            defer state.end_mutation();
            state.mutex.lockUncancelable(state.io);
            defer state.mutex.unlock(state.io);
            defer state.publish();
            if (state.closed.load(.acquire)) return null;

            // The fast path may have seen stale ready fullness. Retry ready before the policy,
            // unless retained overflow must stay ahead of this message.
            var pending = message;
            if (overflow_is_empty(T, &state.overflow)) {
                pending = state.ready.push(message) orelse return .ready;
            }
            const handled = try call_handle(T, state.gpa, &state.overflow, pending);
            return if (handled) .handled else .rejected;
        }

        fn wrap(feedback: Feedback) FeedbackType {
            return if (comptime is_unreliable(T)) .new(feedback) else feedback;
        }

        fn is_disconnected(state: *Self) bool {
            return state.closed.load(.acquire) or state.senders.load(.acquire) == 0;
        }

        /// Pop the next message, refilling ready from overflow.
        fn pop(state: *Self) ?T {
            if (state.ready.pop()) |message| {
                // A freed ready slot lets the oldest overflow message advance.
                state.refill();
                return message;
            }
            // Empty ready may race with stale activity, so `refill` decides whether
            // overflow is worth locking.
            state.refill();
            return state.ready.pop();
        }

        fn refill(state: *Self) void {
            // Skip the overflow lock unless non-empty overflow was published.
            if (state.activity.load(.monotonic) & overflow_has_messages == 0) return;
            state.begin_mutation();
            defer state.end_mutation();
            state.mutex.lockUncancelable(state.io);
            defer state.mutex.unlock(state.io);
            defer state.publish();
            var pusher: ReadyPusher(T) = .{ .ready = &state.ready };
            drain_overflow(T, &state.overflow, &pusher);
        }

        /// Discard everything buffered, outside the overflow lock (commonware `drain`).
        fn drain(state: *Self) void {
            state.begin_mutation();
            defer state.end_mutation();
            while (state.ready.pop()) |message| discard(T, message);
            state.mutex.lockUncancelable(state.io);
            var overflow = state.overflow;
            state.overflow = .empty;
            state.publish();
            state.mutex.unlock(state.io);
            var pusher: DiscardPusher(T) = .{};
            drain_overflow(T, &overflow, &pusher);
            assert(overflow_is_empty(T, &overflow));
            overflow.deinit(state.gpa);
            // A sender may have passed the fast-path activity check before this mutation
            // began, so drain ready again.
            while (state.ready.pop()) |message| discard(T, message);
        }

        fn begin_mutation(state: *Self) void {
            _ = state.activity.fetchAdd(overflow_mutation, .monotonic);
        }

        fn end_mutation(state: *Self) void {
            const activity = state.activity.fetchSub(overflow_mutation, .monotonic);
            assert(activity >= overflow_mutation);
        }

        /// Publish whether overflow holds messages (overflow lock held). Only the lock holder
        /// changes the bit, so it is read exactly here, and a publish that would not change it
        /// (every rejected or dropped message) skips the read-modify-write.
        fn publish(state: *Self) void {
            const has_messages = !overflow_is_empty(T, &state.overflow);
            const published = state.activity.load(.monotonic) & overflow_has_messages != 0;
            if (has_messages == published) return;
            if (has_messages) {
                _ = state.activity.fetchOr(overflow_has_messages, .monotonic);
            } else {
                _ = state.activity.fetchAnd(~overflow_has_messages, .monotonic);
            }
            const now_published = state.activity.load(.monotonic) & overflow_has_messages != 0;
            assert(now_published == has_messages);
        }

        /// Release one handle, freeing the state with the last.
        fn release(state: *Self) void {
            if (state.handles.fetchSub(1, .acq_rel) != 1) return;
            assert(state.senders.load(.monotonic) == 0);
            assert(state.closed.load(.monotonic));
            assert(overflow_is_empty(T, &state.overflow));
            assert(state.ready.pop() == null);
            const gpa = state.gpa;
            state.ready.deinit(gpa);
            state.overflow.deinit(gpa);
            state.backoff.deinit();
            gpa.destroy(state);
        }
    };
}

/// Bounded multi-producer, multi-consumer ready queue (crossbeam `ArrayQueue`). Each slot's
/// stamp holds the lap and index at which it is next free (pushable) or full (poppable).
fn Ready(comptime T: type) type {
    return struct {
        const Self = @This();
        const Slot = struct { stamp: std.atomic.Value(usize), message: T };
        const Padded = struct {
            value: std.atomic.Value(usize) align(padded_bytes) = .init(0),
            const padded_bytes = 128;
            comptime {
                assert(@sizeOf(@This()) == padded_bytes);
            }
        };

        /// Each index on 128 bytes of its own (crossbeam's `CachePadded`, which covers the
        /// adjacent-line prefetcher), so a producer's CAS on `tail` does not evict the
        /// read-only fields below or the consumer's `head`.
        head: Padded = .{},
        tail: Padded = .{},
        slots: []Slot,
        capacity: u32,
        /// A power of two above `capacity`: positions are `lap * one_lap + index`.
        one_lap: usize,

        fn init(gpa: Allocator, capacity: u32) Allocator.Error!Self {
            assert(capacity > 0);
            const slots = try gpa.alloc(Slot, capacity);
            for (slots, 0..) |*slot, index| {
                slot.* = .{ .stamp = .init(index), .message = undefined };
            }
            const one_lap = std.math.ceilPowerOfTwoAssert(usize, @as(usize, capacity) + 1);
            assert(one_lap > capacity);
            return .{ .slots = slots, .capacity = capacity, .one_lap = one_lap };
        }

        fn deinit(ready: *Self, gpa: Allocator) void {
            gpa.free(ready.slots);
            ready.* = undefined;
        }

        /// The position after `position`, wrapping the index into the next lap.
        fn next(ready: *const Self, position: usize) usize {
            const index = position & (ready.one_lap - 1);
            const lap = position & ~(ready.one_lap - 1);
            return if (index + 1 < ready.capacity) position + 1 else lap +% ready.one_lap;
        }

        /// Push `message`, or hand it back when ready is full.
        pub fn push(ready: *Self, message: T) ?T {
            var tail = ready.tail.value.load(.monotonic);
            var backoff: Backoff = .{};
            while (true) {
                const slot = &ready.slots[tail & (ready.one_lap - 1)];
                const stamp = slot.stamp.load(.acquire);
                if (stamp == tail) {
                    const moved_to = ready.next(tail);
                    const index = &ready.tail.value;
                    const moved = index.cmpxchgWeak(tail, moved_to, .seq_cst, .monotonic);
                    if (moved) |seen| {
                        tail = seen;
                        backoff.spin();
                        continue;
                    }
                    slot.message = message;
                    slot.stamp.store(tail + 1, .release);
                    return null;
                }
                if (stamp +% ready.one_lap == tail + 1) {
                    // The slot is still full from the previous lap.
                    const head = ready.head.value.load(.seq_cst);
                    if (head +% ready.one_lap == tail) return message;
                } else {
                    // Another producer moved the tail but has not stamped its slot yet.
                    std.atomic.spinLoopHint();
                }
                tail = ready.tail.value.load(.monotonic);
            }
        }

        /// Pop the oldest message, or null when ready is empty.
        fn pop(ready: *Self) ?T {
            var head = ready.head.value.load(.monotonic);
            var backoff: Backoff = .{};
            while (true) {
                const slot = &ready.slots[head & (ready.one_lap - 1)];
                const stamp = slot.stamp.load(.acquire);
                if (stamp == head + 1) {
                    const moved_to = ready.next(head);
                    const index = &ready.head.value;
                    const moved = index.cmpxchgWeak(head, moved_to, .seq_cst, .monotonic);
                    if (moved) |seen| {
                        head = seen;
                        backoff.spin();
                        continue;
                    }
                    const message = slot.message;
                    slot.stamp.store(head +% ready.one_lap, .release);
                    return message;
                }
                if (stamp == head) {
                    const tail = ready.tail.value.load(.seq_cst);
                    if (tail == head) return null;
                } else {
                    // Another consumer moved the head but has not stamped its slot yet.
                    std.atomic.spinLoopHint();
                }
                head = ready.head.value.load(.monotonic);
            }
        }
    };
}

/// crossbeam's `Backoff::spin` after a lost CAS: 1, 2, 4, ... up to 64 spin hints, so
/// contending producers stop bouncing the index's cache line on every retry.
const Backoff = struct {
    step: u32 = 0,

    const spin_limit = 6;

    fn spin(backoff: *Backoff) void {
        assert(backoff.step <= spin_limit);
        const spins = @as(u32, 1) << @intCast(backoff.step);
        for (0..spins) |_| std.atomic.spinLoopHint();
        if (backoff.step < spin_limit) backoff.step += 1;
    }
};

/// Receiver parking (futures `AtomicWaker`): a futex word whose high bits count wakes and
/// whose low bit marks a parked receiver. Both sides change it with a read-modify-write, so
/// either the sender sees the parked bit or the receiver's re-check sees the message.
const Waker = struct {
    word: std.atomic.Value(u32) = .init(0),

    const parked_bit: u32 = 1;

    /// Count a wake and wake a parked receiver.
    fn wake(waker: *Waker, io: Io) void {
        const word = waker.word.fetchAdd(parked_bit << 1, .acq_rel);
        if (word & parked_bit != 0) io.futexWake(u32, &waker.word.raw, 1);
    }

    /// Mark the receiver parked; returns the word to wait on.
    fn park(waker: *Waker) u32 {
        return waker.word.fetchOr(parked_bit, .acq_rel) | parked_bit;
    }

    fn unpark(waker: *Waker) void {
        _ = waker.word.fetchAnd(~parked_bit, .monotonic);
    }
};

fn call_handle(
    comptime T: type,
    gpa: Allocator,
    overflow: *T.Overflow,
    message: T,
) Allocator.Error!bool {
    const result = if (comptime handle_can_fail(T))
        try T.handle(gpa, overflow, message)
    else
        T.handle(gpa, overflow, message);
    return if (comptime is_unreliable(T)) result else true;
}

fn discard(comptime T: type, message: T) void {
    if (comptime @hasDecl(T, "discard")) T.discard(message);
}

fn overflow_is_empty(comptime T: type, overflow: *const T.Overflow) bool {
    if (comptime T.Overflow == std.Deque(T)) return overflow.len == 0;
    return overflow.is_empty();
}

/// Overflow `drain`: hand retained messages to `pusher` until it gives one back.
pub fn drain_overflow(comptime T: type, overflow: *T.Overflow, pusher: anytype) void {
    if (comptime T.Overflow != std.Deque(T)) return overflow.drain(pusher);
    deque_drain(T, overflow, pusher);
}

/// `drain` for a `std.Deque(T)` overflow (commonware `impl Overflow for VecDeque`).
pub fn deque_drain(comptime T: type, deque: *std.Deque(T), pusher: anytype) void {
    const len_before = deque.len;
    var iterations: usize = 0;
    while (deque.popFront()) |message| : (iterations += 1) {
        assert(iterations < len_before);
        if (pusher.push(message)) |rejected| {
            // The slot just freed by `popFront` holds it, so this never allocates.
            deque.pushFrontAssumeCapacity(rejected);
            break;
        }
    }
    assert(deque.len <= len_before);
}

fn ReadyPusher(comptime T: type) type {
    return struct {
        ready: *Ready(T),

        pub fn push(pusher: *@This(), message: T) ?T {
            return pusher.ready.push(message);
        }
    };
}

fn DiscardPusher(comptime T: type) type {
    return struct {
        pub fn push(_: *@This(), message: T) ?T {
            discard(T, message);
            return null;
        }
    };
}

test {
    _ = @import("mailbox_test.zig");
}
