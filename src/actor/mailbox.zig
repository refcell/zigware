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
//! - One `std.Io.Mutex` guards ready and overflow and the receiver parks on a
//!   `std.Io.Condition`, instead of a lock-free ready queue, an activity word, and an
//!   `AtomicWaker`. Every interleaving commonware allows is still allowed; the stale-read
//!   retries its fast path needs disappear. The mailbox runs on any `std.Io`, including the
//!   deterministic runtime.
//! - Handles are values, so `Sender.clone`/`Sender.deinit` and `Receiver.deinit` replace Rust's
//!   `Clone`/`Drop`. Copying a handle without `clone` breaks sender counting.
//! - The backoff counter is `backoff_total()` until the runtime has a metrics registry.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;

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

/// Create a new bounded mailbox holding up to `capacity` ready messages.
pub fn new(comptime T: type, gpa: Allocator, io: Io, capacity: u32) Allocator.Error!Pair(T) {
    assert(capacity > 0);
    const state = try gpa.create(State(T));
    errdefer gpa.destroy(state);
    state.* = .{
        .gpa = gpa,
        .io = io,
        .capacity = capacity,
        .ready = try .initCapacity(gpa, capacity),
        .overflow = .empty,
    };
    assert(state.ready.buffer.len >= capacity);
    assert(state.handles == 2);
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
            state.lock();
            defer state.unlock();
            assert(state.senders > 0);
            state.senders += 1;
            state.handles += 1;
            return .{ .state = state };
        }

        /// Release this sender. When the last sender goes, the receiver drains what is
        /// buffered and then reports disconnection.
        pub fn deinit(sender: *Self) void {
            const state = sender.state;
            sender.* = undefined;
            state.lock();
            assert(state.senders > 0);
            assert(state.handles > state.senders - 1);
            state.senders -= 1;
            state.handles -= 1;
            // Wake a receiver parked waiting for data or disconnect.
            if (state.senders == 0) state.condition.signal(state.io);
            const last = state.handles == 0;
            state.unlock();
            if (last) state.destroy();
        }

        /// Ready capacity (soft limit) of the mailbox.
        pub fn capacity(sender: Self) u32 {
            return sender.state.capacity;
        }

        /// Whether the receiver closed the mailbox.
        pub fn is_closed(sender: Self) bool {
            const state = sender.state;
            state.lock();
            defer state.unlock();
            return state.closed;
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

        /// Receive the next message. Returns null after all senders are gone and every
        /// buffered message has been received.
        pub fn recv(receiver: *Self) Io.Cancelable!?T {
            const state = receiver.state;
            state.lock();
            defer state.unlock();
            assert(!state.closed);
            while (true) {
                if (state.pop()) |message| return message;
                if (state.senders == 0) return null;
                try state.condition.wait(state.io, &state.mutex);
            }
        }

        /// Try to receive the next message without waiting.
        pub fn try_recv(receiver: *Self) TryRecvError!T {
            const state = receiver.state;
            state.lock();
            defer state.unlock();
            assert(!state.closed);
            if (state.pop()) |message| return message;
            if (state.senders == 0) return error.Disconnected;
            return error.Empty;
        }

        /// Number of enqueue calls that requested backoff (commonware `backoff` counter).
        pub fn backoff_total(receiver: Self) u64 {
            return receiver.state.backoff_count();
        }

        /// Close the mailbox: later sends return `closed` and every buffered message is
        /// discarded (outside the lock, so a discarded message may own a sender of this
        /// mailbox).
        pub fn deinit(receiver: *Self) void {
            const state = receiver.state;
            receiver.* = undefined;
            state.lock();
            assert(!state.closed);
            state.closed = true;
            var ready = state.ready;
            var overflow = state.overflow;
            state.ready = .empty;
            state.overflow = .empty;
            state.unlock();

            while (ready.popFront()) |message| discard(T, message);
            ready.deinit(state.gpa);
            var pusher: DiscardPusher(T) = .{};
            drain_overflow(T, &overflow, &pusher);
            assert(overflow_is_empty(T, &overflow));
            overflow.deinit(state.gpa);

            state.lock();
            assert(state.handles > state.senders);
            state.handles -= 1;
            const last = state.handles == 0;
            state.unlock();
            if (last) state.destroy();
        }
    };
}

fn State(comptime T: type) type {
    comptime assert(@hasDecl(T, "Overflow"));
    comptime assert(@hasDecl(T, "handle"));
    return struct {
        const Self = @This();
        const FeedbackType = FeedbackOf(T);

        gpa: Allocator,
        io: Io,
        mutex: Io.Mutex = .init,
        condition: Io.Condition = .init,
        capacity: u32,
        ready: std.Deque(T),
        overflow: T.Overflow,
        closed: bool = false,
        /// Live senders; zero means disconnected.
        senders: u32 = 1,
        /// Live handles (senders plus the receiver); zero frees the state.
        handles: u32 = 2,
        backoff: u64 = 0,

        fn lock(state: *Self) void {
            state.mutex.lockUncancelable(state.io);
        }

        fn unlock(state: *Self) void {
            state.mutex.unlock(state.io);
        }

        fn backoff_count(state: *Self) u64 {
            state.lock();
            defer state.unlock();
            return state.backoff;
        }

        fn enqueue(state: *Self, message: T) Allocator.Error!FeedbackType {
            state.lock();
            // Receiver closure makes new sends fail immediately.
            if (state.closed) {
                state.unlock();
                discard(T, message);
                return wrap(.closed);
            }
            defer state.unlock();
            assert(state.ready.len <= state.capacity);

            // Common case: retained overflow stays ahead of this message, else use ready.
            if (overflow_is_empty(T, &state.overflow) and state.ready.len < state.capacity) {
                state.ready.pushBackAssumeCapacity(message);
                state.condition.signal(state.io);
                return wrap(.ok);
            }

            // Slow path: apply the policy.
            const handled = try call_handle(T, state.gpa, &state.overflow, message);
            const feedback: FeedbackType = if (comptime is_unreliable(T))
                (if (handled) .new(.backoff) else .rejected)
            else
                .backoff;
            if (handled) state.backoff += 1;
            // A spill may be the only signal a parked receiver gets; spurious wakes are fine.
            state.condition.signal(state.io);
            return feedback;
        }

        fn wrap(feedback: Feedback) FeedbackType {
            return if (comptime is_unreliable(T)) .new(feedback) else feedback;
        }

        /// Pop the next message, refilling ready from overflow (lock held).
        fn pop(state: *Self) ?T {
            if (state.ready.popFront()) |message| {
                // A freed ready slot lets the oldest overflow message advance.
                state.refill();
                return message;
            }
            state.refill();
            return state.ready.popFront();
        }

        fn refill(state: *Self) void {
            if (overflow_is_empty(T, &state.overflow)) return;
            var pusher: ReadyPusher(T) = .{ .ready = &state.ready, .capacity = state.capacity };
            drain_overflow(T, &state.overflow, &pusher);
            assert(state.ready.len <= state.capacity);
        }

        fn destroy(state: *Self) void {
            assert(state.handles == 0);
            assert(state.senders == 0);
            assert(state.closed);
            assert(state.ready.len == 0);
            assert(overflow_is_empty(T, &state.overflow));
            const gpa = state.gpa;
            state.ready.deinit(gpa);
            state.overflow.deinit(gpa);
            gpa.destroy(state);
        }
    };
}

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
        ready: *std.Deque(T),
        capacity: u32,

        pub fn push(pusher: *@This(), message: T) ?T {
            if (pusher.ready.len >= pusher.capacity) return message;
            pusher.ready.pushBackAssumeCapacity(message);
            return null;
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
