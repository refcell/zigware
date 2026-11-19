//! Track pending consumer deliveries for resolver implementations (commonware
//! `resolver/src/delivery.rs`).
//!
//! Resolvers share one delivery lifecycle: keep a fetch alive while `Consumer.deliver`
//! validates a response, abort that validation if the fetch is pruned, and reuse a cached
//! response for subscribers added while validation was in progress. This module owns that
//! lifecycle without assumptions about how data is fetched.
//!
//! Each delivery waits for the consumer's verdict in its own `std.Io` task (commonware's
//! future pool), which hands the verdict to `next_completion` through a queue. Removing a
//! key marks its delivery canceled; like commonware's biased `select!`, cancellation is
//! decided when the completion is read, so a verdict from a removed entry never completes a
//! replacement. The canceled delivery's receiver is closed only when completions are next
//! read: a verdict sent before then still reaches source accounting.
//!
//! Values: the tracker owns the value passed to `deliver` and hands the consumer a borrowed
//! value for the duration of each `deliver` call. If `C` declares
//! `deinit_value(gpa, value)`, the tracker frees cached values with it.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const codec = @import("codec");
const utils = @import("utils");
const resolver = @import("root.zig");

const oneshot = utils.channel.oneshot;
const Outcome = resolver.Outcome;

/// A wake-up shared by every event source of one actor: the delivery tracker broadcasts it
/// when a verdict arrives, and actors with other sources (fetch tasks, a mailbox forwarder)
/// broadcast the same condition, so one wait covers them all.
pub const Signal = struct {
    mutex: Io.Mutex = .init,
    condition: Io.Condition = .init,
};

/// `next_completion` failed: a canceled delivery closed without a verdict (commonware
/// `Aborted`), or the wait was canceled.
pub const NextError = error{Aborted} || Io.Cancelable;

/// Completed consumer validation for a delivery.
pub fn Completion(comptime K: type, comptime S: type, comptime Context: type) type {
    return struct {
        const Self = @This();

        /// Resolver-specific context associated with the delivery attempt.
        context: Context,
        /// The key passed to the consumer.
        key: K,
        /// The subscribers passed to the consumer (owned; free with `deinit`).
        subscribers: []S,
        /// The consumer's disposition, or null if it dropped the sender without one.
        outcome: ?Outcome,
        /// The tracked fetch was removed before this completion was read. Its verdict applies
        /// only to the source, not to any current fetch for the key.
        canceled: bool,
        /// The cached response was already accepted when this delivery began.
        previously_accepted: bool,

        pub fn delivery(self: Self) resolver.Delivery(K, S) {
            return .{ .key = self.key, .subscribers = self.subscribers };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.subscribers);
            self.* = undefined;
        }
    };
}

/// Tracks in-flight consumer deliveries keyed by resolver key. `Context` comes back with each
/// completion; `State` is per-key resolver state dropped when the key is pruned.
pub fn Tracker(comptime C: type, comptime Context: type, comptime State: type) type {
    comptime resolver.assert_consumer(C);
    return struct {
        const Self = @This();
        const K = C.Key;
        const S = C.Subscriber;
        const V = C.Value;
        pub const Done = Completion(K, S, Context);

        const Slot = struct {
            receiver: oneshot.Receiver(C.Outcome),
            future: Io.Future(void),
            key: K,
            subscribers: []S,
            context: Context,
            previously_accepted: bool,
            /// Owner side: the entry was removed.
            canceled: bool = false,
            /// Owner side: the receiver was closed after cancellation.
            closed: bool = false,
            /// Written by the task under `Shared.mutex` before it queues the slot.
            outcome: ?Outcome = null,
        };

        const Shared = struct {
            /// `own_signal`, or the actor's signal given to `init_with_signal`.
            signal: *Signal,
            own_signal: Signal = .{},
            /// Broadcast with `signal` on every verdict; only `next_completion` waits on it. An
            /// actor sharing `signal` waits on its condition with timeouts, which could consume
            /// a wake meant for another waiter (AGENTS.md: `Io.Condition` counts signals).
            completed: Io.Condition = .init,
            /// Slots whose verdict wait finished, oldest first. Capacity is reserved for
            /// every live slot, so tasks never allocate.
            done: std.ArrayList(*Slot) = .empty,
            /// Deliveries `try_completion` took; each is reported once as `error.Aborted`,
            /// like commonware's pooled wait that finds its `Pending` taken.
            aborted: u32 = 0,
        };

        const Response = struct { context: Context, value: V, accepted: bool };
        const Entry = struct { delivery: ?*Slot = null, response: ?Response = null, state: ?State };

        const KeyContext = struct {
            pub fn hash(_: KeyContext, key: K) u32 {
                var buffer: [codec.max_encode_size(K).?]u8 = undefined;
                const encoded = codec.encode_to(K, key, &buffer);
                return @truncate(std.hash.Wyhash.hash(0, encoded));
            }

            pub fn eql(_: KeyContext, a: K, b: K, _: usize) bool {
                return resolver.eql(K, a, b);
            }
        };

        gpa: Allocator,
        io: Io,
        consumer: C,
        entries: std.ArrayHashMapUnmanaged(K, Entry, KeyContext, true) = .empty,
        /// Every slot not yet returned by `next_completion`.
        live: std.ArrayList(*Slot) = .empty,
        shared: *Shared,

        /// An empty tracker backed by `consumer`.
        pub fn init(gpa: Allocator, io: Io, consumer: C) Allocator.Error!Self {
            return init_with_signal(gpa, io, consumer, null);
        }

        /// A tracker that guards its completions with `signal` (which must outlive it) and
        /// broadcasts it on every verdict; null uses a signal of its own.
        pub fn init_with_signal(
            gpa: Allocator,
            io: Io,
            consumer: C,
            signal: ?*Signal,
        ) Allocator.Error!Self {
            const shared = try gpa.create(Shared);
            shared.* = .{ .signal = undefined };
            shared.signal = signal orelse &shared.own_signal;
            return .{ .gpa = gpa, .io = io, .consumer = consumer, .shared = shared };
        }

        /// Whether a completion is queued, taking the signal's mutex (tests).
        fn has_completion_locked_for_test(self: *Self) bool {
            self.shared.signal.mutex.lockUncancelable(self.io);
            defer self.shared.signal.mutex.unlock(self.io);
            return self.has_completion_locked();
        }

        /// Whether a completion is queued. The caller holds the signal's mutex.
        pub fn has_completion_locked(self: *const Self) bool {
            return self.shared.done.items.len > 0 or self.shared.aborted > 0;
        }

        /// Cancels every pending verdict wait and frees everything.
        pub fn deinit(self: *Self) void {
            for (self.live.items) |slot| {
                slot.future.cancel(self.io);
                self.destroy_slot(slot);
            }
            self.live.deinit(self.gpa);
            for (self.entries.values()) |entry| self.drop_response(entry.response);
            self.entries.deinit(self.gpa);
            self.shared.done.deinit(self.gpa);
            self.gpa.destroy(self.shared);
            self.* = undefined;
        }

        /// Returns true when the key has an active tracked fetch.
        pub fn contains(self: *const Self, key: K) bool {
            return self.entries.contains(key);
        }

        /// Start tracking a key. Returns false (and changes nothing) if already tracked.
        pub fn insert_with_state(self: *Self, key: K, state: State) Allocator.Error!bool {
            const result = try self.entries.getOrPut(self.gpa, key);
            if (result.found_existing) return false;
            result.value_ptr.* = .{ .state = state };
            assert(self.contains(key));
            return true;
        }

        /// Start tracking a key without resolver state.
        pub fn insert(self: *Self, key: K) Allocator.Error!bool {
            comptime assert(State == void);
            return self.insert_with_state(key, {});
        }

        /// Remove a key and cancel any in-progress delivery for it. Returns true if present.
        pub fn remove(self: *Self, key: K) bool {
            const removed = self.entries.fetchSwapRemove(key) orelse return false;
            self.release(removed.value);
            assert(!self.contains(key));
            return true;
        }

        /// Remove a key, canceling any in-progress delivery, and return its state: null if
        /// absent, an inner null if the state was already taken.
        pub fn remove_with_state(self: *Self, key: K) ??State {
            const removed = self.entries.fetchSwapRemove(key) orelse return null;
            self.release(removed.value);
            return removed.value.state;
        }

        /// Take the key's state without removing the key.
        pub fn take_state(self: *Self, key: K) ?State {
            const entry = self.entries.getPtr(key) orelse return null;
            const state = entry.state orelse return null;
            entry.state = null;
            return state;
        }

        /// Borrow the key's state; null if absent or taken.
        pub fn state_mut(self: *Self, key: K) ?*State {
            const entry = self.entries.getPtr(key) orelse return null;
            if (entry.state) |*state| return state;
            return null;
        }

        /// Keep only keys for which `predicate.call(key)` is true; dropped keys cancel their
        /// deliveries. Returns the number removed.
        pub fn retain(self: *Self, predicate: anytype) usize {
            var removed: usize = 0;
            var index = self.entries.count();
            while (index > 0) {
                index -= 1;
                // Swap removal moves an already-visited entry into `index`.
                if (predicate.call(self.entries.keys()[index])) continue;
                const entry = self.entries.values()[index];
                self.entries.swapRemoveAt(index);
                self.release(entry);
                removed += 1;
            }
            return removed;
        }

        /// Remove every key and cancel every in-progress delivery. Returns the number removed.
        pub fn drain(self: *Self) usize {
            const count = self.entries.count();
            for (self.entries.values()) |entry| self.release(entry);
            self.entries.clearRetainingCapacity();
            assert(self.entries.count() == 0);
            return count;
        }

        /// Deliver a newly received response, caching it (the tracker takes ownership of
        /// `value`) so later subscribers can be redelivered the same value. The key must be
        /// tracked and have no delivery in progress.
        pub fn deliver(
            self: *Self,
            delivery: resolver.Delivery(K, S),
            context: Context,
            value: V,
        ) (Allocator.Error || Io.ConcurrentError)!void {
            const entry = self.entries.getPtr(delivery.key).?; // delivery entry
            self.drop_response(entry.response);
            entry.response = .{ .context = context, .value = value, .accepted = false };
            try self.start(delivery, context, value, false);
        }

        /// Deliver the cached response to another set of subscribers (those added while an
        /// earlier validation was pending). The key must be tracked with a cached response.
        pub fn redeliver(
            self: *Self,
            delivery: resolver.Delivery(K, S),
        ) (Allocator.Error || Io.ConcurrentError)!void {
            const entry = self.entries.getPtr(delivery.key).?; // delivery entry
            const response = entry.response.?; // response
            try self.start(delivery, response.context, response.value, response.accepted);
        }

        /// Whether the cached response for this key has been accepted.
        pub fn response_accepted(self: *const Self, key: K) bool {
            const entry = self.entries.getPtr(key) orelse return false;
            const response = entry.response orelse return false;
            return response.accepted;
        }

        /// Mark the cached response accepted. The key must be tracked with a cached response.
        pub fn accept_response(self: *Self, key: K) void {
            const entry = self.entries.getPtr(key).?;
            assert(entry.response != null);
            entry.response.?.accepted = true;
        }

        /// Drop the cached response without removing the key (to retry it).
        pub fn discard_response(self: *Self, key: K) void {
            const entry = self.entries.getPtr(key) orelse return;
            self.drop_response(entry.response);
            entry.response = null;
        }

        /// The number of deliveries not yet returned by `next_completion`.
        pub fn pending(self: *const Self) usize {
            return self.live.items.len;
        }

        /// Wait for the next consumer validation result. A canceled delivery returns its
        /// verdict (for source accounting) or `error.Aborted` when it had none. An active
        /// delivery clears its key's slot so the key can be retried or redelivered.
        pub fn next_completion(self: *Self) NextError!Done {
            self.close_canceled();
            const slot = blk: {
                self.shared.signal.mutex.lockUncancelable(self.io);
                defer self.shared.signal.mutex.unlock(self.io);
                while (self.shared.done.items.len == 0 and self.shared.aborted == 0) {
                    const signal = self.shared.signal;
                    try self.shared.completed.wait(self.io, &signal.mutex);
                }
                if (self.take_aborted_locked()) return error.Aborted;
                break :blk self.shared.done.orderedRemove(0);
            };
            return self.finish(slot);
        }

        /// `next_completion` without waiting: null when no verdict is ready.
        pub fn try_next_completion(self: *Self) error{Aborted}!?Done {
            self.close_canceled();
            const slot = blk: {
                self.shared.signal.mutex.lockUncancelable(self.io);
                defer self.shared.signal.mutex.unlock(self.io);
                if (self.take_aborted_locked()) return error.Aborted;
                if (self.shared.done.items.len == 0) return null;
                break :blk self.shared.done.orderedRemove(0);
            };
            return try self.finish(slot);
        }

        /// Take the completion of the key's delivery if the consumer already sent its verdict
        /// or dropped its sender (commonware `try_completion`). Call this before adding
        /// subscribers to a key so such a verdict cannot retire them. Returns the completion
        /// `next_completion` would otherwise return and frees the delivery slot; the next
        /// `next_completion` then reports `error.Aborted` once for it, as commonware's
        /// abandoned pooled wait does. Returns null if the key has no delivery or its verdict
        /// is still pending.
        pub fn try_completion(self: *Self, key: K) ?Done {
            const entry = self.entries.getPtr(key) orelse return null;
            const slot = entry.delivery orelse return null;
            assert(!slot.canceled); // a canceled slot no longer belongs to an entry
            if (!self.take_queued(slot)) {
                if (!slot.receiver.is_resolved()) return null;
                // The verdict is ready, so the wait returns at once and queues the slot.
                slot.future.await(self.io);
                assert(self.take_queued(slot));
            } else {
                slot.future.await(self.io);
            }
            // Proof: the slot is active, and only a canceled slot aborts.
            const completed = self.retire(slot) catch unreachable;
            self.shared.signal.mutex.lockUncancelable(self.io);
            defer self.shared.signal.mutex.unlock(self.io);
            self.shared.aborted += 1;
            self.shared.signal.condition.broadcast(self.io);
            self.shared.completed.broadcast(self.io);
            return completed;
        }

        /// Consumes one taken delivery's `Aborted` report. The caller holds the signal's mutex.
        fn take_aborted_locked(self: *Self) bool {
            if (self.shared.aborted == 0) return false;
            self.shared.aborted -= 1;
            return true;
        }

        /// Removes `slot` from the completion queue; false if its wait has not queued it.
        fn take_queued(self: *Self, slot: *Slot) bool {
            self.shared.signal.mutex.lockUncancelable(self.io);
            defer self.shared.signal.mutex.unlock(self.io);
            const done = &self.shared.done;
            const index = std.mem.indexOfScalar(*Slot, done.items, slot) orelse return false;
            _ = done.orderedRemove(index);
            return true;
        }

        fn start(
            self: *Self,
            delivery: resolver.Delivery(K, S),
            context: Context,
            value: V,
            previously_accepted: bool,
        ) (Allocator.Error || Io.ConcurrentError)!void {
            assert(delivery.subscribers.len > 0);
            const entry = self.entries.getPtr(delivery.key).?;
            assert(entry.delivery == null);
            const subscribers = try self.gpa.dupe(S, delivery.subscribers);
            errdefer self.gpa.free(subscribers);
            const slot = try self.gpa.create(Slot);
            errdefer self.gpa.destroy(slot);
            try self.live.ensureUnusedCapacity(self.gpa, 1);
            {
                self.shared.signal.mutex.lockUncancelable(self.io);
                defer self.shared.signal.mutex.unlock(self.io);
                const needed = self.live.items.len + 1;
                try self.shared.done.ensureTotalCapacity(self.gpa, needed);
            }
            // Spans are borrowed for the consumer's call only, so they are not kept.
            const shown: resolver.Delivery(K, S) = .{
                .key = delivery.key,
                .subscribers = subscribers,
                .spans = delivery.spans,
            };
            var receiver = try self.consumer.deliver(shown, value);
            errdefer receiver.deinit();
            slot.* = .{
                .receiver = receiver,
                .future = undefined,
                .key = delivery.key,
                .subscribers = subscribers,
                .context = context,
                .previously_accepted = previously_accepted,
            };
            slot.future = try self.io.concurrent(wait_verdict, .{ slot, self.shared, self.io });
            self.live.appendAssumeCapacity(slot);
            entry.delivery = slot;
        }

        /// The task behind each delivery: wait for the verdict, then queue the slot.
        fn wait_verdict(slot: *Slot, shared: *Shared, io: Io) void {
            const outcome: ?Outcome = if (slot.receiver.recv()) |verdict|
                Outcome.from(verdict)
            else |err| switch (err) {
                error.Closed => null,
                // Shutdown: the owner frees the slot.
                error.Canceled => return,
            };
            shared.signal.mutex.lockUncancelable(io);
            defer shared.signal.mutex.unlock(io);
            slot.outcome = outcome;
            assert(shared.done.items.len < shared.done.capacity);
            shared.done.appendAssumeCapacity(slot);
            shared.signal.condition.broadcast(io);
            shared.completed.broadcast(io);
        }

        fn finish(self: *Self, slot: *Slot) error{Aborted}!Done {
            slot.future.await(self.io);
            return self.retire(slot);
        }

        /// Frees a slot whose wait has ended and returns its completion.
        fn retire(self: *Self, slot: *Slot) error{Aborted}!Done {
            const index = std.mem.indexOfScalar(*Slot, self.live.items, slot).?;
            _ = self.live.swapRemove(index);
            defer {
                slot.receiver.deinit();
                self.gpa.destroy(slot);
            }
            // Cancellation belongs to the removed entry. Only an active completion clears a
            // delivery slot; a canceled key may already have a replacement entry.
            if (!slot.canceled) {
                const entry = self.entries.getPtr(slot.key).?; // delivery entry
                assert(entry.delivery == slot);
                entry.delivery = null;
            }
            if (slot.canceled and slot.outcome == null) {
                self.gpa.free(slot.subscribers);
                return error.Aborted;
            }
            return .{
                .context = slot.context,
                .key = slot.key,
                .subscribers = slot.subscribers,
                .outcome = slot.outcome,
                .canceled = slot.canceled,
                .previously_accepted = slot.previously_accepted,
            };
        }

        /// Close the receivers of canceled deliveries so their waits end; a verdict already
        /// sent stays readable. `next_completion` does this first; actors that wait on a shared
        /// signal call it before each wait.
        pub fn close_canceled(self: *Self) void {
            for (self.live.items) |slot| {
                if (!slot.canceled or slot.closed) continue;
                slot.receiver.close();
                slot.closed = true;
            }
        }

        fn release(self: *Self, entry: Entry) void {
            if (entry.delivery) |slot| {
                assert(!slot.canceled);
                slot.canceled = true;
            }
            self.drop_response(entry.response);
        }

        fn drop_response(self: *Self, response: ?Response) void {
            const cached = response orelse return;
            if (comptime @hasDecl(C, "deinit_value")) C.deinit_value(self.gpa, cached.value);
        }

        fn destroy_slot(self: *Self, slot: *Slot) void {
            slot.receiver.deinit();
            self.gpa.free(slot.subscribers);
            self.gpa.destroy(slot);
        }
    };
}

const testing = std.testing;
const runtime = @import("runtime");
const MockKey = @import("p2p/mocks/key.zig").Key;
const MockConsumer = @import("p2p/mocks/consumer.zig").Consumer(MockKey, void);
const TestTracker = Tracker(MockConsumer, u8, void);
const PendingTracker = Tracker(PendingConsumer, u8, void);
const complete: Outcome = .{ .resolved = .complete };

fn mock_key(value: u8) MockKey {
    return .init(value);
}

fn unit_delivery(k: MockKey) resolver.Delivery(MockKey, void) {
    return .{ .key = k, .subscribers = &.{{}} };
}

fn run(comptime body: fn (Io) anyerror!void) !void {
    var runner = try runtime.deterministic.Runner.init(testing.allocator, .{});
    defer runner.deinit();
    try try runner.start(body, .{runner.io()});
}

/// A consumer that keeps every verdict sender so the test decides when (and whether) to send.
const PendingConsumer = struct {
    pub const Key = MockKey;
    pub const Value = []const u8;
    pub const Subscriber = void;
    pub const Outcome = bool;

    senders: *std.ArrayList(oneshot.Sender(bool)),
    io: Io,

    pub fn deliver(
        self: PendingConsumer,
        _: resolver.Delivery(MockKey, void),
        _: []const u8,
    ) Allocator.Error!oneshot.Receiver(bool) {
        var pair = try oneshot.channel(bool, testing.allocator, self.io);
        errdefer pair.receiver.deinit();
        try self.senders.append(testing.allocator, pair.sender);
        return pair.receiver;
    }

    fn pop(self: PendingConsumer) oneshot.Sender(bool) {
        return self.senders.orderedRemove(0);
    }
};

test "insert contains remove round trip" {
    try run(struct {
        fn body(io: Io) !void {
            const consumer = try MockConsumer.init(testing.allocator, io);
            defer consumer.deinit();
            var tracker = try TestTracker.init(testing.allocator, io, consumer);
            defer tracker.deinit();
            try testing.expect(!tracker.contains(mock_key(1)));
            try testing.expect(try tracker.insert(mock_key(1)));
            try testing.expect(tracker.contains(mock_key(1)));
            try testing.expect(!try tracker.insert(mock_key(1)));
            try testing.expect(tracker.remove(mock_key(1)));
            try testing.expect(!tracker.contains(mock_key(1)));
            try testing.expect(!tracker.remove(mock_key(1)));
        }
    }.body);
}

test "state round trip" {
    try run(struct {
        fn body(io: Io) !void {
            const consumer = try MockConsumer.init(testing.allocator, io);
            defer consumer.deinit();
            var tracker = try Tracker(MockConsumer, u8, u8).init(testing.allocator, io, consumer);
            defer tracker.deinit();
            try testing.expect(tracker.state_mut(mock_key(1)) == null);
            try testing.expect(try tracker.insert_with_state(mock_key(1), 5));
            try testing.expectEqual(@as(u8, 5), tracker.state_mut(mock_key(1)).?.*);
            tracker.state_mut(mock_key(1)).?.* = 7;
            try testing.expectEqual(@as(u8, 7), tracker.state_mut(mock_key(1)).?.*);
            // Taking the state leaves the key tracked without state.
            try testing.expectEqual(@as(u8, 7), tracker.take_state(mock_key(1)).?);
            try testing.expect(tracker.contains(mock_key(1)));
            try testing.expect(tracker.state_mut(mock_key(1)) == null);
            const removed = tracker.remove_with_state(mock_key(1)).?;
            try testing.expect(removed == null);
            try testing.expect(tracker.remove_with_state(mock_key(1)) == null);
        }
    }.body);
}

test "deliver completes with context and consumer result" {
    try run(struct {
        fn body(io: Io) !void {
            const gpa = testing.allocator;
            const consumer = try MockConsumer.init(gpa, io);
            defer consumer.deinit();
            var tracker = try TestTracker.init(gpa, io, consumer);
            defer tracker.deinit();
            _ = try tracker.insert(mock_key(7));
            try tracker.deliver(unit_delivery(mock_key(7)), 9, "data");
            var completed = try tracker.next_completion();
            defer completed.deinit(gpa);
            try testing.expectEqual(@as(u8, 9), completed.context);
            try testing.expect(completed.key.eql(mock_key(7)));
            try testing.expect(!completed.canceled);
            try testing.expect(!completed.previously_accepted);
            try testing.expect(completed.outcome.?.eql(complete));
            var event = try consumer.next_event();
            defer event.deinit(gpa);
            try testing.expect(event.key.eql(mock_key(7)));
            try testing.expectEqualStrings("data", event.value);
        }
    }.body);
}

test "remove aborts in flight delivery" {
    try run(struct {
        fn body(io: Io) !void {
            var senders: std.ArrayList(oneshot.Sender(bool)) = .empty;
            defer senders.deinit(testing.allocator);
            const consumer: PendingConsumer = .{ .senders = &senders, .io = io };
            var tracker = try PendingTracker.init(testing.allocator, io, consumer);
            defer tracker.deinit();
            _ = try tracker.insert(mock_key(1));
            try tracker.deliver(unit_delivery(mock_key(1)), 2, "v");
            var sender = consumer.pop();
            try testing.expect(tracker.remove(mock_key(1)));
            try testing.expectError(error.Aborted, tracker.next_completion());
            try testing.expect(sender.is_closed());
            sender.deinit();
            try testing.expectEqual(@as(usize, 0), tracker.pending());
        }
    }.body);
}

const VerdictTiming = enum { before_removal, after_removal, after_close };

const Scenario = struct {
    removal: u8,
    timing: VerdictTiming,
    polled: bool,
};

var scenario: Scenario = undefined;

/// Every removal path must preserve accepted feedback and isolate the replacement.
fn canceled_delivery_body(io: Io) !void {
    const gpa = testing.allocator;
    var senders: std.ArrayList(oneshot.Sender(bool)) = .empty;
    defer senders.deinit(gpa);
    const consumer: PendingConsumer = .{ .senders = &senders, .io = io };
    var tracker = try Tracker(PendingConsumer, u8, u8).init(gpa, io, consumer);
    defer tracker.deinit();
    const k = mock_key(1);
    // Keep the old verdict pending or make it ready without consuming it.
    try testing.expect(try tracker.insert_with_state(k, 10));
    try tracker.deliver(unit_delivery(k), 1, "old");
    var old_sender: ?oneshot.Sender(bool) = consumer.pop();
    if (scenario.polled) try testing.expect(try tracker.try_next_completion() == null);
    if (scenario.timing == .before_removal) try old_sender.?.send(true);
    if (scenario.timing == .before_removal) old_sender = null;
    // Reuse the key before reading the canceled delivery.
    const KeepNone = struct {
        pub fn call(_: @This(), _: MockKey) bool {
            return false;
        }
    };
    switch (scenario.removal) {
        0 => try testing.expect(tracker.remove(k)),
        1 => try testing.expectEqual(@as(u8, 10), tracker.remove_with_state(k).?.?),
        2 => try testing.expectEqual(@as(usize, 1), tracker.retain(KeepNone{})),
        else => try testing.expectEqual(@as(usize, 1), tracker.drain()),
    }
    if (scenario.timing == .after_removal) try old_sender.?.send(true);
    if (scenario.timing == .after_removal) old_sender = null;
    try testing.expect(try tracker.insert_with_state(k, 20));
    try tracker.deliver(unit_delivery(k), 2, "new");
    var new_sender = consumer.pop();
    try expect_canceled_completion(&tracker, &old_sender);
    try testing.expectEqual(@as(u8, 20), tracker.state_mut(k).?.*);
    try testing.expect(tracker.entries.getPtr(k).?.delivery != null);
    try testing.expect(try tracker.try_next_completion() == null);
    // Only the replacement's verdict may complete the new entry.
    try new_sender.send(true);
    var completed = try tracker.next_completion();
    defer completed.deinit(gpa);
    try testing.expect(!completed.canceled);
    try testing.expectEqual(@as(u8, 2), completed.context);
    try testing.expect(completed.key.eql(k));
    try testing.expect(completed.outcome.?.eql(complete));
    try testing.expectEqual(@as(usize, 0), tracker.pending());
}

/// Cancellation closes pending verdicts and preserves accepted ones without touching the
/// replacement's state or delivery.
fn expect_canceled_completion(
    tracker: *Tracker(PendingConsumer, u8, u8),
    old_sender: *?oneshot.Sender(bool),
) !void {
    const result = tracker.next_completion();
    if (scenario.timing == .after_close) {
        try testing.expectError(error.Aborted, result);
        try testing.expectError(error.Closed, old_sender.*.?.send(true));
        old_sender.* = null;
        return;
    }
    var completed = try result;
    defer completed.deinit(testing.allocator);
    try testing.expect(completed.canceled);
    try testing.expect(!completed.previously_accepted);
    try testing.expectEqual(@as(u8, 1), completed.context);
    try testing.expect(completed.outcome.?.eql(complete));
}

test "canceled delivery cannot complete reinserted key" {
    for (0..4) |removal| {
        for ([_]VerdictTiming{ .before_removal, .after_removal, .after_close }) |timing| {
            for ([_]bool{ false, true }) |polled| {
                scenario = .{ .removal = @intCast(removal), .timing = timing, .polled = polled };
                try run(canceled_delivery_body);
            }
        }
    }
}

test "dropped verdict completes without outcome and redelivers" {
    try run(struct {
        fn body(io: Io) !void {
            const gpa = testing.allocator;
            var senders: std.ArrayList(oneshot.Sender(bool)) = .empty;
            defer senders.deinit(gpa);
            const consumer: PendingConsumer = .{ .senders = &senders, .io = io };
            var tracker = try PendingTracker.init(gpa, io, consumer);
            defer tracker.deinit();
            const k = mock_key(3);
            _ = try tracker.insert(k);
            try tracker.deliver(unit_delivery(k), 4, "unjudged");
            var dropped = consumer.pop();
            dropped.deinit();
            var completed = try tracker.next_completion();
            defer completed.deinit(gpa);
            try testing.expectEqual(@as(u8, 4), completed.context);
            try testing.expect(completed.key.eql(k));
            try testing.expect(completed.outcome == null);
            try testing.expect(!tracker.response_accepted(k));
            // The unjudged response can still be handed to other subscribers.
            try tracker.redeliver(unit_delivery(k));
            var sender = consumer.pop();
            try sender.send(true);
            var judged = try tracker.next_completion();
            defer judged.deinit(gpa);
            try testing.expectEqual(@as(u8, 4), judged.context);
            try testing.expect(judged.outcome.?.eql(complete));
        }
    }.body);
}

/// Returns true when `tracker` has no completion ready to report.
fn no_completion(tracker: *PendingTracker) !bool {
    const ready = try tracker.try_next_completion();
    if (ready) |completion| {
        var owned = completion;
        owned.deinit(testing.allocator);
    }
    return ready == null;
}

test "try_completion takes a sent verdict" {
    // commonware `test_try_completion_takes_a_sent_verdict`.
    try run(struct {
        fn body(io: Io) !void {
            const gpa = testing.allocator;
            var senders: std.ArrayList(oneshot.Sender(bool)) = .empty;
            defer senders.deinit(gpa);
            const consumer: PendingConsumer = .{ .senders = &senders, .io = io };
            var tracker = try PendingTracker.init(gpa, io, consumer);
            defer tracker.deinit();
            const k = mock_key(1);

            // Nothing is taken without a delivery or while its verdict is pending.
            try testing.expect(tracker.try_completion(k) == null);
            _ = try tracker.insert(k);
            try testing.expect(tracker.try_completion(k) == null);
            try tracker.deliver(unit_delivery(k), 2, "v");
            var sender = consumer.pop();
            try testing.expect(try no_completion(&tracker));
            try testing.expect(tracker.try_completion(k) == null);

            // A sent verdict is taken once, before the queue reports it.
            try sender.send(true);
            var completed = tracker.try_completion(k).?;
            defer completed.deinit(gpa);
            try testing.expectEqual(@as(u8, 2), completed.context);
            try testing.expect(completed.key.eql(k));
            try testing.expect(completed.outcome.?.eql(complete));
            try testing.expect(!completed.canceled);
            try testing.expect(!completed.previously_accepted);
            try testing.expect(tracker.try_completion(k) == null);

            // The slot is free for the next delivery. The abandoned wait reports `Aborted`
            // once without completing or clearing that delivery.
            tracker.accept_response(k);
            try tracker.redeliver(unit_delivery(k));
            sender = consumer.pop();
            try testing.expectError(error.Aborted, tracker.try_next_completion());
            try testing.expect(try no_completion(&tracker));
            try testing.expectEqual(@as(usize, 1), tracker.pending());
            try take_pending_verdict(io, &tracker, k, &sender);
            try take_dropped_sender(&tracker, k, consumer);
        }
    }.body);
}

/// A verdict pending when read completes through the queue, and one the wait already queued
/// is taken by `try_completion` instead.
fn take_pending_verdict(
    io: Io,
    tracker: *PendingTracker,
    k: MockKey,
    sender: *oneshot.Sender(bool),
) !void {
    const gpa = testing.allocator;
    try testing.expect(tracker.try_completion(k) == null);
    try sender.send(false);
    var judged = try tracker.next_completion();
    defer judged.deinit(gpa);
    try testing.expect(judged.outcome.?.eql(.invalid));
    try testing.expect(judged.previously_accepted);

    try tracker.redeliver(unit_delivery(k));
    var queued_sender = tracker.consumer.pop();
    try queued_sender.send(true);
    // Let the wait queue its slot first.
    while (!tracker.has_completion_locked_for_test()) try io.sleep(.fromMilliseconds(1), .real);
    var queued = tracker.try_completion(k).?;
    defer queued.deinit(gpa);
    try testing.expect(queued.outcome.?.eql(complete));
    try testing.expectError(error.Aborted, tracker.next_completion());
    try testing.expect(try no_completion(tracker));
    try testing.expectEqual(@as(usize, 0), tracker.pending());
}

/// A dropped sender is taken as a completion without an outcome, and the slot is free for
/// the delivery that follows.
fn take_dropped_sender(tracker: *PendingTracker, k: MockKey, consumer: PendingConsumer) !void {
    const gpa = testing.allocator;
    try tracker.redeliver(unit_delivery(k));
    var dropped = consumer.pop();
    dropped.deinit();
    var completed = tracker.try_completion(k).?;
    defer completed.deinit(gpa);
    try testing.expect(completed.outcome == null);
    try testing.expect(!completed.canceled);
    try testing.expect(completed.previously_accepted);
    try tracker.redeliver(unit_delivery(k));
    var last = consumer.pop();
    try last.send(true);
    try testing.expectError(error.Aborted, tracker.next_completion());
    var final = try tracker.next_completion();
    final.deinit(gpa);
}

test "redeliver reuses accepted response for new subscribers" {
    try run(struct {
        fn body(io: Io) !void {
            const gpa = testing.allocator;
            const consumer = try MockConsumer.init(gpa, io);
            defer consumer.deinit();
            var tracker = try TestTracker.init(gpa, io, consumer);
            defer tracker.deinit();
            const k = mock_key(5);
            _ = try tracker.insert(k);
            try tracker.deliver(unit_delivery(k), 3, "first");
            var completed = try tracker.next_completion();
            defer completed.deinit(gpa);
            try testing.expect(!completed.previously_accepted);
            try testing.expect(completed.outcome.?.eql(complete));
            tracker.accept_response(k);
            try testing.expect(tracker.response_accepted(k));
            try tracker.redeliver(unit_delivery(k));
            var redelivered = try tracker.next_completion();
            defer redelivered.deinit(gpa);
            try testing.expectEqual(@as(u8, 3), redelivered.context);
            try testing.expect(redelivered.key.eql(k));
            try testing.expect(redelivered.previously_accepted);
            try testing.expect(redelivered.outcome.?.eql(complete));
            for (0..2) |_| {
                var event = try consumer.next_event();
                defer event.deinit(gpa);
                try testing.expect(event.key.eql(k));
                try testing.expectEqualStrings("first", event.value);
            }
        }
    }.body);
}

test "rejected response can be discarded and replaced" {
    try run(struct {
        fn body(io: Io) !void {
            const gpa = testing.allocator;
            const consumer = try MockConsumer.init(gpa, io);
            defer consumer.deinit();
            const k = mock_key(8);
            try consumer.add_expected(k, "good");
            var tracker = try TestTracker.init(gpa, io, consumer);
            defer tracker.deinit();
            _ = try tracker.insert(k);
            try tracker.deliver(unit_delivery(k), 1, "bad");
            var rejected = try tracker.next_completion();
            defer rejected.deinit(gpa);
            try testing.expect(rejected.outcome.?.eql(.invalid));
            tracker.discard_response(k);
            try testing.expect(!tracker.response_accepted(k));
            try tracker.deliver(unit_delivery(k), 2, "good");
            var accepted = try tracker.next_completion();
            defer accepted.deinit(gpa);
            try testing.expectEqual(@as(u8, 2), accepted.context);
            try testing.expect(accepted.outcome.?.eql(complete));
        }
    }.body);
}

test "deinit cancels pending verdict waits" {
    try run(struct {
        fn body(io: Io) !void {
            var senders: std.ArrayList(oneshot.Sender(bool)) = .empty;
            defer senders.deinit(testing.allocator);
            const consumer: PendingConsumer = .{ .senders = &senders, .io = io };
            var tracker = try PendingTracker.init(testing.allocator, io, consumer);
            for (0..3) |index| {
                _ = try tracker.insert(mock_key(@intCast(index)));
                try tracker.deliver(unit_delivery(mock_key(@intCast(index))), 0, "v");
            }
            tracker.deinit();
            for (senders.items) |*sender| {
                try testing.expect(sender.is_closed());
                sender.deinit();
            }
        }
    }.body);
}

test {
    _ = @import("delivery_fuzz_test.zig");
}

test "redeliver requires a cached response" {
    // commonware `test_redeliver_requires_cached_response` (`should_panic`).
    try utils.death.expect_panic(@src(), "attempt to use null value", struct {
        fn body() !void {
            try run(struct {
                fn run_body(io: Io) !void {
                    const gpa = testing.allocator;
                    const consumer = try MockConsumer.init(gpa, io);
                    defer consumer.deinit();
                    var tracker = try TestTracker.init(gpa, io, consumer);
                    defer tracker.deinit();
                    const k = mock_key(7);
                    _ = try tracker.insert(k);
                    try tracker.deliver(unit_delivery(k), 3, "first");
                    var completed = try tracker.next_completion();
                    defer completed.deinit(gpa);
                    try testing.expect(completed.outcome.?.eql(complete));
                    tracker.discard_response(k);
                    try tracker.redeliver(unit_delivery(k));
                }
            }.run_body);
        }
    }.body);
}
