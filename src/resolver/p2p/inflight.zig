//! In-flight fetch state of the p2p resolver (commonware `resolver/src/p2p/inflight.rs`).
//!
//! Wraps the resolver-agnostic delivery tracker with the p2p engine's per-delivery context
//! (serving peer, response time, response size) and a fetch-duration timer per key: the timer
//! records when the fetch completes or its response is accepted, and a canceled or retained
//! fetch records nothing.
//!
//! Responses are byte strings the inflight state owns (copies of network payloads); they are
//! freed with the allocator when the tracker drops them.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const metrics = @import("runtime").telemetry.metrics;
const resolver = @import("../root.zig");
const delivery_mod = @import("../delivery.zig");
const utils = @import("utils");

const Duration = utils.Duration;
const Timer = metrics.histogram.Timer;

/// The delivery context of a network response: the serving peer, its network response time,
/// and the response size in bytes.
pub fn Source(comptime P: type) type {
    return struct { peer: P, elapsed: Duration, bytes: u64 };
}

/// A consumer of byte values whose cached responses the tracker frees.
fn OwnedBytes(comptime C: type) type {
    comptime assert(C.Value == []const u8);
    return struct {
        pub const Key = C.Key;
        pub const Value = []const u8;
        pub const Subscriber = C.Subscriber;
        pub const Outcome = C.Outcome;

        inner: C,

        const Delivered = @typeInfo(@TypeOf(C.deliver)).@"fn".return_type.?;

        pub fn deliver(
            self: @This(),
            delivery: resolver.Delivery(Key, Subscriber),
            value: Value,
        ) Delivered {
            return self.inner.deliver(delivery, value);
        }

        pub fn deinit_value(gpa: Allocator, value: Value) void {
            gpa.free(value);
        }
    };
}

/// Tracks all in-flight fetch state for consumer `C` (byte values) and peers `P`.
pub fn Inflight(comptime C: type, comptime P: type) type {
    resolver.assert_consumer(C);
    return struct {
        const Self = @This();
        pub const Key = C.Key;
        pub const Subscriber = C.Subscriber;
        pub const Context = Source(P);
        const Tracker = delivery_mod.Tracker(OwnedBytes(C), Context, Timer);
        pub const Completion = Tracker.Done;

        /// Resolver-agnostic delivery state shared with non-p2p resolvers.
        deliveries: Tracker,

        pub fn init(gpa: Allocator, io: Io, consumer: C) Allocator.Error!Self {
            return .{ .deliveries = try .init(gpa, io, .{ .inner = consumer }) };
        }

        pub fn init_with_signal(
            gpa: Allocator,
            io: Io,
            consumer: C,
            signal: *delivery_mod.Signal,
        ) Allocator.Error!Self {
            const wrapped: OwnedBytes(C) = .{ .inner = consumer };
            return .{ .deliveries = try .init_with_signal(gpa, io, wrapped, signal) };
        }

        pub fn deinit(self: *Self) void {
            self.deliveries.deinit();
            self.* = undefined;
        }

        /// Whether there is an in-flight entry for the key.
        pub fn contains(self: *const Self, key: Key) bool {
            return self.deliveries.contains(key);
        }

        /// Inserts a new in-flight entry for the key, which must not be tracked.
        pub fn insert(self: *Self, key: Key, timer: Timer) Allocator.Error!void {
            assert(!self.deliveries.contains(key)); // inflight entry
            assert(try self.deliveries.insert_with_state(key, timer));
        }

        /// Removes the key's entry without recording its duration. Accepted verdicts remain
        /// available for source accounting. Returns whether an entry was present.
        pub fn cancel(self: *Self, key: Key) bool {
            return self.deliveries.remove(key);
        }

        /// Completes the key's entry, recording its duration unless an accepted response
        /// already did. The key must be tracked.
        pub fn complete(self: *Self, io: Io, key: Key) void {
            const state = self.deliveries.remove_with_state(key).?; // inflight entry
            if (state) |timer| timer.observe(io);
            assert(!self.deliveries.contains(key));
        }

        /// Drops entries whose key fails `predicate.call(key)`; returns the dropped count.
        pub fn retain(self: *Self, predicate: anytype) usize {
            return self.deliveries.retain(predicate);
        }

        /// Drops every entry; returns the dropped count.
        pub fn drain(self: *Self) usize {
            return self.deliveries.drain();
        }

        /// Begins a consumer delivery for a network response, taking ownership of `value`
        /// (allocated with the tracker's allocator) and caching it for later subscribers.
        pub fn deliver(
            self: *Self,
            delivery: resolver.Delivery(Key, Subscriber),
            peer: P,
            elapsed: Duration,
            value: []const u8,
        ) !void {
            const context: Context = .{ .peer = peer, .elapsed = elapsed, .bytes = value.len };
            try self.deliveries.deliver(delivery, context, value);
        }

        /// Begins another consumer delivery for an already received response.
        pub fn redeliver(self: *Self, delivery: resolver.Delivery(Key, Subscriber)) !void {
            try self.deliveries.redeliver(delivery);
        }

        /// Marks the current response accepted and records the fetch duration.
        pub fn accept_response(self: *Self, io: Io, key: Key) void {
            self.deliveries.accept_response(key);
            if (self.deliveries.take_state(key)) |timer| timer.observe(io);
            assert(self.deliveries.response_accepted(key));
        }

        /// Drops the current response without completing the fetch.
        pub fn discard_response(self: *Self, key: Key) void {
            self.deliveries.discard_response(key);
        }

        /// Whether the key's cached response was accepted.
        pub fn response_accepted(self: *const Self, key: Key) bool {
            return self.deliveries.response_accepted(key);
        }

        /// The next verdict, or `error.Aborted` for a cancellation without a verdict.
        /// Canceled completions keep source feedback but cannot affect current demand.
        pub fn next_delivery(self: *Self) delivery_mod.NextError!Completion {
            return self.deliveries.next_completion();
        }

        /// The next verdict if one is ready.
        pub fn try_next_delivery(self: *Self) error{Aborted}!?Completion {
            return self.deliveries.try_next_completion();
        }
    };
}
