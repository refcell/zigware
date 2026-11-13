//! A consumer for tests (commonware `resolver/src/p2p/mocks/consumer.rs`).
//!
//! Values are byte strings. A delivery is valid when no value is expected for its key or the
//! value matches the expected one; valid deliveries are recorded as events (owned copies) that
//! a test reads with `next_event` / `try_event`. Copies of a `Consumer` share one state (Rust
//! `Clone`); call `deinit` once.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const utils = @import("utils");
const resolver = @import("../../root.zig");

const oneshot = utils.channel.oneshot;

pub fn Consumer(comptime K: type, comptime S: type) type {
    return struct {
        const Self = @This();

        pub const Key = K;
        pub const Value = []const u8;
        pub const Subscriber = S;
        pub const Outcome = bool;

        /// A delivered (key, value) pair; free with `deinit`.
        pub const Event = struct {
            key: K,
            value: []u8,

            pub fn deinit(self: *Event, gpa: Allocator) void {
                gpa.free(self.value);
                self.* = undefined;
            }
        };

        const Expected = struct { key: K, value: []u8 };

        const Shared = struct {
            gpa: Allocator,
            io: Io,
            mutex: Io.Mutex = .init,
            condition: Io.Condition = .init,
            expected: std.ArrayList(Expected) = .empty,
            events: std.ArrayList(Event) = .empty,
        };

        shared: *Shared,

        pub fn init(gpa: Allocator, io: Io) Allocator.Error!Self {
            const shared = try gpa.create(Shared);
            shared.* = .{ .gpa = gpa, .io = io };
            return .{ .shared = shared };
        }

        pub fn deinit(self: Self) void {
            const shared = self.shared;
            const gpa = shared.gpa;
            for (shared.expected.items) |item| gpa.free(item.value);
            shared.expected.deinit(gpa);
            for (shared.events.items) |*event| event.deinit(gpa);
            shared.events.deinit(gpa);
            gpa.destroy(shared);
        }

        /// Expect `value` for `key` (copied); other values are invalid.
        pub fn add_expected(self: Self, key: K, value: []const u8) Allocator.Error!void {
            const shared = self.shared;
            const copy = try shared.gpa.dupe(u8, value);
            errdefer shared.gpa.free(copy);
            shared.mutex.lockUncancelable(shared.io);
            defer shared.mutex.unlock(shared.io);
            if (find(shared.expected.items, key)) |index| {
                shared.gpa.free(shared.expected.items[index].value);
                shared.expected.items[index].value = copy;
                return;
            }
            try shared.expected.append(shared.gpa, .{ .key = key, .value = copy });
        }

        /// Remove the expected value for `key`; the caller frees the result.
        pub fn pop_expected(self: Self, key: K) ?[]u8 {
            const shared = self.shared;
            shared.mutex.lockUncancelable(shared.io);
            defer shared.mutex.unlock(shared.io);
            const index = find(shared.expected.items, key) orelse return null;
            return shared.expected.swapRemove(index).value;
        }

        /// Validates `value` against the expectation, records valid deliveries, and returns a
        /// receiver that already holds the verdict.
        pub fn deliver(
            self: Self,
            delivery: resolver.Delivery(K, S),
            value: []const u8,
        ) Allocator.Error!oneshot.Receiver(bool) {
            assert(delivery.subscribers.len > 0);
            const shared = self.shared;
            var pair = try oneshot.channel(bool, shared.gpa, shared.io);
            errdefer pair.receiver.deinit();
            const valid = try self.record(delivery.key, value);
            pair.sender.send(valid) catch unreachable; // Proof: the receiver is open.
            assert(pair.receiver.is_ready());
            return pair.receiver;
        }

        fn record(self: Self, key: K, value: []const u8) Allocator.Error!bool {
            const shared = self.shared;
            const copy = try shared.gpa.dupe(u8, value);
            errdefer shared.gpa.free(copy);
            shared.mutex.lockUncancelable(shared.io);
            defer shared.mutex.unlock(shared.io);
            const valid = if (find(shared.expected.items, key)) |index|
                std.mem.eql(u8, shared.expected.items[index].value, value)
            else
                true;
            if (!valid) {
                shared.gpa.free(copy);
                return false;
            }
            try shared.events.append(shared.gpa, .{ .key = key, .value = copy });
            shared.condition.broadcast(shared.io);
            return true;
        }

        /// Wait for the next valid delivery.
        pub fn next_event(self: Self) Io.Cancelable!Event {
            const shared = self.shared;
            shared.mutex.lockUncancelable(shared.io);
            defer shared.mutex.unlock(shared.io);
            while (shared.events.items.len == 0) {
                try shared.condition.wait(shared.io, &shared.mutex);
            }
            return shared.events.orderedRemove(0);
        }

        /// The next valid delivery, if one was recorded.
        pub fn try_event(self: Self) ?Event {
            const shared = self.shared;
            shared.mutex.lockUncancelable(shared.io);
            defer shared.mutex.unlock(shared.io);
            if (shared.events.items.len == 0) return null;
            return shared.events.orderedRemove(0);
        }

        fn find(items: []const Expected, key: K) ?usize {
            for (items, 0..) |item, index| {
                if (resolver.eql(K, item.key, key)) return index;
            }
            return null;
        }
    };
}
