//! Track retained subscribers for keyed resolver demand (commonware
//! `resolver/src/subscribers.rs`).
//!
//! Resolver implementations commonly coalesce many local subscribers behind one peer-visible
//! key. This module owns the subscriber set bookkeeping while the resolver decides how keys
//! are fetched, retried, and delivered.
//!
//! Keys and each key's subscribers are kept in ascending order (commonware's nested
//! `BTreeMap`), as sorted arrays searched by bisection. Each subscriber keeps the span of its
//! first fetch (an owned root copy, `resolver.own_span`), as commonware's `or_insert` does.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const resolver = @import("root.zig");
const Span = resolver.Span;

/// Tracks retained subscribers by resolver key.
pub fn Tracker(comptime K: type, comptime S: type) type {
    return struct {
        const Self = @This();

        const Entry = struct {
            key: K,
            /// Strictly ascending, never empty.
            subscribers: std.ArrayList(S),
            /// One per subscriber, in the same order: its first fetch's span (owned).
            spans: std.ArrayList(?*Span),

            fn deinit(entry: *Entry, gpa: Allocator) void {
                resolver.free_spans(gpa, entry.spans.items);
                entry.spans.deinit(gpa);
                entry.subscribers.deinit(gpa);
            }
        };

        /// Strictly ascending by key.
        entries: std.ArrayList(Entry) = .empty,

        pub const empty: Self = .{};

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.clear(gpa);
            self.entries.deinit(gpa);
            self.* = undefined;
        }

        /// The number of tracked keys.
        pub fn count(self: *const Self) usize {
            return self.entries.items.len;
        }

        /// Returns true if any subscriber is retained for the key.
        pub fn contains(self: *const Self, key: K) bool {
            return self.find(key).found;
        }

        /// Add subscribers for a key (duplicates merge). Returns true if this created a new
        /// key entry.
        pub fn insert(self: *Self, gpa: Allocator, key: K, added: []const S) Allocator.Error!bool {
            return self.insert_spanned(gpa, key, added, null);
        }

        /// `insert` with each added subscriber's span (`spans`, owned, one per subscriber, or
        /// null for none). A new subscriber takes its span, leaving null in `spans`; an
        /// existing one keeps its first span, and the caller still owns the duplicate's.
        pub fn insert_spanned(
            self: *Self,
            gpa: Allocator,
            key: K,
            added: []const S,
            spans: ?[]?*Span,
        ) Allocator.Error!bool {
            assert(added.len > 0);
            if (spans) |items| assert(items.len == added.len);
            const position = self.find(key);
            if (!position.found) {
                const entry: Entry = .{ .key = key, .subscribers = .empty, .spans = .empty };
                try self.entries.insert(gpa, position.index, entry);
            }
            const entry = &self.entries.items[position.index];
            for (added, 0..) |subscriber, index| {
                const slot = find_subscriber(entry.subscribers.items, subscriber);
                if (slot.found) continue;
                insert_subscriber(gpa, entry, slot.index, subscriber) catch |err| {
                    // Never leave an empty entry behind.
                    if (entry.subscribers.items.len == 0) self.remove_at(gpa, position.index);
                    return err;
                };
                if (spans) |items| {
                    entry.spans.items[slot.index] = items[index];
                    items[index] = null;
                }
            }
            assert(entry.subscribers.items.len > 0);
            assert(entry.spans.items.len == entry.subscribers.items.len);
            return !position.found;
        }

        fn insert_subscriber(gpa: Allocator, entry: *Entry, index: usize, subscriber: S) !void {
            try entry.spans.ensureUnusedCapacity(gpa, 1);
            try entry.subscribers.insert(gpa, index, subscriber);
            entry.spans.insertAssumeCapacity(index, null);
            assert(entry.spans.items.len == entry.subscribers.items.len);
        }

        /// Remove all subscribers for a key. Returns true if the key was present.
        pub fn remove(self: *Self, gpa: Allocator, key: K) bool {
            const position = self.find(key);
            if (!position.found) return false;
            self.remove_at(gpa, position.index);
            assert(!self.contains(key));
            return true;
        }

        /// Remove every tracked key.
        pub fn clear(self: *Self, gpa: Allocator) void {
            for (self.entries.items) |*entry| entry.deinit(gpa);
            self.entries.clearRetainingCapacity();
            assert(self.entries.items.len == 0);
        }

        /// Retain only subscribers for which `predicate.call(key, subscriber)` returns true.
        /// Appends the keys whose subscriber sets became empty (and were removed), ascending.
        pub fn retain(
            self: *Self,
            gpa: Allocator,
            predicate: anytype,
            removed: *std.ArrayList(K),
        ) Allocator.Error!void {
            // Reserve first so the walk below cannot fail halfway.
            try removed.ensureUnusedCapacity(gpa, self.entries.items.len);
            var kept: usize = 0;
            for (self.entries.items) |*entry| {
                var kept_subscribers: usize = 0;
                for (entry.subscribers.items, entry.spans.items) |subscriber, span| {
                    if (!predicate.call(entry.key, subscriber)) {
                        resolver.free_span(gpa, span);
                        continue;
                    }
                    entry.subscribers.items[kept_subscribers] = subscriber;
                    entry.spans.items[kept_subscribers] = span;
                    kept_subscribers += 1;
                }
                entry.subscribers.shrinkRetainingCapacity(kept_subscribers);
                entry.spans.shrinkRetainingCapacity(kept_subscribers);
                if (kept_subscribers == 0) {
                    removed.appendAssumeCapacity(entry.key);
                    entry.deinit(gpa);
                    continue;
                }
                self.entries.items[kept] = entry.*;
                kept += 1;
            }
            self.entries.shrinkRetainingCapacity(kept);
            assert(self.entries.items.len == kept);
        }

        /// The subscribers waiting on a key, ascending, or null if the key is not tracked.
        /// The slice is borrowed and valid until the tracker next changes.
        pub fn pending(self: *const Self, key: K) ?[]const S {
            const position = self.find(key);
            if (!position.found) return null;
            const result = self.entries.items[position.index].subscribers.items;
            assert(result.len > 0);
            return result;
        }

        /// The spans of `pending(key)`'s subscribers, in the same order (borrowed, as
        /// `pending`), or null if the key is not tracked.
        pub fn pending_spans(self: *const Self, key: K) ?[]const ?*Span {
            const position = self.find(key);
            if (!position.found) return null;
            const entry = &self.entries.items[position.index];
            assert(entry.spans.items.len == entry.subscribers.items.len);
            return entry.spans.items;
        }

        /// Remove subscribers whose delivery has completed. Returns the remaining subscribers
        /// for the key (borrowed, as `pending`), or null if the key is now complete or was not
        /// tracked.
        pub fn remove_delivered(
            self: *Self,
            gpa: Allocator,
            key: K,
            delivered: []const S,
        ) ?[]const S {
            assert(delivered.len > 0);
            const position = self.find(key);
            if (!position.found) return null;
            const entry = &self.entries.items[position.index];
            for (delivered) |subscriber| {
                const slot = find_subscriber(entry.subscribers.items, subscriber);
                if (!slot.found) continue;
                _ = entry.subscribers.orderedRemove(slot.index);
                resolver.free_span(gpa, entry.spans.orderedRemove(slot.index));
            }
            if (entry.subscribers.items.len == 0) {
                self.remove_at(gpa, position.index);
                return null;
            }
            return entry.subscribers.items;
        }

        fn remove_at(self: *Self, gpa: Allocator, index: usize) void {
            assert(index < self.entries.items.len);
            var entry = self.entries.orderedRemove(index);
            entry.deinit(gpa);
        }

        const Position = struct { index: usize, found: bool };

        fn find(self: *const Self, key: K) Position {
            const index = std.sort.lowerBound(Entry, self.entries.items, key, compare_key);
            const found = index < self.entries.items.len and
                resolver.eql(K, self.entries.items[index].key, key);
            return .{ .index = index, .found = found };
        }

        fn compare_key(key: K, entry: Entry) std.math.Order {
            return resolver.order(K, key, entry.key);
        }

        fn find_subscriber(items: []const S, subscriber: S) Position {
            const index = std.sort.lowerBound(S, items, subscriber, compare_subscriber);
            const found = index < items.len and resolver.eql(S, items[index], subscriber);
            return .{ .index = index, .found = found };
        }

        fn compare_subscriber(subscriber: S, item: S) std.math.Order {
            return resolver.order(S, subscriber, item);
        }
    };
}

const testing = std.testing;

const EvenSubscribers = struct {
    pub fn call(_: EvenSubscribers, _: i32, subscriber: i32) bool {
        return @rem(subscriber, 2) == 0;
    }
};

test "insert merges and deduplicates subscribers" {
    const gpa = testing.allocator;
    var tracker: Tracker(i32, i32) = .empty;
    defer tracker.deinit(gpa);
    try testing.expect(try tracker.insert(gpa, 1, &.{ 10, 11 }));
    try testing.expect(!try tracker.insert(gpa, 1, &.{ 11, 12 }));
    try testing.expectEqualSlices(i32, &.{ 10, 11, 12 }, tracker.pending(1).?);
}

test "retain prunes subscribers and reports removed keys" {
    const gpa = testing.allocator;
    var tracker: Tracker(i32, i32) = .empty;
    defer tracker.deinit(gpa);
    _ = try tracker.insert(gpa, 1, &.{11});
    _ = try tracker.insert(gpa, 2, &.{ 20, 21 });
    var removed: std.ArrayList(i32) = .empty;
    defer removed.deinit(gpa);
    try tracker.retain(gpa, EvenSubscribers{}, &removed);
    try testing.expectEqualSlices(i32, &.{1}, removed.items);
    try testing.expect(!tracker.contains(1));
    try testing.expectEqualSlices(i32, &.{20}, tracker.pending(2).?);
}

test "remove delivered returns remaining subscribers" {
    const gpa = testing.allocator;
    var tracker: Tracker(i32, i32) = .empty;
    defer tracker.deinit(gpa);
    _ = try tracker.insert(gpa, 1, &.{ 10, 11, 12 });
    const remaining = tracker.remove_delivered(gpa, 1, &.{ 10, 12 });
    try testing.expectEqualSlices(i32, &.{11}, remaining.?);
    try testing.expect(tracker.contains(1));
}

test "remove delivered removes completed key" {
    const gpa = testing.allocator;
    var tracker: Tracker(i32, i32) = .empty;
    defer tracker.deinit(gpa);
    _ = try tracker.insert(gpa, 1, &.{ 10, 11 });
    try testing.expect(tracker.remove_delivered(gpa, 1, &.{ 10, 11 }) == null);
    try testing.expect(!tracker.contains(1));
    try testing.expect(tracker.pending(2) == null);
    try testing.expect(!tracker.remove(gpa, 1));
}

test "unit subscribers coalesce" {
    const gpa = testing.allocator;
    var tracker: Tracker(u8, void) = .empty;
    defer tracker.deinit(gpa);
    try testing.expect(try tracker.insert(gpa, 3, &.{ {}, {} }));
    try testing.expectEqual(@as(usize, 1), tracker.pending(3).?.len);
    try testing.expect(tracker.remove_delivered(gpa, 3, &.{{}}) == null);
}

/// Model check against a naive map of sets over a random operation sequence.
fn tracker_model(_: void, smith: *std.testing.Smith) anyerror!void {
    const gpa = testing.allocator;
    var tracker: Tracker(u8, u8) = .empty;
    defer tracker.deinit(gpa);
    var model: [8]u16 = @splat(0); // key -> subscriber bitset (subscribers 0..15)
    var removed: std.ArrayList(u8) = .empty;
    defer removed.deinit(gpa);
    // Operations come from raw bytes: `Smith.value` maps a random 8-byte word outside the
    // type's range to its minimum and `Smith.eos` ends random input almost at once, so the
    // seeded driver would otherwise replay one operation.
    var raw: [3 * 64]u8 = undefined;
    smith.bytes(&raw);
    for (0..raw.len / 3) |step| {
        const key = raw[3 * step] % 8;
        const subscriber = raw[3 * step + 1] % 16;
        const bit = @as(u16, 1) << @intCast(subscriber);
        switch (raw[3 * step + 2] % 4) {
            0 => {
                const created = try tracker.insert(gpa, key, &.{subscriber});
                try testing.expectEqual(model[key] == 0, created);
                model[key] |= bit;
            },
            1 => {
                try testing.expectEqual(model[key] != 0, tracker.remove(gpa, key));
                model[key] = 0;
            },
            2 => {
                const was_tracked = model[key] != 0;
                const remaining = tracker.remove_delivered(gpa, key, &.{subscriber});
                if (was_tracked) model[key] &= ~bit;
                try testing.expectEqual(model[key] != 0, remaining != null);
            },
            else => {
                removed.clearRetainingCapacity();
                const Keep = struct {
                    floor: u8,
                    pub fn call(self: @This(), _: u8, item: u8) bool {
                        return item >= self.floor;
                    }
                };
                try tracker.retain(gpa, Keep{ .floor = subscriber }, &removed);
                const mask = ~((@as(u16, 1) << @intCast(subscriber)) -% 1);
                for (&model, 0..) |*set, index| {
                    const emptied = set.* != 0 and set.* & mask == 0;
                    const reported = std.mem.indexOfScalar(u8, removed.items, @intCast(index));
                    try testing.expectEqual(emptied, reported != null);
                    set.* &= mask;
                }
            },
        }
        try expect_matches(&tracker, &model);
    }
}

fn expect_matches(tracker: *const Tracker(u8, u8), model: *const [8]u16) !void {
    var tracked: usize = 0;
    for (model, 0..) |set, key| {
        const pending = tracker.pending(@intCast(key)) orelse {
            try testing.expectEqual(@as(u16, 0), set);
            continue;
        };
        tracked += 1;
        var bits: u16 = 0;
        for (pending, 0..) |subscriber, index| {
            if (index > 0) try testing.expect(pending[index - 1] < subscriber);
            bits |= @as(u16, 1) << @intCast(subscriber);
        }
        try testing.expectEqual(set, bits);
    }
    try testing.expectEqual(tracked, tracker.count());
}

test "fuzz: subscriber tracker matches a model" {
    const p2p = @import("p2p");
    try p2p.fuzz.run({}, tracker_model, 0x7375627363726962, 500);
}

test "each subscriber keeps its own fetch span" {
    const gpa = testing.allocator;
    const traces = @import("runtime").telemetry.traces;
    const tracer = traces.Tracer.none;
    var first = tracer.span("test.first_fetch", .{});
    var second = tracer.span("test.second_fetch", .{});
    var tracker: Tracker(i32, i32) = .empty;
    defer tracker.deinit(gpa);
    var first_spans = [_]?*Span{try resolver.own_span(gpa, &first)};
    defer resolver.free_spans(gpa, &first_spans);
    try testing.expect(try tracker.insert_spanned(gpa, 1, &.{10}, &first_spans));
    // The second fetch joins subscriber 11 under its own span and re-requests 10, which
    // keeps its original span.
    var second_spans = [_]?*Span{
        try resolver.own_span(gpa, &second),
        try resolver.own_span(gpa, &second),
    };
    defer resolver.free_spans(gpa, &second_spans);
    try testing.expect(!try tracker.insert_spanned(gpa, 1, &.{ 10, 11 }, &second_spans));
    // The duplicate's span stays with the caller; the new subscriber's moved.
    try testing.expect(second_spans[0] != null and second_spans[1] == null);

    try testing.expectEqualSlices(i32, &.{ 10, 11 }, tracker.pending(1).?);
    const spans = tracker.pending_spans(1).?;
    try testing.expectEqualStrings("test.first_fetch", spans[0].?.name);
    try testing.expectEqualStrings("test.second_fetch", spans[1].?.name);
    try testing.expect(tracker.pending_spans(2) == null);
}
