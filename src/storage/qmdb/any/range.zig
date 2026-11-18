//! Ordered range scans of an `any` database (commonware's ordered `stream_range` and `keys`).
//!
//! `Range(D)` walks the active keys of an ordered database in ascending order within a range,
//! one translated-key bucket at a time: it reads the bucket's updates, emits those in range in
//! key order, and moves to the bucket of the largest key's successor until the links wrap or
//! pass the range's end. Zig has no async streams, so it is a pull iterator: `next` returns the
//! next pair (the caller owns the value) or null at the end. A read error leaves the cursor
//! where it was, so the next call reads the same bucket again.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("codec");
const value_mod = @import("../value.zig");
const diff_mod = @import("diff.zig");

/// A bound of a key range (Rust's `Bound`).
pub fn Bound(comptime K: type) type {
    return union(enum) { included: K, excluded: K, unbounded };
}

pub fn Range(comptime D: type) type {
    return struct {
        const Self = @This();
        const K = D.Key;
        const V = D.Value;
        pub const Pair = struct { key: K, value: V };
        const Cursor = union(enum) { start, next: K, done };

        db: *D,
        start: Bound(K),
        end: Bound(K),
        cursor: Cursor,
        /// The current bucket's pairs in range, in descending key order (popped from the end).
        pending: std.ArrayList(D.Update) = .empty,

        pub fn init(db: *D, start: Bound(K), end: Bound(K)) Self {
            comptime assert(D.Update.siblings);
            const empty = switch (start) {
                .unbounded => false,
                .included => |*s| switch (end) {
                    .included => |*e| order(s, e) == .gt,
                    .excluded => |*e| order(s, e) != .lt,
                    .unbounded => false,
                },
                .excluded => |*s| switch (end) {
                    .included, .excluded => |*e| order(s, e) != .lt,
                    .unbounded => false,
                },
            };
            const cursor: Cursor = if (empty) .done else .start;
            return .{ .db = db, .start = start, .end = end, .cursor = cursor };
        }

        pub fn deinit(self: *Self) void {
            for (self.pending.items) |*update| update.deinit(self.db.gpa);
            self.pending.deinit(self.db.gpa);
            self.* = undefined;
        }

        fn order(a: *const K, b: *const K) std.math.Order {
            return diff_mod.order(K, a, b);
        }

        fn past_end(self: *const Self, key: *const K) bool {
            return switch (self.end) {
                .included => |*e| order(key, e) == .gt,
                .excluded => |*e| order(key, e) != .lt,
                .unbounded => false,
            };
        }

        fn before_start(self: *const Self, key: *const K) bool {
            return switch (self.start) {
                .included => |*s| order(key, s) == .lt,
                .excluded => |*s| order(key, s) != .gt,
                .unbounded => false,
            };
        }

        /// The next active pair in range, ascending; the caller owns its value.
        pub fn next(self: *Self) !?Pair {
            while (true) {
                if (self.pending.pop()) |update| {
                    return .{ .key = update.key, .value = update.value };
                }
                if (!try self.fetch()) return null;
            }
        }

        /// The next active key in range, ascending (commonware's `keys`).
        pub fn next_key(self: *Self) !?K {
            const pair = try self.next() orelse return null;
            codec.free(V, self.db.gpa, pair.value);
            return pair.key;
        }

        /// Reads the cursor's bucket into `pending` and advances the cursor; false at the end.
        fn fetch(self: *Self) !bool {
            assert(self.pending.items.len == 0);
            const snapshot = &self.db.snapshot;
            switch (self.cursor) {
                .done => return false,
                .next => |*key| {
                    var values = snapshot.get(value_mod.bytes(K, key));
                    try self.read_bucket(&values);
                },
                .start => switch (self.start) {
                    .unbounded => {
                        var values = snapshot.first_translated_key() orelse return false;
                        try self.read_bucket(&values);
                    },
                    .included, .excluded => |*bound| {
                        // The bound's own bucket may hold keys below it; when no active key
                        // shares its translated key, the following bucket starts.
                        const bytes = value_mod.bytes(K, bound);
                        var own = snapshot.get(bytes);
                        if (own.count() > 0) {
                            try self.read_bucket(&own);
                        } else {
                            const neighbor = snapshot.next_translated_key(bytes) orelse
                                return false;
                            if (neighbor.cycled) return false;
                            var values = neighbor.values;
                            try self.read_bucket(&values);
                        }
                    },
                },
            }
            self.advance();
            return true;
        }

        /// Reads every update of a bucket into `pending`, sorted by descending key.
        fn read_bucket(self: *Self, values: anytype) !void {
            const gpa = self.db.gpa;
            errdefer {
                for (self.pending.items) |*update| update.deinit(gpa);
                self.pending.clearRetainingCapacity();
            }
            while (values.next()) |loc| {
                try self.pending.ensureUnusedCapacity(gpa, 1);
                self.pending.appendAssumeCapacity(try self.db.read_update(loc.*));
            }
            if (self.pending.items.len == 0) return error.DataCorrupted; // Buckets are non-empty.
            std.mem.sort(D.Update, self.pending.items, {}, greater);
        }

        fn greater(_: void, a: D.Update, b: D.Update) bool {
            return diff_mod.order(K, &a.key, &b.key) == .gt;
        }

        /// Moves the cursor past the bucket in `pending` (its largest key's successor) and drops
        /// the pairs outside the range.
        fn advance(self: *Self) void {
            const gpa = self.db.gpa;
            const last = self.pending.items[0];
            const wraps = order(&last.next_key, &last.key) != .gt;
            const ends = wraps or self.past_end(&last.next_key);
            self.cursor = if (ends) .done else .{ .next = last.next_key };
            var kept: usize = 0;
            for (self.pending.items) |*update| {
                if (self.before_start(&update.key) or self.past_end(&update.key)) {
                    update.deinit(gpa);
                    continue;
                }
                self.pending.items[kept] = update.*;
                kept += 1;
            }
            self.pending.shrinkRetainingCapacity(kept);
            assert(kept <= self.pending.capacity);
        }
    };
}
