//! The tip at least one honest validator has reached (commonware `aggregation/safe_tip.rs`).
//!
//! Tracks each validator's highest reported tip and answers the `f`th highest one, where `f`
//! is the most faults the set tolerates (`N3f1`). The `f` highest tips (`hi`) may all come
//! from faulty validators; the highest of the remaining `n - f` (`lo`) was reported by at
//! least one honest validator.
//!
//! Storage is fixed at `init`: validators sit in key order with their tips, and `hi`/`lo` are
//! sorted (height, count) arrays (commonware's `BTreeMap<Height, usize>`), so updates never
//! allocate.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const utils = @import("utils");
const Height = @import("../types.zig").Height;

/// A multiset of heights: a sorted array of distinct heights with their counts.
pub const Counts = struct {
    entries: []Entry = &.{},
    len: usize = 0,

    pub const Entry = struct { height: Height, count: u32 };

    pub fn init(gpa: Allocator, capacity: usize) Allocator.Error!Counts {
        assert(capacity > 0);
        return .{ .entries = try gpa.alloc(Entry, capacity) };
    }

    pub fn deinit(self: *Counts, gpa: Allocator) void {
        gpa.free(self.entries);
        self.* = undefined;
    }

    fn items(self: *const Counts) []const Entry {
        return self.entries[0..self.len];
    }

    /// The position of `height`, or where it would be inserted.
    fn search(self: *const Counts, height: Height) struct { usize, bool } {
        var low: usize = 0;
        var high: usize = self.len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            switch (Height.order(self.entries[middle].height, height)) {
                .lt => low = middle + 1,
                .gt => high = middle,
                .eq => return .{ middle, true },
            }
        }
        return .{ low, false };
    }

    /// The number of validators at `height`, or null when none are.
    pub fn get(self: *const Counts, height: Height) ?u32 {
        const position, const found = self.search(height);
        return if (found) self.entries[position].count else null;
    }

    pub fn contains(self: *const Counts, height: Height) bool {
        return self.get(height) != null;
    }

    /// The number of distinct heights.
    pub fn count(self: *const Counts) usize {
        return self.len;
    }

    pub fn min(self: *const Counts) ?Height {
        return if (self.len == 0) null else self.entries[0].height;
    }

    pub fn max(self: *const Counts) ?Height {
        return if (self.len == 0) null else self.entries[self.len - 1].height;
    }

    /// Adds one validator at `height`.
    pub fn inc(self: *Counts, height: Height) void {
        const position, const found = self.search(height);
        if (found) {
            self.entries[position].count += 1;
            return;
        }
        assert(self.len < self.entries.len);
        std.mem.copyBackwards(
            Entry,
            self.entries[position + 1 .. self.len + 1],
            self.entries[position..self.len],
        );
        self.entries[position] = .{ .height = height, .count = 1 };
        self.len += 1;
    }

    /// Removes one validator at `height`, dropping the height at zero. Panics when no
    /// validator is at `height`.
    pub fn dec(self: *Counts, height: Height) void {
        const position, const found = self.search(height);
        if (!found) @panic("Cannot decrement a non-existent entry");
        assert(self.entries[position].count > 0);
        self.entries[position].count -= 1;
        if (self.entries[position].count > 0) return;
        std.mem.copyForwards(
            Entry,
            self.entries[position .. self.len - 1],
            self.entries[position + 1 .. self.len],
        );
        self.len -= 1;
    }

    pub fn eql(a: *const Counts, b: *const Counts) bool {
        if (a.len != b.len) return false;
        for (a.items(), b.items()) |left, right| {
            if (left.height != right.height or left.count != right.count) return false;
        }
        return true;
    }
};

/// Each validator's highest reported tip, and the `f`th highest of them.
pub fn SafeTip(comptime P: type) type {
    return struct {
        const Self = @This();
        const Set = utils.ordered.Set(P);

        /// Validators in key order; `tips[i]` is `keys[i]`'s highest tip.
        keys: []P = &.{},
        tips: []Height = &.{},
        /// Scratch for `reconcile`, the same length as `keys`.
        keys_next: []P = &.{},
        tips_next: []Height = &.{},
        /// The `f` highest tips.
        hi: Counts = .{},
        /// The `n - f` lowest tips; its maximum is the safe tip.
        lo: Counts = .{},

        pub const empty: Self = .{};

        /// Starts every validator of `validators` at height zero. Panics when the set is
        /// empty.
        pub fn init(self: *Self, gpa: Allocator, validators: *const Set) Allocator.Error!void {
            assert(self.keys.len == 0);
            const n = validators.len();
            if (n == 0) @panic("empty validator set");
            const f = validators.max_faults(utils.N3f1);
            assert(f < n);
            self.keys = try gpa.dupe(P, validators.items);
            self.tips = try gpa.alloc(Height, n);
            @memset(self.tips, .zero());
            self.keys_next = try gpa.alloc(P, n);
            self.tips_next = try gpa.alloc(Height, n);
            self.hi = try .init(gpa, n);
            self.lo = try .init(gpa, n);
            self.lo.inc(.zero());
            self.lo.entries[0].count = @intCast(n - f);
            if (f > 0) {
                self.hi.inc(.zero());
                self.hi.entries[0].count = f;
            }
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            if (self.keys.len > 0) {
                gpa.free(self.keys);
                gpa.free(self.tips);
                gpa.free(self.keys_next);
                gpa.free(self.tips_next);
                self.hi.deinit(gpa);
                self.lo.deinit(gpa);
            }
            self.* = undefined;
        }

        fn position(keys: []const P, key: P) ?usize {
            var low: usize = 0;
            var high: usize = keys.len;
            while (low < high) {
                const middle = low + (high - low) / 2;
                switch (utils.ordered.order(P, keys[middle], key)) {
                    .lt => low = middle + 1,
                    .gt => high = middle,
                    .eq => return middle,
                }
            }
            return null;
        }

        /// `key`'s highest reported tip, or null when `key` is not a validator.
        pub fn tip(self: *const Self, key: P) ?Height {
            const index = position(self.keys, key) orelse return null;
            return self.tips[index];
        }

        /// Replaces the validator set with one of the same size: leaving validators' tips
        /// drop to zero, and joining validators start at zero. Panics when the size differs.
        pub fn reconcile(self: *Self, validators: *const Set) void {
            if (validators.len() != self.keys.len) @panic("Validator set size mismatch");
            for (self.keys, self.tips) |key, old| {
                if (validators.position(key) == null) self.remove(old);
            }
            for (validators.items, self.keys_next, self.tips_next) |key, *next_key, *next_tip| {
                next_key.* = key;
                next_tip.* = self.tip(key) orelse .zero();
            }
            std.mem.swap([]P, &self.keys, &self.keys_next);
            std.mem.swap([]Height, &self.tips, &self.tips_next);
            assert(self.keys.len == validators.len());
        }

        /// Moves a leaving validator's tip `old` to zero in the heaps.
        fn remove(self: *Self, old: Height) void {
            const new: Height = .zero();
            // Case 1: the tip was already zero.
            if (old == new) return;
            // Case 2: the value can stay in `lo`.
            if (self.lo.contains(old)) {
                self.lo.dec(old);
                self.lo.inc(new);
                return;
            }
            // Case 3: every `lo` value is at most the new value, so it can stay in `hi`.
            const stay_in_hi = if (self.lo.max()) |max_lo| max_lo.get() <= new.get() else true;
            if (stay_in_hi) {
                self.hi.dec(old);
                self.hi.inc(new);
                return;
            }
            // Case 4: move it to `lo`, and the largest `lo` value up to `hi`.
            self.hi.dec(old);
            self.lo.inc(new);
            const max_lo = self.lo.max().?;
            assert(max_lo.get() > new.get());
            self.lo.dec(max_lo);
            self.hi.inc(max_lo);
        }

        /// Raises `key`'s tip to `new`. Returns the old tip, or null when `key` is not a
        /// validator or `new` is not higher.
        pub fn update(self: *Self, key: P, new: Height) ?Height {
            const index = position(self.keys, key) orelse return null;
            const old = self.tips[index];
            if (old.get() >= new.get()) return null;
            self.tips[index] = new;
            // Case 1: the value can stay in `hi`.
            if (self.hi.contains(old)) {
                self.hi.dec(old);
                self.hi.inc(new);
                return old;
            }
            // Case 2: every `hi` value is at least the new value, so it can stay in `lo`.
            const stay_in_lo = if (self.hi.min()) |min_hi| min_hi.get() >= new.get() else true;
            if (stay_in_lo) {
                self.lo.dec(old);
                self.lo.inc(new);
                return old;
            }
            // Case 3: move it to `hi`, and the smallest `hi` value down to `lo`.
            self.lo.dec(old);
            self.hi.inc(new);
            const min_hi = self.hi.min().?;
            assert(min_hi.get() < new.get());
            self.hi.dec(min_hi);
            self.lo.inc(min_hi);
            return old;
        }

        /// The `f`th highest tip. Panics before `init`.
        pub fn get(self: *const Self) Height {
            return self.lo.max() orelse @panic("Empty validator set");
        }
    };
}

test {
    _ = @import("safe_tip_test.zig");
}
