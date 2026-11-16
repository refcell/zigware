//! Commitments this node certified (commonware `marshal/core/certified.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const utils = @import("utils");
const Height = @import("../../types.zig").Height;

/// Commitments of proposals this node certified, and ancestors of them, indexed by height.
///
/// A certified block arrives bound to its commitment, and its certification, by this node or by
/// the honest validators consensus required, checked its embedded parent commitment against a
/// root-bound parent. So recording a certified block also records its parent, and a block
/// fetched under this knowledge extends it to that block's parent. Entries at or below the
/// finalized tip are pruned and cannot be reinserted.
///
/// Entries sit in one array sorted by height, then commitment (commonware's
/// `BTreeMap<Height, BTreeSet<C>>`).
pub fn Certified(comptime C: type) type {
    return struct {
        const Self = @This();
        pub const Entry = struct { height: Height, commitment: C };

        entries: std.ArrayList(Entry),
        min: Height,

        pub const empty: Self = .{ .entries = .empty, .min = .new(1) };

        pub fn deinit(self: *Self, gpa: Allocator) void {
            self.entries.deinit(gpa);
            self.* = undefined;
        }

        fn order(a: Entry, b: Entry) std.math.Order {
            const by_height = a.height.order(b.height);
            if (by_height != .eq) return by_height;
            return utils.ordered.order(C, a.commitment, b.commitment);
        }

        /// The index of the first entry not below `entry`, and whether it equals `entry`.
        fn search(self: *const Self, entry: Entry) struct { usize, bool } {
            var low: usize = 0;
            var high: usize = self.entries.items.len;
            while (low < high) {
                const middle = low + (high - low) / 2;
                switch (order(self.entries.items[middle], entry)) {
                    .lt => low = middle + 1,
                    .gt => high = middle,
                    .eq => return .{ middle, true },
                }
            }
            return .{ low, false };
        }

        /// Records `commitment` at `height` as certified unless below the retention minimum.
        pub fn insert(self: *Self, gpa: Allocator, height: Height, commitment: C) !void {
            if (height.get() < self.min.get()) return;
            const entry: Entry = .{ .height = height, .commitment = commitment };
            const index, const found = self.search(entry);
            if (found) return;
            try self.entries.insert(gpa, index, entry);
            assert(self.contains(height, commitment));
        }

        /// Whether `commitment` at `height` is known certified.
        pub fn contains(self: *const Self, height: Height, commitment: C) bool {
            return self.search(.{ .height = height, .commitment = commitment })[1];
        }

        /// The certified commitments at `height`.
        pub fn at(self: *const Self, height: Height) []const Entry {
            var start: usize = 0;
            while (start < self.entries.items.len) : (start += 1) {
                if (self.entries.items[start].height.get() >= height.get()) break;
            }
            var end = start;
            while (end < self.entries.items.len) : (end += 1) {
                if (self.entries.items[end].height.get() != height.get()) break;
            }
            return self.entries.items[start..end];
        }

        /// Retains entries at or above `min` and rejects future inserts below it. The
        /// retention minimum never decreases.
        pub fn retain(self: *Self, min: Height) void {
            if (min.get() <= self.min.get()) return;
            self.min = min;
            var count: usize = 0;
            for (self.entries.items) |entry| {
                if (entry.height.get() >= min.get()) break;
                count += 1;
            }
            const all = self.entries.items;
            std.mem.copyForwards(Entry, all[0 .. all.len - count], all[count..]);
            self.entries.shrinkRetainingCapacity(all.len - count);
            assert(self.entries.items.len == 0 or self.entries.items[0].height.get() >= min.get());
        }
    };
}

const testing = std.testing;
const Sha256 = @import("cryptography").Sha256;

test "contains is height scoped and retain keeps from min" {
    const gpa = testing.allocator;
    var certified: Certified(Sha256.Digest) = .empty;
    defer certified.deinit(gpa);
    const a = Sha256.hash(&.{"a"});
    const b = Sha256.hash(&.{"b"});
    const c = Sha256.hash(&.{"c"});
    try certified.insert(gpa, .new(5), a);
    try certified.insert(gpa, .new(6), c);
    try certified.insert(gpa, .new(7), b);

    try testing.expect(certified.contains(.new(5), a));
    try testing.expect(!certified.contains(.new(6), a));
    try testing.expect(!certified.contains(.new(5), b));

    certified.retain(.new(6));
    try testing.expect(!certified.contains(.new(5), a));
    try testing.expect(certified.contains(.new(6), c));
    try testing.expect(certified.contains(.new(7), b));

    // Late inserts cannot restore pruned heights, even after a stale retain.
    certified.retain(.new(4));
    try certified.insert(gpa, .new(5), a);
    try certified.insert(gpa, .new(6), a);
    try testing.expect(!certified.contains(.new(5), a));
    try testing.expect(certified.contains(.new(6), a));
    try testing.expectEqual(2, certified.at(.new(6)).len);

    var genesis: Certified(Sha256.Digest) = .empty;
    defer genesis.deinit(gpa);
    try genesis.insert(gpa, .zero(), a);
    try testing.expect(!genesis.contains(.zero(), a));
}
