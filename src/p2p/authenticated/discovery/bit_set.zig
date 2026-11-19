//! The primary peers of one peer set, sorted, with one knowledge bit per peer: set when we
//! hold the peer's address (commonware
//! `p2p/src/authenticated/discovery/actors/tracker/bit_set.rs`).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const types = @import("types.zig");

const BitMap = types.BitMap;

pub fn BitSet(comptime P: type) type {
    return struct {
        const Self = @This();

        /// Sorted and deduplicated; owned.
        ordered: []P,
        /// Bit `i` is set when we know the address of `ordered[i]`.
        knowledge: BitMap,

        /// Takes ownership of `ordered`, which must be sorted and deduplicated.
        pub fn init(gpa: Allocator, ordered: []P) Allocator.Error!Self {
            for (ordered[0..ordered.len -| 1], 0..) |peer, index| {
                assert(P.order(peer, ordered[index + 1]) == .lt);
            }
            const knowledge = try BitMap.zeroes(gpa, ordered.len);
            assert(knowledge.len() == ordered.len);
            return .{ .ordered = ordered, .knowledge = knowledge };
        }

        pub fn deinit(set: *Self, gpa: Allocator) void {
            gpa.free(set.ordered);
            set.knowledge.deinit(gpa);
            set.* = undefined;
        }

        pub fn len(set: *const Self) usize {
            return set.ordered.len;
        }

        /// The index of `peer`, if present.
        pub fn position(set: *const Self, peer: P) ?usize {
            var low: usize = 0;
            var high: usize = set.ordered.len;
            while (low < high) {
                const middle = low + (high - low) / 2;
                switch (P.order(set.ordered[middle], peer)) {
                    .eq => return middle,
                    .lt => low = middle + 1,
                    .gt => high = middle,
                }
            }
            return null;
        }

        /// Marks `peer` known or unknown. Returns whether it is in the set.
        pub fn update(set: *Self, peer: P, known: bool) bool {
            const index = set.position(peer) orelse return false;
            set.knowledge.set(index, known);
            return true;
        }

        /// Like `update`, for the peer at `index`.
        pub fn update_at(set: *Self, index: usize, known: bool) bool {
            if (index >= set.ordered.len) return false;
            set.knowledge.set(index, known);
            return true;
        }

        /// A copy of the knowledge bits, owned by the caller.
        pub fn copy_knowledge(set: *const Self, gpa: Allocator) Allocator.Error!BitMap {
            return set.knowledge.clone(gpa);
        }
    };
}

const testing = std.testing;
const cryptography = @import("cryptography");
const death = @import("utils").death;
const ed25519 = cryptography.ed25519;
const PublicKey = ed25519.PublicKey;

fn key(seed: u64) PublicKey {
    return ed25519.PrivateKey.from_seed(seed).public_key();
}

fn test_set() !BitSet(PublicKey) {
    // Seeds 1, 2, 3 sort as 1 < 2 < 3 (keys 478b.., 5925.., ec89..).
    const ordered = try testing.allocator.dupe(PublicKey, &.{ key(1), key(2), key(3) });
    std.sort.pdq(PublicKey, ordered, {}, PublicKey.less_than);
    return BitSet(PublicKey).init(testing.allocator, ordered);
}

fn expect_bits(set: *const BitSet(PublicKey), expected: []const bool) !void {
    try testing.expectEqual(@as(u64, expected.len), set.knowledge.len());
    for (expected, 0..) |bit, index| try testing.expectEqual(bit, set.knowledge.get(index));
}

test "initialization sorts peers and knows none" {
    var set = try test_set();
    defer set.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 3), set.len());
    for ([_]u64{ 1, 2, 3 }, 0..) |seed, index| {
        try testing.expect(set.ordered[index].eql(key(seed)));
        try testing.expectEqual(@as(?usize, index), set.position(key(seed)));
    }
    try expect_bits(&set, &.{ false, false, false });
}

test "update a single peer" {
    var set = try test_set();
    defer set.deinit(testing.allocator);
    try testing.expect(set.update(key(3), true));
    try expect_bits(&set, &.{ false, false, true });
    try testing.expect(set.update(key(3), true));
    try expect_bits(&set, &.{ false, false, true });
    try testing.expect(set.update(key(3), false));
    try expect_bits(&set, &.{ false, false, false });
    try testing.expect(!set.update(key(4), true));
    try expect_bits(&set, &.{ false, false, false });
}

test "update_at matches update by peer" {
    var set = try test_set();
    defer set.deinit(testing.allocator);
    try testing.expect(set.update_at(1, true));
    try expect_bits(&set, &.{ false, true, false });
    try testing.expect(set.update(key(2), false));
    try testing.expect(!set.update_at(10, true));
    try expect_bits(&set, &.{ false, false, false });
}

test "update multiple peers and copy knowledge" {
    var set = try test_set();
    defer set.deinit(testing.allocator);
    try testing.expect(set.update(key(2), true));
    try testing.expect(set.update(key(1), true));
    try testing.expect(set.update(key(3), true));
    try expect_bits(&set, &.{ true, true, true });
    try testing.expect(set.update(key(2), false));
    try expect_bits(&set, &.{ true, false, true });
    var copy = try set.copy_knowledge(testing.allocator);
    defer copy.deinit(testing.allocator);
    try testing.expect(copy.eql(&set.knowledge));
}

test "empty set" {
    const ordered = try testing.allocator.alloc(PublicKey, 0);
    var set = try BitSet(PublicKey).init(testing.allocator, ordered);
    defer set.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 0), set.len());
    try testing.expect(!set.update(key(1), true));
    try testing.expect(!set.update_at(0, true));
}

test "copied knowledge stays as it was after later updates" {
    var set = try test_set();
    defer set.deinit(testing.allocator);
    const gpa = testing.allocator;
    var before = try set.copy_knowledge(gpa);
    defer before.deinit(gpa);
    try testing.expect(set.update(key(2), true));
    var first = try set.copy_knowledge(gpa);
    defer first.deinit(gpa);
    try expect_bits(&set, &.{ false, true, false });
    try testing.expect(!before.eql(&first));
    try testing.expect(set.update(key(3), true));
    try expect_bits(&set, &.{ false, true, true });
    try testing.expect(!first.eql(&set.knowledge));
    // The first copy still knows nobody.
    for (0..3) |bit| try testing.expect(!before.get(bit));
}

test "a single peer set" {
    const ordered = try testing.allocator.dupe(PublicKey, &.{key(42)});
    var set = try BitSet(PublicKey).init(testing.allocator, ordered);
    defer set.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), set.len());
    try testing.expect(set.ordered[0].eql(key(42)));
    try testing.expectEqual(@as(?usize, 0), set.position(key(42)));
    try expect_bits(&set, &.{false});
    try testing.expect(set.update(key(42), true));
    try expect_bits(&set, &.{true});
    try testing.expect(set.update(key(42), false));
    try expect_bits(&set, &.{false});
}

test "indexing past the last peer panics (test_index_out_of_bounds_positive)" {
    try death.expect_panic(@src(), "index out of bounds", struct {
        fn body() !void {
            const ordered = try testing.allocator.dupe(PublicKey, &.{key(1)});
            var set = try BitSet(PublicKey).init(testing.allocator, ordered);
            defer set.deinit(testing.allocator);
            var index: usize = 1;
            _ = &index;
            _ = set.ordered[index];
        }
    }.body);
}
