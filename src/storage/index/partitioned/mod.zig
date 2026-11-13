//! Partitioned indices: the first `P` bytes of a key select one of `256^P` partitions and the
//! translator maps the rest (port of commonware's `storage/src/index/partitioned`).
//!
//! Partitions are ordered by prefix, so a partitioned index is a flat index over the composite
//! key `(partition, translated sub-key)`, which `Translator(T, P)` produces. The unordered
//! variant is exactly `index.unordered.Index` over it. The ordered variant keeps commonware's
//! partitioned semantics, which differ from the flat ordered index: a key's values iterate in
//! insertion order (see `ordered.zig`). Commonware stores each partition as a sorted array that
//! spills to a `BTreeMap`; here every partition shares one balanced tree over the composite key,
//! which has the same results and O(log n) operations without a spill threshold.
//!
//! Commonware's crate-private `Partitioned` trait (`new_range`/`install_range`, for parallel
//! merkleization in qmdb) is not ported yet; it comes with qmdb.

const std = @import("std");
const assert = std.debug.assert;
const translator_module = @import("../../translator.zig");

pub const unordered = @import("unordered.zig");
pub const ordered = @import("ordered.zig");

/// The bytes of the partition index.
const index_int_size = 4;

pub const Split = struct { partition: u32, sub_key: []const u8 };

/// The partition of `key` (its first `P` bytes, big-endian, right-padded with zeros when the
/// key is shorter) and the rest of the key.
pub fn partition_index_and_sub_key(comptime P: usize, key: []const u8) Split {
    comptime assert(P > 0); // P must be greater than 0
    comptime assert(P <= 3); // P must be 3 or less
    const used = @min(P, key.len);
    var bytes: [index_int_size]u8 = @splat(0);
    @memcpy(bytes[index_int_size - P ..][0..used], key[0..used]);
    const partition = std.mem.readInt(u32, &bytes, .big);
    assert(partition < (@as(u32, 1) << @intCast(8 * P)));
    return .{ .partition = partition, .sub_key = key[used..] };
}

/// A translator over composite keys `(partition, T's key of the rest)`, ordered by partition
/// then sub-key.
pub fn Translator(comptime T: type, comptime P: usize) type {
    translator_module.check(T);
    return struct {
        const Self = @This();

        pub const Key = struct { partition: u32, key: T.Key };
        pub const ordered = T.ordered;
        pub const partition_count: u32 = @as(u32, 1) << @intCast(8 * P);

        inner: T,

        pub fn init(inner: T) Self {
            return .{ .inner = inner };
        }

        pub fn transform(self: Self, key: []const u8) Key {
            const split = partition_index_and_sub_key(P, key);
            return .{ .partition = split.partition, .key = self.inner.transform(split.sub_key) };
        }

        pub fn hash(self: Self, key: Key) u64 {
            // Spread the partition so equal sub-keys in different partitions hash apart.
            const partition_hash = @as(u64, key.partition) *% 0x9e37_79b9_7f4a_7c15;
            return self.inner.hash(key.key) ^ partition_hash;
        }

        pub fn order(a: Key, b: Key) std.math.Order {
            const by_partition = std.math.order(a.partition, b.partition);
            if (by_partition != .eq) return by_partition;
            return T.order(a.key, b.key);
        }

        pub fn eql(a: Key, b: Key) bool {
            return a.partition == b.partition and T.eql(a.key, b.key);
        }
    };
}

const testing = std.testing;

fn expect_split(comptime P: usize, key: []const u8, partition: u32, sub_key: []const u8) !void {
    const split = partition_index_and_sub_key(P, key);
    try testing.expectEqual(partition, split.partition);
    try testing.expectEqualSlices(u8, sub_key, split.sub_key);
}

test "partitioned prefix length 1" {
    try expect_split(1, &.{}, 0, "");
    try expect_split(1, &.{0x01}, 1, "");
    try expect_split(1, &.{ 0x00, 0x01 }, 0, &.{0x01});
    try expect_split(1, &.{ 0x00, 0x00, 0x01 }, 0, &.{ 0x00, 0x01 });
}

test "partitioned prefix length 2" {
    try expect_split(2, &.{}, 0, "");
    // Short keys are right-padded, so this routes to 0x0100, not 0x0001.
    try expect_split(2, &.{0x01}, 0x0100, "");
    try expect_split(2, &.{ 0x00, 0x01 }, 1, "");
    try expect_split(2, &.{ 0x00, 0xff, 0x01 }, 0xff, &.{0x01});
    try expect_split(2, &.{ 0x01, 0xff, 0x02 }, 0x01ff, &.{0x02});
}

test "partitioned prefix length 3" {
    try expect_split(3, &.{}, 0, "");
    try expect_split(3, &.{0x01}, 0x010000, "");
    try expect_split(3, &.{ 0x00, 0x01 }, 0x000100, "");
    try expect_split(3, &.{ 0x00, 0x01, 0x02 }, 0x0102, "");
    try expect_split(3, &.{ 0x00, 0x01, 0x02, 0x03 }, 0x0102, &.{0x03});
    try expect_split(3, &.{ 0x01, 0xff, 0xab, 0xcd, 0xef }, 0x01ffab, &.{ 0xcd, 0xef });
}

test "partition index preserves key order" {
    const keys = [_][]const u8{
        &.{},                   &.{0x00},               &.{ 0x00, 0x00 }, &.{ 0x00, 0x80 },
        &.{ 0x00, 0xff },       &.{ 0x00, 0xff, 0x01 }, &.{0x01},         &.{ 0x01, 0x00 },
        &.{ 0x01, 0x00, 0x05 }, &.{ 0x01, 0xff },       &.{0x02},         &.{0xff},
        &.{ 0xff, 0xff },
    };
    var previous: u32 = 0;
    for (keys[0 .. keys.len - 1], keys[1..]) |a, b| {
        try testing.expect(std.mem.order(u8, a, b) == .lt);
    }
    for (keys) |key| {
        const partition = partition_index_and_sub_key(2, key).partition;
        try testing.expect(partition >= previous);
        previous = partition;
    }
}

test {
    testing.refAllDecls(@This());
}
