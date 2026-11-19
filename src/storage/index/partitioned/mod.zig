//! Partitioned indices: the first `P` bytes of a key select one of `256^P` partitions and the
//! translator maps the rest (port of commonware's `storage/src/index/partitioned`).
//!
//! Partitions are ordered by prefix, so a partitioned index is a flat index over the composite
//! key `(partition, translated sub-key)`, which `Translator(T, P)` produces. The unordered
//! variant is exactly `index.unordered.Index` over it. The ordered variant keeps commonware's
//! partitioned semantics, which differ from the flat ordered index: a key's values iterate in
//! insertion order (see `ordered.zig`). As commonware's, it stores each partition as sorted
//! arrays that spill to an ordered tree.
//!
//! Commonware's crate-private `Partitioned` trait (for qmdb's parallel snapshot build) is
//! `Range`: each variant's `new_range` makes an empty index restricted to a contiguous run of
//! partitions, a worker fills it through its cursor operations, and `install_range` moves its
//! contents into the full index. Commonware's ranges update the full index's metrics live; here
//! the range keeps its own counters and `install_range` adds them to the full index's.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
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
        pub const prefix_length = P;
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

/// Asserts that partitions `[offset, offset + count)` hold `key`.
fn assert_covers(comptime P: usize, offset: u32, count: u32, key: []const u8) void {
    const partition = partition_index_and_sub_key(P, key).partition;
    assert(partition >= offset);
    assert(partition - offset < count);
}

/// A worker's view of partitions `[offset, offset + count)` of a partitioned `Index`
/// (commonware's `RangeIndex`): only the cursor operations and the value walk, each key's
/// partition asserted inside the range. `absorb(full, part)` moves `part`'s contents into
/// `full`, which must hold none of its keys, leaving `part` empty and unchanged on error.
pub fn Range(
    comptime Index: type,
    comptime absorb: fn (*Index, *Index) Allocator.Error!void,
) type {
    const Tr = Index.Translator;
    comptime assert(@hasDecl(Tr, "partition_count")); // Index must be partitioned.
    return struct {
        const Self = @This();

        index: Index,
        /// The first global partition the range covers.
        offset: u32,
        /// The number of partitions the range covers.
        count: u32,

        /// An empty range over partitions `[offset, offset + count)` of `full`.
        pub fn init(full: *const Index, offset: u32, count: u32) Self {
            assert(count > 0);
            assert(@as(u64, offset) + count <= Tr.partition_count);
            const index = if (comptime @hasDecl(Index, "init_range"))
                Index.init_range(full.gpa, full.translator, offset, count)
            else
                Index.init(full.gpa, full.translator);
            return .{ .index = index, .offset = offset, .count = count };
        }

        pub fn deinit(self: *Self) void {
            self.index.deinit();
            self.* = undefined;
        }

        /// A cursor over the values of `key`, whose partition the range must cover.
        pub fn get_mut(self: *Self, key: []const u8) ?Index.Cursor {
            assert_covers(Tr.prefix_length, self.offset, self.count, key);
            return self.index.get_mut(key);
        }

        /// A cursor over the values of `key`, or, if it has none, inserts `value` and returns
        /// null. The range must cover `key`'s partition.
        pub fn get_mut_or_insert(
            self: *Self,
            key: []const u8,
            value: Index.Value,
        ) Allocator.Error!?Index.Cursor {
            assert_covers(Tr.prefix_length, self.offset, self.count, key);
            return self.index.get_mut_or_insert(key, value);
        }

        /// Visits every value the range holds, in unspecified order.
        pub fn for_each_value(
            self: *const Self,
            visit_context: anytype,
            comptime visit: fn (@TypeOf(visit_context), *const Index.Value) void,
        ) void {
            self.index.for_each_value(visit_context, visit);
        }

        /// Moves the range's contents into `full` and frees the range. `full` must hold no key
        /// of the range's partitions. On error the range and `full` are unchanged.
        pub fn install(self: *Self, full: *Index) Allocator.Error!void {
            const keys_before = full.keys();
            const keys_moved = self.index.keys();
            try absorb(full, &self.index);
            assert(full.keys() == keys_before + keys_moved);
            assert(self.index.keys() == 0);
            self.deinit();
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
