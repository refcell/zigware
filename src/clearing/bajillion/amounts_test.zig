//! Tests of `amounts.zig` (commonware `bajillion/amounts.rs` tests).

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const storage = @import("storage");
const amounts = @import("amounts.zig");
const t = @import("testing.zig");

const Sha256 = t.Sha256;
const TestAmounts = t.TestAmounts;
const gpa = testing.allocator;

fn expect_entries(value: *const TestAmounts, expected: []const TestAmounts.Entry) !void {
    try testing.expectEqual(expected.len, value.entries.len);
    for (value.entries, expected) |a, b| {
        try testing.expect(a[0].eql(b[0]));
        try testing.expectEqual(b[1], a[1]);
    }
}

// Building amounts sorts the entries by account. An account reads back its amount and
// position, or zero and no position when it has no amount.
test "amounts: new sorts entries" {
    const keys = t.accounts(4);
    var value = try TestAmounts.init(gpa, &.{ .{ keys[2], 3 }, .{ keys[0], 1 }, .{ keys[1], 2 } });
    defer value.deinit(gpa);
    try expect_entries(&value, &.{ .{ keys[0], 1 }, .{ keys[1], 2 }, .{ keys[2], 3 } });
    try testing.expectEqual(@as(usize, 3), value.len());
    try testing.expectEqual(@as(?u64, 6), value.total());
    try testing.expectEqual(@as(u64, 2), value.get(&keys[1]));
    try testing.expectEqual(@as(u64, 0), value.get(&keys[3]));
    try testing.expectEqual(@as(?usize, 2), value.position(&keys[2]));
    try testing.expectEqual(@as(?usize, null), value.position(&keys[3]));
}

// Zero amounts and repeated accounts are refused, and no entries form the empty amounts.
test "amounts: new rejects invalid entries" {
    const keys = t.accounts(2);
    try testing.expectError(error.ZeroAmount, TestAmounts.init(gpa, &.{.{ keys[0], 0 }}));
    try testing.expectError(
        error.Duplicate,
        TestAmounts.init(gpa, &.{ .{ keys[0], 1 }, .{ keys[0], 2 } }),
    );
    var none = try TestAmounts.init(gpa, &.{});
    defer none.deinit(gpa);
    try testing.expect(none.is_empty());
}

// Combining adds amounts per account in either order and refuses a sum that overflows.
test "amounts: combine" {
    const keys = t.accounts(3);
    var left = try TestAmounts.init(gpa, &.{ .{ keys[0], 1 }, .{ keys[1], 2 } });
    defer left.deinit(gpa);
    var right = try TestAmounts.init(gpa, &.{ .{ keys[1], 3 }, .{ keys[2], 4 } });
    defer right.deinit(gpa);
    var combined = try left.combine(gpa, &right);
    defer combined.deinit(gpa);
    var reversed = try right.combine(gpa, &left);
    defer reversed.deinit(gpa);
    try testing.expect(combined.eql(&reversed));
    try expect_entries(&combined, &.{ .{ keys[0], 1 }, .{ keys[1], 5 }, .{ keys[2], 4 } });
    var same = try left.combine(gpa, &TestAmounts.empty);
    defer same.deinit(gpa);
    try testing.expect(same.eql(&left));

    const max = std.math.maxInt(u64);
    var full = try TestAmounts.init(gpa, &.{.{ keys[0], max }});
    defer full.deinit(gpa);
    var one = try TestAmounts.init(gpa, &.{.{ keys[0], 1 }});
    defer one.deinit(gpa);
    try testing.expectError(error.Overflow, full.combine(gpa, &one));
    var overflowing = try TestAmounts.init(gpa, &.{ .{ keys[0], max }, .{ keys[1], 1 } });
    defer overflowing.deinit(gpa);
    try testing.expectEqual(@as(?u64, null), overflowing.total());
}

// A leaf hashes the account and the amount's big-endian encoding, for primitive and wide
// amounts alike.
test "amounts: leaf hashes account and big-endian amount" {
    const key = t.accounts(1)[0];
    var five_u64: [8]u8 = undefined;
    std.mem.writeInt(u64, &five_u64, 5, .big);
    var five_u128: [16]u8 = undefined;
    std.mem.writeInt(u128, &five_u128, 5, .big);
    var five_u256: [32]u8 = @splat(0);
    five_u256[31] = 5;
    const PublicKey = t.PublicKey;
    try testing.expect(amounts.leaf(Sha256, PublicKey, u64, &key, 5)
        .eql(Sha256.hash(&.{ key.as_slice(), &five_u64 })));
    try testing.expect(amounts.leaf(Sha256, PublicKey, u128, &key, 5)
        .eql(Sha256.hash(&.{ key.as_slice(), &five_u128 })));
    try testing.expect(amounts.leaf(Sha256, PublicKey, u256, &key, 5)
        .eql(Sha256.hash(&.{ key.as_slice(), &five_u256 })));
}

// The root changes with every account, every amount, and the number of entries.
test "amounts: root commits to entries" {
    const keys = t.accounts(2);
    var empty_tree = try storage.bmt.Builder(Sha256).init(gpa, 0);
    defer empty_tree.deinit(gpa);
    var built = try empty_tree.build(gpa);
    defer built.deinit(gpa);
    try testing.expect(TestAmounts.empty.root(Sha256).eql(built.root()));

    var one = try TestAmounts.init(gpa, &.{.{ keys[0], 1 }});
    defer one.deinit(gpa);
    var two = try TestAmounts.init(gpa, &.{.{ keys[0], 2 }});
    defer two.deinit(gpa);
    var other = try TestAmounts.init(gpa, &.{.{ keys[1], 1 }});
    defer other.deinit(gpa);
    var both = try one.combine(gpa, &other);
    defer both.deinit(gpa);
    const roots = [_]Sha256.Digest{
        TestAmounts.empty.root(Sha256), one.root(Sha256),  two.root(Sha256),
        other.root(Sha256),             both.root(Sha256),
    };
    for (roots, 0..) |a, i| {
        for (roots[i + 1 ..]) |b| try testing.expect(!a.eql(b));
    }
}

fn leaf(key: *const t.PublicKey, amount: *const u64) Sha256.Digest {
    return amounts.leaf(Sha256, t.PublicKey, u64, key, amount.*);
}

// Every account, present or absent, opens to its amount under the root.
test "amounts: lookup" {
    const keys = t.accounts(5);
    var value = try TestAmounts.init(gpa, &.{ .{ keys[1], 10 }, .{ keys[3], 30 } });
    defer value.deinit(gpa);
    const root = value.root(Sha256);
    var tree = try value.tree(Sha256, gpa);
    defer tree.deinit(gpa);
    try testing.expect(tree.root().eql(root));
    for (&keys) |*key| {
        var opening = try value.lookup(Sha256.Digest, gpa, &tree, key);
        defer opening.deinit(gpa);
        const opened = try opening.verify(Sha256, &root, key, leaf);
        try testing.expectEqual(value.get(key), opened orelse 0);
    }
}

// Decoding refuses unsorted, repeated, and zero entries, and more entries than the limit.
test "amounts: decode rejects non-canonical entries" {
    const keys = t.accounts(2);
    const range: codec.RangeCfg(usize) = .to_inclusive(8);
    const Entries = []const TestAmounts.Entry;
    const invalid = [_]Entries{
        &.{ .{ keys[1], 1 }, .{ keys[0], 1 } },
        &.{ .{ keys[0], 1 }, .{ keys[0], 2 } },
        &.{.{ keys[0], 0 }},
    };
    for (invalid) |entries| {
        const encoded = try codec.encode(Entries, gpa, entries);
        defer gpa.free(encoded);
        try testing.expectError(error.Invalid, codec.decode_cfg(TestAmounts, gpa, encoded, range));
    }

    var value = try TestAmounts.init(gpa, &.{ .{ keys[0], 1 }, .{ keys[1], 2 } });
    defer value.deinit(gpa);
    const encoded = try codec.encode(TestAmounts, gpa, value);
    defer gpa.free(encoded);
    var decoded = try codec.decode_cfg(TestAmounts, gpa, encoded, range);
    defer decoded.deinit(gpa);
    try testing.expect(decoded.eql(&value));
    try testing.expectError(
        error.InvalidLength,
        codec.decode_cfg(TestAmounts, gpa, encoded, .to_inclusive(1)),
    );
}

// The allocation-free root matches the root of the tree `storage.bmt` builds, at every width
// around the powers of two.
test "amounts: streaming root matches the bmt" {
    for (0..70) |count| {
        var builder = try storage.bmt.Builder(Sha256).init(gpa, count);
        defer builder.deinit(gpa);
        var streaming: amounts.RootBuilder(Sha256) = .{};
        for (0..count) |index| {
            const entry = Sha256.hash(&.{std.mem.asBytes(&@as(u64, index))});
            _ = try builder.add(gpa, &entry);
            streaming.add(&entry);
        }
        var tree = try builder.build(gpa);
        defer tree.deinit(gpa);
        try testing.expect(streaming.finish().eql(tree.root()));
    }
}
