//! Tests of the immutable database over owned byte values (`Vec<u8>`): batches own the values
//! they are given, diffs own their entries' values, and every read hands the caller an owned
//! copy. The leak-checking allocator catches any slip.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const merkle = @import("../../merkle/mod.zig");
const verify = @import("../verify.zig");
const support = @import("test_support.zig");

const gpa = testing.allocator;
const families = .{ merkle.mmr.Family, merkle.mmb.Family };
const Bytes = []const u8;
const fill = support.fill;

/// An owned value of `len` copies of `byte`.
fn make(byte: u8, len: usize) !Bytes {
    const bytes = try gpa.alloc(u8, len);
    @memset(bytes, byte);
    return bytes;
}

/// Checks `got` (owned, freed here) against `len` copies of `byte`, or null.
fn expect_value(expected: ?struct { u8, usize }, got: ?Bytes) !void {
    defer codec.free(?Bytes, gpa, got);
    const want = expected orelse return testing.expectEqual(@as(?Bytes, null), got);
    try testing.expectEqual(want[1], got.?.len);
    for (got.?) |byte| try testing.expectEqual(want[0], byte);
}

/// Sets `fill(key)` to `len` copies of `key` in `batch`.
fn set(batch: anytype, key: u8, len: usize) !void {
    const value = try make(key, len);
    errdefer gpa.free(value);
    try batch.set(fill(key), value);
}

test "immutable owned values: reads return copies across reopen" {
    inline for (families) |F| {
        const Db = support.Bytes(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open_db(Db, null);
        errdefer db.deinit();
        var batch = try db.new_batch();
        try set(&batch, 1, 3);
        try set(&batch, 2, 0);
        // A later set of a key in the batch replaces the earlier one, which is freed.
        try set(&batch, 1, 5);
        batch.with_metadata(try make(9, 2));
        try expect_value(.{ 1, 5 }, try batch.get(&fill(1), &db));
        const merkleized = try batch.merkleize(&db);
        defer merkleized.release();
        try expect_value(.{ 1, 5 }, try merkleized.get(&fill(1), &db));
        try db.apply_batch(merkleized);
        try db.sync();
        const root = db.root();
        db.deinit();
        db = try harness.open_db(Db, null);
        try testing.expect(db.root().eql(root));
        try expect_value(.{ 9, 2 }, try db.get_metadata());
        var out: [3]?Bytes = undefined;
        try db.get_many(&.{ fill(1), fill(2), fill(3) }, &out);
        try expect_value(.{ 1, 5 }, out[0]);
        try expect_value(.{ 2, 0 }, out[1]);
        try expect_value(null, out[2]);
        var proved = try db.proof(0, 4);
        defer proved.deinit(gpa);
        const Op = Db.Operation;
        const items = proved.items;
        const ok = try verify.verify(F, support.Sha256, Op, gpa, &proved.proof, 0, items, &root);
        try testing.expect(ok);
        try db.destroy();
    }
}

test "immutable owned values: chains keep released ancestors' values" {
    inline for (families) |F| {
        const Db = support.Bytes(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open_db(Db, null);
        defer db.deinit();
        // A dropped batch frees its sets and its replaced metadata.
        var dropped = try db.new_batch();
        try set(&dropped, 7, 4);
        dropped.with_metadata(try make(8, 1));
        dropped.with_metadata(try make(8, 3));
        dropped.deinit();
        var parent_batch = try db.new_batch();
        try set(&parent_batch, 1, 6);
        const parent = try parent_batch.merkleize(&db);
        var child_batch = parent.new_batch();
        try set(&child_batch, 2, 2);
        try expect_value(.{ 1, 6 }, try child_batch.get(&fill(1), &db));
        const child = try child_batch.merkleize(&db);
        defer child.release();
        parent.release();
        var out: [2]?Bytes = undefined;
        try child.get_many(&.{ fill(1), fill(2) }, &db, &out);
        try expect_value(.{ 1, 6 }, out[0]);
        try expect_value(.{ 2, 2 }, out[1]);
        try db.apply_batch(child);
        try testing.expect(db.root().eql(child.root()));
        try expect_value(.{ 1, 6 }, try db.get(&fill(1)));
        try expect_value(.{ 2, 2 }, try db.get(&fill(2)));
    }
}
