//! Tests of the `any` database over owned byte values (`Vec<u8>`, commonware's
//! `any/{unordered,ordered}/variable.rs` value type): batches own the values they are given,
//! the floor walk moves owned values, and every read hands the caller a copy. The
//! leak-checking allocator catches any slip. Every scenario runs unordered and ordered, under
//! both families.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const codec = @import("codec");
const merkle = @import("../../merkle/mod.zig");
const verify = @import("../verify.zig");
const floor_mod = @import("../floor.zig");
const support = @import("test_support.zig");

const gpa = testing.allocator;
const Digest = support.Digest;
const Bytes = []const u8;
const key = support.to_digest;
const databases = .{
    support.UnorderedBytes(merkle.mmr.Family),
    support.UnorderedBytes(merkle.mmb.Family),
    support.OrderedBytes(merkle.mmr.Family),
    support.OrderedBytes(merkle.mmb.Family),
};

/// An owned value of `len` copies of `byte`.
fn make(byte: u8, len: usize) !Bytes {
    const bytes = try gpa.alloc(u8, len);
    @memset(bytes, byte);
    return bytes;
}

/// What a test expects of a value: `len` copies of `byte`.
const Shape = struct { byte: u8, len: usize };

fn shape_of(i: usize, round: usize) Shape {
    return .{ .byte = @intCast((i * 7 + round) % 251), .len = (i + round) % 6 };
}

/// Checks `got` (owned, freed here) against `expected`.
fn expect_value(expected: ?Shape, got: ?Bytes) !void {
    defer codec.free(?Bytes, gpa, got);
    const want = expected orelse return testing.expectEqual(@as(?Bytes, null), got);
    try testing.expect(got != null);
    try testing.expectEqual(want.len, got.?.len);
    for (got.?) |byte| try testing.expectEqual(want.byte, byte);
}

/// Writes `shape` (null deletes) to `key(i)` in `batch`.
fn write(batch: anytype, i: usize, shape: ?Shape) !void {
    const s = shape orelse return batch.write(key(i), null);
    const value = try make(s.byte, s.len);
    errdefer gpa.free(value);
    try batch.write(key(i), value);
}

/// Checks every key of `model` through `db.get` and `db.get_many`.
fn expect_model(db: anytype, model: []const ?Shape) !void {
    var keys: [32]Digest = undefined;
    var out: [32]?Bytes = undefined;
    assert(model.len <= keys.len);
    for (model, 0..) |shape, i| {
        try expect_value(shape, try db.get(&key(i)));
        keys[i] = key(i);
    }
    try db.get_many(keys[0..model.len], out[0..model.len]);
    for (model, out[0..model.len]) |shape, got| try expect_value(shape, got);
}

test "any owned values: rounds of writes move values through the floor and reopen" {
    inline for (databases) |Db| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        errdefer db.deinit();
        var model: [20]?Shape = @splat(null);
        for (0..12) |round| {
            var batch = try db.new_batch();
            const merkleized = merkleized: {
                errdefer batch.deinit();
                // A superseded write in the batch is freed with it.
                try write(&batch, round % 20, shape_of(round, 1000));
                for (0..20) |i| {
                    if ((i + round) % 3 != 0) continue;
                    const shape: ?Shape = if ((i * round) % 7 == 3) null else shape_of(i, round);
                    try write(&batch, i, shape);
                    model[i] = shape;
                }
                try write(&batch, round % 20, model[round % 20]);
                batch.with_metadata(try make(9, round));
                batch.with_metadata(try make(9, round % 4));
                break :merkleized try batch.merkleize(&db);
            };
            defer merkleized.release();
            try db.apply_batch(merkleized);
        }
        try expect_model(&db, &model);
        try expect_value(.{ .byte = 9, .len = 11 % 4 }, try db.get_metadata());
        // The floor moved past the first rounds, so their updates were rewritten at the tip.
        try testing.expect(db.inactivity_floor() > 20);
        try db.sync();
        const root = db.root();
        db.deinit();
        db = try harness.open(Db, null);
        try testing.expect(db.root().eql(root));
        try expect_model(&db, &model);
        var proved = try db.proof(db.inactivity_floor(), 8);
        defer proved.deinit(gpa);
        const Op = Db.Operation;
        const start = db.inactivity_floor();
        const items = proved.items;
        const sha = support.Sha256;
        const ok = try verify.verify(Db.Family, sha, Op, gpa, &proved.proof, start, items, &root);
        try testing.expect(ok);
        if (comptime Db.Update.siblings) try expect_links(&db, &model);
        try db.destroy();
    }
}

/// Checks the ordered links of each active key in `model`: its value and the next active key,
/// wrapping (`get_with_next_key`), and the next above it (`get_next_key`).
fn expect_links(db: anytype, model: []const ?Shape) !void {
    for (model, 0..) |shape, i| {
        const expected = shape orelse continue;
        var above: ?Digest = null;
        var smallest: ?Digest = null;
        for (model, 0..) |other, j| {
            if (other == null) continue;
            const k = key(j);
            if (smallest == null or std.mem.order(u8, &k.bytes, &smallest.?.bytes) == .lt) {
                smallest = k;
            }
            if (std.mem.order(u8, &k.bytes, &key(i).bytes) != .gt) continue;
            if (above == null or std.mem.order(u8, &k.bytes, &above.?.bytes) == .lt) above = k;
        }
        const found = (try db.get_with_next_key(&key(i))) orelse return error.TestUnexpectedResult;
        try expect_value(expected, found.value);
        try testing.expect(found.next_key.eql(above orelse smallest.?));
        const next = try db.get_next_key(&key(i));
        try testing.expectEqual(above == null, next == null);
        if (above) |a| try testing.expect(next.?.eql(a));
    }
}

/// A floor policy that writes a value of its own for every update it moves (exercising
/// `Entry.replace`): the values come from `pool` and belong to the walk once written.
const Replace = struct {
    pool: []Bytes,
    used: usize = 0,

    pub fn evicts(_: *const Replace) bool {
        return false;
    }

    pub fn limits(_: *const Replace, made_inactive: usize) floor_mod.Limits {
        return .{ .entries = made_inactive + 1, .skips = std.math.maxInt(u64) };
    }

    pub fn decide(
        self: *Replace,
        comptime K: type,
        comptime V: type,
        entry: floor_mod.Entry(K, V),
    ) floor_mod.Decision(V) {
        if (self.used == self.pool.len) return entry.keep();
        defer self.used += 1;
        return entry.replace(self.pool[self.used]);
    }
};

test "any owned values: chains, staging, and replacing policies" {
    inline for (databases) |Db| {
        const Mutation = Db.UnmerkleizedBatch.Mutation;
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        var parent_batch = try db.new_batch();
        for (0..6) |i| try write(&parent_batch, i, shape_of(i, 0));
        const parent = try parent_batch.merkleize(&db);
        var child_batch = parent.new_batch();
        try write(&child_batch, 1, shape_of(1, 1));
        try write(&child_batch, 2, null);
        try expect_value(shape_of(3, 0), try child_batch.get(&key(3), &db));
        try expect_value(shape_of(1, 1), try child_batch.get(&key(1), &db));
        const child = try child_batch.merkleize(&db);
        defer child.release();
        // The child keeps the released parent's values alive.
        parent.release();
        try expect_value(shape_of(4, 0), try child.get(&key(4), &db));
        try expect_value(null, try child.get(&key(2), &db));
        try db.apply_batch(child);
        // Staged reads hand out copies; puts and unstaged writes belong to the batch.
        var batch = try db.new_batch();
        const keys = [_]Digest{ key(0), key(1), key(2) };
        var values: [keys.len]?Bytes = undefined;
        var staged = staged: {
            errdefer batch.deinit();
            break :staged try batch.stage(&keys, &db, &values);
        };
        try expect_value(shape_of(0, 0), values[0]);
        try expect_value(shape_of(1, 1), values[1]);
        try expect_value(null, values[2]);
        const slots = [_]Db.Slot{ .keep, .{ .put = try make(5, 5) }, .delete };
        const unstaged = [_]Mutation{.{ .key = key(9), .value = try make(6, 1) }};
        var pool: [4]Bytes = undefined;
        for (&pool, 0..) |*value, i| value.* = try make(@intCast(200 + i), 2);
        var replace: Replace = .{ .pool = &pool };
        defer for (pool[replace.used..]) |value| gpa.free(value);
        const merkleized = staged.merkleize_with(&slots, &unstaged, &db, &replace) catch |err| {
            staged.deinit();
            return err;
        };
        defer merkleized.release();
        try testing.expect(replace.used > 0);
        try db.apply_batch(merkleized);
        try expect_value(.{ .byte = 5, .len = 5 }, try db.get(&key(1)));
        try expect_value(.{ .byte = 6, .len = 1 }, try db.get(&key(9)));
        try expect_value(null, try db.get(&key(2)));
    }
}
