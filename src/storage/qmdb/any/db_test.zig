//! Tests of the unordered `any` database, ported from commonware's `qmdb/any/{mod,batch}.rs`
//! scenarios, plus a randomized model check: chained batches against a key-value model, with
//! the live snapshot and bitmap compared to the reopened database's rebuild.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const merkle = @import("../../merkle/mod.zig");
const verify = @import("../verify.zig");
const floor_mod = @import("../floor.zig");
const support = @import("test_support.zig");

const gpa = testing.allocator;
const families = .{ merkle.mmr.Family, merkle.mmb.Family };
const Digest = support.Digest;
const Sha256 = support.Sha256;
const Write = support.Write;
const key = support.to_digest;
const val = support.to_val;

fn expect_value(db: anytype, k: Digest, expected: ?Digest) !void {
    const actual = try db.get(&k);
    if (expected) |e| {
        try testing.expect(actual != null and actual.?.eql(e));
    } else {
        try testing.expect(actual == null);
    }
}

test "any empty database and initial root" {
    inline for (families) |F| {
        const Db = support.UnorderedFixed(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        try testing.expectEqual(merkle.Range{ .start = 0, .end = 1 }, db.bounds());
        try testing.expect(db.is_empty());
        try testing.expect(db.root().eql(@import("mod.zig").initial_root(F, Db.Update, Sha256)));
        try testing.expect(try db.get_metadata() == null);
        try expect_value(&db, key(1), null);
    }
}

test "any writes, deletes, and recovery" {
    inline for (families) |F| {
        const Db = support.UnorderedFixed(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        errdefer db.deinit();
        try support.apply_writes(Db, &db, &.{
            .{ .key = key(1), .value = val(1, 1) },
            .{ .key = key(2), .value = val(2, 1) },
            .{ .key = key(3), .value = val(3, 1) },
        });
        try expect_value(&db, key(2), val(2, 1));
        try testing.expectEqual(@as(usize, 3), db.active_keys);
        try support.apply_writes(Db, &db, &.{
            .{ .key = key(2), .value = null },
            .{ .key = key(3), .value = val(3, 2) },
            .{ .key = key(4), .value = null }, // Deleting an absent key does nothing.
        });
        try expect_value(&db, key(2), null);
        try expect_value(&db, key(3), val(3, 2));
        try testing.expectEqual(@as(usize, 2), db.active_keys);
        try db.commit();
        const committed = db.root();
        // A batch applied without a commit is durable only as far as the journal synced it
        // (here a filled blob syncs before rolling over), so a crash keeps the database at one
        // of the two commit points.
        try support.apply_writes(Db, &db, &.{.{ .key = key(5), .value = val(5, 1) }});
        const applied = db.root();
        harness.storage.crash();
        db.deinit();
        db = try harness.open(Db, null);
        const kept = db.root().eql(applied);
        try testing.expect(kept or db.root().eql(committed));
        try testing.expectEqual(@as(usize, if (kept) 3 else 2), db.active_keys);
        try expect_value(&db, key(1), val(1, 1));
        try expect_value(&db, key(3), val(3, 2));
        try expect_value(&db, key(5), if (kept) val(5, 1) else null);
        // A batch that fills no blob is lost.
        const reopened = db.root();
        try support.apply_writes(Db, &db, &.{.{ .key = key(6), .value = val(6, 1) }});
        try testing.expect(db.bounds().end % 7 != 0);
        harness.storage.crash();
        db.deinit();
        db = try harness.open(Db, null);
        try testing.expect(db.root().eql(reopened));
        try expect_value(&db, key(6), null);
        try db.destroy();
    }
}

test "any later writes of a key in one batch win" {
    inline for (families) |F| {
        const Db = support.UnorderedFixed(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        var batch = try db.new_batch();
        try batch.write(key(1), val(1, 1));
        try batch.write(key(1), null);
        try batch.write(key(1), val(1, 2));
        try testing.expect((try batch.get(&key(1), &db)).?.eql(val(1, 2)));
        // `Hold` keeps the floor, so no active operation moves.
        var hold: floor_mod.Hold = .{};
        const merkleized = try batch.merkleize_with(&db, &hold);
        defer merkleized.release();
        try db.apply_batch(merkleized);
        try expect_value(&db, key(1), val(1, 2));
        // The initial commit, one update, and the commit.
        try testing.expectEqual(@as(u64, 3), db.bounds().end);
    }
}

test "any chained batches read through and apply with dropped parents" {
    inline for (families) |F| {
        const Db = support.UnorderedFixed(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        try support.apply_writes(Db, &db, &.{.{ .key = key(1), .value = val(1, 1) }});
        var parent_batch = try db.new_batch();
        try parent_batch.write(key(1), null);
        try parent_batch.write(key(2), val(2, 1));
        const parent = try parent_batch.merkleize(&db);
        var child_batch = parent.new_batch();
        try testing.expect(try child_batch.get(&key(1), &db) == null);
        try child_batch.write(key(1), val(1, 3));
        try child_batch.write(key(2), null);
        const child = try child_batch.merkleize(&db);
        defer child.release();
        // The child keeps the parent's changes after the parent is released.
        parent.release();
        try testing.expect((try child.get(&key(1), &db)).?.eql(val(1, 3)));
        try testing.expect(try child.get(&key(2), &db) == null);
        try db.apply_batch(child);
        try testing.expect(db.root().eql(child.root()));
        try expect_value(&db, key(1), val(1, 3));
        try expect_value(&db, key(2), null);
        try testing.expectEqual(@as(usize, 1), db.active_keys);
    }
}

test "any sequential parent then child apply matches the chained root" {
    inline for (families) |F| {
        const Db = support.UnorderedFixed(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        var parent_batch = try db.new_batch();
        try parent_batch.write(key(1), val(1, 1));
        const parent = try parent_batch.merkleize(&db);
        defer parent.release();
        var child_batch = parent.new_batch();
        try child_batch.write(key(1), val(1, 2));
        try child_batch.write(key(2), val(2, 2));
        const child = try child_batch.merkleize(&db);
        defer child.release();
        try db.apply_batch(parent);
        try testing.expect((try child.get(&key(2), &db)).?.eql(val(2, 2)));
        try db.apply_batch(child);
        try testing.expect(db.root().eql(child.root()));
        try expect_value(&db, key(1), val(1, 2));
        // A sibling of the applied chain is stale.
        var sibling_batch = try db.new_batch();
        try sibling_batch.write(key(3), val(3, 3));
        const sibling = try sibling_batch.merkleize(&db);
        defer sibling.release();
        try support.apply_writes(Db, &db, &.{.{ .key = key(4), .value = val(4, 4) }});
        try testing.expectError(error.StaleBatch, db.apply_batch(sibling));
        try testing.expectError(error.StaleRead, sibling.get(&key(3), &db));
    }
}

test "any proofs verify and pruning respects the floor" {
    inline for (families) |F| {
        const Db = support.UnorderedFixed(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        for (0..6) |round| {
            var writes: [10]Write = undefined;
            for (&writes, 0..) |*w, i| w.* = .{ .key = key(i), .value = val(i, round) };
            try support.apply_writes(Db, &db, &writes);
        }
        const root = db.root();
        const end = db.bounds().end;
        var all = try db.proof(0, end);
        defer all.deinit(gpa);
        try testing.expectEqual(@as(usize, @intCast(end)), all.items.len);
        const Op = Db.Operation;
        try testing.expect(try verify.verify(F, Sha256, Op, gpa, &all.proof, 0, all.items, &root));
        try testing.expect(!try verify.verify(F, Sha256, Op, gpa, &all.proof, 1, all.items, &root));
        const floor = db.inactivity_floor();
        try testing.expect(floor > 0);
        try testing.expectError(error.PruneBeyondMinRequired, db.prune(floor + 1));
        try db.prune(floor);
        try testing.expect(db.root().eql(root));
        for (0..10) |i| try expect_value(&db, key(i), val(i, 5));
        var tail = try db.proof(floor, 4);
        defer tail.deinit(gpa);
        const proof = &tail.proof;
        try testing.expect(try verify.verify(F, Sha256, Op, gpa, proof, floor, tail.items, &root));
    }
}

/// A random write over a small key space, so keys are often updated, deleted, and recreated.
fn random_write(random: std.Random, salt: u64) Write {
    const k = random.uintLessThan(u64, 24);
    const k_digest = if (k >= 16) support.colliding_digest(7, k) else key(k);
    const value: ?Digest = if (random.uintLessThan(u8, 4) == 0) null else val(k, salt);
    return .{ .key = k_digest, .value = value };
}

const Model = std.AutoHashMapUnmanaged([32]u8, [32]u8);

fn model_apply(model: *Model, writes: []const Write) !void {
    for (writes) |w| {
        if (w.value) |v| {
            try model.put(gpa, w.key.bytes, v.bytes);
        } else {
            _ = model.remove(w.key.bytes);
        }
    }
}

/// Checks `db` against `model`, then reopens it and checks the rebuilt snapshot and bitmap.
fn check_and_reopen(comptime Db: type, harness: *support.Harness, db: *Db, model: *Model) !void {
    try testing.expectEqual(@as(usize, model.count()), db.active_keys);
    for (0..24) |k| {
        const k_digest = if (k >= 16) support.colliding_digest(7, k) else key(k);
        const expected: ?Digest = if (model.get(k_digest.bytes)) |v| .{ .bytes = v } else null;
        try expect_value(db, k_digest, expected);
    }
    var bits: std.DynamicBitSetUnmanaged = try .initEmpty(gpa, @intCast(db.bitmap.len()));
    defer bits.deinit(gpa);
    var bit = db.inactivity_floor_loc;
    while (bit < db.bitmap.len()) : (bit += 1) {
        if (db.bitmap.get_bit(bit)) bits.set(@intCast(bit));
    }
    const root = db.root();
    const floor = db.inactivity_floor_loc;
    try db.sync();
    db.deinit();
    db.* = try harness.open(Db, null);
    try testing.expect(db.root().eql(root));
    try testing.expectEqual(@as(usize, model.count()), db.active_keys);
    try testing.expectEqual(@as(u64, bits.bit_length), db.bitmap.len());
    bit = floor;
    while (bit < db.bitmap.len()) : (bit += 1) {
        try testing.expectEqual(bits.isSet(@intCast(bit)), db.bitmap.get_bit(bit));
    }
}

test "any randomized chains match a model and the rebuilt snapshot" {
    inline for (families) |F| {
        const Db = support.UnorderedFixed(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        var model: Model = .empty;
        defer model.deinit(gpa);
        var prng = std.Random.DefaultPrng.init(0x5eed_a11);
        const random = prng.random();
        var salt: u64 = 0;
        for (0..60) |_| {
            // A chain of up to three batches. Each batch may be applied as soon as it is
            // merkleized, and the batch below it released, so the tip applies with applied,
            // pending, and dropped ancestors in every mix.
            const depth = random.uintLessThan(usize, 3) + 1;
            var chain: [3]?*Db.MerkleizedBatch = .{ null, null, null };
            defer for (chain) |batch| if (batch) |b| b.release();
            var applied: usize = 0;
            for (0..depth) |level| {
                const merkleized = merkleized: {
                    const parent = if (level > 0) chain[level - 1] else null;
                    var batch = if (parent) |p| p.new_batch() else try db.new_batch();
                    errdefer batch.deinit();
                    var writes: [6]Write = undefined;
                    const count = random.uintLessThan(usize, writes.len + 1);
                    for (writes[0..count]) |*w| {
                        salt += 1;
                        w.* = random_write(random, salt);
                        try batch.write(w.key, w.value);
                    }
                    try model_apply(&model, writes[0..count]);
                    break :merkleized try batch.merkleize(&db);
                };
                chain[level] = merkleized;
                if (random.boolean()) {
                    try db.apply_batch(merkleized);
                    applied = level + 1;
                }
                // Merkleizing past a dropped, unapplied ancestor is stale (as in commonware),
                // so an ancestor is released early only once applied or after the last batch.
                const releasable = applied >= level or level + 1 == depth;
                if (level > 0 and releasable and random.boolean()) {
                    chain[level - 1].?.release();
                    chain[level - 1] = null;
                }
            }
            const tip = chain[depth - 1].?;
            if (applied < depth) try db.apply_batch(tip);
            try testing.expect(db.root().eql(tip.root()));
            try check_and_reopen(Db, &harness, &db, &model);
        }
    }
}
