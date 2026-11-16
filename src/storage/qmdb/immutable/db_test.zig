//! Tests of the immutable database, ported from commonware's `qmdb/immutable/mod.rs` scenarios,
//! plus a randomized chain check against a model and the reopened rebuild. Every scenario runs
//! under both families. Commonware's `drop(db)` is `deinit` here: it closes without syncing.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const merkle = @import("../../merkle/mod.zig");
const verify = @import("../verify.zig");
const immutable = @import("mod.zig");
const support = @import("test_support.zig");

const gpa = testing.allocator;
const families = .{ merkle.mmr.Family, merkle.mmb.Family };
const Digest = support.Digest;
const Sha256 = support.Sha256;
const fill = support.fill;

fn expect_value(actual: ?Digest, expected: ?Digest) !void {
    if (expected) |e| {
        try testing.expect(actual != null and actual.?.eql(e));
    } else {
        try testing.expect(actual == null);
    }
}

/// Sets `fill(key)` to `fill(key + 100)` for each of `keys` in one batch with `floor` (or the
/// database's), applies it, and commits.
fn commit_sets(db: anytype, keys: []const u8, floor: ?u64) !void {
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        for (keys) |k| try batch.set(fill(k), fill(k +% 100));
        if (floor) |f| batch.with_inactivity_floor(f);
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    try db.apply_batch(merkleized);
    try db.commit();
}

/// Merkleizes a batch setting `fill(key)` to `fill(value)` on `parent`, or on `db` if null.
fn merkleize_set(
    db: anytype,
    parent: anytype,
    key: u8,
    value: u8,
) anyerror!*@typeInfo(@TypeOf(db)).pointer.child.MerkleizedBatch {
    const Parent = @TypeOf(parent);
    const link: ?*@typeInfo(@TypeOf(db)).pointer.child.MerkleizedBatch =
        if (Parent == @TypeOf(null)) null else parent;
    var batch = if (link) |p| p.new_batch() else try db.new_batch();
    errdefer batch.deinit();
    try batch.set(fill(key), fill(value));
    return batch.merkleize(db);
}

test "immutable empty database survives reopen" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        errdefer db.deinit();
        try testing.expectEqual(merkle.Range{ .start = 0, .end = 1 }, db.bounds());
        try testing.expectEqual(@as(u64, 0), db.inactivity_floor());
        try testing.expect(try db.get_metadata() == null);
        const initial = immutable.initial_root(F, Digest, support.Encoding, Sha256);
        try testing.expect(db.root().eql(initial));
        // An unmerkleized batch is lost on reopen.
        var dropped = try db.new_batch();
        try dropped.set(fill(1), fill(2));
        dropped.deinit();
        db.deinit();
        db = try harness.open(F, null);
        try testing.expect(db.root().eql(initial));
        try commit_sets(&db, &.{}, null);
        try testing.expectEqual(@as(u64, 2), db.bounds().end);
        const root = db.root();
        db.deinit();
        db = try harness.open(F, null);
        try testing.expect(db.root().eql(root));
        try db.destroy();
    }
}

test "immutable sets, metadata, and recovery" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        errdefer db.deinit();
        try expect_value(try db.get(&fill(1)), null);
        var batch = try db.new_batch();
        try batch.set(fill(1), fill(3));
        batch.with_metadata(fill(99));
        const first = try batch.merkleize(&db);
        defer first.release();
        try db.apply_batch(first);
        try db.commit();
        try expect_value(try db.get(&fill(1)), fill(3));
        try testing.expectEqual(@as(u64, 3), db.bounds().end);
        try expect_value(try db.get_metadata(), fill(99));
        try db.sync();
        try commit_sets(&db, &.{2}, null);
        try testing.expectEqual(@as(u64, 5), db.bounds().end);
        try expect_value(try db.get_metadata(), null);
        const root = db.root();
        // A crash keeps the committed (unsynced) sets: reopen replays them.
        harness.storage.crash();
        db.deinit();
        db = try harness.open(F, null);
        try testing.expect(db.root().eql(root));
        try testing.expectEqual(@as(u64, 5), db.bounds().end);
        try expect_value(try db.get(&fill(1)), fill(3));
        try expect_value(try db.get(&fill(2)), fill(102));
        try expect_value(try db.get(&fill(5)), null);
        try db.destroy();
    }
}

test "immutable proofs verify against the root" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        defer db.deinit();
        try commit_sets(&db, &.{ 1, 2, 3 }, null);
        const root = db.root();
        var proved = try db.proof(0, 100);
        defer proved.deinit(gpa);
        const Op = support.Fixed(F).Operation;
        const proof = &proved.proof;
        try testing.expectEqual(@as(usize, 5), proved.items.len);
        try testing.expect(try verify.verify(F, Sha256, Op, gpa, proof, 0, proved.items, &root));
        try testing.expect(!try verify.verify(F, Sha256, Op, gpa, proof, 1, proved.items, &root));
    }
}

test "immutable prune retires sets below the boundary" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        defer db.deinit();
        for (0..20) |i| try commit_sets(&db, &.{@intCast(i)}, db.bounds().end);
        const root = db.root();
        const end = db.bounds().end;
        try testing.expectError(error.PruneBeyondMinRequired, db.prune(db.inactivity_floor() + 1));
        try db.prune(end - 5);
        try testing.expect(db.root().eql(root));
        try testing.expect(db.bounds().start > 0);
        try expect_value(try db.get(&fill(0)), null);
        try expect_value(try db.get(&fill(19)), fill(119));
    }
}

test "immutable chain reads survive dropped ancestors" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        defer db.deinit();
        try commit_sets(&db, &.{0}, null);
        const a = try merkleize_set(&db, null, 1, 101);
        const b = try merkleize_set(&db, a, 2, 102);
        const c = try merkleize_set(&db, b, 3, 103);
        defer c.release();
        var child = c.new_batch();
        defer child.deinit();
        a.release();
        b.release();
        for (0..4) |i| {
            const k: u8 = @intCast(i);
            try expect_value(try c.get(&fill(k), &db), fill(k + 100));
            try expect_value(try child.get(&fill(k), &db), fill(k + 100));
        }
        // Merkleizing past dropped, unapplied ancestors is stale.
        try testing.expectError(error.StaleBatch, child.merkleize(&db));
        try db.apply_batch(c);
        for (0..4) |i| {
            const k: u8 = @intCast(i);
            try expect_value(try db.get(&fill(k)), fill(k + 100));
        }
    }
}

test "immutable batches resolve keys set in any order" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        defer db.deinit();
        var batch = try db.new_batch();
        var at: u8 = 8;
        while (at > 0) : (at -= 1) try batch.set(fill(at - 1), fill(at + 99));
        const parent = try batch.merkleize(&db);
        defer parent.release();
        var draft = parent.new_batch();
        var keys: [8]Digest = undefined;
        for (&keys, 0..) |*k, i| k.* = fill(@intCast(i));
        var values: [8]?Digest = undefined;
        try parent.get_many(&keys, &db, &values);
        for (values, 0..) |v, i| try expect_value(v, fill(@as(u8, @intCast(i)) + 100));
        try draft.get_many(&keys, &db, &values);
        for (values, 0..) |v, i| try expect_value(v, fill(@as(u8, @intCast(i)) + 100));
        const child = try draft.merkleize(&db);
        defer child.release();
        try child.get_many(&keys, &db, &values);
        for (values, 0..) |v, i| try expect_value(v, fill(@as(u8, @intCast(i)) + 100));
    }
}

test "immutable stale siblings and forks are refused" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        defer db.deinit();
        const batch = try merkleize_set(&db, null, 1, 101);
        defer batch.release();
        const sibling = try merkleize_set(&db, null, 1, 102);
        defer sibling.release();
        var pins: [merkle.max_pinned_nodes]Digest = undefined;
        var proof = try batch.proof(&db);
        proof.deinit(gpa);
        _ = try batch.pinned_nodes(&db, &pins);
        try db.apply_batch(sibling);
        try testing.expectError(error.StaleRead, batch.proof(&db));
        try testing.expectError(error.StaleRead, batch.pinned_nodes(&db, &pins));
        try testing.expectError(error.StaleBatch, db.apply_batch(batch));
        // A child of a sibling parent is stale once the other parent applies.
        const parent_a = try merkleize_set(&db, null, 2, 102);
        defer parent_a.release();
        const parent_b = try merkleize_set(&db, null, 3, 103);
        defer parent_b.release();
        const child_b = try merkleize_set(&db, parent_b, 4, 104);
        defer child_b.release();
        try db.apply_batch(parent_a);
        try testing.expectError(error.StaleBatch, db.validate_batch(child_b));
    }
}

test "immutable batch reads ignore sets below their floor" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        defer db.deinit();
        try commit_sets(&db, &.{1}, null); // `old` at location 1.
        try commit_sets(&db, &.{ 10, 11, 12, 13, 14, 15, 16, 17 }, null);
        const base = db.bounds().end;
        var batch = try db.new_batch();
        try batch.set(fill(2), fill(102));
        batch.with_inactivity_floor(base);
        const parent = try batch.merkleize(&db);
        defer parent.release();
        try expect_value(try parent.get(&fill(1), &db), null);
        try expect_value(try parent.get(&fill(2), &db), fill(102));
        var child = parent.new_batch();
        try expect_value(try child.get(&fill(1), &db), null);
        try child.set(fill(3), fill(103));
        child.with_inactivity_floor(base + 3);
        const grandchild = try child.merkleize(&db);
        defer grandchild.release();
        for ([_]u8{ 1, 2, 3 }) |k| try expect_value(try grandchild.get(&fill(k), &db), null);
        try db.apply_batch(parent);
        try db.commit();
        // The database itself still reads below the floor; batches on it do not.
        try expect_value(try db.get(&fill(1)), fill(101));
        var on_db = try db.new_batch();
        defer on_db.deinit();
        try expect_value(try on_db.get(&fill(1), &db), null);
        try db.prune(base);
        try testing.expect(db.bounds().start > 1);
        try expect_value(try on_db.get(&fill(2), &db), fill(102));
        try expect_value(try db.get(&fill(1)), null);
    }
}

test "immutable floors may not regress or pass the commit" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        defer db.deinit();
        for ([_]u64{ 100, 3 }) |floor| {
            var batch = try db.new_batch();
            defer batch.deinit();
            try batch.set(fill(1), fill(2));
            batch.with_inactivity_floor(floor);
            try testing.expectError(error.FloorBeyondCommit, batch.merkleize(&db));
        }
        var batch = try db.new_batch();
        try batch.set(fill(1), fill(2));
        batch.with_inactivity_floor(2); // The commit location is the largest valid floor.
        const parent = try batch.merkleize(&db);
        defer parent.release();
        var child = parent.new_batch();
        defer child.deinit();
        try child.set(fill(3), fill(4));
        child.with_inactivity_floor(1);
        try testing.expectError(error.FloorRegressed, child.merkleize(&db));
    }
}

/// Applies random chains of fresh keys, sometimes pruning, and checks every key against the
/// model and the reopened rebuild.
fn check_random_chains(comptime F: type, seed: u64) !void {
    var harness = try support.Harness.init(gpa);
    defer harness.deinit();
    var db = try harness.open(F, null);
    defer db.deinit();
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var next_key: u64 = 0;
    for (0..30) |_| {
        const depth = random.uintLessThan(usize, 3) + 1;
        var chain: [3]?*support.Fixed(F).MerkleizedBatch = .{ null, null, null };
        defer for (chain) |batch| if (batch) |b| b.release();
        var applied: usize = 0;
        for (0..depth) |level| {
            const parent = if (level > 0) chain[level - 1] else null;
            var batch = if (parent) |p| p.new_batch() else try db.new_batch();
            errdefer batch.deinit();
            for (0..random.uintLessThan(usize, 5)) |_| {
                try batch.set(support.to_digest(next_key), support.to_val(next_key, 0));
                next_key += 1;
            }
            const floor = @max(batch.inactivity_floor, db.bounds().end -| 8);
            batch.with_inactivity_floor(if (random.boolean()) floor else batch.inactivity_floor);
            chain[level] = try batch.merkleize(&db);
            if (random.boolean()) {
                try db.apply_batch(chain[level].?);
                applied = level + 1;
            }
            if (level > 0 and (applied >= level or level + 1 == depth) and random.boolean()) {
                chain[level - 1].?.release();
                chain[level - 1] = null;
            }
        }
        if (applied < depth) try db.apply_batch(chain[depth - 1].?);
        if (random.uintLessThan(u8, 4) == 0) try db.prune(db.inactivity_floor());
        try check_and_reopen(F, &harness, &db, next_key);
    }
}

/// Reads every key through a batch on `db` (so only sets at or above the floor count) into
/// `out`, returning how many were found. Found values must be the ones set.
fn batch_reads(db: anytype, out: []?Digest) !u64 {
    var batch = try db.new_batch();
    defer batch.deinit();
    var found: u64 = 0;
    for (out, 0..) |*slot, k| {
        slot.* = try batch.get(&support.to_digest(k), db);
        if (slot.*) |v| {
            try testing.expect(v.eql(support.to_val(k, 0)));
            found += 1;
        }
    }
    return found;
}

/// Syncs and reopens `db`, checking that the root and every batch read survive and that the
/// rebuilt index holds exactly the sets from the floor on.
fn check_and_reopen(comptime F: type, harness: *support.Harness, db: anytype, keys: u64) !void {
    const before = try gpa.alloc(?Digest, @intCast(keys));
    defer gpa.free(before);
    const after = try gpa.alloc(?Digest, @intCast(keys));
    defer gpa.free(after);
    const found = try batch_reads(db, before);
    const root = db.root();
    try db.sync();
    db.deinit();
    db.* = try harness.open(F, null);
    try testing.expect(db.root().eql(root));
    try testing.expectEqual(found, try batch_reads(db, after));
    for (before, after) |x, y| try expect_value(y, x);
    try testing.expectEqual(found, db.snapshot.len());
    try testing.expectEqual(db.inactivity_floor(), db.snapshot.start);
}

test "immutable randomized chains match the reopened rebuild" {
    inline for (families) |F| try check_random_chains(F, 0x1aaa_7e5d);
}
