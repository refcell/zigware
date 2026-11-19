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
const qmdb = @import("../mod.zig");
const metrics = @import("runtime").telemetry.metrics;

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
        const keys = [_]Digest{ fill(0), fill(1), fill(2), fill(3) };
        var values: [4]?Digest = undefined;
        try c.get_many(&keys, &db, &values);
        for (values, 0..) |v, i| try expect_value(v, fill(@as(u8, @intCast(i)) + 100));
        try child.get_many(&keys, &db, &values);
        for (values, 0..) |v, i| try expect_value(v, fill(@as(u8, @intCast(i)) + 100));
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

test "immutable init_from_log rebuilds an opened log and refuses an empty one" {
    inline for (families) |F| {
        const Db = support.Fixed(F);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        const cfg = harness.cfg(Db);
        const storage = harness.storage.interface();
        const scope = metrics.Scope.init(&harness.registry).child("db");
        const options: qmdb.InitOptions = .{ .replay_from_floor = true };
        const empty = try qmdb.init_journal(Db.Journal, gpa, storage, cfg.merkle, cfg.log, options);
        const refused = Db.init_from_log(gpa, scope, empty, cfg.translator);
        try testing.expectError(error.HistoricalFloorPruned, refused);
        var db = try harness.open(F, null);
        errdefer db.deinit();
        try commit_sets(&db, &.{ 1, 2 }, null);
        try commit_sets(&db, &.{3}, 3);
        try db.sync();
        const root = db.root();
        db.deinit();
        const log = try qmdb.init_journal(Db.Journal, gpa, storage, cfg.merkle, cfg.log, options);
        harness.registry.deinit();
        harness.registry = metrics.Registry.init(gpa);
        const reopened = metrics.Scope.init(&harness.registry).child("db");
        db = try Db.init_from_log(gpa, reopened, log, cfg.translator);
        try testing.expect(db.root().eql(root));
        try testing.expectEqual(@as(u64, 3), db.inactivity_floor());
        // The index starts at the floor: sets below it are not served.
        try expect_value(try db.get(&fill(1)), null);
        try expect_value(try db.get(&fill(3)), fill(103));
        try db.destroy();
    }
}

// Commonware's run_inactivity_floor_tracking: a default floor keeps the database's, an explicit
// floor takes effect at apply (before any commit), and a reopen restores it.
test "immutable inactivity floor tracks applies and survives reopen" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        defer db.deinit();
        try testing.expectEqual(@as(u64, 0), db.inactivity_floor());
        const first = try merkleize_set(&db, null, 1, 2);
        defer first.release();
        try db.apply_batch(first);
        try testing.expectEqual(@as(u64, 0), db.inactivity_floor());
        var batch = try db.new_batch();
        try batch.set(fill(3), fill(4));
        batch.with_inactivity_floor(3);
        const second = try batch.merkleize(&db);
        defer second.release();
        try db.apply_batch(second);
        try testing.expectEqual(@as(u64, 3), db.inactivity_floor());
        try db.commit();
        try db.sync();
        db.deinit();
        db = try harness.open(F, null);
        try testing.expectEqual(@as(u64, 3), db.inactivity_floor());
    }
}

/// Sets `fill(key)` with `floor` in one batch on the database and applies it.
fn apply_set_with_floor(db: anytype, key: u8, floor: u64) !void {
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        try batch.set(fill(key), fill(key + 1));
        batch.with_inactivity_floor(floor);
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    try db.apply_batch(merkleized);
}

// Commonware's run_floor_monotonicity and run_floor_monotonicity_violation: a batch may keep
// or raise the database's floor, never lower it.
test "immutable floors may stay or rise but not regress from the database" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        defer db.deinit();
        try apply_set_with_floor(&db, 1, 2); // The commit location, 2, is the largest floor.
        try testing.expectEqual(@as(u64, 2), db.inactivity_floor());
        try apply_set_with_floor(&db, 3, 2);
        try testing.expectEqual(@as(u64, 2), db.inactivity_floor());
        try apply_set_with_floor(&db, 5, 5);
        try testing.expectEqual(@as(u64, 5), db.inactivity_floor());
        var batch = try db.new_batch();
        defer batch.deinit();
        try batch.set(fill(7), fill(8));
        batch.with_inactivity_floor(4);
        try testing.expectError(error.FloorRegressed, batch.merkleize(&db));
        try testing.expectEqual(@as(u64, 7), db.bounds().end);
    }
}

// Commonware's run_chained_floor_beyond_commit: a child's floor bound is its own commit
// location, which counts its parent's operations.
test "immutable a chained floor may reach but not pass the child's commit" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        defer db.deinit();
        var batch = try db.new_batch();
        try batch.set(fill(1), fill(2));
        batch.with_inactivity_floor(2);
        const parent = try batch.merkleize(&db);
        defer parent.release();
        var beyond = parent.new_batch();
        defer beyond.deinit();
        try beyond.set(fill(3), fill(4));
        beyond.with_inactivity_floor(5); // One past the child's commit at 4.
        try testing.expectError(error.FloorBeyondCommit, beyond.merkleize(&db));
        var at_commit = parent.new_batch();
        try at_commit.set(fill(3), fill(4));
        at_commit.with_inactivity_floor(4);
        const child = try at_commit.merkleize(&db);
        defer child.release();
        try testing.expectEqual(@as(u64, 4), child.bounds.inactivity_floor);
    }
}

// Commonware's fixed.rs test_batch_inherits_floor_but_not_metadata: a child inherits its
// parent's floor but not its metadata, and so does a batch from the database after the parent
// applies. (Its compact half belongs to the compact database's tests.)
test "immutable batches inherit the floor but not the metadata" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        defer db.deinit();
        var batch = try db.new_batch();
        try batch.set(fill(1), fill(9));
        batch.with_metadata(fill(9));
        batch.with_inactivity_floor(1);
        const parent = try batch.merkleize(&db);
        defer parent.release();
        var inherited = parent.new_batch();
        const child = try inherited.merkleize(&db);
        defer child.release();
        var cleared = parent.new_batch();
        cleared.with_metadata(fill(9));
        cleared.with_metadata(null);
        cleared.with_inactivity_floor(1);
        const explicit = try cleared.merkleize(&db);
        defer explicit.release();
        try testing.expect(child.root().eql(explicit.root()));
        try testing.expectEqual(@as(u64, 1), child.bounds.inactivity_floor);
        var regressed = parent.new_batch();
        defer regressed.deinit();
        regressed.with_inactivity_floor(0);
        try testing.expectError(error.FloorRegressed, regressed.merkleize(&db));
        try db.apply_batch(parent);
        try expect_value(try db.get_metadata(), fill(9));
        var from_db = try db.new_batch();
        const fresh = try from_db.merkleize(&db);
        defer fresh.release();
        try testing.expect(fresh.root().eql(explicit.root()));
        try db.apply_batch(explicit);
        try expect_value(try db.get_metadata(), null);
        var after = try db.new_batch();
        const next = try after.merkleize(&db);
        defer next.release();
        try testing.expectEqual(@as(u64, 1), next.bounds.inactivity_floor);
    }
}

/// Expects `get_many` of `keys` through `reader` to fail with `error.StaleRead`.
fn expect_stale_many(reader: anytype, db: anytype, keys: []const Digest) !void {
    var out: [4]?Digest = undefined;
    assert(keys.len <= out.len);
    try testing.expectError(error.StaleRead, reader.get_many(keys, db, out[0..keys.len]));
}

// Commonware's run_stale_fork_refuses: once one fork applies, every read and merkleize through
// the other fork (and through batches built before the apply) is refused, even with no keys.
test "immutable reads through a losing fork are stale" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        defer db.deinit();
        const winner = try merkleize_set(&db, null, 1, 3);
        defer winner.release();
        const loser = try merkleize_set(&db, null, 1, 4);
        defer loser.release();
        try testing.expectEqual(winner.bounds.tip.size, loser.bounds.tip.size);
        try testing.expect(!winner.root().eql(loser.root()));
        var child = loser.new_batch();
        defer child.deinit();
        try child.set(fill(2), fill(5));
        var direct = try db.new_batch();
        defer direct.deinit();
        try direct.set(fill(2), fill(6));
        try db.apply_batch(winner);
        try testing.expectError(error.StaleRead, direct.get(&fill(1), &db));
        try expect_stale_many(&direct, &db, &.{fill(1)});
        try testing.expectError(error.StaleRead, child.get(&fill(1), &db));
        try expect_stale_many(&child, &db, &.{fill(1)});
        try testing.expectError(error.StaleRead, loser.get(&fill(1), &db));
        try expect_stale_many(&child, &db, &.{});
        try expect_stale_many(loser, &db, &.{});
        try testing.expectError(error.StaleBatch, child.merkleize(&db));
        try testing.expectError(error.StaleBatch, db.validate_batch(loser));
    }
}

// Commonware's run_descendant_apply_makes_parent_reads_stale: after a child applies, it still
// reads, but its parent (whose operations the child carried) is stale.
test "immutable applying a child makes its parent's reads stale" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        defer db.deinit();
        const parent = try merkleize_set(&db, null, 1, 3);
        defer parent.release();
        try expect_value(try parent.get(&fill(1), &db), fill(3));
        const child = try merkleize_set(&db, parent, 2, 4);
        defer child.release();
        try db.apply_batch(child);
        try expect_value(try child.get(&fill(1), &db), fill(3));
        try testing.expectError(error.StaleRead, parent.get(&fill(1), &db));
        try expect_stale_many(parent, &db, &.{fill(1)});
        // Commonware's run_stale_batch_child_applied_before_parent.
        try testing.expectError(error.StaleBatch, db.apply_batch(parent));
    }
}

// Commonware's run_merkleize_foreign_db: a batch built on one database does not merkleize
// against another of the same size.
test "immutable batches do not merkleize against a foreign database" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var other = try support.Harness.init(gpa);
        defer other.deinit();
        var db = try harness.open(F, null);
        defer db.deinit();
        var foreign = try other.open(F, null);
        defer foreign.deinit();
        const ours = try merkleize_set(&db, null, 1, 11);
        defer ours.release();
        try db.apply_batch(ours);
        const theirs = try merkleize_set(&foreign, null, 1, 99);
        defer theirs.release();
        try foreign.apply_batch(theirs);
        try testing.expectEqual(db.bounds().end, foreign.bounds().end);
        try testing.expect(!db.root().eql(foreign.root()));
        var direct = try db.new_batch();
        defer direct.deinit();
        try direct.set(fill(2), fill(22));
        try testing.expectError(error.StaleBatch, direct.merkleize(&foreign));
        const parent = try merkleize_set(&db, null, 3, 33);
        defer parent.release();
        var child = parent.new_batch();
        defer child.deinit();
        try child.set(fill(4), fill(44));
        try testing.expectError(error.StaleBatch, child.merkleize(&foreign));
    }
}

// Commonware's run_merkleize_stale_sibling: an unmerkleized batch, direct or on an unapplied
// parent, refuses to merkleize once a sibling applies.
test "immutable unmerkleized batches refuse to merkleize after a sibling applies" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        defer db.deinit();
        var direct = try db.new_batch();
        defer direct.deinit();
        try direct.set(fill(1), fill(11));
        const first = try merkleize_set(&db, null, 2, 22);
        defer first.release();
        try db.apply_batch(first);
        try testing.expectError(error.StaleBatch, direct.merkleize(&db));
        const parent = try merkleize_set(&db, null, 3, 33);
        defer parent.release();
        var child = parent.new_batch();
        defer child.deinit();
        try child.set(fill(4), fill(44));
        const second = try merkleize_set(&db, null, 5, 55);
        defer second.release();
        try db.apply_batch(second);
        try testing.expectError(error.StaleBatch, child.merkleize(&db));
    }
}

// Commonware's run_stale_batch_rejected: a refused stale batch changes nothing, also on reopen.
test "immutable a refused stale batch leaves the database unchanged" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        defer db.deinit();
        const batch_a = try merkleize_set(&db, null, 1, 10);
        defer batch_a.release();
        const batch_b = try merkleize_set(&db, null, 2, 20);
        defer batch_b.release();
        try db.apply_batch(batch_a);
        try expect_value(try db.get(&fill(1)), fill(10));
        try expect_value(try db.get(&fill(2)), null);
        try expect_value(try db.get_metadata(), null);
        try db.commit();
        const root = db.root();
        const size = db.bounds().end;
        try testing.expectError(error.StaleBatch, db.apply_batch(batch_b));
        db.deinit();
        db = try harness.open(F, null);
        try testing.expect(db.root().eql(root));
        try testing.expectEqual(size, db.bounds().end);
        try expect_value(try db.get(&fill(1)), fill(10));
        try expect_value(try db.get(&fill(2)), null);
    }
}

// The first half of commonware's run_stale_batch_chained: sibling children of one parent.
test "immutable sibling children of a common parent are stale once one applies" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        defer db.deinit();
        const common = try merkleize_set(&db, null, 10, 10);
        defer common.release();
        const sibling_a = try merkleize_set(&db, common, 11, 11);
        defer sibling_a.release();
        const sibling_b = try merkleize_set(&db, common, 12, 12);
        defer sibling_b.release();
        try db.apply_batch(sibling_a);
        try testing.expectError(error.StaleBatch, db.validate_batch(sibling_b));
    }
}

/// The snapshot locations of `fill(key)` for each of `keys`, one per key (sorted within).
fn snapshot_locations(db: anytype, comptime keys: []const u8) ![keys.len]u64 {
    var result: [keys.len]u64 = undefined;
    for (keys, &result) |k, *slot| {
        const bytes = fill(k);
        var positions = db.snapshot.get(&bytes.bytes);
        slot.* = positions.next() orelse return error.TestUnexpectedResult;
        try testing.expect(positions.next() == null); // One location per key.
    }
    return result;
}

// Commonware's run_partial_ancestor_commit: applying a descendant over an applied ancestor and
// unapplied ones (one empty) indexes one location per key, as the reopened rebuild does.
test "immutable a descendant applies over a partly applied chain" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        defer db.deinit();
        const a = try merkleize_set(&db, null, 1, 1);
        defer a.release();
        var empty = a.new_batch();
        const e = try empty.merkleize(&db);
        defer e.release();
        const b = try merkleize_set(&db, e, 2, 2);
        defer b.release();
        const c = try merkleize_set(&db, b, 3, 3);
        defer c.release();
        try db.apply_batch(a);
        try db.apply_batch(c);
        try testing.expect(db.root().eql(c.root()));
        for ([_]u8{ 1, 2, 3 }) |k| try expect_value(try db.get(&fill(k)), fill(k));
        try testing.expectEqual(@as(u64, 3), db.snapshot.len());
        const live = try snapshot_locations(&db, &.{ 1, 2, 3 });
        try db.sync();
        db.deinit();
        db = try harness.open(F, null);
        try testing.expectEqual(@as(u64, 3), db.snapshot.len());
        try testing.expectEqual(live, try snapshot_locations(&db, &.{ 1, 2, 3 }));
    }
}

// Commonware's run_delayed_merkleize_after_ancestor_apply: a held child merkleizes to the same
// root after an ancestor applies, after that ancestor is released (the boundary advances to
// the database), and after its own parent applies.
test "immutable held children merkleize after their ancestors apply" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        defer db.deinit();
        const a = try merkleize_set(&db, null, 1, 1);
        var a_held = true;
        defer if (a_held) a.release();
        const b = try merkleize_set(&db, a, 2, 2);
        defer b.release();
        const pending = try merkleize_set(&db, b, 3, 3);
        defer pending.release();
        const expected = pending.root();
        var held = b.new_batch();
        errdefer held.deinit();
        try held.set(fill(3), fill(3));
        try db.apply_batch(a);
        const live = try merkleize_set(&db, b, 3, 3);
        defer live.release();
        try testing.expect(live.root().eql(expected));
        a.release();
        a_held = false;
        const retired = try held.merkleize(&db);
        defer retired.release();
        try testing.expect(retired.bounds.db.eql(db.commitment()));
        try testing.expect(retired.root().eql(expected));
        var last = b.new_batch();
        errdefer last.deinit();
        try last.set(fill(3), fill(3));
        try db.apply_batch(b);
        const c = try last.merkleize(&db);
        defer c.release();
        try testing.expect(c.root().eql(expected));
        try db.apply_batch(c);
        try testing.expect(db.root().eql(expected));
        for ([_]u8{ 1, 2, 3 }) |k| try expect_value(try db.get(&fill(k)), fill(k));
    }
}

// Commonware's run_child_root_matches_pending_and_committed: a child of an unapplied parent
// has the root of the same set merkleized on the database once the parent commits.
test "immutable a pending child's root matches the committed rebuild" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        defer db.deinit();
        const parent = try merkleize_set(&db, null, 1, 1);
        defer parent.release();
        const pending = try merkleize_set(&db, parent, 2, 2);
        defer pending.release();
        try db.apply_batch(parent);
        try db.commit();
        const committed = try merkleize_set(&db, null, 2, 2);
        defer committed.release();
        try testing.expect(pending.root().eql(committed.root()));
    }
}

// The rest of commonware's run_to_batch: a child chained from `to_batch` applies and reads.
test "immutable a child of to_batch applies and reads" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        defer db.deinit();
        try commit_sets(&db, &.{1}, null);
        const snapshot = try db.to_batch();
        defer snapshot.release();
        try testing.expect(snapshot.root().eql(db.root()));
        const child = try merkleize_set(&db, snapshot, 2, 102);
        defer child.release();
        try expect_value(try child.get(&fill(1), &db), fill(101));
        try db.apply_batch(child);
        try testing.expect(db.root().eql(child.root()));
        try expect_value(try db.get(&fill(1)), fill(101));
        try expect_value(try db.get(&fill(2)), fill(102));
    }
}

// Commonware's run_merkleize_across_prune: a child built before its parent applied still
// merkleizes to the same root after the database prunes to the parent's floor.
test "immutable a held child merkleizes across a prune" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        defer db.deinit();
        var seed: [40]u8 = undefined;
        for (&seed, 0..) |*k, i| k.* = @intCast(i);
        try commit_sets(&db, &seed, null); // Spans several journal blobs.
        var batch = try db.new_batch();
        try batch.set(fill(200), fill(212));
        batch.with_inactivity_floor(db.bounds().end + 1); // The parent's own commit.
        const parent = try batch.merkleize(&db);
        defer parent.release();
        var child = parent.new_batch();
        errdefer child.deinit();
        try child.set(fill(201), fill(213));
        const twin = try merkleize_set(&db, parent, 201, 213);
        const expected = twin.root();
        twin.release();
        try db.apply_batch(parent);
        try db.commit();
        try db.prune(db.inactivity_floor());
        try testing.expect(db.bounds().start > 0); // The prune removed history.
        const merkleized = try child.merkleize(&db);
        defer merkleized.release();
        try testing.expect(merkleized.root().eql(expected));
    }
}

// The rest of commonware's run_batch_chain and run_batch_chained_merkleized_get: a chain reads
// a key none of it set as absent, and a later batch sets it.
test "immutable a chain reads unset keys as absent until a later batch sets them" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        defer db.deinit();
        const parent = try merkleize_set(&db, null, 1, 11);
        defer parent.release();
        const child = try merkleize_set(&db, parent, 2, 12);
        defer child.release();
        try expect_value(try child.get(&fill(1), &db), fill(11));
        try expect_value(try child.get(&fill(2), &db), fill(12));
        try expect_value(try child.get(&fill(3), &db), null);
        try db.apply_batch(child);
        try db.commit();
        try expect_value(try db.get(&fill(1)), fill(11));
        try expect_value(try db.get(&fill(2)), fill(12));
        try expect_value(try db.get(&fill(3)), null);
        try commit_sets(&db, &.{3}, null);
        try expect_value(try db.get(&fill(3)), fill(103));
    }
}
