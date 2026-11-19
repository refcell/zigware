//! Recovery, pruning, and multi-key reads of the immutable database (commonware's
//! `qmdb/immutable/mod.rs` scenarios `run_recovery_from_failed_{merkle,log}_sync`,
//! `run_prune_after_uncommitted_apply_batch_recovery`, `run_prune_beyond_floor`,
//! `run_prune_collision_bucket`, and `run_get_many{,_duplicate_keys}`). Every scenario runs
//! under both families; a storage `crash` discards what was not synced, as commonware's
//! deterministic runtime does on an unclean drop.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const merkle = @import("../../merkle/mod.zig");
const metrics = @import("runtime").telemetry.metrics;
const support = @import("test_support.zig");

const gpa = testing.allocator;
const families = .{ merkle.mmr.Family, merkle.mmb.Family };
const Digest = support.Digest;
const fill = support.fill;
const to_digest = support.to_digest;

fn expect_values(actual: []const ?Digest, expected: []const ?Digest) !void {
    try testing.expectEqual(expected.len, actual.len);
    for (actual, expected) |a, e| {
        if (e) |value| {
            try testing.expect(a != null and a.?.eql(value));
        } else {
            try testing.expect(a == null);
        }
    }
}

fn expect_value(actual: ?Digest, expected: ?Digest) !void {
    try expect_values(&.{actual}, &.{expected});
}

/// Sets `to_digest(i)` to `fill(i)` for `i` in `[first, end)` in one batch, and applies it.
fn apply_range(db: anytype, first: u64, end: u64) !void {
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        for (first..end) |i| try batch.set(to_digest(i), fill(@truncate(i)));
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    try db.apply_batch(merkleized);
    assert(db.bounds().end > end - first);
}

/// Sets each pair in one batch with inactivity floor `floor`, and applies it (uncommitted).
fn apply_sets(db: anytype, pairs: []const [2]Digest, floor: ?u64) !void {
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        for (pairs) |pair| try batch.set(pair[0], pair[1]);
        if (floor) |f| batch.with_inactivity_floor(f);
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    try db.apply_batch(merkleized);
}

/// The root, inactivity floor, and size of a database.
const State = struct {
    root: Digest,
    floor: u64,
    end: u64,

    fn of(db: anytype) State {
        const state: State = .{
            .root = db.root(),
            .floor = db.inactivity_floor(),
            .end = db.bounds().end,
        };
        assert(state.floor < state.end);
        return state;
    }

    fn eql(a: State, b: State) bool {
        return a.root.eql(b.root) and a.floor == b.floor and a.end == b.end;
    }
};

fn open_small_sections(comptime F: type, harness: *support.Harness) !support.Fixed(F) {
    const D = support.Fixed(F);
    harness.registry.deinit();
    harness.registry = .init(gpa);
    const scope = metrics.Scope.init(&harness.registry).child("db");
    var cfg = harness.cfg(D);
    cfg.log.items_per_blob = 1;
    return D.init(gpa, harness.storage.interface(), scope, cfg, null);
}

test "immutable recovers from a failed merkle sync by replaying the log" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        errdefer db.deinit();
        const elements: u64 = 1000;
        try apply_range(&db, 0, elements);
        try db.commit();
        try testing.expectEqual(elements + 2, db.bounds().end);
        try db.sync();
        const halfway_root = db.root();
        try apply_range(&db, elements, elements * 2);
        // The commit makes the log durable; the crash loses the unsynced Merkle nodes.
        try db.commit();
        harness.storage.crash();
        db.deinit();
        db = try harness.open(F, null);
        try testing.expectEqual(@as(u64, 2003), db.bounds().end);
        const root = db.root();
        try testing.expect(!root.eql(halfway_root));
        db.deinit();
        db = try harness.open(F, null);
        try testing.expectEqual(@as(u64, 2003), db.bounds().end);
        try testing.expect(db.root().eql(root));
        try db.destroy();
    }
}

test "immutable recovers the last commit after a failed log sync" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        errdefer db.deinit();
        try apply_sets(&db, &.{.{ fill(1), fill(3) }}, null);
        try db.commit();
        const first_commit_root = db.root();
        // Sets never merkleized are lost.
        var lost = try db.new_batch();
        try lost.set(fill(2), fill(4));
        lost.deinit();
        harness.storage.crash();
        db.deinit();
        db = try harness.open(F, null);
        try testing.expectEqual(@as(u64, 3), db.bounds().end);
        try testing.expect(db.root().eql(first_commit_root));
        try db.destroy();
    }
}

test "immutable reopen after pruning an uncommitted floor is coherent" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        errdefer db.deinit();
        // Fill more than one log blob, with a durable floor that still needs the oldest.
        var pairs: [6][2]Digest = undefined;
        for (&pairs, 0..) |*pair, i| pair.* = .{ fill(@intCast(i)), fill(@intCast(i + 10)) };
        try apply_sets(&db, &pairs, null);
        try db.sync();
        const durable = State.of(&db);
        const buffered_floor = db.bounds().end;
        try apply_sets(&db, &.{.{ fill(100), fill(101) }}, buffered_floor);
        const buffered = State.of(&db);
        try testing.expect(!buffered.root.eql(durable.root));
        try db.prune(buffered_floor);
        try testing.expect(db.bounds().start > 0);
        harness.storage.crash();
        db.deinit();
        // Reopen must not recover the old floor once the prune removed what it needs.
        db = try harness.open(F, null);
        try testing.expect(db.bounds().start <= db.inactivity_floor());
        const recovered = State.of(&db);
        try testing.expect(recovered.eql(durable) or recovered.eql(buffered));
        try db.destroy();
    }
}

test "immutable prune may not pass the inactivity floor" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        errdefer db.deinit();
        try testing.expectError(error.PruneBeyondMinRequired, db.prune(1));
        const k1: Digest = .{ .bytes = "12345678901234567890123456789012".* };
        const k2: Digest = .{ .bytes = "abcdefghijklmnopqrstuvwxyz123456".* };
        const k3: Digest = .{ .bytes = "99999999999999999999999999999999".* };
        try apply_sets(&db, &.{ .{ k1, fill(1) }, .{ k2, fill(2) } }, 3);
        try testing.expectEqual(@as(u64, 3), db.bounds().end - 1);
        try apply_sets(&db, &.{.{ k3, fill(3) }}, 5);
        try db.prune(3);
        const floor = db.inactivity_floor();
        try testing.expectEqual(@as(u64, 5), floor);
        try testing.expectError(error.PruneBeyondMinRequired, db.prune(floor + 1));
        try db.destroy();
    }
}

test "immutable prune retires only the pruned location of a collision bucket" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try open_small_sections(F, &harness);
        errdefer db.deinit();
        // Two keys sharing their first two bytes collide under TwoCap.
        var k1: Digest = .{ .bytes = @splat(0) };
        k1.bytes[0] = 0xAA;
        k1.bytes[1] = 0xBB;
        var k2 = k1;
        k1.bytes[31] = 0x01;
        k2.bytes[31] = 0x02;
        const k3 = fill(3);
        // 0: initial commit, 1: Set(k1), 2: commit, 3-4: Set(k2), Set(k3), 5: commit(floor 4).
        try apply_sets(&db, &.{.{ k1, fill(1) }}, null);
        try apply_sets(&db, &.{ .{ k2, fill(2) }, .{ k3, fill(3) } }, 4);
        try expect_value(try db.get(&k1), fill(1));
        try expect_value(try db.get(&k2), fill(2));
        try testing.expectEqual(@as(u64, 3), db.snapshot.len());
        try db.prune(2);
        try testing.expectEqual(@as(u64, 2), db.bounds().start);
        try testing.expectEqual(@as(u64, 2), db.snapshot.len());
        try expect_value(try db.get(&k1), null);
        try expect_value(try db.get(&k2), fill(2));
        try expect_value(try db.get(&k3), fill(3));
        try db.destroy();
    }
}

test "immutable get_many reads the database, batches, and chains" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        errdefer db.deinit();
        const k1 = fill(1);
        const k2 = fill(2);
        const k3 = fill(3);
        const k4 = fill(4);
        const missing = fill(99);
        try apply_sets(&db, &.{ .{ k1, fill(11) }, .{ k2, fill(12) } }, null);
        try db.commit();
        var out: [4]?Digest = undefined;
        try db.get_many(&.{ k1, k2, missing }, out[0..3]);
        try expect_values(out[0..3], &.{ fill(11), fill(12), null });
        try db.get_many(&.{}, out[0..0]);
        // An unmerkleized batch reads its sets, then the database.
        var pending = try db.new_batch();
        try pending.set(k3, fill(13));
        try pending.get_many(&.{ k3, k1, missing }, &db, out[0..3]);
        try expect_values(out[0..3], &.{ fill(13), fill(11), null });
        // A merkleized batch reads its diff, then the database.
        const parent = try pending.merkleize(&db);
        defer parent.release();
        try parent.get_many(&.{ k1, k3, missing }, &db, out[0..3]);
        try expect_values(out[0..3], &.{ fill(11), fill(13), null });
        // A child reads its sets, its parent's diff, then the database.
        var child = parent.new_batch();
        defer child.deinit();
        try child.set(k4, fill(14));
        try child.get_many(&.{ k1, k3, k4, missing }, &db, &out);
        try expect_values(&out, &.{ fill(11), fill(13), fill(14), null });
        // Every slot of a repeated key is filled.
        try db.get_many(&.{ k1, missing, k1, k1 }, &out);
        try expect_values(&out, &.{ fill(11), null, fill(11), fill(11) });
        try db.destroy();
    }
}
