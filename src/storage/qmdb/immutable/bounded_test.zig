//! Bounded initialization of the immutable database (commonware's `qmdb/immutable/mod.rs`
//! `run_bounded_initialization_*` scenarios, as `fixed.rs` runs them): reopening with
//! `max_size` selects an earlier commit and rebuilds that commit's snapshot and floor. Every
//! scenario runs under both families. Commonware drops a database by shadowing it; here each
//! open first closes the previous handle with `deinit`.

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

const Pair = struct { Digest, Digest };

fn expect_value(actual: ?Digest, expected: ?Digest) !void {
    if (expected) |e| {
        try testing.expect(actual != null and actual.?.eql(e));
    } else {
        try testing.expect(actual == null);
    }
}

/// Commonware's `commit_sets_with_floor` (and `commit_sets` with a null `floor`): sets every
/// pair in one batch with `metadata`, applies it, and commits.
fn commit_sets(db: anytype, pairs: []const Pair, metadata: ?Digest, floor: ?u64) !void {
    const before = db.bounds().end;
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        for (pairs) |pair| try batch.set(pair[0], pair[1]);
        if (metadata) |m| batch.with_metadata(m);
        if (floor) |f| batch.with_inactivity_floor(f);
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    try db.apply_batch(merkleized);
    try db.commit();
    assert(db.bounds().end == before + pairs.len + 1);
}

/// Opens the fixed database with one operation per log blob (commonware's
/// `small_sections_config`), so pruning removes history at every commit.
fn open_small_sections(
    comptime F: type,
    harness: *support.Harness,
    max_size: ?u64,
) !support.Fixed(F) {
    const D = support.Fixed(F);
    harness.registry.deinit();
    harness.registry = .init(gpa);
    const scope = metrics.Scope.init(&harness.registry).child("db");
    var cfg = harness.cfg(D);
    cfg.log.items_per_blob = 1;
    return D.init(gpa, harness.storage.interface(), scope, cfg, max_size);
}

test "immutable bounded initialization recovers an earlier commit" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        errdefer db.deinit();
        const k1 = to_digest(1);
        const k2 = to_digest(2);
        const k3 = to_digest(3);
        const k4 = to_digest(4);
        try commit_sets(&db, &.{ .{ k1, fill(11) }, .{ k2, fill(22) } }, fill(44), null);
        const size_before = db.bounds().end;
        const root_before = db.root();
        try commit_sets(&db, &.{ .{ k3, fill(33) }, .{ k4, fill(66) } }, fill(55), null);
        try testing.expect(!db.root().eql(root_before));
        try expect_value(try db.get_metadata(), fill(55));
        try expect_value(try db.get(&k3), fill(33));
        try expect_value(try db.get(&k4), fill(66));
        try db.sync();
        db.deinit();
        db = try harness.open(F, size_before);
        // Committing the bounded state makes it the durable one: a plain reopen keeps it.
        for (0..2) |round| {
            try testing.expect(db.root().eql(root_before));
            try testing.expectEqual(size_before, db.bounds().end);
            try expect_value(try db.get_metadata(), fill(44));
            try expect_value(try db.get(&k1), fill(11));
            try expect_value(try db.get(&k2), fill(22));
            try expect_value(try db.get(&k3), null);
            try expect_value(try db.get(&k4), null);
            if (round == 1) break;
            try db.commit();
            db.deinit();
            db = try harness.open(F, null);
        }
        try db.destroy();
    }
}

test "immutable bounded initialization preserves a colliding retained key" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        errdefer db.deinit();
        // Two keys sharing their first two bytes collide under TwoCap.
        var k1: Digest = .{ .bytes = @splat(0) };
        k1.bytes[0] = 0xAA;
        k1.bytes[1] = 0xBB;
        var k2 = k1;
        k1.bytes[31] = 0x01;
        k2.bytes[31] = 0x02;
        try commit_sets(&db, &.{.{ k1, fill(11) }}, null, null);
        const size_after_first = db.bounds().end;
        try commit_sets(&db, &.{.{ k2, fill(22) }}, null, null);
        try expect_value(try db.get(&k1), fill(11));
        try expect_value(try db.get(&k2), fill(22));
        try db.sync();
        db.deinit();
        db = try harness.open(F, size_after_first);
        // Removing the suffix's key must not wipe the retained key's translator bucket.
        try expect_value(try db.get(&k1), fill(11));
        try expect_value(try db.get(&k2), null);
        try db.destroy();
    }
}

test "immutable bounded initialization at a pruned target fails" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try open_small_sections(F, &harness, null);
        errdefer db.deinit();
        const first_start = db.bounds().end;
        var pairs: [16]Pair = undefined;
        for (&pairs, 0..) |*pair, i| pair.* = .{ to_digest(i), fill(@intCast(i)) };
        try commit_sets(&db, &pairs, null, null);
        var round: u64 = 0;
        while (db.bounds().start <= first_start) {
            round += 1;
            try testing.expect(round <= 64);
            for (&pairs, 0..) |*pair, i| {
                const seed = round * 100 + i;
                pair.* = .{ to_digest(seed), fill(@truncate(seed)) };
            }
            // The floor must reach the batch's commit for the prune to it to succeed.
            try commit_sets(&db, &pairs, null, db.bounds().end + 16);
            try db.prune(db.bounds().end - 1);
        }
        const oldest_retained = db.bounds().start;
        try db.sync();
        db.deinit();
        const at_boundary = open_small_sections(F, &harness, oldest_retained);
        try testing.expectError(error.ItemPruned, at_boundary);
        db = try open_small_sections(F, &harness, null);
        try db.sync();
        db.deinit();
        try testing.expectError(error.ItemPruned, open_small_sections(F, &harness, first_start));
        db = try open_small_sections(F, &harness, null);
        try db.destroy();
    }
}

test "immutable bounded initialization restores the earlier floor" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        errdefer db.deinit();
        try commit_sets(&db, &.{.{ fill(1), fill(2) }}, null, 2);
        const first_size = db.bounds().end;
        try testing.expectEqual(@as(u64, 2), db.inactivity_floor());
        try commit_sets(&db, &.{.{ fill(3), fill(4) }}, null, 4);
        try testing.expectEqual(@as(u64, 4), db.inactivity_floor());
        try db.sync();
        db.deinit();
        db = try harness.open(F, first_size);
        try testing.expectEqual(@as(u64, 2), db.inactivity_floor());
        try db.destroy();
    }
}

test "immutable bounded initialization rebuilds below a later reopen's floor" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        errdefer db.deinit();
        const a = [_]Pair{ .{ fill(1), fill(11) }, .{ fill(2), fill(12) }, .{ fill(3), fill(13) } };
        try commit_sets(&db, &a, null, null);
        const first_size = db.bounds().end;
        const first_root = db.root();
        // Commit B declares batch A inactive.
        const b = [_]Pair{ .{ fill(4), fill(14) }, .{ fill(5), fill(15) }, .{ fill(6), fill(16) } };
        try commit_sets(&db, &b, null, first_size);
        try db.sync();
        db.deinit();
        db = try harness.open(F, null);
        try expect_value(try db.get(&fill(1)), null);
        try db.sync();
        db.deinit();
        db = try harness.open(F, first_size);
        for (a) |pair| try expect_value(try db.get(&pair[0]), pair[1]);
        try testing.expect(db.root().eql(first_root));
        try testing.expectEqual(@as(u64, 0), db.inactivity_floor());
        try expect_value(try db.get(&fill(4)), null);
        try db.destroy();
    }
}

test "immutable bounded initialization rebuilds each commit's own snapshot" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        errdefer db.deinit();
        try commit_sets(&db, &.{.{ fill(1), fill(11) }}, null, null);
        const first_size = db.bounds().end;
        const first_root = db.root();
        try commit_sets(&db, &.{.{ fill(2), fill(12) }}, null, first_size);
        const second_size = db.bounds().end;
        // Commit C's floor excludes both A's and B's keys on reopen.
        try commit_sets(&db, &.{.{ fill(3), fill(13) }}, null, second_size);
        try db.sync();
        db.deinit();
        db = try harness.open(F, null);
        try expect_value(try db.get(&fill(1)), null);
        try expect_value(try db.get(&fill(2)), null);
        try expect_value(try db.get(&fill(3)), fill(13));
        try db.sync();
        db.deinit();
        // B's snapshot: its floor excludes A's key, and its end excludes C's.
        db = try harness.open(F, second_size);
        try expect_value(try db.get(&fill(1)), null);
        try expect_value(try db.get(&fill(2)), fill(12));
        try expect_value(try db.get(&fill(3)), null);
        try db.sync();
        db.deinit();
        db = try harness.open(F, first_size);
        try expect_value(try db.get(&fill(1)), fill(11));
        try expect_value(try db.get(&fill(2)), null);
        try testing.expect(db.root().eql(first_root));
        try testing.expectEqual(@as(u64, 0), db.inactivity_floor());
        try db.destroy();
    }
}
