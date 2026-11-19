//! Prune and build scenarios of commonware's `qmdb/immutable/mod.rs` that need their own log
//! section sizes, under both families.

const std = @import("std");
const testing = std.testing;
const merkle = @import("../../merkle/mod.zig");
const verify = @import("../verify.zig");
const support = @import("test_support.zig");
const metrics = @import("runtime").telemetry.metrics;

const gpa = testing.allocator;
const families = .{ merkle.mmr.Family, merkle.mmb.Family };
const Digest = support.Digest;
const Sha256 = support.Sha256;
const fill = support.fill;
const to_digest = support.to_digest;

/// Opens the fixed database with `items_per_blob` operations per log section.
fn open_sections(
    comptime F: type,
    harness: *support.Harness,
    items_per_blob: u64,
) !support.Fixed(F) {
    const D = support.Fixed(F);
    harness.registry.deinit();
    harness.registry = .init(gpa);
    const scope = metrics.Scope.init(&harness.registry).child("db");
    var cfg = harness.cfg(D);
    cfg.log.items_per_blob = items_per_blob;
    return D.init(gpa, harness.storage.interface(), scope, cfg, null);
}

/// Applies one batch setting `to_digest(i)` to `fill(i)` for `i` in `[first, end)`, with `floor`.
fn apply_hashed(db: anytype, first: u64, end: u64, floor: ?u64) !void {
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        var i = first;
        while (i < end) : (i += 1) try batch.set(to_digest(i), fill(@truncate(i)));
        if (floor) |f| batch.with_inactivity_floor(f);
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    try db.apply_batch(merkleized);
}

fn digest_less(_: void, a: Digest, b: Digest) bool {
    return std.mem.order(u8, &a.bytes, &b.bytes) == .lt;
}

const elements = 2000;
const items_per_section = 5;

/// The key a batch of `to_digest(1..=elements)` sets at location `location` (sorted order).
fn key_at(sorted: *const [elements]Digest, location: u64) Digest {
    return sorted[@intCast(location - 1)];
}

// Commonware's run_pruning: pruning at a section boundary retains exactly it, a mid-section
// prune rounds down, both persist, the reopened snapshot starts at the floor, and proofs of
// pruned operations fail.
test "immutable pruning keeps whole sections and persists across reopen" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try open_sections(F, &harness, items_per_section);
        defer db.deinit();
        var sorted: [elements]Digest = undefined;
        for (&sorted, 1..) |*k, i| k.* = to_digest(i);
        std.mem.sort(Digest, &sorted, {}, digest_less);
        const floor = elements / 2 + items_per_section * 2 - 1;
        const half: merkle.Range = .{ .start = elements / 2, .end = elements + 2 };
        try apply_hashed(&db, 1, elements + 1, floor);
        try testing.expectEqual(@as(u64, elements + 2), db.bounds().end);
        try db.prune((elements + 2) / 2);
        try testing.expectEqual(half, db.bounds());
        const start = db.bounds().start;
        try testing.expect(try db.get(&key_at(&sorted, start - 1)) == null);
        // The key at the retained start is below the floor, so it is not read either; the key
        // at the floor is.
        try testing.expect(try db.get(&key_at(&sorted, start)) == null);
        try testing.expect(try db.get(&key_at(&sorted, floor)) != null);
        const root = db.root();
        try db.sync();
        db.deinit();
        db = try open_sections(F, &harness, items_per_section);
        try testing.expect(db.root().eql(root));
        try testing.expectEqual(half, db.bounds());
        try db.prune(elements / 2 + items_per_section * 2 - 1); // Mid-section: rounds down.
        try testing.expectEqual(@as(u64, elements / 2 + items_per_section), db.bounds().start);
        try db.sync();
        db.deinit();
        db = try open_sections(F, &harness, items_per_section);
        try testing.expectEqual(@as(u64, elements / 2 + items_per_section), db.bounds().start);
        try testing.expect(try db.get(&key_at(&sorted, floor - 1)) == null);
        try testing.expect(try db.get(&key_at(&sorted, floor)) != null);
        try testing.expectError(error.ItemPruned, db.proof(elements / 2, elements / 2 + 100));
    }
}

// Commonware's run_prune_retires_pruned_sets: with one operation per section, each prune
// retires exactly the sets below the retained start from the index, and a set at the retained
// start survives; it is readable when it is at or above the floor.
test "immutable prune retires exactly the sets below the retained start" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try open_sections(F, &harness, 1);
        defer db.deinit();
        // Location 0 is the initial commit, then set `i` at 2i+1 and its commit at 2i+2.
        for (0..10) |i| {
            var batch = try db.new_batch();
            errdefer batch.deinit();
            try batch.set(fill(@intCast(i)), fill(@intCast(i)));
            batch.with_inactivity_floor(db.bounds().end);
            const merkleized = try batch.merkleize(&db);
            defer merkleized.release();
            try db.apply_batch(merkleized);
        }
        try testing.expectEqual(merkle.Range{ .start = 0, .end = 21 }, db.bounds());
        try testing.expectEqual(@as(u64, 10), db.snapshot.len());
        for ([_]u64{ 2, 4, 6 }) |location| {
            try db.prune(location);
            try testing.expectEqual(location, db.bounds().start);
            try testing.expectEqual(10 - location / 2, db.snapshot.len());
        }
        try testing.expect(try db.get(&fill(0)) == null);
        // The set at 9 stays indexed at the pruning boundary, though it is below the floor.
        const key4 = fill(4);
        try db.prune(9); // Retires the set at 7.
        try testing.expectEqual(@as(u64, 6), db.snapshot.len());
        var positions = db.snapshot.get(&key4.bytes);
        try testing.expectEqual(@as(?u64, 9), positions.next());
        try testing.expectEqual(@as(?u64, null), positions.next());
        try testing.expect(try db.get(&key4) == null);
        // Pruning past it retires it from the index too.
        try db.prune(10);
        try testing.expectEqual(@as(u64, 5), db.snapshot.len());
        var retired = db.snapshot.get(&key4.bytes);
        try testing.expectEqual(@as(?u64, null), retired.next());
        // Pruning to the floor keeps the set there, which stays readable.
        try testing.expectEqual(@as(u64, 19), db.inactivity_floor());
        try db.prune(19);
        try testing.expectEqual(@as(u64, 19), db.bounds().start);
        try testing.expectEqual(@as(u64, 1), db.snapshot.len());
        try testing.expect(try db.get(&fill(8)) == null);
        try testing.expect((try db.get(&fill(9))).?.eql(fill(9)));
    }
}

// Commonware's run_build_and_authenticate: 2000 sets survive reopen, and every range of five
// operations (truncated at the end) proves against the root.
test "immutable a large database reopens and proves every range" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        defer db.deinit();
        try apply_hashed(&db, 0, elements, null);
        try db.commit();
        try testing.expectEqual(@as(u64, elements + 2), db.bounds().end);
        const root = db.root();
        db.deinit();
        db = try harness.open(F, null);
        try testing.expect(db.root().eql(root));
        try testing.expectEqual(@as(u64, elements + 2), db.bounds().end);
        for (0..elements) |i| {
            try testing.expect((try db.get(&to_digest(i))).?.eql(fill(@truncate(i))));
        }
        const Op = support.Fixed(F).Operation;
        for (0..elements + 2) |i| {
            var proved = try db.proof(i, 5);
            defer proved.deinit(gpa);
            const items = proved.items;
            try testing.expectEqual(@min(5, elements + 2 - i), items.len);
            const proof = &proved.proof;
            try testing.expect(try verify.verify(F, Sha256, Op, gpa, proof, i, items, &root));
        }
    }
}

fn expect_digest(actual: ?Digest, expected: ?Digest) !void {
    try testing.expectEqual(expected == null, actual == null);
    if (expected) |e| try testing.expect(actual.?.eql(e));
}

// Commonware's run_single_commit_live_set: a floor at its own commit retires its sets from
// reads at once (they stay indexed until pruned), allows pruning to the commit but not past
// it, and keeps the commit's metadata.
test "immutable a commit at its own floor anchors the pruned database" {
    inline for (families) |F| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(F, null);
        defer db.deinit();
        const commit_loc = 4; // The initial commit, three sets, then this commit.
        var batch = try db.new_batch();
        errdefer batch.deinit();
        for ([_]u8{ 1, 2, 3 }) |k| try batch.set(fill(k), fill(k + 10));
        batch.with_metadata(fill(42));
        batch.with_inactivity_floor(commit_loc);
        const merkleized = try batch.merkleize(&db);
        defer merkleized.release();
        try db.apply_batch(merkleized);
        try db.commit();
        try testing.expectEqual(@as(u64, commit_loc + 1), db.bounds().end);
        try testing.expectEqual(@as(u64, commit_loc), db.inactivity_floor());
        const root = db.root();
        try testing.expectEqual(@as(u64, 3), db.snapshot.len());
        const keys = [_]Digest{ fill(1), fill(2), fill(3) };
        var values: [keys.len]?Digest = undefined;
        try db.get_many(&keys, &values);
        for (values) |got| try expect_digest(got, null);
        try db.prune(commit_loc);
        try testing.expect(db.bounds().start <= commit_loc);
        try testing.expectEqual(@as(u64, commit_loc + 1), db.bounds().end);
        try testing.expect(db.root().eql(root));
        try expect_digest(try db.get_metadata(), fill(42));
        try db.sync();
        try testing.expectError(error.PruneBeyondMinRequired, db.prune(commit_loc + 1));
        db.deinit();
        db = try harness.open(F, null);
        try testing.expectEqual(@as(u64, commit_loc + 1), db.bounds().end);
        try testing.expectEqual(@as(u64, commit_loc), db.inactivity_floor());
        try testing.expect(db.root().eql(root));
        try expect_digest(try db.get_metadata(), fill(42));
        for ([_]u8{ 1, 2, 3 }) |k| try expect_digest(try db.get(&fill(k)), null);
        var next = try db.new_batch();
        errdefer next.deinit();
        try next.set(fill(4), fill(14));
        next.with_inactivity_floor(commit_loc + 2);
        const follow = try next.merkleize(&db);
        defer follow.release();
        try db.apply_batch(follow);
        try db.commit();
        try testing.expectEqual(@as(u64, commit_loc + 2), db.inactivity_floor());
        // The new commit's floor retires the new key too, though it stays indexed until pruned.
        try testing.expectEqual(@as(u64, 1), db.snapshot.len());
        try expect_digest(try db.get(&fill(4)), null);
        try expect_digest(try db.get(&fill(1)), null);
        try expect_digest(try db.get_metadata(), null);
    }
}
