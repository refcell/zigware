//! Tests of the compact db, ported from commonware's `qmdb/compact/db.rs` (`compact_db_tests!`)
//! and the keyless and immutable `compact.rs` tests. Each scenario runs over the keyless and
//! immutable fixed dbs of both families.

const std = @import("std");
const testing = std.testing;
const merkle = @import("../../merkle/mod.zig");
const verify = @import("../verify.zig");
const support = @import("test_support.zig");
const compact = @import("mod.zig");

const gpa = testing.allocator;
const Mmr = merkle.mmr.Family;
const Mmb = merkle.mmb.Family;
const digest = support.digest;
const mutate = support.mutate;
const metadata_value = support.metadata_value;
const all_dbs = .{
    support.KeylessFixed(Mmr),
    support.KeylessFixed(Mmb),
    support.ImmutableFixed(Mmr),
    support.ImmutableFixed(Mmb),
};

/// Merkleizes a batch of `count` mutations from `seed` with `metadata` on `db`.
fn merkleize(comptime Db: type, db: *Db, seed: u64, count: u64) !*Db.MerkleizedBatch {
    var batch = try db.new_batch();
    errdefer batch.deinit();
    for (0..count) |i| try mutate(Db, &batch, seed + i);
    return batch.merkleize(db);
}

fn apply(comptime Db: type, db: *Db, seed: u64, count: u64) !void {
    const batch = try merkleize(Db, db, seed, count);
    defer batch.release();
    try db.apply_batch(batch);
}

test "compact fresh db has the initial root and survives reopen" {
    inline for (all_dbs) |Db| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        try testing.expectEqual(@as(u64, 1), db.size());
        const initial = compact.initial_root(Db.Family, Db.Operation, support.Sha256);
        try testing.expect(db.root().eql(initial));
        db.deinit();
        db = try harness.open(Db, null);
        try testing.expect(db.root().eql(initial));
    }
}

// Commonware's `test_compact_commit_persists_across_reopen` and
// `test_compact_reopen_drops_unsynced_witness`.
test "compact commit persists and an uncommitted witness is dropped" {
    inline for (all_dbs) |Db| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        var batch = try db.new_batch();
        try mutate(Db, &batch, 1);
        batch.with_metadata(metadata_value(Db, 7));
        const merkleized = try batch.merkleize(&db);
        try db.apply_batch(merkleized);
        merkleized.release();
        try db.commit();
        const root = db.root();
        const size = db.size();
        try apply(Db, &db, 10, 3);
        try testing.expect(db.size() > size);
        db.deinit();
        harness.storage.crash();
        db = try harness.open(Db, null);
        try testing.expect(db.root().eql(root));
        try testing.expectEqual(size, db.size());
        try testing.expectEqual(@as(?Db.Value, metadata_value(Db, 7)), try db.get_metadata());
    }
}

// Commonware's `test_compact_bounded_initialization_multiple_commits`,
// `test_compact_initialization_zero_and_above_end`, and
// `test_compact_prune_then_bounded_initialization`.
test "compact bounded initialization selects a retained witness" {
    inline for (all_dbs) |Db| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        // One witness per section, so pruning drops every witness below its boundary.
        harness.items_per_section = 1;
        var db = try harness.open(Db, null);
        defer db.deinit();
        var sizes: [4]u64 = undefined;
        var roots: [4]support.Digest = undefined;
        for (&sizes, &roots, 0..) |*size, *root, i| {
            try apply(Db, &db, 100 * i, 3);
            size.* = db.size();
            root.* = db.root();
        }
        try db.sync();
        try testing.expectError(error.InvalidInitializationBound, harness.open(Db, 0));
        // A bound between commits selects the earlier one, and discards the newer ones.
        db.deinit();
        db = try harness.open(Db, sizes[2] - 1);
        try testing.expectEqual(sizes[1], db.size());
        try testing.expect(db.root().eql(roots[1]));
        db.deinit();
        db = try harness.open(Db, null);
        try testing.expectEqual(sizes[1], db.size());
        // A bound above the end opens the tip; pruning drops the witnesses below it.
        db.deinit();
        db = try harness.open(Db, sizes[3] + 100);
        try testing.expectEqual(sizes[1], db.size());
        try db.prune(sizes[1]);
        db.deinit();
        db = harness.open(Db, sizes[0]) catch |err| open: {
            try testing.expectEqual(error.HistoricalFloorPruned, err);
            break :open try harness.open(Db, sizes[1]);
        };
        try testing.expectEqual(sizes[1], db.size());
        try testing.expect(db.root().eql(roots[1]));
    }
}

// Commonware's `test_compact_stale_batch_rejected`, `test_compact_stale_batch_chained`, and
// `test_compact_sequential_commit_parent_then_child`.
test "compact stale batches are rejected and chains apply in order" {
    inline for (all_dbs) |Db| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        const first = try merkleize(Db, &db, 1, 2);
        defer first.release();
        const sibling = try merkleize(Db, &db, 50, 2);
        defer sibling.release();
        var child_batch = first.new_batch();
        const child = child: {
            errdefer child_batch.deinit();
            try mutate(Db, &child_batch, 9);
            break :child try child_batch.merkleize(&db);
        };
        defer child.release();
        try db.apply_batch(first);
        try testing.expectError(error.StaleBatch, db.apply_batch(sibling));
        try testing.expectError(error.StaleBatch, db.apply_batch(first));
        try db.apply_batch(child);
        try testing.expect(db.root().eql(child.root()));
        // A child applied directly (skipping its parent) reaches the same root.
        var other_harness = try support.Harness.init(gpa);
        defer other_harness.deinit();
        var other = try other_harness.open(Db, null);
        defer other.deinit();
        const parent = try merkleize(Db, &other, 1, 2);
        defer parent.release();
        var direct_batch = parent.new_batch();
        const direct = direct: {
            errdefer direct_batch.deinit();
            try mutate(Db, &direct_batch, 9);
            break :direct try direct_batch.merkleize(&other);
        };
        defer direct.release();
        try other.apply_batch(direct);
        try testing.expect(other.root().eql(db.root()));
    }
}

// Commonware's `test_compact_floor_regressed` and `test_compact_floor_beyond_commit`.
test "compact merkleize checks the inactivity floor" {
    inline for (all_dbs) |Db| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        var advance = try db.new_batch();
        try mutate(Db, &advance, 1);
        advance.with_inactivity_floor(1);
        const advanced = try advance.merkleize(&db);
        try db.apply_batch(advanced);
        advanced.release();
        try testing.expectEqual(@as(u64, 1), db.inactivity_floor());
        var regress = try db.new_batch();
        defer regress.deinit();
        regress.with_inactivity_floor(0);
        try testing.expectError(error.FloorRegressed, regress.merkleize(&db));
        var beyond = try db.new_batch();
        defer beyond.deinit();
        beyond.with_inactivity_floor(db.size() + 1);
        try testing.expectError(error.FloorBeyondCommit, beyond.merkleize(&db));
    }
}

// Commonware's `test_compact_operations_and_proof`.
test "compact batch operations verify with their proof and pinned nodes" {
    inline for (all_dbs) |Db| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        try apply(Db, &db, 1, 5);
        const batch = try merkleize(Db, &db, 20, 4);
        defer batch.release();
        const start, const ops = batch.operations();
        try testing.expectEqual(db.size(), start);
        var proof = try batch.proof(&db);
        defer proof.deinit(gpa);
        var pins: [merkle.max_pinned_nodes]support.Digest = undefined;
        const pinned = try batch.pinned_nodes(&db, &pins);
        const F = Db.Family;
        const O = Db.Operation;
        const root = batch.root();
        try testing.expect(try verify.verify(F, support.Sha256, O, gpa, &proof, start, ops, &root));
        try testing.expect(try verify.verify_with_pinned_nodes(
            F,
            support.Sha256,
            O,
            gpa,
            &proof,
            start,
            ops,
            pinned,
            &root,
        ));
        const snapshot = try db.to_batch();
        defer snapshot.release();
        try testing.expectError(error.Empty, snapshot.proof(&db));
    }
}

// Commonware's `test_serve_retained_witnesses`, `test_serve_refuses_requests_outside_witness`,
// and `test_compact_import_then_apply_persists`.
test "compact serves retained witnesses and imports them" {
    inline for (all_dbs) |Db| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        try apply(Db, &db, 1, 3);
        const old_size = db.size();
        const old_root = db.root();
        try apply(Db, &db, 10, 3);
        try db.sync();
        const tip = db.size();
        try testing.expectError(error.RangeOutOfBounds, db.serve(.{ .boundary = .{
            .size = tip + 1,
            .start = tip,
        } }));
        try testing.expectError(error.ItemPruned, db.serve(.{ .operations = .{
            .size = tip,
            .start = tip - 2,
            .max_ops = 2,
        } }));
        try testing.expectError(error.ItemPruned, db.serve(.{ .boundary = .{
            .size = old_size + 1,
            .start = old_size,
        } }));
        var response = try db.serve(.{ .boundary = .{ .size = old_size, .start = old_size - 1 } });
        defer response.deinit(gpa);
        const served = response.boundary;
        const F = Db.Family;
        const ops = [_]Db.Operation{served.op};
        try testing.expect(try verify.verify_with_pinned_nodes(
            F,
            support.Sha256,
            Db.Operation,
            gpa,
            &served.proof,
            old_size - 1,
            &ops,
            served.pinned_nodes,
            &old_root,
        ));
        // Import the old state into a fresh partition, then keep writing on it.
        var other_harness = try support.Harness.init(gpa);
        defer other_harness.deinit();
        const cfg = other_harness.cfg(Db);
        const op = try @import("operation.zig").clone_commit(Db.Operation, gpa, served.op);
        const storage = other_harness.storage.interface();
        var imported =
            try Db.init_from_sync(gpa, storage, cfg, old_size - 1, served.pinned_nodes, op);
        defer imported.deinit();
        try testing.expect(imported.root().eql(old_root));
        try apply(Db, &imported, 10, 3);
        try testing.expect(imported.root().eql(db.root()));
        try imported.sync();
        imported.deinit();
        imported = try other_harness.open(Db, null);
        try testing.expect(imported.root().eql(db.root()));
        try testing.expectEqual(tip, imported.size());
    }
}

// Commonware's `test_compact_append_order_is_significant`.
test "compact keyless append order changes the root" {
    const Db = support.KeylessFixed(Mmr);
    var harness_a = try support.Harness.init(gpa);
    defer harness_a.deinit();
    var harness_b = try support.Harness.init(gpa);
    defer harness_b.deinit();
    var a = try harness_a.open(Db, null);
    defer a.deinit();
    var b = try harness_b.open(Db, null);
    defer b.deinit();
    for ([_]*Db{ &a, &b }, [_][2]u64{ .{ 1, 2 }, .{ 2, 1 } }) |db, order| {
        var batch = try db.new_batch();
        for (order) |x| try batch.append(support.U64.init(x));
        const merkleized = try batch.merkleize(db);
        defer merkleized.release();
        try db.apply_batch(merkleized);
    }
    try testing.expectEqual(@as(u64, 4), a.size());
    try testing.expectEqual(a.size(), b.size());
    try testing.expect(!a.root().eql(b.root()));
}

// Commonware's `test_compact_set_same_key_twice_keeps_last` and
// `test_compact_set_order_is_insignificant`.
test "compact immutable sets keep the last per key in key order" {
    const Db = support.ImmutableFixed(Mmb);
    var harnesses: [3]support.Harness = undefined;
    for (&harnesses) |*harness| harness.* = try support.Harness.init(gpa);
    defer for (&harnesses) |*harness| harness.deinit();
    var dbs: [3]Db = undefined;
    for (&dbs, &harnesses) |*db, *harness| db.* = try harness.open(Db, null);
    defer for (&dbs) |*db| db.deinit();
    const sets = [3][]const [2]u64{
        &.{ .{ 1, 5 }, .{ 2, 6 }, .{ 1, 7 } },
        &.{ .{ 2, 6 }, .{ 1, 7 } },
        &.{ .{ 1, 7 }, .{ 2, 6 } },
    };
    for (&dbs, sets) |*db, pairs| {
        var batch = try db.new_batch();
        for (pairs) |pair| try batch.set(digest(pair[0]), digest(pair[1]));
        const merkleized = try batch.merkleize(db);
        defer merkleized.release();
        try db.apply_batch(merkleized);
    }
    try testing.expectEqual(@as(u64, 4), dbs[0].size());
    try testing.expect(dbs[0].root().eql(dbs[1].root()));
    try testing.expect(dbs[1].root().eql(dbs[2].root()));
}
