//! Tests of the compact db's sync `Database` interface: the interface check, a served boundary
//! imported through `from_sync_result` and persisted, and the refused journal shapes.

const std = @import("std");
const testing = std.testing;
const codec = @import("codec");
const merkle = @import("../../merkle/mod.zig");
const database = @import("../sync/database.zig");
const op_mod = @import("operation.zig");
const support = @import("test_support.zig");

const gpa = testing.allocator;
const all_dbs = .{
    support.KeylessFixed(merkle.mmr.Family),
    support.KeylessFixed(merkle.mmb.Family),
    support.ImmutableFixed(merkle.mmr.Family),
    support.ImmutableFixed(merkle.mmb.Family),
};

fn apply(comptime Db: type, db: *Db, seed: u64, count: u64) !void {
    var batch = try db.new_batch();
    const merkleized = merkleized: {
        errdefer batch.deinit();
        for (0..count) |i| try support.mutate(Db, &batch, seed + i);
        break :merkleized try batch.merkleize(db);
    };
    defer merkleized.release();
    try db.apply_batch(merkleized);
}

/// A sync journal holding a clone of `op` at `start`.
fn journal_of(comptime Db: type, op: Db.Operation, start: u64) !Db.Journal {
    var journal = Db.Journal.init(gpa, .{ .start = start, .end = start + 1 });
    errdefer journal.deinit();
    const owned = try op_mod.clone_commit(Db.Operation, gpa, op);
    journal.append(&.{owned}) catch |err| {
        codec.free(Db.Operation, gpa, owned);
        return err;
    };
    return journal;
}

test "compact sync imports a served boundary and persists it" {
    inline for (all_dbs) |Db| {
        comptime database.assert_database(Db);
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        try apply(Db, &db, 1, 3);
        try db.sync();
        const size = db.size();
        const root = db.target().root;
        var response = try db.serve(.{ .boundary = .{ .size = size, .start = size - 1 } });
        defer response.deinit(gpa);
        const served = response.boundary;
        var other = try support.Harness.init(gpa);
        defer other.deinit();
        const cfg = other.cfg(Db);
        const storage = other.storage.interface();
        try Db.discard_local_state(gpa, storage, cfg);
        const range: merkle.Range = .{ .start = size - 1, .end = size };
        const journal = try journal_of(Db, served.op, range.start);
        const target = Db.Target.init(root, range.start, range.end);
        const local = try Db.local_pinned_nodes(gpa, storage, cfg, target, &journal);
        try testing.expectEqual(null, local);
        const pins = try gpa.dupe(Db.Digest, served.pinned_nodes);
        var imported =
            try Db.from_sync_result(gpa, storage, undefined, cfg, journal, pins, range, 1);
        try testing.expect(imported.target().root.eql(root));
        try Db.persist_sync_result(&imported);
        imported.deinit();
        var reopened = try other.open(Db, null);
        defer reopened.deinit();
        try testing.expect(reopened.root().eql(root));
        try testing.expectEqual(size, reopened.size());
    }
}

test "compact sync refuses a journal that is not the start commit" {
    inline for (all_dbs) |Db| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        try apply(Db, &db, 1, 2);
        const size = db.size();
        var response = try db.serve(.{ .boundary = .{ .size = size, .start = size - 1 } });
        defer response.deinit(gpa);
        const op = response.boundary.op;
        const cfg = harness.cfg(Db);
        const storage = harness.storage.interface();
        const range: merkle.Range = .{ .start = size - 1, .end = size };
        // The commit at the wrong location.
        const shifted = try journal_of(Db, op, range.start + 1);
        const pins = try gpa.dupe(Db.Digest, response.boundary.pinned_nodes);
        try testing.expectError(
            error.UnexpectedData,
            Db.from_sync_result(gpa, storage, undefined, cfg, shifted, pins, range, 1),
        );
        // Two operations.
        var doubled = try journal_of(Db, op, range.start);
        const second = try op_mod.clone_commit(Db.Operation, gpa, op);
        doubled.append(&.{second}) catch |err| {
            codec.free(Db.Operation, gpa, second);
            doubled.deinit();
            return err;
        };
        try testing.expectError(
            error.UnexpectedData,
            Db.from_sync_result(gpa, storage, undefined, cfg, doubled, null, range, 1),
        );
        // An empty journal.
        const empty = Db.Journal.init(gpa, .{ .start = range.start, .end = range.end });
        try testing.expectError(
            error.UnexpectedData,
            Db.from_sync_result(gpa, storage, undefined, cfg, empty, null, range, 1),
        );
    }
}

// commonware's compact `validate_target`: the target and every adopted update cover exactly
// the last commit, and a db's own target is one.
test "compact sync accepts only a target covering the last commit" {
    inline for (all_dbs) |Db| {
        var harness = try support.Harness.init(gpa);
        defer harness.deinit();
        var db = try harness.open(Db, null);
        defer db.deinit();
        try apply(Db, &db, 1, 3);
        const reached = db.target();
        try testing.expectEqual(db.size(), reached.end);
        try testing.expectEqual(reached.end - 1, reached.start);
        try Db.validate_target(reached);
        // A merkleized batch reaches the target the db reports once it is applied.
        var batch = try db.new_batch();
        const merkleized = try batch.merkleize(&db);
        defer merkleized.release();
        const expected = merkleized.target();
        try db.apply_batch(merkleized);
        try testing.expect(db.target().eql(expected));
        const wide = Db.Target.init(reached.root, reached.start - 1, reached.end);
        try testing.expectError(error.InvalidTarget, Db.validate_target(wide));
    }
}
